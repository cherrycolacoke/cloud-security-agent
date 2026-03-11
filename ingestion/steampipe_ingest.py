#!/usr/bin/env python3
"""
steampipe_ingest.py
-------------------
Syncs live AWS inventory via Steampipe into cloud_security PostgreSQL.

Usage:
  python3 steampipe_ingest.py --sync    # live AWS data via Steampipe
  python3 steampipe_ingest.py --sample  # load sample data (no AWS needed)
"""

import argparse
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values

DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}
STEAMPIPE_DB = {
    "host":    "localhost",
    "port":    9193,
    "dbname":  "steampipe",
    "user":    "steampipe",
    "password": os.getenv("STEAMPIPE_PASSWORD", ""),
}

STEAMPIPE_QUERIES = {
    "instances": """
        SELECT instance_id, account_id, region, arn AS resource_arn,
               instance_state, instance_type, launch_time,
               vpc_id, subnet_id, private_ip_address AS private_ip,
               public_ip_address AS public_ip, public_dns_name AS public_dns,
               iam_instance_profile_arn AS iam_instance_profile,
               key_name, tags ->> 'Name' AS name_tag,
               tags, to_jsonb(i) AS raw_json
        FROM aws_ec2_instance i WHERE instance_state != 'terminated'
    """,
    "s3": """
        SELECT name AS bucket_name, account_id, region,
               'arn:aws:s3:::' || name AS resource_arn,
               bucket_policy_is_public AS public_access_blocked,
               versioning_enabled, logging IS NOT NULL AS logging_enabled,
               server_side_encryption_configuration IS NOT NULL AS encryption_enabled,
               creation_date, tags, to_jsonb(b) AS raw_json
        FROM aws_s3_bucket b
    """,
    "iam": """
        SELECT name AS user_name, account_id, user_id,
               arn AS resource_arn, mfa_enabled,
               (login_profile IS NOT NULL) AS has_console_access,
               (mfa_devices IS NOT NULL AND jsonb_array_length(mfa_devices) > 0) AS has_access_keys,
               password_last_used, NULL::timestamptz AS access_key_last_used,
               create_date, tags, to_jsonb(u) AS raw_json
        FROM aws_iam_user u
    """,
    "security_groups": """
        SELECT group_id, group_name, account_id, region,
               'arn:aws:ec2:' || region || ':' || account_id || ':security-group/' || group_id AS resource_arn,
               vpc_id, description,
               EXISTS (
                   SELECT 1 FROM jsonb_array_elements(ip_permissions) r,
                   jsonb_array_elements(r -> 'IpRanges') ip
                   WHERE ip ->> 'CidrIp' = '0.0.0.0/0'
               ) AS allows_all_ingress,
               EXISTS (
                   SELECT 1 FROM jsonb_array_elements(ip_permissions) r,
                   jsonb_array_elements(r -> 'IpRanges') ip
                   WHERE ip ->> 'CidrIp' = '0.0.0.0/0'
                   AND (r ->> 'FromPort')::int <= 22
                   AND (r ->> 'ToPort')::int >= 22
               ) AS allows_ssh_public,
               EXISTS (
                   SELECT 1 FROM jsonb_array_elements(ip_permissions) r,
                   jsonb_array_elements(r -> 'IpRanges') ip
                   WHERE ip ->> 'CidrIp' = '0.0.0.0/0'
                   AND (r ->> 'FromPort')::int <= 3389
                   AND (r ->> 'ToPort')::int >= 3389
               ) AS allows_rdp_public,
               tags, to_jsonb(sg) AS raw_json
        FROM aws_vpc_security_group sg
    """,
    "vpcs": """
        SELECT vpc_id, account_id, region, cidr_block,
               is_default, state, tags, to_jsonb(v) AS raw_json
        FROM aws_vpc v
    """,
}


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def log_sync(conn, table, rows, duration_ms, status="success", error=None):
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO steampipe_sync_log (table_name, rows_synced, duration_ms, status, error_msg)
                    VALUES (%s, %s, %s, %s, %s)
                """, (table, rows, duration_ms, status, error))
    except Exception as e:
        print(f"  [WARN] Could not log sync: {e}")


def upsert_instances(conn, rows):
    sql = """INSERT INTO aws_instances (
        instance_id, account_id, region, resource_arn,
        instance_state, instance_type, launch_time,
        vpc_id, subnet_id, private_ip, public_ip, public_dns,
        iam_instance_profile, key_name, name_tag, tags, raw_json, synced_at
    ) VALUES %s ON CONFLICT (instance_id) DO UPDATE SET
        instance_state=EXCLUDED.instance_state, public_ip=EXCLUDED.public_ip,
        iam_instance_profile=EXCLUDED.iam_instance_profile,
        tags=EXCLUDED.tags, raw_json=EXCLUDED.raw_json, synced_at=NOW()"""
    template = """(%(instance_id)s,%(account_id)s,%(region)s,%(resource_arn)s,
        %(instance_state)s,%(instance_type)s,%(launch_time)s,
        %(vpc_id)s,%(subnet_id)s,%(private_ip)s,%(public_ip)s,%(public_dns)s,
        %(iam_instance_profile)s,%(key_name)s,%(name_tag)s,
        %(tags)s::jsonb,%(raw_json)s::jsonb,NOW())"""
    with conn:
        with conn.cursor() as cur:
            execute_values(cur, sql, rows, template=template)
            return cur.rowcount


def upsert_s3(conn, rows):
    sql = """INSERT INTO aws_s3_buckets (
        bucket_name,account_id,region,resource_arn,public_access_blocked,
        versioning_enabled,logging_enabled,encryption_enabled,
        creation_date,tags,raw_json,synced_at
    ) VALUES %s ON CONFLICT (bucket_name) DO UPDATE SET
        public_access_blocked=EXCLUDED.public_access_blocked,
        encryption_enabled=EXCLUDED.encryption_enabled,
        tags=EXCLUDED.tags,raw_json=EXCLUDED.raw_json,synced_at=NOW()"""
    template = """(%(bucket_name)s,%(account_id)s,%(region)s,%(resource_arn)s,
        %(public_access_blocked)s,%(versioning_enabled)s,%(logging_enabled)s,
        %(encryption_enabled)s,%(creation_date)s,
        %(tags)s::jsonb,%(raw_json)s::jsonb,NOW())"""
    with conn:
        with conn.cursor() as cur:
            execute_values(cur, sql, rows, template=template)
            return cur.rowcount


def upsert_iam(conn, rows):
    sql = """INSERT INTO aws_iam_users (
        user_name,account_id,user_id,resource_arn,mfa_enabled,
        has_console_access,has_access_keys,password_last_used,
        access_key_last_used,create_date,tags,raw_json,synced_at
    ) VALUES %s ON CONFLICT (user_id) DO UPDATE SET
        mfa_enabled=EXCLUDED.mfa_enabled,has_access_keys=EXCLUDED.has_access_keys,
        password_last_used=EXCLUDED.password_last_used,
        tags=EXCLUDED.tags,raw_json=EXCLUDED.raw_json,synced_at=NOW()"""
    template = """(%(user_name)s,%(account_id)s,%(user_id)s,%(resource_arn)s,
        %(mfa_enabled)s,%(has_console_access)s,%(has_access_keys)s,
        %(password_last_used)s,%(access_key_last_used)s,%(create_date)s,
        %(tags)s::jsonb,%(raw_json)s::jsonb,NOW())"""
    with conn:
        with conn.cursor() as cur:
            execute_values(cur, sql, rows, template=template)
            return cur.rowcount


def upsert_security_groups(conn, rows):
    sql = """INSERT INTO aws_security_groups (
        group_id,group_name,account_id,region,resource_arn,vpc_id,description,
        allows_all_ingress,allows_ssh_public,allows_rdp_public,tags,raw_json,synced_at
    ) VALUES %s ON CONFLICT (group_id) DO UPDATE SET
        allows_all_ingress=EXCLUDED.allows_all_ingress,
        allows_ssh_public=EXCLUDED.allows_ssh_public,
        allows_rdp_public=EXCLUDED.allows_rdp_public,
        tags=EXCLUDED.tags,raw_json=EXCLUDED.raw_json,synced_at=NOW()"""
    template = """(%(group_id)s,%(group_name)s,%(account_id)s,%(region)s,%(resource_arn)s,
        %(vpc_id)s,%(description)s,%(allows_all_ingress)s,%(allows_ssh_public)s,
        %(allows_rdp_public)s,%(tags)s::jsonb,%(raw_json)s::jsonb,NOW())"""
    with conn:
        with conn.cursor() as cur:
            execute_values(cur, sql, rows, template=template)
            return cur.rowcount


def upsert_vpcs(conn, rows):
    sql = """INSERT INTO aws_vpcs (
        vpc_id,account_id,region,cidr_block,is_default,state,tags,raw_json,synced_at
    ) VALUES %s ON CONFLICT (vpc_id) DO UPDATE SET
        state=EXCLUDED.state,tags=EXCLUDED.tags,raw_json=EXCLUDED.raw_json,synced_at=NOW()"""
    template = """(%(vpc_id)s,%(account_id)s,%(region)s,%(cidr_block)s,
        %(is_default)s,%(state)s,%(tags)s::jsonb,%(raw_json)s::jsonb,NOW())"""
    with conn:
        with conn.cursor() as cur:
            execute_values(cur, sql, rows, template=template)
            return cur.rowcount


UPSERT_FNS = {
    "instances": upsert_instances,
    "s3": upsert_s3,
    "iam": upsert_iam,
    "security_groups": upsert_security_groups,
    "vpcs": upsert_vpcs,
}


def sync_live(tables):
    print(f"[{ts()}] Connecting to Steampipe (port 9193)...")
    sec_conn = psycopg2.connect(**DB_CONFIG)

    for table in tables:
        query = STEAMPIPE_QUERIES.get(table)
        if not query:
            continue
        print(f"[{ts()}] Querying: {table}...")
        start = time.time()
        sp_conn = psycopg2.connect(**STEAMPIPE_DB)
        try:
            with sp_conn.cursor() as cur:
                cur.execute(query)
                cols = [d[0] for d in cur.description]
                rows = [dict(zip(cols, row)) for row in cur.fetchall()]
            for row in rows:
                for k, v in row.items():
                    if isinstance(v, (dict, list)):
                        row[k] = json.dumps(v)
            count = UPSERT_FNS[table](sec_conn, rows)
            duration = int((time.time() - start) * 1000)
            log_sync(sec_conn, table, count, duration)
            print(f"[{ts()}] ✓ {table}: {len(rows)} rows ({duration}ms)")
        except Exception as e:
            duration = int((time.time() - start) * 1000)
            log_sync(sec_conn, table, 0, duration, "error", str(e))
            print(f"[{ts()}] ✗ {table}: {e}")
        finally:
            sp_conn.close()

    sec_conn.close()


def sync_sample():
    print(f"[{ts()}] Loading sample data...")
    path = Path(__file__).parent.parent / "sample_data" / "steampipe_sample.json"
    with open(path) as f:
        data = json.load(f)
    sec_conn = psycopg2.connect(**DB_CONFIG)
    for table, rows in data.items():
        if not rows:
            continue
        start = time.time()
        try:
            for row in rows:
                for k, v in row.items():
                    if isinstance(v, (dict, list)):
                        row[k] = json.dumps(v)
            count = UPSERT_FNS[table](sec_conn, rows)
            duration = int((time.time() - start) * 1000)
            log_sync(sec_conn, table, count, duration)
            print(f"[{ts()}] ✓ {table}: {len(rows)} rows")
        except Exception as e:
            print(f"[{ts()}] ✗ {table}: {e}")
    sec_conn.close()


def print_summary():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            print(f"\n── Inventory summary ────────────────────────────")
            for tbl, label in [
                ("aws_instances","EC2 Instances"),("aws_s3_buckets","S3 Buckets"),
                ("aws_iam_users","IAM Users"),("aws_security_groups","Security Groups"),
                ("aws_vpcs","VPCs"),
            ]:
                cur.execute(f"SELECT COUNT(*) FROM {tbl}")
                print(f"  {label:<20} {cur.fetchone()[0]:>5} rows")
            print()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--sync",   action="store_true")
    group.add_argument("--sample", action="store_true")
    parser.add_argument("--tables", nargs="+",
                        choices=["instances","s3","iam","security_groups","vpcs"],
                        default=["instances","s3","iam","security_groups","vpcs"])
    args = parser.parse_args()
    if args.sample:
        sync_sample()
    else:
        sync_live(args.tables)
    print_summary()
    print(f"[{ts()}] Done.")


if __name__ == "__main__":
    main()