#!/usr/bin/env python3
"""
trivy_ingest.py
---------------
Runs Trivy via AWS SSM on all running EC2 instances and ingests
CVEs into PostgreSQL. Results uploaded to S3 to bypass SSM 24KB limit.

Usage:
  python3 trivy_ingest.py --scan-all
  python3 trivy_ingest.py --scan-instance i-xxxx
  python3 trivy_ingest.py --file output.json
"""

import argparse
import base64
import gzip
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import boto3
import psycopg2
from psycopg2.extras import execute_values

DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}
AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "024863982143")
S3_BUCKET      = f"cloud-sec-agent-{AWS_ACCOUNT_ID}"
OUTPUT_DIR     = Path("./trivy_output")

TRIVY_INSTALL = (
    "which trivy || "
    "(curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin)"
)


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def get_ssm_instances() -> list[dict]:
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    ssm = boto3.client("ssm", region_name=AWS_REGION)
    managed = {
        i["InstanceId"]
        for i in ssm.describe_instance_information().get("InstanceInformationList", [])
        if i.get("PingStatus") == "Online"
    }
    reservations = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    ).get("Reservations", [])
    instances = []
    for r in reservations:
        for inst in r.get("Instances", []):
            iid = inst["InstanceId"]
            if iid in managed:
                name = next((t["Value"] for t in inst.get("Tags", []) if t["Key"] == "Name"), iid)
                instances.append({"instance_id": iid, "name": name, "region": AWS_REGION})
    print(f"[{ts()}] Found {len(instances)} SSM-managed running instances")
    return instances


def ssm_run(ssm, instance_id: str, commands: list[str], timeout: int = 600) -> tuple[str, bool]:
    """Send SSM command and wait. Returns (stdout, success)."""
    response = ssm.send_command(
        InstanceIds=[instance_id],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": commands},
        TimeoutSeconds=timeout,
    )
    command_id = response["Command"]["CommandId"]
    for attempt in range(timeout // 10):
        time.sleep(10)
        result = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        status = result["Status"]
        if status in ("Success", "Failed", "Cancelled", "TimedOut"):
            stdout = result.get("StandardOutputContent", "")
            stderr = result.get("StandardErrorContent", "")
            if status != "Success":
                print(f"[{ts()}] ✗ SSM status: {status}")
                if stderr:
                    print(f"  stderr: {stderr[:500]}")
                return stdout, False
            return stdout, True
        print(f"  [{attempt+1}] Status: {status}...")
    return "", False


def run_trivy_ssm(instance_id: str) -> dict | None:
    ssm = boto3.client("ssm", region_name=AWS_REGION)
    s3  = boto3.client("s3",  region_name=AWS_REGION)
    OUTPUT_DIR.mkdir(exist_ok=True)

    # Step 1: Install Trivy
    print(f"[{ts()}] Checking Trivy install on {instance_id}...")
    _, ok = ssm_run(ssm, instance_id, [TRIVY_INSTALL], timeout=120)
    if not ok:
        print(f"[{ts()}] ✗ Trivy install failed")
        return None

    # Step 2: Scan and upload to S3
    s3_key   = f"trivy/{instance_id}.json"
    scan_cmd = (
        f"rm -rf /tmp/trivy* && "
        f"TRIVY_CACHE_DIR=/var/tmp/trivy trivy rootfs / "
        f"--scanners vuln --format json "
        f"--severity CRITICAL,HIGH,MEDIUM,LOW "
        f"--output /tmp/trivy_results.json --quiet 2>/dev/null && "
        f"aws s3 cp /tmp/trivy_results.json s3://{S3_BUCKET}/{s3_key} --region {AWS_REGION} && "
        f"echo TRIVY_DONE"
    )
    print(f"[{ts()}] Running Trivy scan on {instance_id} (3-5 min)...")
    out, ok = ssm_run(ssm, instance_id, [scan_cmd], timeout=600)

    if not ok or "TRIVY_DONE" not in out:
        print(f"[{ts()}] ✗ Trivy scan or S3 upload failed on {instance_id}")
        return None

    # Step 3: Download from S3 (no size limit)
    out_path = OUTPUT_DIR / f"{instance_id}.json"
    print(f"[{ts()}] Downloading results from s3://{S3_BUCKET}/{s3_key}...")
    try:
        s3.download_file(S3_BUCKET, s3_key, str(out_path))
    except Exception as e:
        print(f"[{ts()}] ✗ S3 download failed: {e}")
        return None

    json_output = out_path.read_text()
    print(f"[{ts()}] Downloaded {len(json_output)//1024}KB → {out_path}")

    try:
        data = json.loads(json_output)
        print(f"[{ts()}] ✓ Trivy scan complete for {instance_id}")
        return data
    except json.JSONDecodeError as e:
        print(f"[{ts()}] ✗ JSON parse error: {e}")
        return None


def parse_trivy_output(data, instance_id: str) -> list[dict]:
    rows = []
    resource_arn = f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_ID}:instance/{instance_id}"
    results = data if isinstance(data, list) else data.get("Results", [])
    for result in results:
        vulns = result.get("Vulnerabilities") or []
        for v in vulns:
            rows.append({
                "resource_arn":      resource_arn,
                "instance_id":       instance_id,
                "account_id":        AWS_ACCOUNT_ID,
                "region":            AWS_REGION,
                "cve_id":            v.get("VulnerabilityID", ""),
                "severity":          v.get("Severity", "UNKNOWN").upper(),
                "cvss_score":        (v.get("CVSS") or {}).get("nvd", {}).get("V3Score")
                                     or (v.get("CVSS") or {}).get("redhat", {}).get("V3Score")
                                     or None,
                "package_name":      v.get("PkgName", ""),
                "installed_version": v.get("InstalledVersion", ""),
                "fixed_version":     v.get("FixedVersion", ""),
                "title":             v.get("Title", ""),
                "description":       (v.get("Description") or "")[:1000],
                "primary_url":       v.get("PrimaryURL", ""),
                "status":            "OPEN",
                "raw_json":          json.dumps(v),
            })
    return rows


def ingest(rows: list[dict]) -> int:
    if not rows:
        return 0
    sql = """
        INSERT INTO trivy_vulnerabilities (
            resource_arn, instance_id, account_id, region,
            cve_id, severity, cvss_score, package_name,
            installed_version, fixed_version, title, description,
            primary_url, status, raw_json
        ) VALUES %s
        ON CONFLICT (resource_arn, cve_id, package_name)
        DO UPDATE SET
            severity          = EXCLUDED.severity,
            cvss_score        = EXCLUDED.cvss_score,
            installed_version = EXCLUDED.installed_version,
            fixed_version     = EXCLUDED.fixed_version,
            status            = EXCLUDED.status,
            raw_json          = EXCLUDED.raw_json,
            ingested_at       = NOW()
    """
    template = """(
        %(resource_arn)s, %(instance_id)s, %(account_id)s, %(region)s,
        %(cve_id)s, %(severity)s, %(cvss_score)s, %(package_name)s,
        %(installed_version)s, %(fixed_version)s, %(title)s, %(description)s,
        %(primary_url)s, %(status)s, %(raw_json)s
    )"""
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, rows, template=template)
                inserted = cur.rowcount
        print(f"[{ts()}] ✓ Upserted {inserted} rows into trivy_vulnerabilities")
        return inserted
    finally:
        conn.close()


def print_summary():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT severity, COUNT(*) FROM trivy_vulnerabilities
                WHERE status='OPEN'
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3 ELSE 4 END
            """)
            rows = cur.fetchall()
            print("\n── CVE summary (open) ───────────────────────────")
            for sev, cnt in rows:
                print(f"  {sev:<12} {cnt:>5}")
            print()
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser()
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan-all",      action="store_true")
    group.add_argument("--scan-instance", metavar="INSTANCE_ID")
    group.add_argument("--file",          metavar="JSON_FILE")
    parser.add_argument("--no-alert", action="store_true")
    args = parser.parse_args()

    all_rows = []

    if args.file:
        print(f"[{ts()}] Loading {args.file}...")
        with open(args.file) as f:
            data = json.load(f)
        instance_id = Path(args.file).stem.split(".")[0]
        all_rows = parse_trivy_output(data, instance_id)

    elif args.scan_instance:
        data = run_trivy_ssm(args.scan_instance)
        if data:
            all_rows = parse_trivy_output(data, args.scan_instance)

    else:
        instances = get_ssm_instances()
        if not instances:
            print(f"[{ts()}] No SSM-managed instances found.")
            sys.exit(0)
        for inst in instances:
            data = run_trivy_ssm(inst["instance_id"])
            if data:
                all_rows.extend(parse_trivy_output(data, inst["instance_id"]))

    print(f"[{ts()}] Parsed {len(all_rows)} CVEs total")
    ingest(all_rows)
    print_summary()
    print(f"[{ts()}] Done.")

    if not args.no_alert:
        try:
            from slack_alert import send_new_critical_alerts
            send_new_critical_alerts()
        except Exception as e:
            print(f"[{ts()}] Slack alert skipped: {e}")


if __name__ == "__main__":
    main()
    