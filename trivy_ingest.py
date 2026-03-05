#!/usr/bin/env python3
"""
trivy_ingest.py
---------------
Runs Trivy (via AWS SSM on EC2 instances) or reads existing Trivy JSON
output, and ingests CVE findings into PostgreSQL.

Usage
-----
# Scan all running EC2 instances via SSM and ingest:
    python trivy_ingest.py --scan-all

# Scan a specific instance:
    python trivy_ingest.py --scan-instance i-0abc123def456

# Ingest an existing Trivy JSON file:
    python trivy_ingest.py --file trivy_output.json

# Multiple files:
    python trivy_ingest.py --file instance1.json instance2.json
"""

import argparse
import json
import os
import time
import sys
from datetime import datetime, timezone
from pathlib import Path

import boto3
import psycopg2
from psycopg2.extras import execute_values

# ── DB connection ─────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "localhost"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}

# ── Config ────────────────────────────────────────────────────────────────────
AWS_REGION      = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_PROFILE     = os.getenv("AWS_PROFILE", "default")
AWS_ACCOUNT_ID  = os.getenv("AWS_ACCOUNT_ID", "")   # optional, auto-detected if empty
OUTPUT_DIR      = Path("./trivy_output")

# Trivy command to run on each EC2 instance via SSM
# rootfs mode scans the entire OS package set for CVEs
TRIVY_SSM_CMD = (
    "trivy rootfs / "
    "--scanners vuln "
    "--format json "
    "--severity CRITICAL,HIGH,MEDIUM,LOW "
    "--quiet "
    "2>/dev/null || "
    # Install trivy if not present, then re-run
    "(curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh "
    "| sh -s -- -b /usr/local/bin && "
    "trivy rootfs / --scanners vuln --format json --severity CRITICAL,HIGH,MEDIUM,LOW --quiet 2>/dev/null)"
)


# ─────────────────────────────────────────────────────────────────────────────
def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def get_boto_session():
    return boto3.Session(profile_name=AWS_PROFILE, region_name=AWS_REGION)


def get_account_id(session) -> str:
    if AWS_ACCOUNT_ID:
        return AWS_ACCOUNT_ID
    sts = session.client("sts")
    return sts.get_caller_identity()["Account"]


# ─────────────────────────────────────────────────────────────────────────────
def list_running_instances(session) -> list[dict]:
    """Return all running EC2 instances with SSM agent registered."""
    ec2 = session.client("ec2")
    ssm = session.client("ssm")

    # Get all running instances
    resp = ec2.describe_instances(Filters=[{"Name": "instance-state-name", "Values": ["running"]}])
    all_ids = [
        i["InstanceId"]
        for r in resp["Reservations"]
        for i in r["Instances"]
    ]

    if not all_ids:
        print(f"[{ts()}] No running instances found.")
        return []

    # Filter to only SSM-managed instances
    ssm_resp = ssm.describe_instance_information(
        Filters=[{"Key": "InstanceIds", "Values": all_ids}]
    )
    ssm_ids = {i["InstanceId"] for i in ssm_resp["InstanceInformationList"]}

    instances = [
        {
            "instance_id": i["InstanceId"],
            "region":      AWS_REGION,
            "arn":         f"arn:aws:ec2:{AWS_REGION}:{get_account_id(session)}:instance/{i['InstanceId']}",
        }
        for r in resp["Reservations"]
        for i in r["Instances"]
        if i["InstanceId"] in ssm_ids
    ]

    print(f"[{ts()}] Found {len(instances)} SSM-managed running instances "
          f"(skipped {len(all_ids) - len(instances)} without SSM)")
    return instances


# ─────────────────────────────────────────────────────────────────────────────
def run_trivy_on_instance(session, instance: dict) -> dict | None:
    """
    Send Trivy command to an EC2 instance via SSM Run Command.
    Returns parsed Trivy JSON output or None on failure.
    """
    ssm = session.client("ssm")
    iid = instance["instance_id"]

    print(f"[{ts()}]   Sending Trivy to {iid} via SSM …")

    resp = ssm.send_command(
        InstanceIds=[iid],
        DocumentName="AWS-RunShellScript",
        Parameters={"commands": [TRIVY_SSM_CMD]},
        TimeoutSeconds=600,
        Comment=f"Trivy scan triggered by security agent",
    )
    command_id = resp["Command"]["CommandId"]

    # Poll for completion (max 10 minutes)
    for attempt in range(60):
        time.sleep(10)
        result = ssm.get_command_invocation(CommandId=command_id, InstanceId=iid)
        status = result["Status"]

        if status == "Success":
            output = result.get("StandardOutputContent", "")
            if not output.strip():
                print(f"[{ts()}]   [{iid}] Trivy returned empty output — skipping")
                return None
            try:
                return json.loads(output)
            except json.JSONDecodeError as e:
                print(f"[{ts()}]   [{iid}] Could not parse Trivy JSON: {e}", file=sys.stderr)
                return None

        elif status in ("Failed", "Cancelled", "TimedOut"):
            err = result.get("StandardErrorContent", "")
            print(f"[{ts()}]   [{iid}] SSM command {status}: {err[:200]}", file=sys.stderr)
            return None

        print(f"[{ts()}]   [{iid}] Status: {status} (attempt {attempt+1}/60) …")

    print(f"[{ts()}]   [{iid}] Timed out waiting for Trivy", file=sys.stderr)
    return None


# ─────────────────────────────────────────────────────────────────────────────
def parse_trivy_output(raw: dict, instance: dict, account_id: str) -> list[dict]:
    """
    Parse Trivy JSON output into rows for the DB.
    Trivy JSON structure:
      { "Results": [ { "Target": "...", "Vulnerabilities": [...] } ] }
    """
    rows = []
    results = raw.get("Results") or raw.get("results") or []

    for result in results:
        target = result.get("Target", "/")
        vulns  = result.get("Vulnerabilities") or []

        for v in vulns:
            try:
                cvss_score = None
                # Try to extract CVSS score from various locations
                cvss = v.get("CVSS") or {}
                for source in ("nvd", "redhat", "ghsa"):
                    if source in cvss:
                        cvss_score = cvss[source].get("V3Score") or cvss[source].get("V2Score")
                        if cvss_score:
                            break
                if not cvss_score:
                    cvss_score = v.get("NvdCvssScoreV3") or v.get("CvssScore")

                rows.append({
                    "resource_arn":       instance["arn"],
                    "instance_id":        instance["instance_id"],
                    "account_id":         account_id,
                    "region":             instance["region"],
                    "cve_id":             v.get("VulnerabilityID", ""),
                    "severity":           (v.get("Severity") or "UNKNOWN").upper(),
                    "cvss_score":         float(cvss_score) if cvss_score else None,
                    "package_name":       v.get("PkgName", ""),
                    "installed_version":  v.get("InstalledVersion", ""),
                    "fixed_version":      v.get("FixedVersion", ""),
                    "target":             target,
                    "pkg_type":           v.get("Type", ""),
                    "title":              v.get("Title", ""),
                    "description":        (v.get("Description") or "")[:1000],
                    "primary_url":        v.get("PrimaryURL", ""),
                    "status":             "OPEN",
                    "raw_json":           json.dumps(v),
                })
            except Exception as e:
                print(f"  [WARN] Could not parse vuln: {e}", file=sys.stderr)

    return rows


# ─────────────────────────────────────────────────────────────────────────────
def ingest(rows: list[dict]) -> tuple[int, int]:
    """Upsert vulnerability rows into PostgreSQL."""
    if not rows:
        print(f"[{ts()}] No rows to ingest.")
        return 0, 0

    insert_sql = """
        INSERT INTO trivy_vulnerabilities (
            resource_arn, instance_id, account_id, region,
            cve_id, severity, cvss_score, package_name,
            installed_version, fixed_version, target, pkg_type,
            title, description, primary_url, status, raw_json
        ) VALUES %s
        ON CONFLICT (resource_arn, cve_id, package_name)
        DO UPDATE SET
            severity          = EXCLUDED.severity,
            cvss_score        = EXCLUDED.cvss_score,
            fixed_version     = EXCLUDED.fixed_version,
            description       = EXCLUDED.description,
            status            = EXCLUDED.status,
            raw_json          = EXCLUDED.raw_json,
            ingested_at       = NOW()
    """

    template = """(
        %(resource_arn)s, %(instance_id)s, %(account_id)s, %(region)s,
        %(cve_id)s, %(severity)s, %(cvss_score)s, %(package_name)s,
        %(installed_version)s, %(fixed_version)s, %(target)s, %(pkg_type)s,
        %(title)s, %(description)s, %(primary_url)s, %(status)s, %(raw_json)s
    )"""

    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, insert_sql, rows, template=template, page_size=500)
                inserted = cur.rowcount
        print(f"[{ts()}] ✓ Upserted {inserted} rows into trivy_vulnerabilities")
        return inserted, 0
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
def print_summary():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT severity, COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE status = 'OPEN') AS open_count
                FROM trivy_vulnerabilities
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
                    ELSE 5 END
            """)
            rows = cur.fetchall()
            print("\n── CVE severity summary (all-time) ─────────────────")
            print(f"  {'Severity':<12} {'Total':>7} {'Open':>7}")
            print(f"  {'-'*28}")
            for sev, total, open_count in rows:
                print(f"  {sev:<12} {total:>7} {open_count:>7}")

            # Also show correlated risks if any
            cur.execute("SELECT COUNT(*) FROM v_critical_risks")
            count = cur.fetchone()[0]
            if count:
                print(f"\n  ⚠  {count} instances are BOTH publicly exposed AND have CRITICAL/HIGH CVEs")
                print("     Run: SELECT * FROM v_critical_risks;")
            print()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
def load_json_file(path: Path) -> tuple[dict, dict]:
    """Load a Trivy JSON file. Returns (trivy_data, mock_instance_info)."""
    with open(path) as f:
        data = json.load(f)
    # Derive instance info from filename if possible
    stem = path.stem  # e.g. "i-0abc123" or "trivy_output"
    instance = {
        "instance_id": stem if stem.startswith("i-") else "local",
        "region":      AWS_REGION,
        "arn":         f"arn:aws:ec2:{AWS_REGION}:000000000000:instance/{stem}",
    }
    return data, instance


# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Ingest Trivy CVE findings into PostgreSQL")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--scan-all",       action="store_true",
                       help="Scan all running EC2 instances via SSM")
    group.add_argument("--scan-instance",  metavar="INSTANCE_ID",
                       help="Scan a specific EC2 instance via SSM")
    group.add_argument("--file",           nargs="+", metavar="JSON_FILE",
                       help="Ingest one or more existing Trivy JSON files")
    args = parser.parse_args()

    OUTPUT_DIR.mkdir(exist_ok=True)
    all_rows: list[dict] = []

    if args.file:
        for f in args.file:
            path = Path(f)
            print(f"[{ts()}] Loading {path} …")
            data, instance = load_json_file(path)
            rows = parse_trivy_output(data, instance, account_id="000000000000")
            print(f"[{ts()}] Parsed {len(rows)} CVEs from {path.name}")
            all_rows.extend(rows)

    else:
        session    = get_boto_session()
        account_id = get_account_id(session)
        print(f"[{ts()}] AWS account: {account_id} | region: {AWS_REGION}")

        if args.scan_all:
            instances = list_running_instances(session)
        else:
            instances = [{
                "instance_id": args.scan_instance,
                "region":      AWS_REGION,
                "arn":         f"arn:aws:ec2:{AWS_REGION}:{account_id}:instance/{args.scan_instance}",
            }]

        for instance in instances:
            raw = run_trivy_on_instance(session, instance)
            if raw:
                rows = parse_trivy_output(raw, instance, account_id)
                print(f"[{ts()}]   {instance['instance_id']}: {len(rows)} CVEs found")
                all_rows.extend(rows)

                # Save raw output for reference
                out_path = OUTPUT_DIR / f"{instance['instance_id']}.json"
                with open(out_path, "w") as f:
                    json.dump(raw, f, indent=2)

    if all_rows:
        ingest(all_rows)
        print_summary()
    else:
        print(f"[{ts()}] No CVEs found.")

    print(f"[{ts()}] Done. total_cves={len(all_rows)}")


if __name__ == "__main__":
    main()
