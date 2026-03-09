#!/usr/bin/env python3
"""
pmapper_ingest.py
-----------------
Runs PMapper against AWS IAM to find privilege escalation paths,
then ingests the results into the iam_risks PostgreSQL table.

PMapper builds a directed graph of IAM principals and finds paths
where a low-privilege role can escalate to admin.

Usage
-----
# Test with sample data (no AWS needed):
    python3 pmapper_ingest.py --sample

# Run PMapper against real AWS and ingest:
    python3 pmapper_ingest.py --run

# Ingest an existing PMapper JSON output file:
    python3 pmapper_ingest.py --file pmapper_output.json
"""

import argparse
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import execute_values

# ── DB connection ─────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}

AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "123456789012")
AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
OUTPUT_DIR     = Path("./pmapper_output")


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ─────────────────────────────────────────────────────────────────────────────
def run_pmapper() -> Path:
    """
    Run PMapper to build the IAM graph and find escalation paths.
    PMapper workflow:
      1. pmapper graph create        — builds IAM graph for the account
      2. pmapper analysis            — finds escalation paths
      3. pmapper visualize           — outputs JSON we can parse
    """
    OUTPUT_DIR.mkdir(exist_ok=True)

    print(f"[{ts()}] Step 1: Building IAM graph with PMapper...")
    subprocess.run(["pmapper", "graph", "create"], check=True)

    print(f"[{ts()}] Step 2: Analysing privilege escalation paths...")
    output_file = OUTPUT_DIR / "pmapper_analysis.json"
    result = subprocess.run(
        ["pmapper", "analysis", "--output", "json"],
        capture_output=True, text=True
    )

    with open(output_file, "w") as f:
        f.write(result.stdout)

    print(f"[{ts()}] PMapper analysis saved to {output_file}")
    return output_file


# ─────────────────────────────────────────────────────────────────────────────
def parse_pmapper_output(raw: list, account_id: str) -> list[dict]:
    """
    Parse PMapper JSON analysis output into DB rows.
    PMapper outputs a list of findings like:
    {
        "title": "...",
        "description": "...",
        "detail": {
            "source": "arn:...",
            "destination": "arn:...",
            "path": [...]
        }
    }
    """
    rows = []

    for finding in raw:
        try:
            detail     = finding.get("detail") or finding.get("details") or {}
            source_arn = detail.get("source") or finding.get("source_arn", "")
            target_arn = detail.get("destination") or finding.get("target_arn", "")
            path_nodes = detail.get("path") or finding.get("path", [])

            # Build human-readable path string
            if isinstance(path_nodes, list) and path_nodes:
                path_str = " -> ".join(
                    n.get("arn", str(n)) if isinstance(n, dict) else str(n)
                    for n in path_nodes
                )
            else:
                path_str = f"{source_arn} -> {target_arn}"

            # Extract method names
            methods = []
            if isinstance(path_nodes, list):
                for node in path_nodes:
                    if isinstance(node, dict) and "action" in node:
                        methods.append(node["action"])

            # Determine source/target names from ARN
            source_name = source_arn.split("/")[-1] if source_arn else ""
            target_name = target_arn.split("/")[-1] if target_arn else ""
            source_type = "role" if ":role/" in source_arn else "user"
            target_type = "role" if ":role/" in target_arn else "user"

            # Is target admin?
            target_is_admin = any(
                keyword in target_name.lower()
                for keyword in ["admin", "root", "superuser", "fullaccess", "poweruser"]
            ) or finding.get("is_admin_path", False)

            # Severity based on target and hops
            hops = len(path_nodes) - 1 if isinstance(path_nodes, list) and path_nodes else 1
            if target_is_admin and hops <= 2:
                severity = "CRITICAL"
            elif target_is_admin:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            rows.append({
                "account_id":    account_id,
                "region":        AWS_REGION,
                "source_arn":    source_arn,
                "source_type":   source_type,
                "source_name":   source_name,
                "target_arn":    target_arn,
                "target_type":   target_type,
                "target_name":   target_name,
                "target_is_admin": target_is_admin,
                "path":          path_str,
                "hops":          max(hops, 1),
                "methods":       methods if methods else ["sts:AssumeRole"],
                "severity":      severity,
                "description":   finding.get("description", ""),
                "raw_json":      json.dumps(finding),
            })

        except Exception as e:
            print(f"  [WARN] Could not parse finding: {e}", file=sys.stderr)

    return rows


# ─────────────────────────────────────────────────────────────────────────────
def ingest(rows: list[dict]) -> int:
    if not rows:
        print(f"[{ts()}] No rows to ingest.")
        return 0

    sql = """
        INSERT INTO iam_risks (
            account_id, region,
            source_arn, source_type, source_name,
            target_arn, target_type, target_name, target_is_admin,
            path, hops, methods, severity, description, raw_json
        ) VALUES %s
        ON CONFLICT (account_id, source_arn, target_arn)
        DO UPDATE SET
            path            = EXCLUDED.path,
            hops            = EXCLUDED.hops,
            methods         = EXCLUDED.methods,
            severity        = EXCLUDED.severity,
            target_is_admin = EXCLUDED.target_is_admin,
            description     = EXCLUDED.description,
            raw_json        = EXCLUDED.raw_json,
            ingested_at     = NOW()
    """
    template = """(
        %(account_id)s, %(region)s,
        %(source_arn)s, %(source_type)s, %(source_name)s,
        %(target_arn)s, %(target_type)s, %(target_name)s, %(target_is_admin)s,
        %(path)s, %(hops)s, %(methods)s, %(severity)s, %(description)s,
        %(raw_json)s
    )"""

    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, sql, rows, template=template)
                inserted = cur.rowcount
        print(f"[{ts()}] ✓ Upserted {inserted} rows into iam_risks")
        return inserted
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
def print_summary():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            print(f"\n── IAM Risk summary ─────────────────────────────")

            cur.execute("""
                SELECT severity, COUNT(*), COUNT(*) FILTER (WHERE target_is_admin)
                FROM iam_risks
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    ELSE 4 END
            """)
            rows = cur.fetchall()
            print(f"  {'Severity':<12} {'Paths':>6} {'To Admin':>10}")
            print(f"  {'-'*30}")
            for sev, total, admin in rows:
                print(f"  {sev:<12} {total:>6} {admin:>10}")

            # Show admin escalation paths
            cur.execute("SELECT COUNT(*) FROM v_admin_escalation_paths")
            admin_count = cur.fetchone()[0]
            if admin_count:
                print(f"\n  ⚠  {admin_count} direct paths to ADMIN access found")
                print("     Run: SELECT * FROM v_admin_escalation_paths;")

            # Show full attack chains
            cur.execute("SELECT COUNT(*) FROM v_full_attack_chains WHERE target_is_admin = TRUE")
            chain_count = cur.fetchone()[0]
            if chain_count:
                print(f"\n  🔴 {chain_count} COMPLETE ATTACK CHAINS found")
                print(f"     (public instance + CVE + IAM escalation to admin)")
                print(f"     Run: SELECT * FROM v_full_attack_chains;")
            print()
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
def load_sample():
    path = Path(__file__).parent / "pmapper_sample.json"
    with open(path) as f:
        return json.load(f)


# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Ingest PMapper IAM escalation paths into PostgreSQL")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run",    action="store_true",
                       help="Run PMapper against real AWS and ingest")
    group.add_argument("--sample", action="store_true",
                       help="Load sample data (no AWS needed)")
    group.add_argument("--file",   metavar="JSON_FILE",
                       help="Ingest an existing PMapper JSON output file")
    args = parser.parse_args()

    if args.sample:
        print(f"[{ts()}] Loading sample PMapper data...")
        raw = load_sample()
    elif args.file:
        print(f"[{ts()}] Loading {args.file}...")
        with open(args.file) as f:
            data = json.load(f)
        raw = data.get("findings", []) if isinstance(data, dict) else data
    else:
        output_file = run_pmapper()
        with open(output_file) as f:
            data = json.load(f)
        raw = data.get("findings", []) if isinstance(data, dict) else data

    rows = parse_pmapper_output(raw, AWS_ACCOUNT_ID)
    print(f"[{ts()}] Parsed {len(rows)} escalation paths")

    ingest(rows)
    print_summary()
    print(f"[{ts()}] Done.")


if __name__ == "__main__":
    main()
