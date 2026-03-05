#!/usr/bin/env python3
"""
prowler_ingest.py
-----------------
Runs Prowler (or reads an existing JSON output file) and ingests
findings into PostgreSQL.

Usage
-----
# Run Prowler and ingest immediately:
    python prowler_ingest.py --run

# Ingest an existing Prowler JSON file:
    python prowler_ingest.py --file prowler_output.json

# Multiple files (e.g. from multi-account runs):
    python prowler_ingest.py --file account1.json account2.json
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
# Prefer environment variables; fall back to defaults for local dev.
DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "localhost"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}

# ── Prowler run config ────────────────────────────────────────────────────────
PROWLER_OUTPUT_DIR  = Path("./prowler_output")
PROWLER_OUTPUT_FILE = PROWLER_OUTPUT_DIR / "prowler_output.json"


# ─────────────────────────────────────────────────────────────────────────────
def run_prowler() -> Path:
    """Invoke Prowler CLI and return the path to the JSON output."""
    PROWLER_OUTPUT_DIR.mkdir(exist_ok=True)

    cmd = [
        "prowler", "aws",
        "--output-formats", "json",
        "--output-directory", str(PROWLER_OUTPUT_DIR),
        "--output-filename", "prowler_output",
        # Add extra flags as needed, e.g.:
        # "--role", "arn:aws:iam::123456789012:role/SecurityAuditRole",
        # "--checks", "iam_root_hardware_mfa_enabled",
    ]

    print(f"[{ts()}] Running Prowler …")
    print(f"  Command: {' '.join(cmd)}\n")

    result = subprocess.run(cmd, capture_output=False)
    if result.returncode not in (0, 3):          # 3 = findings found (normal)
        print(f"[ERROR] Prowler exited with code {result.returncode}", file=sys.stderr)
        sys.exit(1)

    # Prowler appends a timestamp; find the newest .json file
    candidates = sorted(PROWLER_OUTPUT_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not candidates:
        print("[ERROR] No JSON output found after Prowler run.", file=sys.stderr)
        sys.exit(1)

    print(f"[{ts()}] Prowler finished → {candidates[-1]}")
    return candidates[-1]


# ─────────────────────────────────────────────────────────────────────────────
def load_findings(json_path: Path) -> list[dict]:
    """Load and return findings from a Prowler JSON file."""
    print(f"[{ts()}] Loading findings from {json_path} …")
    with open(json_path) as f:
        data = json.load(f)

    # Prowler v3+ wraps everything in a top-level list
    if isinstance(data, list):
        return data
    # Some versions nest under a key
    for key in ("findings", "data", "results"):
        if key in data:
            return data[key]
    raise ValueError(f"Unrecognised Prowler JSON structure in {json_path}")


# ─────────────────────────────────────────────────────────────────────────────
def parse_finding(raw: dict) -> dict | None:
    """
    Map a single Prowler finding dict to our DB schema.
    Returns None if the finding should be skipped.
    """
    # ── Prowler v3 field names ───────────────────────────────────────────────
    # (v2 used slightly different keys; add a fallback layer if needed)
    try:
        resource_arn = (
            raw.get("resource_arn")
            or raw.get("resource", {}).get("arn", "")
            or raw.get("ResourceArn", "")
        )

        check_id = (
            raw.get("check_id")
            or raw.get("CheckID", "")
            or raw.get("check_metadata", {}).get("CheckID", "")
        )

        check_title = (
            raw.get("check_title")
            or raw.get("CheckTitle", "")
            or raw.get("check_metadata", {}).get("CheckTitle", "")
        )

        severity = (
            raw.get("severity")
            or raw.get("Severity", "")
            or raw.get("check_metadata", {}).get("Severity", "")
        ).upper()

        status = (
            raw.get("status")
            or raw.get("Status", "")
        ).upper()

        remediation = raw.get("remediation") or raw.get("Remediation") or {}
        if isinstance(remediation, str):
            recommendation     = remediation
            recommendation_url = ""
            remediation_code   = ""
        else:
            recommendation     = remediation.get("Recommendation", {}).get("Text", "")
            recommendation_url = remediation.get("Recommendation", {}).get("Url", "")
            remediation_code   = json.dumps(remediation.get("Code", {})) if remediation.get("Code") else ""

        return {
            "account_id":         str(raw.get("account_id") or raw.get("AccountId") or ""),
            "account_name":       str(raw.get("account_name") or raw.get("AccountName") or ""),
            "region":             str(raw.get("region") or raw.get("Region") or ""),
            "resource_arn":       resource_arn,
            "resource_type":      str(raw.get("resource_type") or raw.get("ResourceType") or ""),
            "check_id":           check_id,
            "check_title":        check_title,
            "service":            str(raw.get("service_name") or raw.get("Service") or ""),
            "severity":           severity,
            "status":             status,
            "description":        str(raw.get("description") or raw.get("Description") or ""),
            "risk":               str(raw.get("risk") or raw.get("Risk") or ""),
            "recommendation":     recommendation,
            "recommendation_url": recommendation_url,
            "remediation_code":   remediation_code,
            "raw_json":           json.dumps(raw),
        }

    except Exception as exc:
        print(f"  [WARN] Could not parse finding: {exc}\n  Raw: {str(raw)[:200]}", file=sys.stderr)
        return None


# ─────────────────────────────────────────────────────────────────────────────
def ingest(findings: list[dict]) -> tuple[int, int]:
    """Insert findings into Postgres. Returns (inserted, skipped)."""

    rows = [r for f in findings if (r := parse_finding(f)) is not None]
    print(f"[{ts()}] Parsed {len(rows)} findings (skipped {len(findings) - len(rows)} unparseable)")

    if not rows:
        return 0, len(findings)

    insert_sql = """
        INSERT INTO prowler_findings (
            account_id, account_name, region, resource_arn, resource_type,
            check_id, check_title, service, severity, status,
            description, risk, recommendation, recommendation_url,
            remediation_code, raw_json
        ) VALUES %s
        ON CONFLICT (account_id, resource_arn, check_id)
        DO UPDATE SET
            status             = EXCLUDED.status,
            severity           = EXCLUDED.severity,
            description        = EXCLUDED.description,
            recommendation     = EXCLUDED.recommendation,
            remediation_code   = EXCLUDED.remediation_code,
            raw_json           = EXCLUDED.raw_json,
            ingested_at        = NOW()
    """

    template = """(
        %(account_id)s, %(account_name)s, %(region)s, %(resource_arn)s, %(resource_type)s,
        %(check_id)s, %(check_title)s, %(service)s, %(severity)s, %(status)s,
        %(description)s, %(risk)s, %(recommendation)s, %(recommendation_url)s,
        %(remediation_code)s, %(raw_json)s
    )"""

    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn:
            with conn.cursor() as cur:
                execute_values(cur, insert_sql, rows, template=template, page_size=500)
                inserted = cur.rowcount
        print(f"[{ts()}] ✓ Upserted {inserted} rows into prowler_findings")
        return inserted, len(findings) - len(rows)
    finally:
        conn.close()


# ─────────────────────────────────────────────────────────────────────────────
def print_summary():
    """Print a quick severity summary from the DB after ingestion."""
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT severity, COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE status = 'FAIL') AS failures
                FROM prowler_findings
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4
                    ELSE 5 END
            """)
            rows = cur.fetchall()
            print("\n── Severity summary (all-time) ─────────────────")
            print(f"  {'Severity':<15} {'Total':>7} {'Failures':>10}")
            print(f"  {'-'*34}")
            for sev, total, fails in rows:
                print(f"  {sev:<15} {total:>7} {fails:>10}")
            print()
    finally:
        conn.close()


def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Ingest Prowler findings into PostgreSQL")
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run",  action="store_true",
                       help="Run Prowler now, then ingest")
    group.add_argument("--file", nargs="+", metavar="JSON_FILE",
                       help="Ingest one or more existing Prowler JSON files")
    args = parser.parse_args()

    all_findings: list[dict] = []

    if args.run:
        json_path = run_prowler()
        all_findings.extend(load_findings(json_path))
    else:
        for f in args.file:
            all_findings.extend(load_findings(Path(f)))

    inserted, skipped = ingest(all_findings)
    print_summary()
    print(f"[{ts()}] Done. inserted={inserted}, skipped={skipped}")


if __name__ == "__main__":
    main()
