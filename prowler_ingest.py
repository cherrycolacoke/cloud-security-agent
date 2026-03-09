#!/usr/bin/env python3
"""
prowler_ingest.py
-----------------
Runs Prowler 5 against AWS (json-ocsf format) and ingests findings
into PostgreSQL. Calls Slack alert helper at the end.

Usage:
  python3 prowler_ingest.py --run          # real AWS scan
  python3 prowler_ingest.py --file sample_findings.json
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

DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}

PROWLER_BIN        = "/Users/lekhan/.local/bin/prowler"
PROWLER_OUTPUT_DIR = Path("./prowler_output")


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ── Run Prowler ───────────────────────────────────────────────────────────────
def run_prowler() -> Path:
    PROWLER_OUTPUT_DIR.mkdir(exist_ok=True)
    cmd = [
        PROWLER_BIN, "aws",
        "--output-formats", "json-ocsf",
        "--output-directory", str(PROWLER_OUTPUT_DIR),
        "--output-filename", "prowler_output",
        "--region", os.getenv("AWS_DEFAULT_REGION", "us-east-1"),
    ]
    print(f"[{ts()}] Running Prowler 5 (json-ocsf)...")
    print(f"  Command: {' '.join(cmd)}\n")
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode not in (0, 3):
        print(f"[ERROR] Prowler exited with code {result.returncode}", file=sys.stderr)
        sys.exit(1)
    candidates = sorted(PROWLER_OUTPUT_DIR.glob("*.ocsf.json"), key=lambda p: p.stat().st_mtime)
    if not candidates:
        # fallback to any json
        candidates = sorted(PROWLER_OUTPUT_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
    if not candidates:
        print("[ERROR] No JSON output found after Prowler run.", file=sys.stderr)
        sys.exit(1)
    print(f"[{ts()}] Prowler finished → {candidates[-1]}")
    return candidates[-1]


# ── Parse OCSF finding ────────────────────────────────────────────────────────
def parse_finding(raw: dict) -> dict | None:
    try:
        # Prowler 5 OCSF format
        resources   = raw.get("resources") or [{}]
        resource    = resources[0] if resources else {}
        resource_arn = resource.get("uid") or raw.get("resource_arn") or ""

        finding_info = raw.get("finding_info") or {}
        check_id     = finding_info.get("uid") or raw.get("check_id") or ""
        check_title  = finding_info.get("title") or raw.get("check_title") or ""

        severity_id  = raw.get("severity_id") or 0
        severity_map = {0:"INFORMATIONAL",1:"LOW",2:"MEDIUM",3:"HIGH",4:"CRITICAL"}
        severity     = raw.get("severity") or severity_map.get(severity_id, "INFORMATIONAL")

        status_id    = raw.get("status_id") or 0
        status_map   = {1:"PASS", 2:"FAIL", 3:"MANUAL", 4:"MUTED"}
        status       = raw.get("status") or status_map.get(status_id, "UNKNOWN")

        remediation  = raw.get("remediation") or {}
        if isinstance(remediation, str):
            recommendation = remediation
            recommendation_url = ""
            remediation_code = ""
        else:
            recommendation     = remediation.get("desc") or remediation.get("Recommendation", {}).get("Text", "")
            recommendation_url = ""
            refs = remediation.get("references") or []
            if refs:
                recommendation_url = refs[0] if isinstance(refs[0], str) else ""
            remediation_code = json.dumps(remediation.get("code", {})) if remediation.get("code") else ""

        cloud = raw.get("cloud") or {}
        account_id = (cloud.get("account") or {}).get("uid") or raw.get("account_id") or ""
        region     = raw.get("region") or (resource.get("region")) or ""
        service    = (raw.get("metadata") or {}).get("product", {}).get("feature", {}).get("name") or raw.get("service_name") or ""

        return {
            "account_id":         str(account_id),
            "account_name":       str(cloud.get("account", {}).get("name") or ""),
            "region":             str(region),
            "resource_arn":       str(resource_arn),
            "resource_type":      str(resource.get("type") or ""),
            "check_id":           str(check_id),
            "check_title":        str(check_title),
            "service":            str(service),
            "severity":           str(severity).upper(),
            "status":             str(status).upper(),
            "description":        str(raw.get("message") or raw.get("description") or ""),
            "risk":               str(raw.get("risk") or ""),
            "recommendation":     str(recommendation),
            "recommendation_url": str(recommendation_url),
            "remediation_code":   str(remediation_code),
            "raw_json":           json.dumps(raw),
        }
    except Exception as exc:
        print(f"  [WARN] Could not parse finding: {exc}", file=sys.stderr)
        return None


# ── Load findings ─────────────────────────────────────────────────────────────
def load_findings(json_path: Path) -> list[dict]:
    print(f"[{ts()}] Loading findings from {json_path} ...")
    findings = []
    with open(json_path) as f:
        content = f.read()
    # File may contain multiple concatenated JSON arrays — split and parse each
    decoder = json.JSONDecoder()
    pos = 0
    content = content.strip()
    while pos < len(content):
        try:
            obj, idx = decoder.raw_decode(content, pos)
            if isinstance(obj, list):
                findings.extend([i for i in obj if isinstance(i, dict)])
            elif isinstance(obj, dict):
                findings.append(obj)
            pos = idx
            # skip whitespace between arrays
            while pos < len(content) and content[pos] in ' \n\r\t,':
                pos += 1
        except json.JSONDecodeError:
            break
    print(f"[{ts()}] Loaded {len(findings)} raw findings")
    return findings

# ── Ingest ────────────────────────────────────────────────────────────────────
def ingest(findings: list[dict]) -> tuple[int, int]:
    rows = [r for f in findings if (r := parse_finding(f)) is not None]
    # Deduplicate by conflict key before insert
    seen = {}
    for r in rows:
        key = (r["account_id"], r["resource_arn"], r["check_id"])
        seen[key] = r
    rows = list(seen.values())
    print(f"[{ts()}] Parsed {len(rows)} findings (skipped {len(findings) - len(rows)} unparseable)")
    if not rows:
        return 0, len(findings)

    sql = """
        INSERT INTO prowler_findings (
            account_id, account_name, region, resource_arn, resource_type,
            check_id, check_title, service, severity, status,
            description, risk, recommendation, recommendation_url,
            remediation_code, raw_json
        ) VALUES %s
        ON CONFLICT (account_id, resource_arn, check_id)
        DO UPDATE SET
            status           = EXCLUDED.status,
            severity         = EXCLUDED.severity,
            description      = EXCLUDED.description,
            recommendation   = EXCLUDED.recommendation,
            remediation_code = EXCLUDED.remediation_code,
            raw_json         = EXCLUDED.raw_json,
            ingested_at      = NOW()
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
                execute_values(cur, sql, rows, template=template, page_size=500)
                inserted = cur.rowcount
        print(f"[{ts()}] ✓ Upserted {inserted} rows into prowler_findings")
        return inserted, len(findings) - len(rows)
    finally:
        conn.close()


# ── Summary ───────────────────────────────────────────────────────────────────
def print_summary():
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT severity, COUNT(*) AS total,
                       COUNT(*) FILTER (WHERE status='FAIL') AS failures
                FROM prowler_findings
                GROUP BY severity
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
                    WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
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


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser()
    group  = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--run",  action="store_true")
    group.add_argument("--file", nargs="+", metavar="JSON_FILE")
    parser.add_argument("--no-alert", action="store_true", help="Skip Slack alert")
    args = parser.parse_args()

    all_findings = []
    if args.run:
        all_findings.extend(load_findings(run_prowler()))
    else:
        for f in args.file:
            all_findings.extend(load_findings(Path(f)))

    inserted, skipped = ingest(all_findings)
    print_summary()
    print(f"[{ts()}] Done. inserted={inserted}, skipped={skipped}")

    if not args.no_alert:
        try:
            from slack_alert import send_new_critical_alerts
            send_new_critical_alerts()
        except Exception as e:
            print(f"[{ts()}] Slack alert skipped: {e}")


if __name__ == "__main__":
    main()
