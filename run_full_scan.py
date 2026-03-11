#!/usr/bin/env python3
"""
run_full_scan.py
----------------
Orchestrates the full AI Cloud Security Agent pipeline across one or
more AWS accounts defined in accounts.yaml.

Steps per account:
  1. Prowler  → prowler_findings
  2. Trivy    → trivy_vulnerabilities
  3. Steampipe → inventory tables
  4. PMapper  → iam_risks
  5. LLM Agent → security_report_<account>.md
  6. Slack alerts

Usage:
  python3 run_full_scan.py                          # all accounts, live AWS
  python3 run_full_scan.py --account production     # single account by name
  python3 run_full_scan.py --account 024863982143   # single account by ID
  python3 run_full_scan.py --sample                 # sample data, no AWS needed
  python3 run_full_scan.py --skip trivy steampipe   # skip specific steps
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

from account_manager import AccountManager

PROJECT_DIR = Path(__file__).parent
PYTHON      = sys.executable
LOG_DIR     = PROJECT_DIR / "logs"


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def run(step_name: str, cmd: list[str], log_file: Path, env: dict = None) -> bool:
    print(f"\n{'='*60}")
    print(f"[{ts()}] STEP: {step_name}")
    print(f"{'='*60}")

    step_env = {**os.environ, **(env or {})}

    with open(log_file, "a") as log:
        log.write(f"\n\n[{ts()}] === {step_name} ===\n")
        result = subprocess.run(
            cmd,
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=step_env,
        )
        log.write(result.stdout)
        print(result.stdout)
        if result.returncode != 0:
            print(f"[{ts()}] ✗ {step_name} failed (exit {result.returncode})")
            log.write(f"\n[ERROR] Exit code: {result.returncode}\n")
            return False
        print(f"[{ts()}] ✓ {step_name} complete")
        return True


def scan_account(account: dict, args: argparse.Namespace,
                 log_file: Path, report_dir: Path) -> tuple[int, int]:
    """
    Run the full pipeline for a single AWS account.
    Returns (steps_run, steps_failed).
    """
    account_id   = account["id"]
    account_name = account.get("name", account_id)
    region       = account.get("region", "us-east-1")

    # Per-account env overrides passed to every subprocess
    account_env = {
        "AWS_ACCOUNT_ID":      account_id,
        "AWS_DEFAULT_REGION":  region,
    }
    if "profile" in account:
        account_env["AWS_PROFILE"] = account["profile"]

    report_file = report_dir / f"security_report_{account_name}.md"

    print(f"\n{'#'*60}")
    print(f"  Account: {account_name} ({account_id})  |  Region: {region}")
    print(f"{'#'*60}")

    steps_run    = 0
    steps_failed = 0

    # ── 1. Prowler ─────────────────────────────────────────────────────────────
    if "prowler" not in args.skip:
        if args.sample:
            cmd = [PYTHON, "ingestion/prowler_ingest.py", "--file", "sample_data/sample_findings.json", "--no-alert"]
        else:
            cmd = [PYTHON, "ingestion/prowler_ingest.py", "--run", "--no-alert"]
        ok = run(f"Prowler [{account_name}]", cmd, log_file, account_env)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 2. Trivy ───────────────────────────────────────────────────────────────
    if "trivy" not in args.skip:
        if args.sample:
            cmd = [PYTHON, "ingestion/trivy_ingest.py", "--file", "sample_data/i-0abc123def456.json", "--no-alert"]
        else:
            cmd = [PYTHON, "ingestion/trivy_ingest.py", "--scan-all", "--no-alert"]
        ok = run(f"Trivy [{account_name}]", cmd, log_file, account_env)
        steps_run += 1
        if not ok:
            steps_failed += 1

        if args.sample:
            fix_cmd = [
                "psql", "-U", os.getenv("PGUSER", "secadmin"),
                "-d", os.getenv("PGDATABASE", "cloud_security"),
                "-c",
                "UPDATE trivy_vulnerabilities "
                "SET resource_arn = 'arn:aws:ec2:us-east-1:123456789012:instance/i-0abc123def456' "
                "WHERE instance_id = 'i-0abc123def456';"
            ]
            subprocess.run(fix_cmd, cwd=PROJECT_DIR, env={**os.environ, **account_env})

    # ── 3. Steampipe ───────────────────────────────────────────────────────────
    if "steampipe" not in args.skip:
        cmd = [PYTHON, "ingestion/steampipe_ingest.py", "--sample" if args.sample else "--sync"]
        ok  = run(f"Steampipe [{account_name}]", cmd, log_file, account_env)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 4. PMapper ─────────────────────────────────────────────────────────────
    if "pmapper" not in args.skip:
        cmd = [PYTHON, "ingestion/pmapper_ingest.py", "--sample" if args.sample else "--run"]
        ok  = run(f"PMapper [{account_name}]", cmd, log_file, account_env)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 5. LLM Agent ───────────────────────────────────────────────────────────
    if "llm" not in args.skip:
        cmd = [PYTHON, "llm_agent.py", "--analyse", "--output", str(report_file)]
        ok  = run(f"LLM Agent [{account_name}]", cmd, log_file, account_env)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 6. Slack alerts ────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"[{ts()}] STEP: Slack Alerts [{account_name}]")
    print(f"{'='*60}")
    try:
        from slack_alert import send_new_critical_alerts
        send_new_critical_alerts()
        print(f"[{ts()}] ✓ Slack alerts sent")
    except Exception as e:
        print(f"[{ts()}] Slack alerts skipped: {e}")

    return steps_run, steps_failed


def main():
    parser = argparse.ArgumentParser(description="Run full AI Cloud Security Agent pipeline")
    parser.add_argument("--account", metavar="ID_OR_NAME",
                        help="Target a specific account by ID or name (default: all)")
    parser.add_argument("--sample", action="store_true",
                        help="Use sample data instead of live AWS scans")
    parser.add_argument("--skip", nargs="+",
                        choices=["prowler", "trivy", "steampipe", "pmapper", "llm"],
                        default=[],
                        help="Skip specific pipeline steps")
    args = parser.parse_args()

    # ── Load accounts ──────────────────────────────────────────────────────────
    mgr      = AccountManager()
    accounts = mgr.select(args.account)

    LOG_DIR.mkdir(exist_ok=True)
    date_str   = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file   = LOG_DIR / f"scan_{date_str}.log"
    report_dir = PROJECT_DIR  # reports land next to the scripts

    print(f"\n{'#'*60}")
    print(f"  AI Cloud Security Agent — Full Pipeline")
    print(f"  Accounts:  {len(accounts)}  ({', '.join(a.get('name', a['id']) for a in accounts)})")
    print(f"  Mode:      {'SAMPLE DATA' if args.sample else 'LIVE AWS'}")
    print(f"  Started:   {ts()}")
    print(f"  Log:       {log_file}")
    print(f"{'#'*60}")

    total_run    = 0
    total_failed = 0

    for account in accounts:
        # Verify credentials before scanning (skip in sample mode)
        if not args.sample:
            ok, msg = mgr.verify(account)
            if not ok:
                print(f"\n[{ts()}] ✗ Skipping {account.get('name', account['id'])}: {msg}")
                continue
            print(f"\n[{ts()}] {msg}")

        run_count, fail_count = scan_account(account, args, log_file, report_dir)
        total_run    += run_count
        total_failed += fail_count

    # ── Final summary ──────────────────────────────────────────────────────────
    print(f"\n{'#'*60}")
    print(f"  Pipeline Complete")
    print(f"  Accounts scanned: {len(accounts)}")
    print(f"  Steps run:        {total_run}  |  Failed: {total_failed}")
    print(f"  Log:              {log_file}")
    print(f"  Finished:         {ts()}")
    print(f"{'#'*60}\n")

    sys.exit(1 if total_failed > 0 else 0)


if __name__ == "__main__":
    main()
