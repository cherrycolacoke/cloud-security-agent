#!/usr/bin/env python3
"""
run_full_scan.py
----------------
Orchestrates the full AI Cloud Security Agent pipeline:
  1. Prowler → prowler_findings
  2. Trivy   → trivy_vulnerabilities
  3. Steampipe → inventory tables
  4. PMapper → iam_risks
  5. LLM Agent → security_report.md
  6. Slack alerts fire automatically from prowler + trivy steps

Usage:
  python3 run_full_scan.py              # full run
  python3 run_full_scan.py --sample     # use sample data (no AWS needed)
  python3 run_full_scan.py --skip trivy steampipe  # skip specific steps
"""

import argparse
import subprocess
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
PYTHON      = sys.executable
LOG_DIR     = PROJECT_DIR / "logs"


def ts():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def run(step_name: str, cmd: list[str], log_file: Path) -> bool:
    print(f"\n{'='*60}")
    print(f"[{ts()}] STEP: {step_name}")
    print(f"{'='*60}")
    with open(log_file, "a") as log:
        log.write(f"\n\n[{ts()}] === {step_name} ===\n")
        result = subprocess.run(
            cmd,
            cwd=PROJECT_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        log.write(result.stdout)
        print(result.stdout)
        if result.returncode != 0:
            print(f"[{ts()}] ✗ {step_name} failed (exit {result.returncode})")
            log.write(f"\n[ERROR] Exit code: {result.returncode}\n")
            return False
        print(f"[{ts()}] ✓ {step_name} complete")
        return True


def main():
    parser = argparse.ArgumentParser(description="Run full AI Cloud Security Agent pipeline")
    parser.add_argument("--sample", action="store_true",
                        help="Use sample data instead of live AWS scans")
    parser.add_argument("--skip", nargs="+",
                        choices=["prowler","trivy","steampipe","pmapper","llm"],
                        default=[],
                        help="Skip specific steps")
    args = parser.parse_args()

    LOG_DIR.mkdir(exist_ok=True)
    date_str  = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file  = LOG_DIR / f"scan_{date_str}.log"
    report_file = PROJECT_DIR / "security_report.md"

    print(f"\n{'#'*60}")
    print(f"  AI Cloud Security Agent — Full Pipeline Run")
    print(f"  Mode: {'SAMPLE DATA' if args.sample else 'LIVE AWS'}")
    print(f"  Started: {ts()}")
    print(f"  Log: {log_file}")
    print(f"{'#'*60}")

    steps_run    = 0
    steps_failed = 0

    # ── 1. Prowler ─────────────────────────────────────────────────────────────
    if "prowler" not in args.skip:
        if args.sample:
            cmd = [PYTHON, "prowler_ingest.py", "--file", "sample_findings.json", "--no-alert"]
        else:
            cmd = [PYTHON, "prowler_ingest.py", "--run", "--no-alert"]
        ok = run("Prowler — AWS Config Scan", cmd, log_file)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 2. Trivy ───────────────────────────────────────────────────────────────
    if "trivy" not in args.skip:
        if args.sample:
            cmd = [PYTHON, "trivy_ingest.py", "--file", "i-0abc123def456.json", "--no-alert"]
        else:
            cmd = [PYTHON, "trivy_ingest.py", "--scan-all", "--no-alert"]
        ok = run("Trivy — CVE Scan via SSM", cmd, log_file)
        steps_run += 1
        if not ok:
            steps_failed += 1

        # Fix ARN for sample data
        if args.sample:
            fix_cmd = [
                "psql", "-U", os.getenv("PGUSER","secadmin"),
                "-d", os.getenv("PGDATABASE","cloud_security"),
                "-c", "UPDATE trivy_vulnerabilities SET resource_arn = 'arn:aws:ec2:us-west-2:123456789012:instance/i-0abc123def456' WHERE instance_id = 'i-0abc123def456';"
            ]
            subprocess.run(fix_cmd, cwd=PROJECT_DIR)

    # ── 3. Steampipe ───────────────────────────────────────────────────────────
    if "steampipe" not in args.skip:
        if args.sample:
            cmd = [PYTHON, "steampipe_ingest.py", "--sample"]
        else:
            cmd = [PYTHON, "steampipe_ingest.py", "--sync"]
        ok = run("Steampipe — AWS Inventory Sync", cmd, log_file)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 4. PMapper ─────────────────────────────────────────────────────────────
    if "pmapper" not in args.skip:
        if args.sample:
            cmd = [PYTHON, "pmapper_ingest.py", "--sample"]
        else:
            cmd = [PYTHON, "pmapper_ingest.py", "--run"]
        ok = run("PMapper — IAM Escalation Analysis", cmd, log_file)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 5. LLM Agent ───────────────────────────────────────────────────────────
    if "llm" not in args.skip:
        cmd = [PYTHON, "llm_agent.py", "--analyse", "--output", str(report_file)]
        ok = run("LLM Agent — AI Security Report", cmd, log_file)
        steps_run += 1
        if not ok:
            steps_failed += 1

    # ── 6. Slack alerts ────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"[{ts()}] STEP: Slack Alerts")
    print(f"{'='*60}")
    try:
        from slack_alert import send_new_critical_alerts
        send_new_critical_alerts()
        print(f"[{ts()}] ✓ Slack alerts sent")
    except Exception as e:
        print(f"[{ts()}] Slack alerts skipped: {e}")

    # ── Summary ────────────────────────────────────────────────────────────────
    print(f"\n{'#'*60}")
    print(f"  Pipeline Complete")
    print(f"  Steps run: {steps_run}  |  Failed: {steps_failed}")
    print(f"  Report: {report_file}")
    print(f"  Log: {log_file}")
    print(f"  Finished: {ts()}")
    print(f"{'#'*60}\n")

    sys.exit(1 if steps_failed > 0 else 0)


if __name__ == "__main__":
    main()
