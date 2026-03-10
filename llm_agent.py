#!/usr/bin/env python3
"""
llm_agent.py
------------
AI Security Agent — reads correlated findings from PostgreSQL
and uses Claude Haiku (via Amazon Bedrock) to generate
prioritised remediation advice.

The agent reads from these views:
  - v_full_attack_chains     (highest priority — complete attack chains)
  - v_critical_risks         (Prowler + Trivy correlated)
  - v_admin_escalation_paths (IAM privilege escalation)
  - v_public_s3_findings     (public S3 buckets)
  - v_risky_iam_users        (IAM users without MFA)

Usage
-----
# Full analysis of all findings:
    python3 llm_agent.py --analyse

# Analyse only critical attack chains:
    python3 llm_agent.py --analyse --mode chains

# Analyse a specific instance:
    python3 llm_agent.py --analyse --instance i-0abc123def456

# Save report to file:
    python3 llm_agent.py --analyse --output report.md
"""

import argparse
import boto3
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import psycopg2
from psycopg2.extras import RealDictCursor

# ── Config ────────────────────────────────────────────────────────────────────
DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}

AWS_REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
AWS_ACCOUNT_ID = os.getenv("AWS_ACCOUNT_ID", "")
MODEL_ID    = "meta.llama3-70b-instruct-v1:0"
MAX_TOKENS  = 2000


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


# ── DB helpers ────────────────────────────────────────────────────────────────
def query_db(sql, params=None):
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_attack_chains(instance_id=None):
    sql = "SELECT * FROM v_full_attack_chains"
    if instance_id:
        sql += " WHERE instance_id = %s"
        return query_db(sql, (instance_id,))
    return query_db(sql)


def get_critical_risks():
    return query_db("SELECT * FROM v_critical_risks LIMIT 20")


def get_escalation_paths():
    return query_db("SELECT * FROM v_admin_escalation_paths")


def get_public_s3():
    return query_db("""
        SELECT bucket_name, region, public_access_blocked,
               encryption_enabled, check_title, severity
        FROM v_public_s3_findings
        LIMIT 10
    """)


def get_risky_iam():
    return query_db("""
        SELECT user_name, mfa_enabled, has_access_keys,
               password_last_used, check_title, severity
        FROM v_risky_iam_users
        LIMIT 10
    """)


def get_summary_counts():
    return query_db("""
        SELECT
            (SELECT COUNT(*) FROM prowler_findings WHERE status='FAIL')     AS prowler_failures,
            (SELECT COUNT(*) FROM trivy_vulnerabilities WHERE status='OPEN' AND severity IN ('CRITICAL','HIGH')) AS critical_cves,
            (SELECT COUNT(*) FROM iam_risks WHERE target_is_admin=TRUE)     AS admin_paths,
            (SELECT COUNT(*) FROM aws_instances WHERE instance_state='running' AND public_ip IS NOT NULL) AS public_instances,
            (SELECT COUNT(*) FROM v_full_attack_chains)                     AS full_attack_chains
    """)[0]


# ── Bedrock / LLM ─────────────────────────────────────────────────────────────
def call_claude(prompt: str) -> str:
    client = boto3.client("bedrock-runtime", region_name=AWS_REGION)

    system = (
        "You are an expert AWS cloud security engineer. "
        "You analyse security findings and provide clear, prioritised, "
        "actionable remediation steps. Be specific — name exact AWS services, "
        "CLI commands, and console steps. Format your response in clean markdown. "
        "Always start with the most critical risk first."
    )

    full_prompt = (
        f"<|begin_of_text|><|start_header_id|>system<|end_header_id|>\n"
        f"{system}<|eot_id|>"
        f"<|start_header_id|>user<|end_header_id|>\n"
        f"{prompt}<|eot_id|>"
        f"<|start_header_id|>assistant<|end_header_id|>"
    )

    body = {
        "prompt":       full_prompt,
        "max_gen_len":  2000,
        "temperature":  0.2,
    }

    response = client.invoke_model(
        modelId=MODEL_ID,
        body=json.dumps(body),
        contentType="application/json",
        accept="application/json"
    )

    result = json.loads(response["body"].read())
    return result["generation"]


# ── Prompt builders ───────────────────────────────────────────────────────────
def build_full_analysis_prompt(chains, risks, escalations, s3_findings, iam_findings, counts):
    # Pull rich context directly
    import psycopg2, os
    db = {
        "host": os.getenv("PGHOST","127.0.0.1"), "port": int(os.getenv("PGPORT","5432")),
        "dbname": os.getenv("PGDATABASE","cloud_security"),
        "user": os.getenv("PGUSER","secadmin"), "password": os.getenv("PGPASSWORD","changeme"),
    }
    conn = psycopg2.connect(**db)
    cur  = conn.cursor()

    # Instances with public IPs + their SG status
    cur.execute("""
        SELECT i.instance_id, i.public_ip, i.instance_type, i.iam_instance_profile,
               i.name_tag,
               sg.allows_all_ingress, sg.allows_ssh_public, sg.group_id
        FROM aws_instances i
        LEFT JOIN aws_security_groups sg ON sg.vpc_id = i.vpc_id
        WHERE i.instance_state = 'running' AND i.public_ip IS NOT NULL
    """)
    instances = cur.fetchall()

    # CVEs per instance
    cur.execute("""
        SELECT instance_id, cve_id, severity, cvss_score, package_name,
               installed_version, fixed_version, title
        FROM trivy_vulnerabilities
        WHERE status = 'OPEN' AND severity IN ('CRITICAL','HIGH')
        ORDER BY cvss_score DESC
    """)
    cves = cur.fetchall()

    # S3 buckets
    cur.execute("""
        SELECT bucket_name, public_access_blocked, versioning_enabled, encryption_enabled
        FROM aws_s3_buckets
    """)
    buckets = cur.fetchall()

    # Top Prowler findings with real titles
    cur.execute("""
        SELECT check_title, severity, resource_arn, risk, recommendation
        FROM prowler_findings
        WHERE status = 'NEW' AND severity IN ('CRITICAL','HIGH')
        ORDER BY severity, check_title
        LIMIT 15
    """)
    prowler = cur.fetchall()

    conn.close()

    # Build instance context
    instance_block = ""
    for inst in instances:
        iid, pip, itype, iam_profile, name, all_open, ssh_open, sgid = inst
        role_name = iam_profile.split("/")[-1] if iam_profile else "None"
        instance_block += f"""
Instance: {iid} ({name or 'unnamed'})
  Public IP:      {pip}
  Type:           {itype}
  IAM Role:       {role_name}
  Security Group: {sgid} — All ports open: {all_open}, SSH public: {ssh_open}
"""
        # Attach CVEs for this instance
        inst_cves = [c for c in cves if c[0] == iid]
        if inst_cves:
            instance_block += "  CVEs:\n"
            for c in inst_cves:
                _, cve_id, sev, score, pkg, ver, fix, title = c
                instance_block += f"    - {cve_id} [{sev} {score}] {pkg} {ver} — {title}\n"
                if fix:
                    instance_block += f"      Fix: upgrade to {fix}\n"

    # S3 block
    s3_block = ""
    for b in buckets:
        bname, pub_blocked, versioning, encrypted = b
        s3_block += f"  - {bname}: public_access_blocked={pub_blocked}, versioning={versioning}, encrypted={encrypted}\n"

    # Prowler block
    prowler_block = ""
    for row in prowler:
        title, sev, arn, risk, rec = row
        resource = arn.split(":")[-1] if arn else "unknown"
        prowler_block += f"  [{sev}] {title} — {resource}\n"
        if rec:
            prowler_block += f"    Fix: {rec}\n"

    prompt = f"""
You are a senior AWS cloud security engineer analysing a real AWS account ({os.getenv('AWS_ACCOUNT_ID','unknown')}, {os.getenv('AWS_DEFAULT_REGION','us-east-1')}).
You have been given specific, real data about this account. Use the EXACT resource IDs, IPs, CVE IDs,
and role names in your response. Do NOT use placeholders like <instance-id> or <role-name>.
Be specific and concise. Every recommendation must reference the actual resource.

═══════════════════════════════════════════════════
REAL ACCOUNT DATA
═══════════════════════════════════════════════════

── PUBLIC EC2 INSTANCES & VULNERABILITIES ──
{instance_block}

── S3 BUCKETS ──
{s3_block}

── IAM ROLE PERMISSIONS ──
SecurityTestRole (attached to i-0e57d36efa7cfb216):
  - AmazonS3FullAccess  → can read/write/delete ALL S3 buckets
  - AmazonSSMManagedInstanceCore → can receive SSM commands

── TOP PROWLER MISCONFIGURATIONS ──
{prowler_block}

── ATTACK CHAIN ANALYSIS ──
Complete attack path identified:
1. i-0e57d36efa7cfb216 is reachable at 100.54.21.88 (all ports open via sg-0467a3a5cf6842bcc)
2. CVE-2025-15558 (Docker CLI privilege escalation, CVSS 7.3) — attacker gets root on instance
3. Root on instance → query IMDS at 169.254.169.254 → get SecurityTestRole credentials
4. SecurityTestRole has AmazonS3FullAccess → attacker can exfiltrate cloud-sec-agent-024863982143
5. Bucket has public_access_blocked=false and versioning=false → no recovery after deletion

═══════════════════════════════════════════════════
PROVIDE THE FOLLOWING (use real resource IDs only):
═══════════════════════════════════════════════════

1. EXECUTIVE SUMMARY (3-4 sentences, mention the specific attack path above)

2. TOP 5 PRIORITISED ACTIONS
   For each: exact AWS CLI command using real IDs, not placeholders.
   Order by what stops the attack chain fastest.

3. ATTACK CHAIN WALKTHROUGH
   Walk through the 5-step attack path above as if you are the attacker.
   Explain what data is at risk and what the business impact is.

4. QUICK WINS (under 5 minutes each, exact commands with real IDs)
"""
    return prompt


def build_chain_prompt(chains):
    prompt = f"""
Analyse these complete attack chains found in an AWS account:

{json.dumps(chains, indent=2, default=str)}

For each attack chain:
1. Explain the attack scenario in plain English (how would an attacker exploit this?)
2. Give the exact remediation steps with AWS CLI commands
3. Rate the urgency (how quickly should this be fixed?)
4. Explain what happens if left unpatched

Be specific about instance names, CVE IDs, and IAM role names from the data above.
"""
    return prompt


# ── Report output ─────────────────────────────────────────────────────────────
def save_report(content: str, output_path: str):
    path = Path(output_path)
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    full_content = f"# AI Cloud Security Agent Report\n**Generated:** {timestamp}\n\n{content}"
    path.write_text(full_content)
    print(f"[{ts()}] Report saved to {path}")


def print_report(content: str):
    print("\n" + "═" * 70)
    print("  AI CLOUD SECURITY AGENT — ANALYSIS REPORT")
    print("═" * 70)
    print(content)
    print("═" * 70 + "\n")


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="AI Security Agent — analyse findings with Claude Haiku")
    parser.add_argument("--analyse",  action="store_true", required=True,
                        help="Run security analysis")
    parser.add_argument("--mode",     choices=["full", "chains", "iam", "s3"],
                        default="full", help="What to analyse (default: full)")
    parser.add_argument("--instance", metavar="INSTANCE_ID",
                        help="Analyse a specific instance only")
    parser.add_argument("--output",   metavar="FILE",
                        help="Save report to markdown file (e.g. report.md)")
    args = parser.parse_args()

    print(f"[{ts()}] AI Cloud Security Agent starting...")
    print(f"[{ts()}] Model: {MODEL_ID} via Amazon Bedrock ({AWS_REGION})")
    print(f"[{ts()}] Fetching findings from database...")

    # Fetch all data
    counts      = get_summary_counts()
    chains      = get_attack_chains(args.instance)
    risks       = get_critical_risks()
    escalations = get_escalation_paths()
    s3_findings = get_public_s3()
    iam_findings= get_risky_iam()

    print(f"[{ts()}] Found:")
    print(f"         {counts['prowler_failures']} Prowler failures")
    print(f"         {counts['critical_cves']} Critical/High CVEs")
    print(f"         {counts['admin_paths']} IAM paths to admin")
    print(f"         {counts['full_attack_chains']} complete attack chains")
    print(f"[{ts()}] Sending to Claude Haiku for analysis...")

    # Build prompt based on mode
    if args.mode == "chains" or args.instance:
        prompt = build_chain_prompt(chains)
    else:
        prompt = build_full_analysis_prompt(
            chains, risks, escalations, s3_findings, iam_findings, counts
        )

    # Call Claude
    report = call_claude(prompt)

    # Output
    print_report(report)

    if args.output:
        save_report(report, args.output)

    print(f"[{ts()}] Done.")


if __name__ == "__main__":
    main()
