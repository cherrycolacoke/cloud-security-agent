#!/usr/bin/env python3
"""
slack_alert.py
--------------
Sends Slack notifications for critical security findings.
Called automatically at the end of prowler_ingest.py and trivy_ingest.py.

Reads:
  - SLACK_WEBHOOK_URL from .env
  - v_full_attack_chains and v_critical_risks from cloud_security DB

Usage:
  from slack_alert import send_new_critical_alerts
  send_new_critical_alerts()

Or standalone:
  python3 slack_alert.py
"""

import json
import os
import urllib.request
import urllib.error
from datetime import datetime, timezone

import psycopg2
from psycopg2.extras import RealDictCursor

DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
RISK_SCORE_THRESHOLD = 12


def ts():
    return datetime.now(timezone.utc).strftime("%H:%M:%S UTC")


def query_db(sql):
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def get_critical_chains():
    return query_db("""
        SELECT instance_id, name_tag, public_ip, region,
               misconfiguration, misconfig_severity,
               cve_id, cvss_score, package_name, fixed_version,
               escalation_path, escalates_to, target_is_admin,
               risk_score
        FROM v_full_attack_chains
        WHERE risk_score > %s
           OR target_is_admin = TRUE
        ORDER BY risk_score DESC NULLS LAST
        LIMIT 10
    """ .replace("%s", str(RISK_SCORE_THRESHOLD)))


def get_critical_risks():
    return query_db("""
        SELECT resource_arn, exposure, network_severity,
               cve_id, cvss_score, package_name, cve_title
        FROM v_critical_risks
        ORDER BY cvss_score DESC NULLS LAST
        LIMIT 10
    """)


def send_slack(message: dict):
    if not SLACK_WEBHOOK_URL:
        print(f"[{ts()}] SLACK_WEBHOOK_URL not set — skipping Slack alert")
        return False
    try:
        data = json.dumps(message).encode("utf-8")
        req  = urllib.request.Request(
            SLACK_WEBHOOK_URL,
            data=data,
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            ok = resp.read().decode() == "ok"
            if ok:
                print(f"[{ts()}] ✓ Slack alert sent")
            return ok
    except urllib.error.URLError as e:
        print(f"[{ts()}] ✗ Slack send failed: {e}")
        return False


def format_chain_alert(chains):
    if not chains:
        return None

    lines = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🔴 Critical Attack Chains Detected"}
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{len(chains)} complete attack chain(s)* found in your AWS account.\nAn attacker could exploit these to achieve full account takeover."
            }
        },
        {"type": "divider"}
    ]

    for c in chains[:3]:  # max 3 chains per alert
        admin_flag = "⚠️ ESCALATES TO ADMIN" if c.get("target_is_admin") else ""
        lines.append({
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Instance:*\n`{c.get('instance_id', 'N/A')}` ({c.get('name_tag', 'unnamed')})"},
                {"type": "mrkdwn", "text": f"*Public IP:*\n`{c.get('public_ip', 'none')}`"},
                {"type": "mrkdwn", "text": f"*CVE:*\n`{c.get('cve_id', 'N/A')}` CVSS {c.get('cvss_score', 'N/A')} ({c.get('package_name', '')})"},
                {"type": "mrkdwn", "text": f"*Fix:*\nUpgrade to `{c.get('fixed_version', 'no fix yet')}`"},
                {"type": "mrkdwn", "text": f"*Misconfiguration:*\n{c.get('misconfiguration', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Risk Score:*\n`{c.get('risk_score', 'N/A')}` {admin_flag}"},
            ]
        })
        if c.get("escalation_path"):
            lines.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*IAM Path:* `{c.get('escalation_path', 'N/A')}`"
                }
            })
        lines.append({"type": "divider"})

    lines.append({
        "type": "section",
        "text": {
            "type": "mrkdwn",
            "text": "Run `python3 llm_agent.py --analyse --output report.md` for full remediation advice."
        }
    })

    return {"blocks": lines}


def format_risks_alert(risks):
    if not risks:
        return None

    text_lines = [f"*🟠 {len(risks)} Critical/High CVE+Misconfiguration Correlations*\n"]
    for r in risks[:5]:
        text_lines.append(
            f"• `{r.get('cve_id')}` CVSS {r.get('cvss_score')} | "
            f"{r.get('package_name')} | "
            f"{r.get('exposure', '')[:60]}"
        )

    return {
        "blocks": [{
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(text_lines)}
        }]
    }


def send_new_critical_alerts():
    """
    Main entry point — called from prowler_ingest.py and trivy_ingest.py.
    """
    if not SLACK_WEBHOOK_URL:
        print(f"[{ts()}] Slack webhook not configured — add SLACK_WEBHOOK_URL to .env")
        return

    print(f"[{ts()}] Checking for critical findings to alert...")

    chains = get_critical_chains()
    risks  = get_critical_risks()

    if not chains and not risks:
        print(f"[{ts()}] No critical findings above threshold — no alert sent")
        return

    if chains:
        msg = format_chain_alert(chains)
        if msg:
            send_slack(msg)

    if risks and not chains:
        msg = format_risks_alert(risks)
        if msg:
            send_slack(msg)


if __name__ == "__main__":
    send_new_critical_alerts()
