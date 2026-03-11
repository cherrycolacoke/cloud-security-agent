#!/usr/bin/env python3
"""
dashboard.py
------------
Web dashboard for the AI Cloud Security Agent.
Reads from the cloud_security PostgreSQL database and renders findings
in a browser.

Usage:
    cd dashboard/
    python3 dashboard.py

Then open: http://localhost:5001
"""

import os
import sys
from pathlib import Path

# Add project root to path so we can import DB config
sys.path.insert(0, str(Path(__file__).parent.parent))

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime, timezone

app = Flask(__name__)

app.secret_key = os.getenv("DASHBOARD_SECRET_KEY", "change-this-secret")
DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "changeme")


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("authenticated"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if request.form.get("password") == DASHBOARD_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("index"))
        error = "Incorrect password"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


DB_CONFIG = {
    "host":     os.getenv("PGHOST",     "127.0.0.1"),
    "port":     int(os.getenv("PGPORT", "5432")),
    "dbname":   os.getenv("PGDATABASE", "cloud_security"),
    "user":     os.getenv("PGUSER",     "secadmin"),
    "password": os.getenv("PGPASSWORD", "changeme"),
}


def query(sql, params=None):
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def query_one(sql, params=None):
    rows = query(sql, params)
    return rows[0] if rows else {}


# ── Routes ────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    return render_template("index.html")


@app.route("/api/summary")
@login_required
def api_summary():
    data = query_one("""
        SELECT
            (SELECT COUNT(*) FROM prowler_findings WHERE status = 'FAIL')                          AS prowler_failures,
            (SELECT COUNT(*) FROM prowler_findings WHERE status = 'FAIL' AND severity = 'CRITICAL') AS critical_findings,
            (SELECT COUNT(*) FROM prowler_findings WHERE status = 'FAIL' AND severity = 'HIGH')     AS high_findings,
            (SELECT COUNT(*) FROM trivy_vulnerabilities WHERE status = 'OPEN' AND severity IN ('CRITICAL','HIGH')) AS critical_cves,
            (SELECT COUNT(*) FROM iam_risks WHERE target_is_admin = TRUE)                           AS admin_paths,
            (SELECT COUNT(*) FROM v_full_attack_chains)                                             AS attack_chains,
            (SELECT COUNT(*) FROM aws_instances WHERE instance_state = 'running')                   AS running_instances,
            (SELECT COUNT(*) FROM aws_instances WHERE instance_state = 'running' AND public_ip IS NOT NULL) AS public_instances,
            (SELECT COUNT(*) FROM aws_s3_buckets)                                                   AS s3_buckets,
            (SELECT COUNT(*) FROM aws_s3_buckets WHERE public_access_blocked = FALSE)               AS public_buckets,
            (SELECT MAX(ingested_at) FROM prowler_findings)                                         AS last_scan
    """)
    # Serialize datetime
    if data.get("last_scan"):
        data["last_scan"] = data["last_scan"].strftime("%Y-%m-%d %H:%M UTC")
    return jsonify(data)


@app.route("/api/severity_breakdown")
@login_required
def api_severity_breakdown():
    rows = query("""
        SELECT severity, COUNT(*) AS total
        FROM prowler_findings
        WHERE status = 'FAIL'
        GROUP BY severity
        ORDER BY CASE severity
            WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
            WHEN 'MEDIUM'   THEN 3 WHEN 'LOW'  THEN 4 ELSE 5 END
    """)
    return jsonify(rows)


@app.route("/api/attack_chains")
@login_required
def api_attack_chains():
    rows = query("""
        SELECT
            instance_id, name_tag, public_ip, region,
            misconfiguration, misconfig_severity,
            cve_id, cvss_score, package_name, fixed_version,
            escalation_path, escalates_to, target_is_admin,
            risk_score
        FROM v_full_attack_chains
        ORDER BY risk_score DESC NULLS LAST
        LIMIT 20
    """)
    return jsonify(rows)


@app.route("/api/critical_findings")
@login_required
def api_critical_findings():
    rows = query("""
        SELECT check_title, severity, resource_arn, region, service,
               description, recommendation, ingested_at
        FROM prowler_findings
        WHERE status = 'FAIL' AND severity IN ('CRITICAL', 'HIGH')
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 ELSE 2 END, ingested_at DESC
        LIMIT 50
    """)
    for r in rows:
        if r.get("ingested_at"):
            r["ingested_at"] = r["ingested_at"].strftime("%Y-%m-%d %H:%M")
    return jsonify(rows)


@app.route("/api/cves")
@login_required
def api_cves():
    rows = query("""
        SELECT instance_id, cve_id, severity, cvss_score,
               package_name, installed_version, fixed_version, title
        FROM trivy_vulnerabilities
        WHERE status = 'OPEN' AND severity IN ('CRITICAL', 'HIGH')
        ORDER BY cvss_score DESC NULLS LAST
        LIMIT 50
    """)
    return jsonify(rows)


@app.route("/api/iam_risks")
@login_required
def api_iam_risks():
    rows = query("""
        SELECT source_name, source_type, target_name, target_type,
               target_is_admin, hops, severity, path
        FROM iam_risks
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3 END
        LIMIT 30
    """)
    return jsonify(rows)


@app.route("/api/instances")
@login_required
def api_instances():
    rows = query("""
        SELECT i.instance_id, i.name_tag, i.instance_type, i.instance_state,
               i.public_ip, i.region, i.iam_instance_profile,
               sg.allows_all_ingress, sg.allows_ssh_public
        FROM aws_instances i
        LEFT JOIN aws_security_groups sg ON sg.vpc_id = i.vpc_id
        WHERE i.instance_state = 'running'
        ORDER BY i.public_ip NULLS LAST
        LIMIT 50
    """)
    return jsonify(rows)


@app.route("/api/services_breakdown")
@login_required
def api_services_breakdown():
    rows = query("""
        SELECT service, COUNT(*) AS failures
        FROM prowler_findings
        WHERE status = 'FAIL' AND service IS NOT NULL AND service != ''
        GROUP BY service
        ORDER BY failures DESC
        LIMIT 10
    """)
    return jsonify(rows)


@app.route("/api/report")
@login_required
def api_report():
    import glob
    project_root = Path(__file__).parent.parent
    # Find the most recent report file
    reports = sorted(project_root.glob("security_report*.md"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        return jsonify({"content": None, "filename": None, "generated": None})
    report = reports[0]
    content = report.read_text()
    generated = datetime.fromtimestamp(report.stat().st_mtime, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return jsonify({"content": content, "filename": report.name, "generated": generated})


if __name__ == "__main__":
    print("\n" + "="*50)
    print("  AI Cloud Security Agent — Dashboard")
    print("  Open: http://localhost:5001")
    print("="*50 + "\n")
    app.run(host="0.0.0.0", port=5001, debug=False)
