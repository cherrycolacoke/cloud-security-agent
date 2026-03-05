# Prowler → PostgreSQL Setup

This folder contains everything needed to run Prowler and store its findings
in a PostgreSQL database — the first building block of your AI cloud security agent.

---

## Folder Structure

```
prowler-psql/
├── docker-compose.yml   # Spin up Postgres locally (dev)
├── init.sql             # Schema: prowler_findings table + views
├── prowler_ingest.py    # Run Prowler and/or ingest JSON → Postgres
├── requirements.txt     # Python deps
└── .env.example         # Copy → .env and fill in secrets
```

---

## Step 1 — Start PostgreSQL

**Option A: Local dev with Docker (recommended to start)**
```bash
docker compose up -d
```
Postgres will be available on `localhost:5432`. The schema (`init.sql`) is
applied automatically on first start.

**Option B: AWS RDS / existing Postgres**  
Skip Docker. Just make sure your DB is reachable and run `init.sql` manually:
```bash
psql -h <your-host> -U secadmin -d cloud_security -f init.sql
```

---

## Step 2 — Set Up Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## Step 3 — Configure Credentials

```bash
cp .env.example .env
# Edit .env — set PGPASSWORD, AWS_PROFILE, etc.
source .env   # or use: export $(cat .env | xargs)
```

Make sure your AWS credentials have the **SecurityAudit** managed policy
(or at minimum read-only access to the services you want to scan).

---

## Step 4 — Run Prowler and Ingest

**Run Prowler now and ingest immediately:**
```bash
python prowler_ingest.py --run
```

**Ingest an existing Prowler JSON file (useful if you already ran Prowler):**
```bash
python prowler_ingest.py --file prowler_output.json
```

**Multi-account: ingest multiple files at once:**
```bash
python prowler_ingest.py --file account_A.json account_B.json
```

After ingestion you'll see a severity summary printed to the terminal.

---

## Step 5 — Query the DB

Connect to Postgres and explore:
```bash
psql -h localhost -U secadmin -d cloud_security
```

```sql
-- All critical failures
SELECT account_id, region, service, check_title, resource_arn
FROM v_open_failures
WHERE severity = 'CRITICAL';

-- Severity breakdown
SELECT * FROM v_severity_summary;

-- Resources with multiple failures (noisy/risky resources)
SELECT resource_arn, COUNT(*) AS failure_count
FROM prowler_findings
WHERE status = 'FAIL'
GROUP BY resource_arn
ORDER BY failure_count DESC
LIMIT 20;
```

---

## What the Schema Looks Like

| Column | Description |
|---|---|
| `resource_arn` | **The join key** — links to Trivy findings later |
| `check_id` | Prowler check identifier (e.g. `iam_root_mfa_enabled`) |
| `severity` | CRITICAL / HIGH / MEDIUM / LOW |
| `status` | FAIL / PASS / WARNING |
| `description` | What's wrong |
| `recommendation` | How to fix it |
| `remediation_code` | IaC snippet when available |
| `raw_json` | Full Prowler payload (JSONB, queryable) |
| `ingested_at` | Timestamp of ingestion |

The `UNIQUE(account_id, resource_arn, check_id)` constraint means re-running
ingestion is safe — it upserts (updates existing rows) rather than duplicating.

---

## Scheduling (Optional)

Add a cron job to run nightly:
```bash
# Run every night at 1am UTC
0 1 * * * cd /path/to/prowler-psql && source .env && .venv/bin/python prowler_ingest.py --run >> prowler_cron.log 2>&1
```

---

## Next Step: Trivy Integration

Once Prowler is flowing into the DB, adding Trivy follows the same pattern:
1. Run `trivy rootfs / --scanners vuln --format json` on each EC2 (via SSM)
2. Write a `trivy_ingest.py` script (same structure as this one)
3. Store results in a `trivy_vulnerabilities` table with `resource_arn` as key
4. JOIN the two tables to find instances that are **both** publicly exposed AND have CVEs
