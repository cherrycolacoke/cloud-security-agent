# AI Cloud Security Agent

An automated AWS security scanning agent that combines Prowler, Trivy, Steampipe, and PMapper
into a single pipeline — with an LLM (via Amazon Bedrock) generating prioritised remediation reports.

Supports **multiple AWS accounts** out of the box.

---

## What It Does

1. **Prowler** — scans AWS config for misconfigurations (297+ checks)
2. **Trivy** — scans EC2 instances for CVEs via SSM
3. **Steampipe** — syncs live AWS inventory (EC2, S3, IAM, VPCs, Security Groups)
4. **PMapper** — finds IAM privilege escalation paths
5. **LLM Agent** — sends all findings to Llama 3 via Amazon Bedrock, generates a prioritised markdown report
6. **Slack** — sends alerts for critical attack chains automatically

---

## Quickstart

### Prerequisites
- Python 3.11+
- Docker (for PostgreSQL)
- AWS CLI configured (`aws configure`)
- Terraform 1.3+ (for AWS setup)

---

### Step 1 — Provision AWS Infrastructure (2 minutes)

This creates the IAM role, S3 bucket, and permissions your agent needs.

```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars — set your region and AWS profile

terraform init
terraform apply
```

Terraform will output your **role ARN** and **account ID** — copy these for Step 3.

---

### Step 2 — Set Up the Agent Locally

```bash
git clone https://github.com/cherrycolacoke/cloud-security-agent
cd cloud-security-agent

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Copy and fill in environment variables
cp .env.example .env
# Edit .env — set PGPASSWORD, SLACK_WEBHOOK_URL, etc.
source .env
```

Start PostgreSQL:
```bash
docker run -d \
  --name cloud-security-db \
  -e POSTGRES_USER=secadmin \
  -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_DB=cloud_security \
  -p 5432:5432 \
  postgres:15

psql -h localhost -U secadmin -d cloud_security -f init.sql
psql -h localhost -U secadmin -d cloud_security -f steampipe_schema.sql
psql -h localhost -U secadmin -d cloud_security -f trivy_schema.sql
psql -h localhost -U secadmin -d cloud_security -f pmapper_schema.sql
```

---

### Step 3 — Configure Your Accounts

Edit `accounts.yaml` with the outputs from `terraform apply`:

```yaml
accounts:
  - id: "123456789012"       # your AWS account ID
    name: production
    region: us-east-1
    role_arn: arn:aws:iam::123456789012:role/CloudSecurityAgentRole
```

Verify credentials work:
```bash
python3 account_manager.py --verify
```

---

### Step 4 — Run

```bash
# Full scan (live AWS)
python3 run_full_scan.py

# Single account
python3 run_full_scan.py --account production

# Sample data only (no AWS needed — for testing)
python3 run_full_scan.py --sample

# Skip specific steps
python3 run_full_scan.py --skip trivy steampipe
```

The LLM report is saved to `security_report_<account>.md`.

---

### Step 5 — Schedule Nightly Scans (Optional)

```bash
bash cron_setup.sh
```

This installs a cron job that runs the full pipeline every night at 1am.

---

## Adding More AWS Accounts

Just add a block to `accounts.yaml`:

```yaml
accounts:
  - id: "111122223333"
    name: staging
    region: us-east-1
    role_arn: arn:aws:iam::111122223333:role/CloudSecurityAgentRole

  - id: "444455556666"
    name: dev
    region: ap-south-1
    profile: dev-profile    # or use role_arn for cross-account
```

Run Terraform in each new account to provision the role, then add to `accounts.yaml`.
The next `run_full_scan.py` run will scan all accounts automatically.

---

## Project Structure

```
cloud-security-agent/
├── terraform/               # AWS infrastructure (IAM, S3)
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars.example
├── account_manager.py       # Multi-account credential management
├── accounts.yaml            # Account registry
├── run_full_scan.py         # Main pipeline orchestrator
├── llm_agent.py             # LLM analysis via Amazon Bedrock
├── prowler_ingest.py        # Prowler findings → PostgreSQL
├── trivy_ingest.py          # CVE scans via SSM → PostgreSQL
├── steampipe_ingest.py      # AWS inventory → PostgreSQL
├── pmapper_ingest.py        # IAM escalation paths → PostgreSQL
├── auto_remediate.py        # Auto-fix findings (with confirmation)
├── slack_alert.py           # Slack notifications
├── init.sql                 # Core DB schema
├── steampipe_schema.sql     # Inventory tables
├── trivy_schema.sql         # CVE tables
├── pmapper_schema.sql       # IAM risk tables
└── cron_setup.sh            # Nightly cron installer
```

---

## IAM Permissions

The Terraform module grants:
- `SecurityAudit` — read-only access for Prowler checks
- `ReadOnlyAccess` — inventory access for Steampipe
- `ssm:SendCommand` — run Trivy on EC2 instances
- `s3:*` on the agent bucket — store Trivy results
- `bedrock:InvokeModel` — call Llama 3 for analysis

No write permissions to your AWS resources (except auto_remediate.py which requires explicit confirmation).
