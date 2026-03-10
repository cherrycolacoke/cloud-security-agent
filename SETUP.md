# Setup Guide — AI Cloud Security Agent

This guide walks you through setting up the agent on your own machine from scratch.
Estimated time: **20–30 minutes**.

---

## What You Need Before Starting

- A Mac or Linux machine (Windows works via WSL2)
- An AWS account with billing enabled
- AWS CLI installed ([download here](https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2.html))
- Terraform installed ([download here](https://developer.hashicorp.com/terraform/install))
- Docker installed ([download here](https://docs.docker.com/get-docker/))
- Python 3.11 or higher (`python3 --version` to check)
- Git installed

---

## Step 1 — Configure AWS CLI

If you haven't already, set up your AWS credentials:

```bash
aws configure
```

Enter when prompted:
- **AWS Access Key ID** — from IAM → Users → your user → Security credentials
- **AWS Secret Access Key** — same place
- **Default region** — use `us-east-1` (required for Bedrock Llama 3)
- **Output format** — `json`

Verify it works:
```bash
aws sts get-caller-identity
```

You should see your Account ID and ARN printed. If you get an error, your credentials are wrong.

---

## Step 2 — Enable Bedrock Model Access

The agent uses **Llama 3 70B via Amazon Bedrock** for its AI analysis. You need to enable it manually in the AWS console — it's free to request, you only pay per use.

1. Go to [AWS Console → Bedrock](https://console.aws.amazon.com/bedrock)
2. Make sure you're in **us-east-1** (top right region selector)
3. In the left sidebar click **"Model access"**
4. Click **"Modify model access"**
5. Find **Meta → Llama 3 70B Instruct** and tick the checkbox
6. Click **"Next"** → **"Submit"**
7. Wait 1–2 minutes for status to change to **"Access granted"**

> ⚠️ If you skip this step the LLM analysis will fail with an "Access denied" error.

---

## Step 3 — Clone the Repo

```bash
git clone https://github.com/cherrycolacoke/cloud-security-agent
cd cloud-security-agent
```

---

## Step 4 — Provision AWS Infrastructure with Terraform

This creates everything the agent needs in your AWS account:
- IAM role (`CloudSecurityAgentRole`) with SecurityAudit + ReadOnly permissions
- S3 bucket for storing Trivy scan results
- SSM and Bedrock permissions

```bash
cd terraform/

# Copy the example config
cp terraform.tfvars.example terraform.tfvars
```

Open `terraform.tfvars` and set your region and profile:
```hcl
aws_region  = "us-east-1"   # must match the region where you enabled Bedrock
aws_profile = "default"      # matches your aws configure profile name
environment = "production"
```

Now run Terraform:
```bash
terraform init
terraform apply
```

Type `yes` when prompted. It takes about 30 seconds.

At the end you'll see output like this — **copy it, you'll need it in Step 6**:
```
role_arn   = "arn:aws:iam::123456789012:role/CloudSecurityAgentRole"
account_id = "123456789012"
s3_bucket  = "cloud-sec-agent-123456789012"
```

Go back to the project root:
```bash
cd ..
```

---

## Step 5 — Set Up Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate      # on Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Install additional tools:

**Prowler** (AWS config scanner):
```bash
pip install prowler
```

**Trivy** (CVE scanner — Mac):
```bash
brew install trivy
```

**Trivy** (Linux):
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
```

**Steampipe** (AWS inventory — Mac):
```bash
brew tap turbot/tap
brew install steampipe
steampipe plugin install aws
```

**Steampipe** (Linux):
```bash
sudo /bin/sh -c "$(curl -fsSL https://steampipe.io/install/steampipe.sh)"
steampipe plugin install aws
```

---

## Step 6 — Configure the Agent

**Set up environment variables:**
```bash
cp .env.example .env
```

Open `.env` and fill in:
```bash
export PGHOST=127.0.0.1
export PGPORT=5432
export PGDATABASE=cloud_security
export PGUSER=secadmin
export PGPASSWORD=changeme          # pick any password

export AWS_PROFILE=default          # your aws configure profile name
export AWS_DEFAULT_REGION=us-east-1
export AWS_ACCOUNT_ID=123456789012  # your actual AWS account ID

export SLACK_WEBHOOK_URL=           # optional — leave blank to skip Slack

export BEDROCK_MODEL_ID=meta.llama3-70b-instruct-v1:0
```

**Configure your account:**

Open `accounts.yaml` and replace the example with your details from the Terraform output:
```yaml
accounts:
  - id: "123456789012"          # your AWS account ID
    name: production
    region: us-east-1
    role_arn: arn:aws:iam::123456789012:role/CloudSecurityAgentRole
```

---

## Step 7 — Start PostgreSQL

The agent stores all findings in a local PostgreSQL database. Start it with Docker:

```bash
docker run -d \
  --name cloud-security-db \
  -e POSTGRES_USER=secadmin \
  -e POSTGRES_PASSWORD=changeme \
  -e POSTGRES_DB=cloud_security \
  -p 5432:5432 \
  postgres:15
```

Wait 5 seconds for it to start, then load the database schema:

```bash
source .env

psql -h 127.0.0.1 -U secadmin -d cloud_security -f init.sql
psql -h 127.0.0.1 -U secadmin -d cloud_security -f steampipe_schema.sql
psql -h 127.0.0.1 -U secadmin -d cloud_security -f trivy_schema.sql
psql -h 127.0.0.1 -U secadmin -d cloud_security -f pmapper_schema.sql
```

Each command should print `CREATE TABLE` or `CREATE VIEW` — no errors.

---

## Step 8 — Verify Everything Works

```bash
source .env

# Check AWS credentials and role access
python3 account_manager.py --verify
```

You should see:
```
✓ 123456789012 (production) → arn:aws:iam::123456789012:assumed-role/CloudSecurityAgentRole/...
```

If you see an error here, double-check your `accounts.yaml` role_arn and that Terraform ran successfully.

---

## Step 9 — Run Your First Scan

**Test with sample data first (no real AWS scan, instant):**
```bash
python3 run_full_scan.py --sample
```

This runs the full pipeline against sample data so you can see everything working before hitting real AWS.

**Full live scan against your AWS account:**
```bash
python3 run_full_scan.py
```

This will take 10–20 minutes depending on how many resources are in your account. It will:
1. Run Prowler (checks ~300 AWS config rules)
2. Scan EC2 instances with Trivy via SSM
3. Sync AWS inventory via Steampipe
4. Analyse IAM escalation paths with PMapper
5. Generate an AI security report → `security_report_production.md`
6. Send Slack alerts if configured

---

## Step 10 — Schedule Nightly Scans (Optional)

```bash
bash cron_setup.sh
```

This installs a cron job that runs the full scan every night at 1am automatically.

---

## Troubleshooting

**`aws sts get-caller-identity` fails**
→ Run `aws configure` again and double-check your Access Key ID and Secret

**`terraform apply` fails with "Access Denied"**
→ Your IAM user needs `AdministratorAccess` or at minimum `IAMFullAccess` + `S3FullAccess`

**`python3 account_manager.py --verify` fails**
→ Make sure `accounts.yaml` has the correct `role_arn` from the Terraform output

**Bedrock returns "Access denied to the model"**
→ Go back to Step 2 and confirm model access status is "Access granted" in the console

**Prowler fails with no findings**
→ Make sure `source .env` was run before `python3 run_full_scan.py`

**psql: connection refused**
→ Your Docker container isn't running. Check with `docker ps` and restart if needed:
```bash
docker start cloud-security-db
```

**Steampipe connection fails**
→ Start the Steampipe service manually:
```bash
steampipe service start
```

---

## Adding a Second AWS Account

1. Run Terraform in the new account:
```bash
cd terraform/
# Edit terraform.tfvars with the new account's profile
terraform apply
```

2. Add the new account to `accounts.yaml`:
```yaml
accounts:
  - id: "111122223333"
    name: staging
    region: us-east-1
    role_arn: arn:aws:iam::111122223333:role/CloudSecurityAgentRole
```

3. The next `run_full_scan.py` will scan both accounts automatically.
