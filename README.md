# AI Cloud Security Agent

An AI-powered AWS security scanner that combines Prowler, Trivy, Steampipe, and PMapper into a single pipeline — ingesting findings into PostgreSQL, generating LLM-powered remediation reports via Amazon Bedrock, and surfacing everything in a web dashboard.

![Python](https://img.shields.io/badge/Python-3.11-blue?style=flat-square&logo=python)
![AWS](https://img.shields.io/badge/AWS-Bedrock-orange?style=flat-square&logo=amazon-aws)
![Terraform](https://img.shields.io/badge/Terraform-1.x-purple?style=flat-square&logo=terraform)
![Docker](https://img.shields.io/badge/Docker-Compose-2496ED?style=flat-square&logo=docker)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## What It Does

1. **Scans** your AWS account with Prowler (misconfigurations), Trivy (CVEs), Steampipe (inventory), and PMapper (IAM privilege escalation)
2. **Ingests** all findings into a PostgreSQL database with a unified schema
3. **Correlates** findings into complete attack chains — e.g. public instance + unpatched CVE + overprivileged IAM role = full compromise path
4. **Generates** an AI security report with prioritised remediation steps and AWS CLI commands via Amazon Bedrock (Llama 3)
5. **Alerts** on new critical findings via Slack
6. **Visualises** everything in a password-protected web dashboard

---

## Dashboard

| Overview | Attack Chains | LLM Report |
|----------|--------------|------------|
| Stat cards, severity breakdown, top vulnerable services | Complete exploit paths ranked by risk score | AI-generated remediation steps with copy-paste AWS CLI commands |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Your AWS Account                      │
│                                                             │
│   Prowler ──┐                                               │
│   Trivy   ──┼──► ingestion/ ──► PostgreSQL ──► LLM Agent   │
│   Steampipe─┤        │              │              │        │
│   PMapper ──┘        │         Dashboard        Slack       │
│                      │              │                       │
│              sample_data/    http://localhost:5001          │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
cloud-security-agent/
│
├── ingestion/                  # Data ingestion from each scanner
│   ├── prowler_ingest.py       # Prowler findings → PostgreSQL
│   ├── trivy_ingest.py         # Trivy CVEs → PostgreSQL
│   ├── steampipe_ingest.py     # AWS inventory → PostgreSQL
│   └── pmapper_ingest.py       # IAM risk graph → PostgreSQL
│
├── dashboard/                  # Web dashboard
│   ├── dashboard.py            # Flask app with REST API
│   └── templates/
│       ├── index.html          # Main dashboard (6 tabs)
│       └── login.html          # Password-protected login
│
├── schema/                     # PostgreSQL schema definitions
│   ├── init.sql                # Core findings tables + views
│   ├── steampipe_schema.sql    # AWS inventory tables
│   ├── trivy_schema.sql        # CVE tables
│   └── pmapper_schema.sql      # IAM risk graph tables
│
├── terraform/                  # AWS infrastructure as code
│   ├── main.tf                 # IAM role + S3 bucket
│   ├── ec2.tf                  # EC2 instance (optional)
│   ├── variables.tf
│   ├── outputs.tf
│   └── terraform.tfvars.example
│
├── scripts/                    # Shell scripts
│   ├── run_prowler.sh          # Prowler scan wrapper
│   ├── steampipe_setup.sh      # Steampipe install + config
│   └── cron_setup.sh           # Nightly cron job setup
│
├── sample_data/                # Sample scan outputs for testing
│   ├── sample_findings.json    # Prowler sample
│   ├── steampipe_sample.json   # Steampipe sample
│   ├── pmapper_sample.json     # PMapper sample
│   └── i-0abc123def456.json    # Trivy sample
│
├── run_full_scan.py            # Main pipeline orchestrator
├── llm_agent.py                # Amazon Bedrock LLM report generator
├── account_manager.py          # Multi-account AWS session manager
├── slack_alert.py              # Slack notifications
│
├── accounts.yaml.example       # Account config template (copy → accounts.yaml)
├── .env.example                # Environment variables template (copy → .env)
├── docker-compose.yml          # Full stack: Postgres + dashboard + scanner
├── Dockerfile                  # Container image
├── deploy.sh                   # One-command deployment
├── requirements.txt
└── SETUP.md                    # Detailed setup guide
```

---

## Quick Start

### Prerequisites

- AWS account with billing enabled
- [Docker Desktop](https://docs.docker.com/get-docker/)
- [AWS CLI](https://aws.amazon.com/cli/) configured
- [Terraform](https://developer.hashicorp.com/terraform/install) ≥ 1.0

### 1. Clone

```bash
git clone https://github.com/cherrycolacoke/cloud-security-agent
cd cloud-security-agent
```

### 2. Configure

```bash
cp .env.example .env
cp accounts.yaml.example accounts.yaml
```

Edit `.env` with your AWS account ID, DB password, and dashboard password.  
Edit `accounts.yaml` with your account ID and IAM role ARN.

### 3. Provision AWS Infrastructure

```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# set deploy_ec2 = true if you want a hosted dashboard
terraform init && terraform apply
```

Terraform creates the IAM role, S3 bucket, and optionally an EC2 instance.  
Copy the `role_arn` output into `accounts.yaml`.

### 4. Deploy

```bash
source .env
bash deploy.sh
```

Open **http://localhost:5001** (or the EC2 IP if you deployed to AWS).

### 5. Run a Scan

```bash
bash deploy.sh --sample   # instant test with sample data
bash deploy.sh --scan     # full live scan (~15 min)
```

Refresh the dashboard — all findings, CVEs, attack chains, and the LLM report populate automatically.

---

## Configuration

### `.env`

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_ACCOUNT_ID` | Your AWS account ID | required |
| `AWS_DEFAULT_REGION` | Primary region | `us-east-1` |
| `BEDROCK_MODEL_ID` | Bedrock model to use | `meta.llama3-70b-instruct-v1:0` |
| `PGPASSWORD` | PostgreSQL password | `changeme` |
| `DASHBOARD_PASSWORD` | Web dashboard login password | required |
| `SLACK_WEBHOOK_URL` | Slack webhook for alerts | optional |

### `accounts.yaml`

Add as many accounts as needed. Supports AWS CLI profiles and cross-account role assumption via STS.

---

## IAM Permissions Required

The `CloudSecurityAgentRole` created by Terraform has:

- `SecurityAudit` (AWS managed) — read-only access to all services
- `ReadOnlyAccess` (AWS managed) — inventory and config
- Inline policy for SSM, S3 (report storage), and Bedrock (LLM)

---

## Deployment Commands

```bash
bash deploy.sh              # start dashboard + postgres
bash deploy.sh --scan       # run full live scan
bash deploy.sh --sample     # test with sample data
bash deploy.sh --logs       # tail dashboard logs
bash deploy.sh --stop       # stop all containers
```

---

## Scanning Tools

| Tool | What It Scans | Output |
|------|--------------|--------|
| [Prowler](https://github.com/prowler-cloud/prowler) | 300+ AWS security checks | Misconfigurations, compliance |
| [Trivy](https://github.com/aquasecurity/trivy) | EC2 instance CVEs | CVE IDs, CVSS scores, fix versions |
| [Steampipe](https://steampipe.io) | AWS resource inventory | EC2, S3, IAM, SGs, VPCs |
| [PMapper](https://github.com/nccgroup/PMapper) | IAM privilege escalation | Attack paths to admin |

---

## Tech Stack

- **Backend:** Python 3.11, Flask, psycopg2
- **Database:** PostgreSQL 15
- **AI:** Amazon Bedrock (Meta Llama 3 70B)
- **Infrastructure:** Terraform, Docker Compose
- **Scanning:** Prowler, Trivy, Steampipe, PMapper

---

## Detailed Setup

See [SETUP.md](SETUP.md) for a full step-by-step guide covering tool installation, Bedrock model access, and troubleshooting.

---

## License

MIT
