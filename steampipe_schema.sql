-- ============================================================
-- Cloud Security DB: Steampipe AWS Inventory Schema
-- ============================================================
-- These tables store a snapshot of your AWS environment.
-- They are synced by steampipe_ingest.py and used to:
--   1. Know what resources exist (avoid scanning deleted things)
--   2. JOIN with Prowler/Trivy findings for richer context
--   3. Feed the LLM agent with live environment topology
-- ============================================================

-- ── EC2 Instances ─────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aws_instances (
    id                  SERIAL PRIMARY KEY,
    synced_at           TIMESTAMPTZ DEFAULT NOW(),

    -- Identity
    instance_id         TEXT UNIQUE,
    account_id          TEXT,
    region              TEXT,
    resource_arn        TEXT,          -- JOIN key with prowler_findings + trivy_vulnerabilities

    -- State
    instance_state      TEXT,          -- running | stopped | terminated
    instance_type       TEXT,          -- e.g. t3.micro
    launch_time         TIMESTAMPTZ,

    -- Network
    vpc_id              TEXT,
    subnet_id           TEXT,
    private_ip          TEXT,
    public_ip           TEXT,          -- NULL if no public IP
    public_dns          TEXT,

    -- Identity
    iam_instance_profile TEXT,         -- role attached to instance
    key_name            TEXT,

    -- Tags
    name_tag            TEXT,          -- value of the "Name" tag
    tags                JSONB,

    -- Raw
    raw_json            JSONB
);

CREATE INDEX IF NOT EXISTS idx_inst_account  ON aws_instances (account_id);
CREATE INDEX IF NOT EXISTS idx_inst_region   ON aws_instances (region);
CREATE INDEX IF NOT EXISTS idx_inst_state    ON aws_instances (instance_state);
CREATE INDEX IF NOT EXISTS idx_inst_arn      ON aws_instances (resource_arn);
CREATE INDEX IF NOT EXISTS idx_inst_vpc      ON aws_instances (vpc_id);

-- ── S3 Buckets ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aws_s3_buckets (
    id                  SERIAL PRIMARY KEY,
    synced_at           TIMESTAMPTZ DEFAULT NOW(),

    bucket_name         TEXT UNIQUE,
    account_id          TEXT,
    region              TEXT,
    resource_arn        TEXT,

    -- Access
    public_access_blocked   BOOLEAN,
    versioning_enabled      BOOLEAN,
    logging_enabled         BOOLEAN,
    encryption_enabled      BOOLEAN,

    -- Meta
    creation_date       TIMESTAMPTZ,
    tags                JSONB,
    raw_json            JSONB
);

CREATE INDEX IF NOT EXISTS idx_s3_account ON aws_s3_buckets (account_id);
CREATE INDEX IF NOT EXISTS idx_s3_public  ON aws_s3_buckets (public_access_blocked);

-- ── IAM Users ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aws_iam_users (
    id                  SERIAL PRIMARY KEY,
    synced_at           TIMESTAMPTZ DEFAULT NOW(),

    user_name           TEXT,
    account_id          TEXT,
    user_id             TEXT UNIQUE,
    resource_arn        TEXT,

    -- Security posture
    mfa_enabled         BOOLEAN,
    has_console_access  BOOLEAN,
    has_access_keys     BOOLEAN,
    password_last_used  TIMESTAMPTZ,
    access_key_last_used TIMESTAMPTZ,

    -- Meta
    create_date         TIMESTAMPTZ,
    tags                JSONB,
    raw_json            JSONB
);

CREATE INDEX IF NOT EXISTS idx_iam_account ON aws_iam_users (account_id);
CREATE INDEX IF NOT EXISTS idx_iam_mfa     ON aws_iam_users (mfa_enabled);

-- ── Security Groups ───────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aws_security_groups (
    id                  SERIAL PRIMARY KEY,
    synced_at           TIMESTAMPTZ DEFAULT NOW(),

    group_id            TEXT UNIQUE,
    group_name          TEXT,
    account_id          TEXT,
    region              TEXT,
    resource_arn        TEXT,
    vpc_id              TEXT,
    description         TEXT,

    -- Ingress rules summary (full rules in raw_json)
    allows_all_ingress  BOOLEAN DEFAULT FALSE,  -- 0.0.0.0/0 on any port
    allows_ssh_public   BOOLEAN DEFAULT FALSE,  -- port 22 from 0.0.0.0/0
    allows_rdp_public   BOOLEAN DEFAULT FALSE,  -- port 3389 from 0.0.0.0/0

    tags                JSONB,
    raw_json            JSONB
);

CREATE INDEX IF NOT EXISTS idx_sg_account ON aws_security_groups (account_id);
CREATE INDEX IF NOT EXISTS idx_sg_vpc     ON aws_security_groups (vpc_id);
CREATE INDEX IF NOT EXISTS idx_sg_ssh     ON aws_security_groups (allows_ssh_public);

-- ── VPCs ─────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS aws_vpcs (
    id                  SERIAL PRIMARY KEY,
    synced_at           TIMESTAMPTZ DEFAULT NOW(),

    vpc_id              TEXT UNIQUE,
    account_id          TEXT,
    region              TEXT,
    cidr_block          TEXT,
    is_default          BOOLEAN,
    state               TEXT,
    tags                JSONB,
    raw_json            JSONB
);

-- ── Sync log ─────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS steampipe_sync_log (
    id          SERIAL PRIMARY KEY,
    synced_at   TIMESTAMPTZ DEFAULT NOW(),
    table_name  TEXT,
    rows_synced INT,
    duration_ms INT,
    status      TEXT,   -- success | error
    error_msg   TEXT
);

-- ═══════════════════════════════════════════════════════════════════════════════
-- POWER VIEWS — combining inventory + Prowler + Trivy
-- ═══════════════════════════════════════════════════════════════════════════════

-- Instances with public IP + any Prowler FAIL
CREATE OR REPLACE VIEW v_public_instances_with_findings AS
SELECT
    i.instance_id,
    i.name_tag,
    i.instance_type,
    i.public_ip,
    i.iam_instance_profile,
    i.region,
    p.check_title       AS prowler_finding,
    p.severity          AS prowler_severity,
    p.recommendation
FROM aws_instances i
JOIN prowler_findings p ON p.resource_arn = i.resource_arn
WHERE i.public_ip IS NOT NULL
  AND i.instance_state = 'running'
  AND p.status = 'FAIL'
ORDER BY
    CASE p.severity
        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
        WHEN 'MEDIUM'   THEN 3 ELSE 4
    END;

-- Instances with CVEs that also have a public IP (richest risk view)
CREATE OR REPLACE VIEW v_exposed_vulnerable_instances AS
SELECT
    i.instance_id,
    i.name_tag,
    i.public_ip,
    i.iam_instance_profile,
    i.region,
    t.cve_id,
    t.cvss_score,
    t.package_name,
    t.fixed_version,
    t.title             AS cve_title
FROM aws_instances i
JOIN trivy_vulnerabilities t ON t.instance_id = i.instance_id
WHERE i.public_ip IS NOT NULL
  AND i.instance_state = 'running'
  AND t.status = 'OPEN'
  AND t.severity IN ('CRITICAL', 'HIGH')
ORDER BY t.cvss_score DESC NULLS LAST;

-- IAM users without MFA that also have Prowler findings
CREATE OR REPLACE VIEW v_risky_iam_users AS
SELECT
    u.user_name,
    u.mfa_enabled,
    u.has_access_keys,
    u.password_last_used,
    p.check_title,
    p.severity,
    p.description
FROM aws_iam_users u
JOIN prowler_findings p ON p.resource_arn = u.resource_arn
WHERE p.status = 'FAIL'
ORDER BY
    CASE p.severity
        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3
    END;

-- S3 buckets that are public AND have Prowler findings
CREATE OR REPLACE VIEW v_public_s3_findings AS
SELECT
    b.bucket_name,
    b.region,
    b.public_access_blocked,
    b.encryption_enabled,
    p.check_title,
    p.severity,
    p.recommendation
FROM aws_s3_buckets b
JOIN prowler_findings p ON p.resource_arn = b.resource_arn
WHERE b.public_access_blocked = FALSE
  AND p.status = 'FAIL'
ORDER BY
    CASE p.severity
        WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 ELSE 3
    END;
