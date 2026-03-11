-- ============================================================
-- Cloud Security DB: Prowler findings schema
-- ============================================================

CREATE TABLE IF NOT EXISTS prowler_findings (
    id                  SERIAL PRIMARY KEY,
    ingested_at         TIMESTAMPTZ DEFAULT NOW(),

    -- Identity
    account_id          TEXT,
    account_name        TEXT,
    region              TEXT,
    resource_arn        TEXT,          -- key for JOINs with Trivy later
    resource_type       TEXT,

    -- Finding metadata
    check_id            TEXT,          -- e.g. "iam_root_hardware_mfa_enabled"
    check_title         TEXT,
    service             TEXT,          -- e.g. "iam", "s3", "ec2"
    severity            TEXT,          -- CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    status              TEXT,          -- FAIL | PASS | WARNING | MANUAL

    -- Detail
    description         TEXT,
    risk                TEXT,
    recommendation      TEXT,
    recommendation_url  TEXT,
    remediation_code    TEXT,          -- inline IaC snippet when available

    -- Raw payload for reference
    raw_json            JSONB,

    -- Deduplication: same check on same resource
    UNIQUE (account_id, resource_arn, check_id)
);

-- Useful indexes
CREATE INDEX IF NOT EXISTS idx_prowler_severity    ON prowler_findings (severity);
CREATE INDEX IF NOT EXISTS idx_prowler_status      ON prowler_findings (status);
CREATE INDEX IF NOT EXISTS idx_prowler_resource    ON prowler_findings (resource_arn);
CREATE INDEX IF NOT EXISTS idx_prowler_service     ON prowler_findings (service);
CREATE INDEX IF NOT EXISTS idx_prowler_account     ON prowler_findings (account_id);

-- ----------------------------------------------------------------
-- Handy views
-- ----------------------------------------------------------------

-- Only failures, ordered by severity
CREATE OR REPLACE VIEW v_open_failures AS
SELECT
    account_id,
    region,
    service,
    severity,
    check_title,
    resource_arn,
    description,
    recommendation,
    ingested_at
FROM prowler_findings
WHERE status = 'FAIL'
ORDER BY
    CASE severity
        WHEN 'CRITICAL'      THEN 1
        WHEN 'HIGH'          THEN 2
        WHEN 'MEDIUM'        THEN 3
        WHEN 'LOW'           THEN 4
        WHEN 'INFORMATIONAL' THEN 5
        ELSE 6
    END,
    ingested_at DESC;

-- Count by severity (quick dashboard)
CREATE OR REPLACE VIEW v_severity_summary AS
SELECT
    account_id,
    severity,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE status = 'FAIL') AS failures
FROM prowler_findings
GROUP BY account_id, severity
ORDER BY account_id, failures DESC;
