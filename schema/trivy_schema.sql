-- ============================================================
-- Cloud Security DB: Trivy vulnerabilities schema
-- ============================================================

CREATE TABLE IF NOT EXISTS trivy_vulnerabilities (
    id                  SERIAL PRIMARY KEY,
    ingested_at         TIMESTAMPTZ DEFAULT NOW(),

    -- Identity (JOIN key with prowler_findings)
    resource_arn        TEXT,          -- e.g. arn:aws:ec2:us-east-1:123456789:instance/i-0abc123
    instance_id         TEXT,          -- e.g. i-0abc123
    account_id          TEXT,
    region              TEXT,

    -- CVE details
    cve_id              TEXT,          -- e.g. CVE-2025-1234
    severity            TEXT,          -- CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    cvss_score          NUMERIC(4,1),  -- e.g. 9.8
    package_name        TEXT,          -- e.g. nginx
    installed_version   TEXT,          -- e.g. 1.18.0
    fixed_version       TEXT,          -- e.g. 1.18.1  (empty if no fix yet)
    target              TEXT,          -- e.g. / (rootfs) or image name
    pkg_type            TEXT,          -- e.g. dpkg, rpm, apk

    -- Detail
    title               TEXT,
    description         TEXT,
    primary_url         TEXT,          -- NVD/advisory link

    -- Status
    status              TEXT DEFAULT 'OPEN',  -- OPEN | FIXED | IGNORED

    -- Raw payload
    raw_json            JSONB,

    -- Deduplication: same CVE on same resource
    UNIQUE (resource_arn, cve_id, package_name)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_trivy_severity    ON trivy_vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_trivy_resource    ON trivy_vulnerabilities (resource_arn);
CREATE INDEX IF NOT EXISTS idx_trivy_instance    ON trivy_vulnerabilities (instance_id);
CREATE INDEX IF NOT EXISTS idx_trivy_cve         ON trivy_vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_trivy_account     ON trivy_vulnerabilities (account_id);
CREATE INDEX IF NOT EXISTS idx_trivy_status      ON trivy_vulnerabilities (status);

-- ----------------------------------------------------------------
-- Views
-- ----------------------------------------------------------------

-- All open CVEs ordered by severity
CREATE OR REPLACE VIEW v_open_cves AS
SELECT
    account_id,
    region,
    instance_id,
    resource_arn,
    severity,
    cvss_score,
    cve_id,
    package_name,
    installed_version,
    fixed_version,
    title,
    primary_url,
    ingested_at
FROM trivy_vulnerabilities
WHERE status = 'OPEN'
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        WHEN 'LOW'      THEN 4
        ELSE 5
    END,
    cvss_score DESC NULLS LAST;

-- CVE severity summary per instance
CREATE OR REPLACE VIEW v_cve_summary AS
SELECT
    account_id,
    instance_id,
    severity,
    COUNT(*) AS total,
    COUNT(*) FILTER (WHERE status = 'OPEN') AS open_count
FROM trivy_vulnerabilities
GROUP BY account_id, instance_id, severity
ORDER BY account_id, instance_id,
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        WHEN 'LOW'      THEN 4
        ELSE 5
    END;

-- ⭐ THE MONEY QUERY: instances that are publicly exposed AND have CVEs
-- (Prowler + Trivy correlated on resource_arn)
CREATE OR REPLACE VIEW v_critical_risks AS
SELECT
    p.account_id,
    p.region,
    p.resource_arn,
    p.check_title        AS exposure,
    p.severity           AS network_severity,
    t.cve_id,
    t.cvss_score,
    t.package_name,
    t.installed_version,
    t.fixed_version,
    t.title              AS cve_title,
    t.primary_url
FROM prowler_findings p
JOIN trivy_vulnerabilities t ON p.resource_arn = t.resource_arn
WHERE p.status  = 'FAIL'
  AND t.status  = 'OPEN'
  AND t.severity IN ('CRITICAL', 'HIGH')
ORDER BY t.cvss_score DESC NULLS LAST;
