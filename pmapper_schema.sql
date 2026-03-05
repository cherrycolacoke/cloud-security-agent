-- ============================================================
-- Cloud Security DB: PMapper IAM Risks Schema
-- ============================================================
-- Stores IAM privilege escalation paths found by PMapper.
-- Key insight: if a compromised EC2 instance has a role that
-- can escalate to admin, a CVE becomes an account takeover.
-- ============================================================

CREATE TABLE IF NOT EXISTS iam_risks (
    id                  SERIAL PRIMARY KEY,
    ingested_at         TIMESTAMPTZ DEFAULT NOW(),

    account_id          TEXT,
    region              TEXT,

    -- Starting principal (who attacker starts as)
    source_arn          TEXT,
    source_type         TEXT,          -- role | user
    source_name         TEXT,          -- e.g. WebServerRole

    -- Target principal (what they escalate to)
    target_arn          TEXT,
    target_type         TEXT,          -- role | user
    target_name         TEXT,          -- e.g. AdminRole
    target_is_admin     BOOLEAN,

    -- The escalation path
    path                TEXT,          -- e.g. WebServerRole -> DevOpsRole -> AdminRole
    hops                INT,           -- number of steps
    methods             TEXT[],        -- e.g. {sts:AssumeRole, iam:PassRole}

    -- Risk rating
    severity            TEXT,          -- CRITICAL | HIGH | MEDIUM
    description         TEXT,

    raw_json            JSONB,

    UNIQUE (account_id, source_arn, target_arn)
);

CREATE INDEX IF NOT EXISTS idx_iam_source   ON iam_risks (source_arn);
CREATE INDEX IF NOT EXISTS idx_iam_target   ON iam_risks (target_arn);
CREATE INDEX IF NOT EXISTS idx_iam_admin    ON iam_risks (target_is_admin);
CREATE INDEX IF NOT EXISTS idx_iam_severity ON iam_risks (severity);
CREATE INDEX IF NOT EXISTS idx_iam_account  ON iam_risks (account_id);

-- ══════════════════════════════════════════════════════════════════════════
-- THE FULL ATTACK CHAIN VIEW
-- Joins Prowler + Trivy + Steampipe + PMapper into one query
-- This is what the LLM agent will read
-- ══════════════════════════════════════════════════════════════════════════

CREATE OR REPLACE VIEW v_full_attack_chains AS
SELECT
    -- Instance context (Steampipe)
    i.instance_id,
    i.name_tag,
    i.public_ip,
    i.instance_type,
    i.region,

    -- IAM role attached to instance (Steampipe)
    i.iam_instance_profile,

    -- Prowler finding (misconfiguration)
    p.check_title       AS misconfiguration,
    p.severity          AS misconfig_severity,
    p.recommendation    AS misconfig_fix,

    -- Trivy CVE
    t.cve_id,
    t.cvss_score,
    t.package_name,
    t.fixed_version,
    t.title             AS cve_title,

    -- PMapper escalation path
    r.path              AS escalation_path,
    r.hops              AS escalation_hops,
    r.target_name       AS escalates_to,
    r.target_is_admin,
    r.severity          AS iam_severity,

    -- Overall risk score (higher = worse)
    ROUND(
        (t.cvss_score * 1.0) +
        CASE p.severity
            WHEN 'CRITICAL' THEN 3
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 1
            ELSE 0
        END +
        CASE r.severity
            WHEN 'CRITICAL' THEN 3
            WHEN 'HIGH'     THEN 2
            WHEN 'MEDIUM'   THEN 1
            ELSE 0
        END +
        CASE WHEN i.public_ip IS NOT NULL THEN 2 ELSE 0 END
    , 1) AS risk_score

FROM aws_instances i

-- Join Prowler findings on same resource
JOIN prowler_findings p
    ON p.resource_arn = i.resource_arn
    AND p.status = 'FAIL'

-- Join Trivy CVEs on same instance
JOIN trivy_vulnerabilities t
    ON t.instance_id = i.instance_id
    AND t.status = 'OPEN'
    AND t.severity IN ('CRITICAL', 'HIGH')

-- Join PMapper escalation paths where source = instance's IAM role
LEFT JOIN iam_risks r
    ON r.source_arn LIKE '%' || split_part(i.iam_instance_profile, '/', 2) || '%'
    AND r.account_id = i.account_id

WHERE i.instance_state = 'running'

ORDER BY risk_score DESC NULLS LAST, t.cvss_score DESC NULLS LAST;


-- Simple view: just escalation paths to admin
CREATE OR REPLACE VIEW v_admin_escalation_paths AS
SELECT
    account_id,
    source_name,
    source_type,
    target_name,
    path,
    hops,
    methods,
    severity,
    description
FROM iam_risks
WHERE target_is_admin = TRUE
ORDER BY
    CASE severity
        WHEN 'CRITICAL' THEN 1
        WHEN 'HIGH'     THEN 2
        WHEN 'MEDIUM'   THEN 3
        ELSE 4
    END,
    hops ASC;
