-- =============================================================================
-- Security Operations Dashboard – PostgreSQL Schema
-- Retention: 1 year (monthly partitions, auto-drop after 12 months)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_stat_statements";

-- =============================================================================
-- 1. RAW SNAPSHOTS  (partitioned by month)
-- =============================================================================
CREATE TABLE IF NOT EXISTS snapshots (
    id           UUID        DEFAULT uuid_generate_v4(),
    tool         TEXT        NOT NULL,
    collected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    payload      JSONB       NOT NULL,
    PRIMARY KEY (id, collected_at)
) PARTITION BY RANGE (collected_at);

DO $$
DECLARE
    cur_month  DATE := DATE_TRUNC('month', NOW() - INTERVAL '11 months');
    next_month DATE;
    part_name  TEXT;
BEGIN
    LOOP
        next_month := cur_month + INTERVAL '1 month';
        part_name  := 'snapshots_' || TO_CHAR(cur_month, 'YYYY_MM');
        IF NOT EXISTS (SELECT FROM pg_tables WHERE tablename = part_name) THEN
            EXECUTE FORMAT(
                'CREATE TABLE %I PARTITION OF snapshots FOR VALUES FROM (%L) TO (%L)',
                part_name, cur_month, next_month
            );
        END IF;
        cur_month := next_month;
        EXIT WHEN cur_month > DATE_TRUNC('month', NOW()) + INTERVAL '1 month';
    END LOOP;
END $$;

CREATE INDEX IF NOT EXISTS idx_snapshots_tool_time ON snapshots (tool, collected_at DESC);
CREATE INDEX IF NOT EXISTS idx_snapshots_payload   ON snapshots USING GIN (payload);

-- =============================================================================
-- 2. ALERTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS alerts (
    id          UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    tool        TEXT        NOT NULL,
    alert_id    TEXT,
    severity    TEXT        NOT NULL CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    title       TEXT        NOT NULL,
    resource    TEXT,
    status      TEXT        DEFAULT 'Open',
    raw         JSONB,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_alerts_tool_severity ON alerts (tool, severity);
CREATE INDEX IF NOT EXISTS idx_alerts_detected_at   ON alerts (detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_open          ON alerts (status) WHERE status = 'Open';

-- =============================================================================
-- 3. VULNERABILITIES  (Qualys VMDR)
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id             UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    cve_id         TEXT,
    qid            BIGINT,
    title          TEXT        NOT NULL,
    cvss_score     NUMERIC(4,1),
    severity       TEXT        NOT NULL,
    affected_asset TEXT,
    ip_address     INET,
    status         TEXT        DEFAULT 'Open',
    first_detected TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    fixed_at       TIMESTAMPTZ,
    raw            JSONB
);
CREATE INDEX IF NOT EXISTS idx_vulns_cve      ON vulnerabilities (cve_id);
CREATE INDEX IF NOT EXISTS idx_vulns_severity ON vulnerabilities (severity);
CREATE INDEX IF NOT EXISTS idx_vulns_open     ON vulnerabilities (status) WHERE status = 'Open';

-- =============================================================================
-- 4. KPI HISTORY  (hourly aggregated KPIs per tool)
-- =============================================================================
CREATE TABLE IF NOT EXISTS kpi_history (
    id           BIGSERIAL   PRIMARY KEY,
    tool         TEXT        NOT NULL,
    metric_name  TEXT        NOT NULL,
    metric_value NUMERIC,
    recorded_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_kpi_tool_metric_time ON kpi_history (tool, metric_name, recorded_at DESC);

-- =============================================================================
-- 5. PATCH EVENTS  (ManageEngine)
-- =============================================================================
CREATE TABLE IF NOT EXISTS patch_events (
    id             UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    patch_id       TEXT        NOT NULL,
    patch_name     TEXT,
    severity       TEXT,
    os_type        TEXT,
    total_devices  INT,
    patched        INT,
    failed         INT,
    compliance_pct NUMERIC(5,2),
    deployed_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    raw            JSONB
);
CREATE INDEX IF NOT EXISTS idx_patches_deployed ON patch_events (deployed_at DESC);

-- =============================================================================
-- 6. ENCRYPTION SNAPSHOTS  (ManageEngine)
-- =============================================================================
CREATE TABLE IF NOT EXISTS encryption_snapshots (
    id            UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    total_devices INT,
    encrypted     INT,
    unencrypted   INT,
    coverage_pct  NUMERIC(5,2),
    by_os         JSONB,
    recorded_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_enc_recorded ON encryption_snapshots (recorded_at DESC);

-- =============================================================================
-- 7. RETENTION FUNCTIONS  (call via pg_cron or backend /api/maintenance)
-- =============================================================================
CREATE OR REPLACE FUNCTION drop_old_snapshot_partitions() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    cutoff    DATE := DATE_TRUNC('month', NOW() - INTERVAL '12 months');
    part_name TEXT;
BEGIN
    FOR part_name IN
        SELECT tablename FROM pg_tables
        WHERE  tablename LIKE 'snapshots_%'
        AND    TO_DATE(SUBSTRING(tablename FROM 'snapshots_(.+)'), 'YYYY_MM') < cutoff
    LOOP
        EXECUTE 'DROP TABLE IF EXISTS ' || QUOTE_IDENT(part_name);
        RAISE NOTICE 'Dropped old partition: %', part_name;
    END LOOP;
END $$;

CREATE OR REPLACE FUNCTION create_next_snapshot_partition() RETURNS void LANGUAGE plpgsql AS $$
DECLARE
    next_month DATE := DATE_TRUNC('month', NOW() + INTERVAL '1 month');
    part_name  TEXT := 'snapshots_' || TO_CHAR(next_month, 'YYYY_MM');
BEGIN
    IF NOT EXISTS (SELECT FROM pg_tables WHERE tablename = part_name) THEN
        EXECUTE FORMAT('CREATE TABLE %I PARTITION OF snapshots FOR VALUES FROM (%L) TO (%L)',
            part_name, next_month, next_month + INTERVAL '1 month');
        RAISE NOTICE 'Created partition: %', part_name;
    END IF;
END $$;

CREATE OR REPLACE FUNCTION purge_old_data() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM alerts              WHERE created_at    < NOW() - INTERVAL '1 year';
    DELETE FROM vulnerabilities     WHERE first_detected < NOW() - INTERVAL '1 year' AND status = 'Fixed';
    DELETE FROM kpi_history         WHERE recorded_at   < NOW() - INTERVAL '1 year';
    DELETE FROM patch_events        WHERE deployed_at   < NOW() - INTERVAL '1 year';
    DELETE FROM encryption_snapshots WHERE recorded_at  < NOW() - INTERVAL '1 year';
    PERFORM drop_old_snapshot_partitions();
    PERFORM create_next_snapshot_partition();
    RAISE NOTICE 'Retention maintenance complete';
END $$;

-- =============================================================================
-- 8. VIEWS
-- =============================================================================
CREATE OR REPLACE VIEW latest_snapshots AS
    SELECT DISTINCT ON (tool) tool, collected_at, payload
    FROM snapshots ORDER BY tool, collected_at DESC;

CREATE OR REPLACE VIEW open_alert_summary AS
    SELECT tool, severity, COUNT(*) AS count
    FROM alerts WHERE status = 'Open'
    GROUP BY tool, severity ORDER BY tool, severity;

CREATE OR REPLACE VIEW kpi_trend_30d AS
    SELECT tool, metric_name,
           DATE_TRUNC('day', recorded_at) AS day,
           AVG(metric_value)::NUMERIC(8,2) AS avg_value,
           MIN(metric_value) AS min_value,
           MAX(metric_value) AS max_value
    FROM kpi_history
    WHERE recorded_at >= NOW() - INTERVAL '30 days'
    GROUP BY tool, metric_name, day
    ORDER BY tool, metric_name, day;

CREATE OR REPLACE VIEW vuln_aging AS
    SELECT CASE
        WHEN NOW()-first_detected <= INTERVAL '7 days'  THEN '0-7 days'
        WHEN NOW()-first_detected <= INTERVAL '30 days' THEN '8-30 days'
        WHEN NOW()-first_detected <= INTERVAL '60 days' THEN '31-60 days'
        WHEN NOW()-first_detected <= INTERVAL '90 days' THEN '61-90 days'
        ELSE '90+ days' END AS age_bucket,
        severity, COUNT(*) AS count
    FROM vulnerabilities WHERE status = 'Open'
    GROUP BY age_bucket, severity ORDER BY age_bucket;
