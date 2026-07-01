-- =============================================================================
-- Security Operations Dashboard - PostgreSQL Schema
-- Retention: 1 year (monthly partitions)
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- =============================================================================
-- 1. RAW SNAPSHOTS (partitioned by month)
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

-- =============================================================================
-- 3. VULNERABILITIES
-- =============================================================================
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id           UUID        DEFAULT uuid_generate_v4() PRIMARY KEY,
    tool         TEXT        NOT NULL,
    vuln_id      TEXT,
    cve          TEXT,
    severity     TEXT        CHECK (severity IN ('Critical','High','Medium','Low','Info')),
    cvss         NUMERIC(4,2),
    title        TEXT,
    affected_hosts INT       DEFAULT 0,
    status       TEXT        DEFAULT 'Open',
    raw          JSONB,
    first_seen   TIMESTAMPTZ DEFAULT NOW(),
    last_seen    TIMESTAMPTZ DEFAULT NOW()
);

-- =============================================================================
-- 4. INTEGRATIONS  (credentials + per-tool scheduling)
-- =============================================================================
CREATE TABLE IF NOT EXISTS integrations (
    tool_name        VARCHAR(50)  PRIMARY KEY,
    credentials      JSONB        NOT NULL DEFAULT '{}',
    enabled          BOOLEAN      DEFAULT true,
    status           VARCHAR(20)  DEFAULT 'unconfigured',
    refresh_interval INTEGER      DEFAULT 300,
    last_tested      TIMESTAMPTZ,
    last_error       TEXT,
    updated_at       TIMESTAMPTZ  DEFAULT NOW()
);

INSERT INTO integrations (tool_name, refresh_interval) VALUES
    ('fortinet', 300), ('paloalto', 300), ('upguard', 300), ('azure', 300),
    ('qualys', 300), ('manageengine', 300), ('taegis', 300)
ON CONFLICT DO NOTHING;

-- Add refresh_interval if upgrading existing DB
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM information_schema.columns
                   WHERE table_name='integrations' AND column_name='refresh_interval') THEN
        ALTER TABLE integrations ADD COLUMN refresh_interval INTEGER DEFAULT 300;
    END IF;
END $$;
