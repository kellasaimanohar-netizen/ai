-- CertifyAI baseline schema: the tables as they existed when versioned migrations were introduced.
-- Every statement uses IF NOT EXISTS, so it builds an empty database and leaves an existing one unchanged.
-- Timestamps are ISO-8601 text written by the application; date(text) below reads them in SQL.

CREATE OR REPLACE FUNCTION public.date(t text) RETURNS date
    LANGUAGE plpgsql IMMUTABLE
    AS $$
BEGIN
    RETURN t::timestamptz::date;
EXCEPTION WHEN OTHERS THEN
    RETURN NULL;
END;
$$;

-- Accounts and access
CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    name          TEXT NOT NULL,
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('ADMIN', 'USER')),
    status        TEXT NOT NULL DEFAULT 'Active',
    department    TEXT NOT NULL DEFAULT 'AI Safety & Quality Assurance',
    avatar_url    TEXT,
    created_at    TEXT NOT NULL,
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS api_keys (
    id           SERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL,
    name         TEXT NOT NULL,
    key_prefix   TEXT NOT NULL,
    key_hash     TEXT NOT NULL UNIQUE,
    created_at   TEXT NOT NULL,
    last_used_at TEXT,
    revoked_at   TEXT
);

CREATE TABLE IF NOT EXISTS app_settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    updated_by TEXT
);

CREATE TABLE IF NOT EXISTS activity_logs (
    id         SERIAL PRIMARY KEY,
    "timestamp" TEXT NOT NULL,
    event_type TEXT NOT NULL,
    user_id    INTEGER,
    user_email TEXT NOT NULL,
    user_name  TEXT NOT NULL,
    details    TEXT NOT NULL,
    status     TEXT NOT NULL DEFAULT 'SUCCESS'
);

CREATE TABLE IF NOT EXISTS notifications (
    id         SERIAL PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    title      TEXT NOT NULL,
    message    TEXT NOT NULL,
    severity   TEXT NOT NULL DEFAULT 'info',
    link_tab   TEXT,
    link_ref   TEXT,
    dedupe_key TEXT,
    created_at TEXT NOT NULL,
    read_at    TEXT
);

-- Agents, test runs and their results
CREATE TABLE IF NOT EXISTS agents (
    id                SERIAL PRIMARY KEY,
    name              TEXT NOT NULL UNIQUE,
    version           TEXT NOT NULL DEFAULT '1.0',
    description       TEXT,
    capabilities      TEXT,
    tools_count       INTEGER DEFAULT 0,
    destructive_tools TEXT,
    pii_fields        TEXT,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS test_runs (
    id               SERIAL PRIMARY KEY,
    audit_id         TEXT NOT NULL,
    user_id          INTEGER NOT NULL REFERENCES users(id),
    agent_name       TEXT NOT NULL,
    tested_by_email  TEXT NOT NULL,
    tested_by_name   TEXT NOT NULL,
    user_role        TEXT NOT NULL CHECK (user_role IN ('ADMIN', 'USER')),
    mode             TEXT NOT NULL,
    runs_count       INTEGER DEFAULT 1,
    concurrency      INTEGER DEFAULT 10,
    phases_selected  TEXT,
    trust_score      REAL DEFAULT 0.0,
    tier             TEXT NOT NULL,
    enterprise_ready INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    warning_count    INTEGER DEFAULT 0,
    pass_count       INTEGER DEFAULT 0,
    info_count       INTEGER DEFAULT 0,
    duration_ms      REAL DEFAULT 0,
    created_at       TEXT NOT NULL,
    ip_address       TEXT DEFAULT '127.0.0.1',
    notes            TEXT,
    full_result_json TEXT,
    pdf_path         TEXT
);

CREATE TABLE IF NOT EXISTS agent_versions (
    id             SERIAL PRIMARY KEY,
    agent_id       INTEGER REFERENCES agents(id) ON DELETE CASCADE,
    agent_name     TEXT NOT NULL,
    version_num    INTEGER NOT NULL,
    version_label  TEXT NOT NULL,
    trust_score    DOUBLE PRECISION NOT NULL,
    tier           TEXT NOT NULL,
    status         TEXT NOT NULL,
    test_run_id    INTEGER REFERENCES test_runs(id) ON DELETE SET NULL,
    critical_count INTEGER NOT NULL DEFAULT 0,
    warning_count  INTEGER NOT NULL DEFAULT 0,
    pass_count     INTEGER NOT NULL DEFAULT 0,
    info_count     INTEGER NOT NULL DEFAULT 0,
    score_delta    DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    notes          TEXT,
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_findings (
    id             SERIAL PRIMARY KEY,
    test_run_id    INTEGER NOT NULL REFERENCES test_runs(id) ON DELETE CASCADE,
    audit_id       TEXT NOT NULL,
    rule_id        TEXT NOT NULL,
    phase_id       TEXT,
    phase_name     TEXT,
    title          TEXT NOT NULL,
    severity       TEXT NOT NULL,
    description    TEXT,
    expected       TEXT,
    actual         TEXT,
    remediation    TEXT,
    standards_json TEXT DEFAULT '[]',
    created_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS suppressions (
    id          SERIAL PRIMARY KEY,
    agent_name  TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    rule_id     TEXT,
    title       TEXT,
    reason      TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    created_by  INTEGER,
    created_at  TEXT NOT NULL,
    revoked_at  TEXT
);

CREATE TABLE IF NOT EXISTS schedules (
    id            SERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL,
    agent_name    TEXT NOT NULL,
    frequency     TEXT NOT NULL,
    request_json  TEXT NOT NULL,
    active        INTEGER NOT NULL DEFAULT 1,
    next_run_at   TEXT NOT NULL,
    last_run_at   TEXT,
    last_status   TEXT,
    last_audit_id TEXT,
    last_error    TEXT,
    created_at    TEXT NOT NULL
);

-- Live agent monitoring
CREATE TABLE IF NOT EXISTS live_schedules (
    id                   SERIAL PRIMARY KEY,
    user_id              INTEGER,
    name                 TEXT NOT NULL,
    request_json         TEXT NOT NULL,
    frequency_minutes    INTEGER NOT NULL,
    active               INTEGER NOT NULL DEFAULT 1,
    next_run_at          TEXT,
    last_run_at          TEXT,
    last_audit_id        TEXT,
    last_score           DOUBLE PRECISION,
    last_tier            TEXT,
    last_critical        INTEGER,
    last_could_not_run   INTEGER,
    last_latency_ms      DOUBLE PRECISION,
    last_error           TEXT,
    created_at           TEXT NOT NULL,
    health_minutes       INTEGER DEFAULT 5,
    next_health_at       TEXT,
    last_health_at       TEXT,
    health_status        TEXT,
    health_json          TEXT,
    consecutive_failures INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS live_health_checks (
    id          SERIAL PRIMARY KEY,
    schedule_id INTEGER NOT NULL,
    checked_at  TEXT NOT NULL,
    status      TEXT NOT NULL,
    latency_ms  INTEGER,
    issue_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS live_alerts (
    id          SERIAL PRIMARY KEY,
    user_id     INTEGER,
    schedule_id INTEGER,
    agent_name  TEXT,
    audit_id    TEXT,
    kind        TEXT NOT NULL,
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    read_at     TEXT
);

CREATE INDEX IF NOT EXISTS idx_agent_versions_agent ON agent_versions (agent_name, version_num);
CREATE INDEX IF NOT EXISTS idx_audit_findings_run ON audit_findings (test_run_id);
CREATE INDEX IF NOT EXISTS idx_audit_findings_sev ON audit_findings (severity);
CREATE INDEX IF NOT EXISTS idx_live_health_sched ON live_health_checks (schedule_id, checked_at);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_schedules_due ON schedules (active, next_run_at);
CREATE INDEX IF NOT EXISTS idx_suppressions_agent ON suppressions (agent_name);
CREATE INDEX IF NOT EXISTS idx_test_runs_agent ON test_runs (agent_name);
CREATE INDEX IF NOT EXISTS idx_test_runs_audit ON test_runs (audit_id);
CREATE INDEX IF NOT EXISTS idx_test_runs_created_at ON test_runs (created_at);
CREATE INDEX IF NOT EXISTS idx_test_runs_tier ON test_runs (tier);
CREATE INDEX IF NOT EXISTS idx_test_runs_user ON test_runs (user_id);
