-- Separate normal (CertifyAI) agents from live agents, each with its own tests:
--
--   accounts ─┬─ agents      ─── normal_agent_tests ─┐
--             └─ live_agents ─┬─ live_agent_tests ───┴── audit_findings
--                             └─ live_schedules ──── live_health_checks, live_alerts
--
-- Agent ids come from one shared sequence and test ids from another, so every id stays unique across both
-- kinds: existing links (/tests/53), report paths and activity-log entries keep pointing at the same record.
-- The tester's name, email and role are no longer copied into each test; they come from accounts.
-- all_agent_tests and all_agents are read-only views over both kinds, for history, dashboards and reports.
-- Also removes columns nothing used.

-- 1. Columns nothing reads or writes
ALTER TABLE agents DROP COLUMN system_prompt, DROP COLUMN metadata, DROP COLUMN endpoints;
ALTER TABLE test_runs DROP COLUMN ip_address, DROP COLUMN audit_mode, DROP COLUMN schedule_id;
ALTER TABLE audit_findings DROP COLUMN expected, DROP COLUMN actual, DROP COLUMN standards_json;
ALTER TABLE live_health_checks DROP COLUMN issue_count;

-- 2. Shared id sequences
CREATE SEQUENCE agent_id_seq;
SELECT setval('agent_id_seq', COALESCE((SELECT MAX(id) FROM agents), 0) + 1, false);
CREATE SEQUENCE test_id_seq;
SELECT setval('test_id_seq', COALESCE((SELECT MAX(id) FROM test_runs), 0) + 1, false);

-- 3. Live agents get their own table (same ids as before)
CREATE TABLE live_agents (
    id           INTEGER PRIMARY KEY DEFAULT nextval('agent_id_seq'),
    user_id      INTEGER NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name         TEXT NOT NULL,
    repo_path    TEXT,
    openapi_url  TEXT,                 -- set when the user registered the agent on the Live agents page
    target_env   TEXT CHECK (target_env IN ('production', 'staging', 'development')),
    settings_enc TEXT,                 -- API token and test settings, encrypted with DATA_ENCRYPTION_KEY
    version      TEXT NOT NULL DEFAULT 'v1',
    description  TEXT,
    capabilities TEXT,
    tools_count  INTEGER DEFAULT 0,
    last_test_id INTEGER,              -- foreign key added once live_agent_tests exists
    last_error   TEXT,
    created_at   TEXT NOT NULL,
    updated_at   TEXT NOT NULL
);
INSERT INTO live_agents (id, user_id, name, repo_path, openapi_url, target_env, settings_enc, version, description,
                         capabilities, tools_count, last_test_id, last_error, created_at, updated_at)
SELECT id, user_id, name, repo_path, openapi_url, target_env, settings_enc, version, description,
       capabilities, tools_count, last_test_run_id, last_error, created_at, updated_at
FROM agents WHERE agent_kind = 'live';
CREATE UNIQUE INDEX live_agents_user_name_key ON live_agents (user_id, lower(name));
CREATE INDEX idx_live_agents_user ON live_agents (user_id);

ALTER TABLE live_schedules DROP CONSTRAINT live_schedules_agent_fk;
ALTER TABLE live_schedules
    ADD CONSTRAINT live_schedules_live_agent_fk FOREIGN KEY (live_agent_id) REFERENCES live_agents (id) ON DELETE CASCADE;

-- 4. Normal agents keep the agents table
ALTER TABLE test_runs DROP CONSTRAINT test_runs_live_agent_fk, DROP CONSTRAINT test_runs_agent_id_fkey;
DELETE FROM agents WHERE agent_kind = 'live';
DROP INDEX agents_user_kind_name_key;
DROP INDEX IF EXISTS idx_agents_user_kind;
ALTER TABLE agents
    DROP COLUMN agent_kind, DROP COLUMN repo_path, DROP COLUMN openapi_url, DROP COLUMN target_env,
    DROP COLUMN settings_enc, DROP COLUMN last_test_run_id, DROP COLUMN last_error,
    ALTER COLUMN id SET DEFAULT nextval('agent_id_seq');
DROP SEQUENCE IF EXISTS agents_id_seq;
CREATE UNIQUE INDEX agents_user_name_key ON agents (user_id, lower(name));

-- 5. A test table for each kind of agent
CREATE TABLE normal_agent_tests (
    id               INTEGER PRIMARY KEY DEFAULT nextval('test_id_seq'),
    audit_id         TEXT NOT NULL UNIQUE,
    user_id          INTEGER NOT NULL REFERENCES accounts (id),
    agent_id         INTEGER REFERENCES agents (id) ON DELETE SET NULL,
    agent_name       TEXT NOT NULL,
    mode             TEXT NOT NULL,       -- certify, validate or target
    source           TEXT,                -- yaml, repo or openapi: what the audit read
    repo_path        TEXT,
    openapi_url      TEXT,
    runs_count       INTEGER DEFAULT 1,
    concurrency      INTEGER DEFAULT 10,
    phases_selected  TEXT,
    trust_score      DOUBLE PRECISION DEFAULT 0.0,
    tier             TEXT NOT NULL,
    enterprise_ready INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    warning_count    INTEGER DEFAULT 0,
    pass_count       INTEGER DEFAULT 0,
    info_count       INTEGER DEFAULT 0,
    duration_ms      DOUBLE PRECISION DEFAULT 0,
    notes            TEXT,
    full_result_json TEXT,
    pdf_path         TEXT,                -- relative to storage/reports
    created_at       TEXT NOT NULL
);

CREATE TABLE live_agent_tests (
    id               INTEGER PRIMARY KEY DEFAULT nextval('test_id_seq'),
    audit_id         TEXT NOT NULL UNIQUE,
    user_id          INTEGER NOT NULL REFERENCES accounts (id),
    live_agent_id    INTEGER REFERENCES live_agents (id) ON DELETE SET NULL,
    agent_name       TEXT NOT NULL,
    mode             TEXT NOT NULL DEFAULT 'live_probe',
    target_env       TEXT,                -- production, staging or development
    endpoint_url     TEXT,
    openapi_url      TEXT,
    repo_path        TEXT,
    agent_type       TEXT,
    tests_total      INTEGER,
    could_not_run    INTEGER,
    runs_count       INTEGER DEFAULT 1,
    concurrency      INTEGER DEFAULT 1,
    phases_selected  TEXT,
    trust_score      DOUBLE PRECISION DEFAULT 0.0,
    tier             TEXT NOT NULL,
    enterprise_ready INTEGER DEFAULT 0,
    critical_count   INTEGER DEFAULT 0,
    warning_count    INTEGER DEFAULT 0,
    pass_count       INTEGER DEFAULT 0,
    info_count       INTEGER DEFAULT 0,
    duration_ms      DOUBLE PRECISION DEFAULT 0,
    notes            TEXT,
    full_result_json TEXT,
    pdf_path         TEXT,
    created_at       TEXT NOT NULL
);

INSERT INTO normal_agent_tests (id, audit_id, user_id, agent_id, agent_name, mode, source, repo_path, openapi_url,
                                runs_count, concurrency, phases_selected, trust_score, tier, enterprise_ready,
                                critical_count, warning_count, pass_count, info_count, duration_ms, notes,
                                full_result_json, pdf_path, created_at)
SELECT id, audit_id, user_id, agent_id, agent_name, mode, source, repo_path, openapi_url,
       runs_count, concurrency, phases_selected, trust_score, tier, enterprise_ready,
       critical_count, warning_count, pass_count, info_count, duration_ms, notes, full_result_json, pdf_path, created_at
FROM test_runs WHERE test_type = 'certify';

-- A live test's agent is the live agent it was linked to (by agent_id before live agents had a table)
INSERT INTO live_agent_tests (id, audit_id, user_id, live_agent_id, agent_name, mode, target_env, endpoint_url,
                              openapi_url, repo_path, agent_type, tests_total, could_not_run, runs_count, concurrency,
                              phases_selected, trust_score, tier, enterprise_ready, critical_count, warning_count,
                              pass_count, info_count, duration_ms, notes, full_result_json, pdf_path, created_at)
SELECT t.id, t.audit_id, t.user_id, COALESCE(t.live_agent_id, la.id), t.agent_name, t.mode, t.target_env, t.endpoint_url,
       t.openapi_url, t.repo_path, t.agent_type, t.tests_total, t.could_not_run, t.runs_count, t.concurrency,
       t.phases_selected, t.trust_score, t.tier, t.enterprise_ready, t.critical_count, t.warning_count,
       t.pass_count, t.info_count, t.duration_ms, t.notes, t.full_result_json, t.pdf_path, t.created_at
FROM test_runs t LEFT JOIN live_agents la ON la.id = t.agent_id
WHERE t.test_type = 'live';

UPDATE live_agents SET last_test_id = NULL WHERE last_test_id NOT IN (SELECT id FROM live_agent_tests);
ALTER TABLE live_agents
    ADD CONSTRAINT live_agents_last_test_fk FOREIGN KEY (last_test_id) REFERENCES live_agent_tests (id) ON DELETE SET NULL;

CREATE INDEX idx_normal_tests_user ON normal_agent_tests (user_id, created_at);
CREATE INDEX idx_normal_tests_agent ON normal_agent_tests (agent_id);
CREATE INDEX idx_normal_tests_agent_name ON normal_agent_tests (agent_name);
CREATE INDEX idx_live_tests_user ON live_agent_tests (user_id, created_at);
CREATE INDEX idx_live_tests_agent ON live_agent_tests (live_agent_id);
CREATE INDEX idx_live_tests_agent_name ON live_agent_tests (agent_name);

-- 6. A finding belongs to exactly one normal test or one live test.
-- test_run_id is kept as a computed column, so reports keep joining on it.
ALTER TABLE audit_findings
    ADD COLUMN normal_test_id INTEGER REFERENCES normal_agent_tests (id) ON DELETE CASCADE,
    ADD COLUMN live_test_id   INTEGER REFERENCES live_agent_tests (id) ON DELETE CASCADE;
UPDATE audit_findings f SET normal_test_id = f.test_run_id WHERE f.test_run_id IN (SELECT id FROM normal_agent_tests);
UPDATE audit_findings f SET live_test_id = f.test_run_id WHERE f.test_run_id IN (SELECT id FROM live_agent_tests);
ALTER TABLE audit_findings DROP CONSTRAINT audit_findings_test_run_id_fkey;
DROP INDEX IF EXISTS idx_audit_findings_run;
ALTER TABLE audit_findings DROP COLUMN test_run_id;
ALTER TABLE audit_findings
    ADD COLUMN test_run_id INTEGER GENERATED ALWAYS AS (COALESCE(normal_test_id, live_test_id)) STORED,
    ADD CONSTRAINT audit_findings_one_test CHECK ((normal_test_id IS NULL) <> (live_test_id IS NULL));
CREATE INDEX idx_audit_findings_run ON audit_findings (test_run_id);
CREATE INDEX idx_audit_findings_normal ON audit_findings (normal_test_id);
CREATE INDEX idx_audit_findings_live ON audit_findings (live_test_id);

-- 7. The combined table is no longer needed
DROP TABLE test_runs;

-- 8. Read-only views over both kinds. They hold no data; write to the tables above.
CREATE VIEW all_agent_tests AS
SELECT n.id, 'certify'::text AS test_type, n.audit_id, n.user_id, n.agent_id, NULL::integer AS live_agent_id, n.agent_name,
       a.email AS tested_by_email, a.name AS tested_by_name, a.role AS user_role, n.mode,
       n.runs_count, n.concurrency, n.phases_selected, n.trust_score, n.tier, n.enterprise_ready,
       n.critical_count, n.warning_count, n.pass_count, n.info_count, n.duration_ms, n.notes, n.full_result_json, n.pdf_path,
       n.source, n.repo_path, n.openapi_url, NULL::text AS target_env, NULL::text AS endpoint_url, NULL::text AS agent_type,
       NULL::integer AS tests_total, NULL::integer AS could_not_run, n.created_at
FROM normal_agent_tests n JOIN accounts a ON a.id = n.user_id
UNION ALL
SELECT l.id, 'live'::text, l.audit_id, l.user_id, NULL::integer, l.live_agent_id, l.agent_name,
       a.email, a.name, a.role, l.mode,
       l.runs_count, l.concurrency, l.phases_selected, l.trust_score, l.tier, l.enterprise_ready,
       l.critical_count, l.warning_count, l.pass_count, l.info_count, l.duration_ms, l.notes, l.full_result_json, l.pdf_path,
       NULL::text, l.repo_path, l.openapi_url, l.target_env, l.endpoint_url, l.agent_type,
       l.tests_total, l.could_not_run, l.created_at
FROM live_agent_tests l JOIN accounts a ON a.id = l.user_id;

CREATE VIEW all_agents AS
SELECT id, user_id, 'certify'::text AS agent_kind, name, canonical_name, version, description, capabilities, tools_count,
       destructive_tools, pii_fields, status, created_at, updated_at
FROM agents
UNION ALL
SELECT id, user_id, 'live'::text, name, name, version, description, capabilities, tools_count,
       NULL::text, NULL::text, 'ACTIVE'::text, created_at, updated_at
FROM live_agents;
