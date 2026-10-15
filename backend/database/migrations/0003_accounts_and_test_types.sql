-- Separate admin and user accounts, password reset, and separate CertifyAI and live test records.
--
-- Accounts: `accounts` holds what every login shares (id, role, email). `admins` and `users` hold each kind's
-- login details. Everything that belongs to a person points at accounts.id, so it stays attached if a role changes.
-- Tests: `test_runs` holds what every test shares (score, tier, counts, PDF), which is what history, reports
-- and dashboards read. `certify_test_runs` and `live_test_runs` hold what only that kind of test has.
-- A composite key (id + kind) stops a detail row from ever pointing at the wrong kind of parent.

-- 1. Tables nothing in the application used (all empty)
DROP TABLE IF EXISTS api_keys, app_settings, notifications, schedules, suppressions;

-- 2. Accounts
CREATE TABLE accounts (
    id         SERIAL PRIMARY KEY,
    role       TEXT NOT NULL CHECK (role IN ('ADMIN', 'USER')),
    email      TEXT NOT NULL CHECK (email = lower(email)),
    created_at TEXT NOT NULL,
    UNIQUE (id, role)
);
CREATE UNIQUE INDEX accounts_email_key ON accounts (email);

INSERT INTO accounts (id, role, email, created_at)
SELECT id, role, lower(email), created_at FROM users;
SELECT setval(pg_get_serial_sequence('accounts', 'id'), COALESCE(MAX(id), 0) + 1, false) FROM accounts;

ALTER TABLE users RENAME TO users_before_split;

CREATE TABLE admins (
    id            INTEGER PRIMARY KEY,
    role          TEXT NOT NULL DEFAULT 'ADMIN' CHECK (role = 'ADMIN'),
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive')),
    department    TEXT NOT NULL DEFAULT 'Administration',
    avatar_url    TEXT,
    last_login    TEXT,
    FOREIGN KEY (id, role) REFERENCES accounts (id, role) ON DELETE CASCADE
);

CREATE TABLE users (
    id            INTEGER PRIMARY KEY,
    role          TEXT NOT NULL DEFAULT 'USER' CHECK (role = 'USER'),
    name          TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive')),
    department    TEXT NOT NULL DEFAULT 'AI Safety & Quality Assurance',
    avatar_url    TEXT,
    last_login    TEXT,
    FOREIGN KEY (id, role) REFERENCES accounts (id, role) ON DELETE CASCADE
);

INSERT INTO admins (id, name, password_hash, status, department, avatar_url, last_login)
SELECT id, name, password_hash, status, department, avatar_url, last_login FROM users_before_split WHERE role = 'ADMIN';
INSERT INTO users (id, name, password_hash, status, department, avatar_url, last_login)
SELECT id, name, password_hash, status, department, avatar_url, last_login FROM users_before_split WHERE role = 'USER';

-- Everything owned by a person now points at accounts
ALTER TABLE test_runs DROP CONSTRAINT test_runs_user_id_fkey;
ALTER TABLE live_schedules DROP CONSTRAINT live_schedules_user_fk;
ALTER TABLE live_alerts DROP CONSTRAINT live_alerts_user_fk;
ALTER TABLE activity_logs DROP CONSTRAINT activity_logs_user_fk;
DROP TABLE users_before_split;

ALTER TABLE test_runs
    ADD CONSTRAINT test_runs_account_fk FOREIGN KEY (user_id) REFERENCES accounts (id);
ALTER TABLE live_schedules
    ADD CONSTRAINT live_schedules_account_fk FOREIGN KEY (user_id) REFERENCES accounts (id) ON DELETE CASCADE;
ALTER TABLE live_alerts
    ADD CONSTRAINT live_alerts_account_fk FOREIGN KEY (user_id) REFERENCES accounts (id) ON DELETE CASCADE;
ALTER TABLE activity_logs
    ADD CONSTRAINT activity_logs_account_fk FOREIGN KEY (user_id) REFERENCES accounts (id) ON DELETE SET NULL;

-- One place to read any account with its details
CREATE VIEW account_profiles AS
SELECT a.id, a.email, a.role, a.created_at, d.name, d.password_hash, d.status, d.department, d.avatar_url, d.last_login
FROM accounts a
JOIN (
    SELECT id, name, password_hash, status, department, avatar_url, last_login FROM admins
    UNION ALL
    SELECT id, name, password_hash, status, department, avatar_url, last_login FROM users
) d ON d.id = a.id;

-- 3. Forgot password: one-time links. Only a hash of the token is stored, never the token itself.
CREATE TABLE password_resets (
    id           SERIAL PRIMARY KEY,
    account_id   INTEGER NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    token_hash   TEXT NOT NULL UNIQUE,
    expires_at   TIMESTAMPTZ NOT NULL,
    used_at      TIMESTAMPTZ,
    requested_ip TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_password_resets_account ON password_resets (account_id, created_at);

-- 4. Test runs: the kind of test, and a details table for each kind
ALTER TABLE test_runs ADD COLUMN test_type TEXT;
UPDATE test_runs SET test_type = CASE WHEN mode = 'live_probe' THEN 'live' ELSE 'certify' END;
ALTER TABLE test_runs
    ALTER COLUMN test_type SET NOT NULL,
    ADD CONSTRAINT test_runs_test_type_check CHECK (test_type IN ('certify', 'live')),
    ADD CONSTRAINT test_runs_id_type_key UNIQUE (id, test_type);
CREATE INDEX idx_test_runs_type ON test_runs (test_type, created_at);

CREATE TABLE certify_test_runs (
    test_run_id INTEGER PRIMARY KEY,
    test_type   TEXT NOT NULL DEFAULT 'certify' CHECK (test_type = 'certify'),
    audit_mode  TEXT NOT NULL,          -- certify, validate or target
    source      TEXT,                   -- yaml, repo or openapi: what the audit read
    repo_path   TEXT,
    openapi_url TEXT,
    FOREIGN KEY (test_run_id, test_type) REFERENCES test_runs (id, test_type) ON DELETE CASCADE
);

CREATE TABLE live_test_runs (
    test_run_id   INTEGER PRIMARY KEY,
    test_type     TEXT NOT NULL DEFAULT 'live' CHECK (test_type = 'live'),
    target_env    TEXT,                 -- production, staging or development
    endpoint_url  TEXT,
    openapi_url   TEXT,
    repo_path     TEXT,
    agent_type    TEXT,
    tests_total   INTEGER,
    could_not_run INTEGER,
    schedule_id   INTEGER REFERENCES live_schedules (id) ON DELETE SET NULL,
    FOREIGN KEY (test_run_id, test_type) REFERENCES test_runs (id, test_type) ON DELETE CASCADE
);
CREATE INDEX idx_live_test_runs_schedule ON live_test_runs (schedule_id);

INSERT INTO certify_test_runs (test_run_id, audit_mode)
SELECT id, mode FROM test_runs WHERE test_type = 'certify';

-- Older live runs kept these details only in their notes text
INSERT INTO live_test_runs (test_run_id, target_env, endpoint_url, openapi_url, repo_path, agent_type, tests_total, could_not_run)
SELECT id,
       substring(notes from '^Live Agent Audit \(([a-z]+)\)'),
       substring(notes from ' against (\S+)$'),
       NULLIF(substring(notes from 'OpenAPI: ([^|]+?) \|'), 'None'),
       NULLIF(substring(notes from 'Repo: ([^|]+?) \|'), 'None'),
       substring(notes from 'Type: ([a-z_]+)'),
       COALESCE(substring(notes from 'Tests: (\d+)'), substring(notes from 'Probes: (\d+)'))::int,
       substring(notes from '\((\d+) could not run\)')::int
FROM test_runs WHERE test_type = 'live';

-- 5. Report PDFs live on disk under storage/reports/<kind>/; the database keeps the path relative to that folder
UPDATE test_runs
SET pdf_path = test_type || '/' || regexp_replace(audit_id, '[/\\]', '_', 'g') || '.pdf'
WHERE pdf_path IS NOT NULL;
