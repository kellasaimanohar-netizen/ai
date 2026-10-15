-- Fewer tables, same data and rules:
--   accounts   <- admins + users + password_resets
--   test_runs  <- certify_test_runs + live_test_runs
--   agents     <- live_agents
-- Users still only see their own rows, tokens stay encrypted and the activity log stays append-only.

-- 1. One accounts table for admins and users
ALTER TABLE accounts
    ADD COLUMN name             TEXT,
    ADD COLUMN password_hash    TEXT,
    ADD COLUMN status           TEXT NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Inactive')),
    ADD COLUMN department       TEXT,
    ADD COLUMN avatar_url       TEXT,
    ADD COLUMN last_login       TEXT,
    ADD COLUMN reset_token_hash TEXT UNIQUE,      -- the one open "forgot password" link, hashed
    ADD COLUMN reset_expires_at TIMESTAMPTZ;

UPDATE accounts a SET name = d.name, password_hash = d.password_hash, status = d.status, department = d.department,
                      avatar_url = d.avatar_url, last_login = d.last_login
FROM (SELECT id, name, password_hash, status, department, avatar_url, last_login FROM admins
      UNION ALL
      SELECT id, name, password_hash, status, department, avatar_url, last_login FROM users) d
WHERE d.id = a.id;

-- Open, unused reset links carry over
UPDATE accounts a SET reset_token_hash = r.token_hash, reset_expires_at = r.expires_at
FROM (SELECT DISTINCT ON (account_id) account_id, token_hash, expires_at FROM password_resets
      WHERE used_at IS NULL AND expires_at > now() ORDER BY account_id, created_at DESC) r
WHERE r.account_id = a.id;

ALTER TABLE accounts
    ALTER COLUMN name SET NOT NULL,
    ALTER COLUMN password_hash SET NOT NULL,
    ALTER COLUMN department SET NOT NULL;

DROP VIEW account_profiles;
DROP TABLE admins, users, password_resets;
ALTER TABLE accounts DROP CONSTRAINT accounts_id_role_key;

-- 2. One test_runs table for both kinds of test
ALTER TABLE test_runs
    ADD COLUMN audit_mode    TEXT,       -- CertifyAI: certify, validate or target
    ADD COLUMN source        TEXT,       -- CertifyAI: yaml, repo or openapi
    ADD COLUMN repo_path     TEXT,
    ADD COLUMN openapi_url   TEXT,
    ADD COLUMN target_env    TEXT,       -- live: production, staging or development
    ADD COLUMN endpoint_url  TEXT,       -- live
    ADD COLUMN agent_type    TEXT,       -- live
    ADD COLUMN tests_total   INTEGER,    -- live
    ADD COLUMN could_not_run INTEGER,    -- live
    ADD COLUMN schedule_id   INTEGER REFERENCES live_schedules (id) ON DELETE SET NULL,
    ADD COLUMN live_agent_id INTEGER;    -- the foreign key is added below, once live agents are in agents

UPDATE test_runs t SET audit_mode = c.audit_mode, source = c.source, repo_path = c.repo_path, openapi_url = c.openapi_url
FROM certify_test_runs c WHERE c.test_run_id = t.id;
UPDATE test_runs t SET target_env = l.target_env, endpoint_url = l.endpoint_url, openapi_url = l.openapi_url,
                       repo_path = l.repo_path, agent_type = l.agent_type, tests_total = l.tests_total,
                       could_not_run = l.could_not_run, schedule_id = l.schedule_id, live_agent_id = l.live_agent_id
FROM live_test_runs l WHERE l.test_run_id = t.id;

DROP TABLE certify_test_runs, live_test_runs;
ALTER TABLE test_runs
    DROP CONSTRAINT test_runs_id_type_key,
    ADD CONSTRAINT test_runs_details_match_type CHECK (
        (test_type = 'certify' AND target_env IS NULL AND endpoint_url IS NULL AND tests_total IS NULL AND live_agent_id IS NULL)
        OR (test_type = 'live' AND audit_mode IS NULL AND source IS NULL));
DROP INDEX IF EXISTS idx_live_test_runs_schedule;
CREATE INDEX idx_test_runs_live_agent ON test_runs (live_agent_id);

-- 3. One agents table for CertifyAI agents and live agents
ALTER TABLE agents
    ADD COLUMN agent_kind       TEXT NOT NULL DEFAULT 'certify' CHECK (agent_kind IN ('certify', 'live')),
    ADD COLUMN repo_path        TEXT,
    ADD COLUMN openapi_url      TEXT,
    ADD COLUMN target_env       TEXT CHECK (target_env IN ('production', 'staging', 'development')),
    ADD COLUMN settings_enc     TEXT,   -- live: API token and test settings, encrypted with DATA_ENCRYPTION_KEY
    ADD COLUMN last_test_run_id INTEGER REFERENCES test_runs (id) ON DELETE SET NULL,
    ADD COLUMN last_error       TEXT;

-- Agents created by live tests are live agents
UPDATE agents a SET agent_kind = 'live'
WHERE EXISTS (SELECT 1 FROM test_runs t WHERE t.agent_id = a.id AND t.test_type = 'live')
  AND NOT EXISTS (SELECT 1 FROM test_runs t WHERE t.agent_id = a.id AND t.test_type = 'certify');

DROP INDEX agents_user_name_key;
CREATE UNIQUE INDEX agents_user_kind_name_key ON agents (user_id, agent_kind, lower(name));

-- Move each registered live agent in, joining an agent of the same name the user already has
ALTER TABLE agents ADD COLUMN moved_from_live_agent INTEGER;
DO $$
DECLARE la RECORD; new_id INTEGER;
BEGIN
    FOR la IN SELECT * FROM live_agents LOOP
        SELECT id INTO new_id FROM agents
        WHERE user_id = la.user_id AND agent_kind = 'live' AND lower(name) = lower(la.name);
        IF new_id IS NULL THEN
            INSERT INTO agents (user_id, agent_kind, name, canonical_name, created_at, updated_at)
            VALUES (la.user_id, 'live', la.name, la.name, la.created_at::text, la.updated_at::text)
            RETURNING id INTO new_id;
        END IF;
        UPDATE agents SET repo_path = la.repo_path, openapi_url = la.openapi_url, target_env = la.target_env,
                          settings_enc = la.settings_enc, last_test_run_id = la.last_test_run_id, last_error = la.last_error,
                          moved_from_live_agent = la.id
        WHERE id = new_id;
    END LOOP;
END $$;

ALTER TABLE live_schedules DROP CONSTRAINT live_schedules_live_agent_id_fkey;
UPDATE live_schedules s SET live_agent_id = a.id FROM agents a WHERE a.moved_from_live_agent = s.live_agent_id;
UPDATE live_schedules SET live_agent_id = NULL
WHERE live_agent_id IS NOT NULL AND live_agent_id NOT IN (SELECT id FROM agents);
UPDATE test_runs t SET live_agent_id = a.id FROM agents a WHERE a.moved_from_live_agent = t.live_agent_id;
UPDATE test_runs SET live_agent_id = NULL
WHERE live_agent_id IS NOT NULL AND live_agent_id NOT IN (SELECT id FROM agents);

ALTER TABLE agents DROP COLUMN moved_from_live_agent;
DROP TABLE live_agents;

ALTER TABLE live_schedules
    ADD CONSTRAINT live_schedules_agent_fk FOREIGN KEY (live_agent_id) REFERENCES agents (id) ON DELETE CASCADE;
ALTER TABLE test_runs
    ADD CONSTRAINT test_runs_live_agent_fk FOREIGN KEY (live_agent_id) REFERENCES agents (id) ON DELETE SET NULL;
CREATE INDEX idx_agents_user_kind ON agents (user_id, agent_kind);
