-- Many users: every agent and live agent belongs to one account, users only ever see their own,
-- and admins can review everything people did in an append-only activity log.

-- 1. Agents belong to the user who tested them. Two users can each have an agent with the same name.
ALTER TABLE agents
    ADD COLUMN user_id INTEGER REFERENCES accounts (id) ON DELETE CASCADE,
    DROP CONSTRAINT agents_name_key;

-- An agent tested by several accounts becomes one agent per account
INSERT INTO agents (user_id, name, canonical_name, version, description, capabilities, tools_count, destructive_tools,
                    pii_fields, status, endpoints, metadata, system_prompt, created_at, updated_at)
SELECT DISTINCT t.user_id, a.name, a.canonical_name, a.version, a.description, a.capabilities, a.tools_count,
       a.destructive_tools, a.pii_fields, a.status, a.endpoints, a.metadata, a.system_prompt, a.created_at, a.updated_at
FROM agents a
JOIN test_runs t ON lower(t.agent_name) IN (lower(a.name), lower(a.canonical_name))
WHERE a.user_id IS NULL;

-- Tests whose agent had no row yet
INSERT INTO agents (user_id, name, canonical_name, created_at, updated_at)
SELECT DISTINCT ON (t.user_id, lower(t.agent_name)) t.user_id, t.agent_name, t.agent_name, t.created_at, t.created_at
FROM test_runs t
WHERE NOT EXISTS (
    SELECT 1 FROM agents a
    WHERE a.user_id = t.user_id AND lower(t.agent_name) IN (lower(a.name), lower(a.canonical_name))
)
ORDER BY t.user_id, lower(t.agent_name), t.created_at;

-- What is left without an owner was never tested by anyone (demo rows)
DELETE FROM agents WHERE user_id IS NULL;

ALTER TABLE agents ALTER COLUMN user_id SET NOT NULL;
CREATE UNIQUE INDEX agents_user_name_key ON agents (user_id, lower(name));
CREATE INDEX idx_agents_user ON agents (user_id);

UPDATE test_runs t SET agent_id = a.id
FROM agents a
WHERE a.user_id = t.user_id AND lower(t.agent_name) IN (lower(a.name), lower(a.canonical_name));

-- 2. Live agents a user registered, kept on the server instead of in one browser.
-- settings_enc holds the API token and test settings, encrypted with DATA_ENCRYPTION_KEY.
CREATE TABLE live_agents (
    id               SERIAL PRIMARY KEY,
    user_id          INTEGER NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
    name             TEXT NOT NULL,
    repo_path        TEXT,
    openapi_url      TEXT NOT NULL,
    target_env       TEXT NOT NULL DEFAULT 'production' CHECK (target_env IN ('production', 'staging', 'development')),
    settings_enc     TEXT,
    last_test_run_id INTEGER REFERENCES test_runs (id) ON DELETE SET NULL,
    last_error       TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX idx_live_agents_user ON live_agents (user_id);

ALTER TABLE live_test_runs ADD COLUMN live_agent_id INTEGER REFERENCES live_agents (id) ON DELETE SET NULL;
CREATE INDEX idx_live_test_runs_agent ON live_test_runs (live_agent_id);

-- A monitor belongs to its live agent and goes when the agent is removed
ALTER TABLE live_schedules ADD COLUMN live_agent_id INTEGER REFERENCES live_agents (id) ON DELETE CASCADE;
CREATE INDEX idx_live_schedules_agent ON live_schedules (live_agent_id);

-- 3. Activity log: who did what, from where, to which record
ALTER TABLE activity_logs
    ADD COLUMN user_role   TEXT,
    ADD COLUMN ip_address  TEXT,
    ADD COLUMN entity_type TEXT,
    ADD COLUMN entity_id   TEXT;
UPDATE activity_logs l SET user_role = a.role FROM accounts a WHERE a.id = l.user_id;
CREATE INDEX idx_activity_logs_user ON activity_logs (user_id, "timestamp");
CREATE INDEX idx_activity_logs_event ON activity_logs (event_type, "timestamp");

-- Entries can be added but never edited or deleted. The one change allowed is clearing user_id when an
-- account is deleted; the entry keeps the email and name, so the history still says who it was.
CREATE FUNCTION activity_logs_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.user_id IS NULL AND OLD.user_id IS NOT NULL
       AND (to_jsonb(NEW) - 'user_id') = (to_jsonb(OLD) - 'user_id') THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'activity_logs is append-only: entries cannot be changed or deleted';
END;
$$;
CREATE TRIGGER activity_logs_append_only
    BEFORE UPDATE OR DELETE ON activity_logs
    FOR EACH ROW EXECUTE FUNCTION activity_logs_append_only();
