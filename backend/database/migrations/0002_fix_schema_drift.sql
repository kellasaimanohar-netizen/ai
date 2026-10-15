-- Bring the schema in line with what the application writes, and let the database enforce relationships.

-- Agent registration writes these columns; without them every new agent and version failed to save.
ALTER TABLE agents
    ADD COLUMN IF NOT EXISTS canonical_name TEXT,
    ADD COLUMN IF NOT EXISTS status         TEXT NOT NULL DEFAULT 'ACTIVE',
    ADD COLUMN IF NOT EXISTS system_prompt  TEXT,
    ADD COLUMN IF NOT EXISTS endpoints      TEXT NOT NULL DEFAULT '[]',
    ADD COLUMN IF NOT EXISTS metadata       TEXT NOT NULL DEFAULT '{}';
UPDATE agents SET canonical_name = name WHERE canonical_name IS NULL;
ALTER TABLE agents ALTER COLUMN canonical_name SET NOT NULL;
CREATE INDEX IF NOT EXISTS idx_agents_canonical ON agents (lower(canonical_name));
CREATE INDEX IF NOT EXISTS idx_agents_name_lower ON agents (lower(name));

-- The repository links a run to its agent.
ALTER TABLE test_runs ADD COLUMN IF NOT EXISTS agent_id INTEGER REFERENCES agents(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_test_runs_agent_id ON test_runs (agent_id);

-- One row per audit.
DROP INDEX IF EXISTS idx_test_runs_audit;
DROP INDEX IF EXISTS idx_test_runs_audit_id;
ALTER TABLE test_runs ADD CONSTRAINT test_runs_audit_id_key UNIQUE (audit_id);

-- Duplicates of other indexes or of unique constraints.
DROP INDEX IF EXISTS idx_test_runs_agent_name;
DROP INDEX IF EXISTS idx_test_runs_user_id;
DROP INDEX IF EXISTS idx_users_email;

-- Relationships. Deleting a monitor removes its health history; deleting a user removes what only they own.
ALTER TABLE live_health_checks
    ADD CONSTRAINT live_health_checks_schedule_fk FOREIGN KEY (schedule_id) REFERENCES live_schedules(id) ON DELETE CASCADE;
ALTER TABLE live_alerts
    ADD CONSTRAINT live_alerts_schedule_fk FOREIGN KEY (schedule_id) REFERENCES live_schedules(id) ON DELETE SET NULL,
    ADD CONSTRAINT live_alerts_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE live_schedules
    ADD CONSTRAINT live_schedules_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE activity_logs
    ADD CONSTRAINT activity_logs_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
ALTER TABLE api_keys
    ADD CONSTRAINT api_keys_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;
ALTER TABLE notifications
    ADD CONSTRAINT notifications_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- Lookups the pages make often.
CREATE INDEX IF NOT EXISTS idx_live_schedules_user ON live_schedules (user_id);
CREATE INDEX IF NOT EXISTS idx_live_alerts_user ON live_alerts (user_id, read_at);
CREATE INDEX IF NOT EXISTS idx_activity_logs_time ON activity_logs ("timestamp");
