-- agent_versions copied each test's score into a second table. Nothing read it: the version history on every
-- page (v1, v2, score change) is worked out from test_runs, which already holds the same scores.
DROP TABLE IF EXISTS agent_versions;
