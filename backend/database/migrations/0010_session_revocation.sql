-- Signing out, resetting or changing a password ends the account's existing sessions.
-- A token issued (iat, in Unix seconds) before sessions_valid_after is refused.
ALTER TABLE accounts ADD COLUMN IF NOT EXISTS sessions_valid_after BIGINT;
