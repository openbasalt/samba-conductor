-- Settings edited in the web UI (Settings > Passwords): one JSON value per
-- key, with who changed it last.
CREATE TABLE settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL,   -- JSON
    updated_at  TEXT NOT NULL,
    updated_by  TEXT NOT NULL DEFAULT ''
);

-- A user's optional recovery address for password resets by e-mail,
-- verified with a code sent to it. Resets to an address changed less than
-- 72 hours ago go to the directory's mail attribute only.
CREATE TABLE recovery_emails (
    user_sid           TEXT PRIMARY KEY,
    address            TEXT NOT NULL,
    verified_at        TEXT NOT NULL,
    changed_at         TEXT NOT NULL,
    previous_notified  INTEGER NOT NULL DEFAULT 0
);

-- conductor's view of the one-time tokens it asked conductor-provisioner
-- for (never the token or its hash): conductor's own, possibly shorter,
-- expiry, the language of the message, and what the automatic re-issue
-- of an unused invitation needs.
CREATE TABLE link_tokens (
    token_id     TEXT PRIMARY KEY,
    purpose      TEXT NOT NULL,          -- invite or reset
    user_sid     TEXT NOT NULL,
    username     TEXT NOT NULL,
    lang         TEXT NOT NULL,
    issuer_sid   TEXT NOT NULL DEFAULT '',  -- empty for the public reset form
    issuer_name  TEXT NOT NULL DEFAULT '',
    issued_at    TEXT NOT NULL,
    expires_at   TEXT NOT NULL,
    reissue_of   TEXT NOT NULL DEFAULT '',  -- the token this one re-issued automatically
    handled      INTEGER NOT NULL DEFAULT 0 -- the re-issue sweep has looked at it
);
CREATE INDEX link_tokens_user ON link_tokens(user_sid);
CREATE INDEX link_tokens_sweep ON link_tokens(purpose, handled, expires_at);
