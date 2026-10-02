-- Sessions: metadata only. The Kerberos ticket lives in memory, so every row
-- is deleted when conductor starts (a restart means signing in again).
CREATE TABLE sessions (
    id_hash      TEXT PRIMARY KEY,           -- SHA-256 of the cookie value
    user_sid     TEXT NOT NULL,
    username     TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    expires_at   TEXT NOT NULL,              -- absolute timeout
    ip           TEXT NOT NULL,
    user_agent   TEXT NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_sid);

-- TOTP enrollment per AD user (by SID). secret is AES-256-GCM sealed with
-- the key from systemd credentials, bound to the SID.
CREATE TABLE mfa_totp (
    user_sid    TEXT PRIMARY KEY,
    username    TEXT NOT NULL,
    secret      BLOB NOT NULL,
    created_at  TEXT NOT NULL,
    last_step   INTEGER NOT NULL DEFAULT 0   -- replay protection
);

CREATE TABLE mfa_recovery_codes (
    user_sid   TEXT NOT NULL,
    code_hash  TEXT NOT NULL,
    used_at    TEXT,
    PRIMARY KEY (user_sid, code_hash)
);

-- One-time 2FA enrollment links for administrators.
CREATE TABLE enroll_links (
    token_hash  TEXT PRIMARY KEY,
    username    TEXT NOT NULL,              -- lower-case sAMAccountName
    created_by  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    expires_at  TEXT NOT NULL,
    used_at     TEXT
);

-- Append-only, hash-chained audit log.
CREATE TABLE audit (
    id          INTEGER PRIMARY KEY,
    ts          TEXT NOT NULL,
    actor_sid   TEXT NOT NULL,
    actor_name  TEXT NOT NULL,
    action      TEXT NOT NULL,
    target      TEXT NOT NULL,
    detail      TEXT NOT NULL,
    result      TEXT NOT NULL,
    ip          TEXT NOT NULL,
    user_agent  TEXT NOT NULL,
    prev_hash   TEXT NOT NULL,
    hash        TEXT NOT NULL
);
CREATE INDEX audit_ts ON audit(ts);
CREATE INDEX audit_actor ON audit(actor_name);
CREATE INDEX audit_action ON audit(action);

CREATE TRIGGER audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
