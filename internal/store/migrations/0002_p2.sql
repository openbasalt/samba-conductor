-- WebAuthn credentials (security keys, platform authenticators) per AD user
-- (by SID). data is the go-webauthn credential as JSON: public key, sign
-- counter, flags, AAGUID. Nothing secret is stored.
CREATE TABLE webauthn_credentials (
    cred_id      TEXT PRIMARY KEY,           -- base64url credential ID
    user_sid     TEXT NOT NULL,
    username     TEXT NOT NULL,
    name         TEXT NOT NULL,              -- chosen by the user
    data         BLOB NOT NULL,
    created_at   TEXT NOT NULL,
    last_used_at TEXT
);
CREATE INDEX webauthn_user ON webauthn_credentials(user_sid);

-- Bulk jobs (CSV import, actions on selected items): the result of every
-- row, so a run is reported even after a restart. Rows keep their input
-- (CSV fields or the selected object and parameters, never a password) so
-- failed rows can be validated and applied again.
CREATE TABLE bulk_jobs (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    owner_sid   TEXT NOT NULL,
    owner_name  TEXT NOT NULL,
    created_at  TEXT NOT NULL,
    started_at  TEXT,
    finished_at TEXT,
    status      TEXT NOT NULL,               -- previewed, running, done, cancelled, interrupted
    total       INTEGER NOT NULL
);
CREATE INDEX bulk_jobs_created ON bulk_jobs(created_at);

CREATE TABLE bulk_rows (
    job_id   TEXT NOT NULL REFERENCES bulk_jobs(id),
    row_no   INTEGER NOT NULL,
    label    TEXT NOT NULL,                  -- e.g. the username
    target   TEXT NOT NULL,                  -- DN (or the DN to be created)
    input    TEXT NOT NULL,                  -- JSON
    preview  TEXT NOT NULL,                  -- LDIF, secrets redacted
    status   TEXT NOT NULL,                  -- pending, ok, failed, skipped
    error    TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (job_id, row_no)
);
