-- Outgoing e-mail. mail_queue holds the messages waiting for the relay:
-- recipient, subject and bodies are sealed (AES-256-GCM under the key of
-- mfa.key_file, bound to the message id), so a copy of the database does
-- not reveal a link or an address. A row is deleted as soon as the relay
-- accepts the message, it expires, or the relay refuses it for good.
CREATE TABLE mail_queue (
    id                TEXT    PRIMARY KEY,  -- random
    kind              TEXT    NOT NULL,     -- template name (test, invitation, reset, ...)
    recipient_sealed  BLOB    NOT NULL,
    subject_sealed    BLOB    NOT NULL,
    body_text_sealed  BLOB    NOT NULL,
    body_html_sealed  BLOB    NOT NULL,
    reference         TEXT    NOT NULL DEFAULT '',  -- caller's reference (a token id), never personal data
    created_at        TEXT    NOT NULL,
    next_at           TEXT    NOT NULL,     -- next delivery attempt
    attempts          INTEGER NOT NULL DEFAULT 0,
    last_error        TEXT    NOT NULL DEFAULT '',
    expires_at        TEXT    NOT NULL
);
CREATE INDEX mail_queue_next ON mail_queue(next_at);

-- What happened to each message, without its content or recipient (only
-- the recipient's domain). One row per message, updated as it moves.
CREATE TABLE mail_log (
    id                TEXT    PRIMARY KEY,  -- the queue id
    kind              TEXT    NOT NULL,
    recipient_domain  TEXT    NOT NULL,
    reference         TEXT    NOT NULL DEFAULT '',
    status            TEXT    NOT NULL,     -- queued, retrying, sent, failed, expired
    attempts          INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT    NOT NULL,
    updated_at        TEXT    NOT NULL,
    sent_at           TEXT    NOT NULL DEFAULT '',
    error             TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX mail_log_created ON mail_log(created_at);
CREATE INDEX mail_log_sent ON mail_log(sent_at);
