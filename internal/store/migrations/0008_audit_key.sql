-- Keyed audit chain: rows written with the audit key carry an HMAC-SHA256
-- under a key kept outside the database (keyed = 1); rows written before
-- the key existed keep their plain SHA-256 hash (keyed = 0). The first
-- keyed row after unkeyed ones is an "audit.key_start" marker event.
ALTER TABLE audit ADD COLUMN keyed INTEGER NOT NULL DEFAULT 0;

-- The head anchor: the id and hash of the newest row under a MAC of the
-- audit key, rewritten with every append. Rows removed from the end of the
-- chain leave it naming a row that is gone.
CREATE TABLE audit_head (
    singleton  INTEGER PRIMARY KEY CHECK (singleton = 1),
    id         INTEGER NOT NULL,
    hash       TEXT NOT NULL,
    mac        TEXT NOT NULL
);
