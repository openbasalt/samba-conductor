-- Backup and restore drill results reported by conductor-backup (P3), as
-- conductor recorded them: one row per backup run or drill, written once
-- when first seen (the audit log gets an entry at the same time).
CREATE TABLE backup_results (
    kind      TEXT NOT NULL,                 -- backup, drill
    id        TEXT NOT NULL,                 -- backup ID or drill ID
    at        TEXT NOT NULL,                 -- when it happened
    result    TEXT NOT NULL,                 -- ok, partial, failed, passed
    detail    TEXT NOT NULL,                 -- JSON summary (no secrets)
    seen_at   TEXT NOT NULL,
    PRIMARY KEY (kind, id)
);
