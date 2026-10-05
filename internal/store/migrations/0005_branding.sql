-- Branding of the user-facing pages: conductor's self-service and,
-- pushed through conductor-idp's management API, its sign-in pages.
-- Every save is a new version (a revert too: it copies an older one), so
-- the history is append-only; the newest versions are kept. Images are
-- stored once by digest and referenced by the versions that use them.
CREATE TABLE branding_versions (
    version       INTEGER PRIMARY KEY,
    data          TEXT    NOT NULL,           -- JSON of branding.Branding
    created_at    TEXT    NOT NULL,
    created_by    TEXT    NOT NULL,           -- sAMAccountName of the administrator
    reverted_from INTEGER NOT NULL DEFAULT 0  -- the version a revert copied
);
CREATE TABLE branding_assets (
    sha256       TEXT PRIMARY KEY,
    content_type TEXT NOT NULL,
    data         BLOB NOT NULL,
    created_at   TEXT NOT NULL
);
CREATE TABLE branding_version_assets (
    version INTEGER NOT NULL REFERENCES branding_versions(version) ON DELETE CASCADE,
    sha256  TEXT    NOT NULL,
    PRIMARY KEY (version, sha256)
);
