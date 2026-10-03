-- File servers enrolled for conductor-files (P2b): the agent's address and
-- its pinned public key. AD stays the source of truth for access; shares
-- live on the file servers themselves.
CREATE TABLE file_servers (
    id            TEXT PRIMARY KEY,          -- random
    name          TEXT NOT NULL,             -- the agent's host name
    address       TEXT NOT NULL UNIQUE,      -- host:port conductor connects to
    agent_pin     TEXT NOT NULL,             -- sha256:<base64url> of the agent's key
    enrolled_at   TEXT NOT NULL,
    enrolled_by   TEXT NOT NULL,             -- sAMAccountName of the administrator
    agent_version TEXT NOT NULL DEFAULT ''
);
