-- Core account tables. Portable SQL: TEXT/BIGINT only.

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,            -- lowercase username
    display_name TEXT NOT NULL,
    email TEXT NOT NULL,
    srp_version BIGINT NOT NULL,
    srp_modulus_id TEXT NOT NULL,
    srp_salt TEXT NOT NULL,
    srp_verifier TEXT NOT NULL,
    is_admin BIGINT NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_enabled BIGINT NOT NULL DEFAULT 0,
    settings TEXT NOT NULL DEFAULT '{}',  -- JSON user settings overrides
    used_space BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL
);

CREATE TABLE user_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    private_key TEXT NOT NULL,
    key_salt TEXT,
    is_primary BIGINT NOT NULL DEFAULT 0,
    active BIGINT NOT NULL DEFAULT 1,
    flags BIGINT NOT NULL DEFAULT 3,
    fingerprint TEXT,
    created BIGINT NOT NULL
);
CREATE INDEX user_keys_user ON user_keys(user_id);

CREATE TABLE addresses (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL UNIQUE,           -- lowercase
    display_name TEXT NOT NULL DEFAULT '',
    signature TEXT NOT NULL DEFAULT '',
    status BIGINT NOT NULL DEFAULT 1,
    addr_type BIGINT NOT NULL DEFAULT 1,
    ordering BIGINT NOT NULL DEFAULT 1,
    skl_data TEXT,
    skl_signature TEXT,
    created BIGINT NOT NULL
);
CREATE INDEX addresses_user ON addresses(user_id);

CREATE TABLE address_keys (
    id TEXT PRIMARY KEY,
    address_id TEXT NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    private_key TEXT NOT NULL,
    public_key TEXT,
    token TEXT,
    signature TEXT,
    is_primary BIGINT NOT NULL DEFAULT 0,
    active BIGINT NOT NULL DEFAULT 1,
    flags BIGINT NOT NULL DEFAULT 3,
    fingerprint TEXT,
    created BIGINT NOT NULL
);
CREATE INDEX address_keys_address ON address_keys(address_id);

CREATE TABLE sessions (
    uid TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,  -- NULL for unauthenticated sessions
    access_hash TEXT NOT NULL,
    refresh_hash TEXT NOT NULL,
    scopes TEXT NOT NULL,                 -- space separated
    pending_2fa BIGINT NOT NULL DEFAULT 0,
    client_id TEXT NOT NULL DEFAULT '',
    local_key TEXT,
    persistent BIGINT NOT NULL DEFAULT 0,
    password_scope_until BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL,
    access_expires BIGINT NOT NULL,
    refresh_expires BIGINT NOT NULL,
    last_used BIGINT NOT NULL
);
CREATE INDEX sessions_user ON sessions(user_id);

CREATE TABLE srp_challenges (
    id TEXT PRIMARY KEY,                  -- SRPSession
    purpose TEXT NOT NULL,                -- 'login', 'reauth', 'pass_extra'
    username TEXT NOT NULL,
    server_secret TEXT NOT NULL,          -- base64
    server_ephemeral TEXT NOT NULL,       -- base64
    created BIGINT NOT NULL
);

CREATE TABLE session_forks (
    selector TEXT PRIMARY KEY,
    parent_uid TEXT,
    user_id TEXT,
    child_client_id TEXT NOT NULL,
    independent BIGINT NOT NULL DEFAULT 0,
    payload TEXT,
    user_code TEXT,
    child_uid TEXT,
    created BIGINT NOT NULL,
    expires BIGINT NOT NULL
);

CREATE TABLE signup_invites (
    code TEXT PRIMARY KEY,
    created BIGINT NOT NULL,
    used_by TEXT
);

-- Append-only per-user event log. Event IDs handed to clients encode seq.
CREATE TABLE events (
    user_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,
    share_id TEXT,
    target_id TEXT,
    data TEXT,
    created BIGINT NOT NULL,
    PRIMARY KEY (user_id, seq)
);

CREATE TABLE kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);
