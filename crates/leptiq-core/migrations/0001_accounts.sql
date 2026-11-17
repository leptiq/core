-- Leptiq core: accounts, keys and addresses. Portable SQL: TEXT/BIGINT only.
-- (pat_owner_id: personal access tokens are hidden pseudo-users owned by a
-- real user; set by products, read by login.)

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
    created BIGINT NOT NULL,
    pat_owner_id TEXT                     -- set for personal-access-token pseudo-users
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
