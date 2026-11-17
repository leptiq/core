-- Leptiq core: sessions, SRP challenges, session forks, signup invites and
-- second factors.

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
    last_used BIGINT NOT NULL,
    local_id BIGINT NOT NULL DEFAULT 0
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

-- FIDO2 / WebAuthn security keys.
CREATE TABLE fido2_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    credential_id TEXT NOT NULL,          -- base64url
    passkey TEXT NOT NULL,                -- serialized webauthn-rs Passkey
    attestation_format TEXT NOT NULL,
    created BIGINT NOT NULL
);

CREATE INDEX fido2_keys_user ON fido2_keys(user_id);

-- In-flight WebAuthn ceremonies (registration and authentication).
CREATE TABLE webauthn_states (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    state TEXT NOT NULL,
    created BIGINT NOT NULL
);
