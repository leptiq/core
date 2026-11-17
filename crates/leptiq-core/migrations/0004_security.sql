-- Pass session PIN lock (per session).
CREATE TABLE session_locks (
    uid TEXT PRIMARY KEY REFERENCES sessions(uid) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    lock_code_hash TEXT NOT NULL,
    storage_token TEXT NOT NULL,
    unlocked_secs BIGINT NOT NULL,
    failed_attempts BIGINT NOT NULL DEFAULT 0,
    locked BIGINT NOT NULL DEFAULT 0,
    last_activity BIGINT NOT NULL
);

-- Pass extra password (a second SRP verifier for the Pass scope).
CREATE TABLE pass_srp (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    modulus_id TEXT NOT NULL,
    salt TEXT NOT NULL,
    verifier TEXT NOT NULL,
    created BIGINT NOT NULL
);

-- Sessions that proved the Pass extra password.
CREATE TABLE pass_unlocked_sessions (
    uid TEXT PRIMARY KEY REFERENCES sessions(uid) ON DELETE CASCADE,
    unlocked BIGINT NOT NULL
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
