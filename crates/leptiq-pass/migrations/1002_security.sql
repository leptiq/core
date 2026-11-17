-- Leptiq Pass: session PIN lock and the Pass extra password.

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
