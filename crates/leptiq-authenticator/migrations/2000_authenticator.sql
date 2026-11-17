-- Leptiq Authenticator: per-user sync keys and encrypted 2FA entries.
-- Authenticator migrations use versions 2000+.

-- Authenticator keys, encrypted by the client with one of the user's keys.
CREATE TABLE authenticator_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    user_key_id TEXT NOT NULL,
    key TEXT NOT NULL,
    created BIGINT NOT NULL
);
CREATE INDEX authenticator_keys_user ON authenticator_keys(user_id);

-- Entries: opaque ciphertext (encrypted with an authenticator key).
CREATE TABLE authenticator_entries (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    key_id TEXT NOT NULL REFERENCES authenticator_keys(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    content_format_version BIGINT NOT NULL,
    revision BIGINT NOT NULL,
    flags BIGINT NOT NULL DEFAULT 0,
    position BIGINT NOT NULL,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);
CREATE INDEX authenticator_entries_user ON authenticator_entries(user_id, position);
