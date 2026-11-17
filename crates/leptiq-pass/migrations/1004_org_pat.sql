-- Leptiq Pass: organization policies and personal access tokens.

-- Instance-wide organization (policies managed by admins).
CREATE TABLE org_reports (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    report TEXT NOT NULL,
    updated BIGINT NOT NULL
);

CREATE TABLE org_url_pauses (
    id TEXT PRIMARY KEY,
    url TEXT NOT NULL,
    vals TEXT NOT NULL,
    created BIGINT NOT NULL
);

CREATE TABLE personal_access_tokens (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    pat_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expire_time BIGINT,
    last_used BIGINT,
    created BIGINT NOT NULL
);

CREATE INDEX personal_access_tokens_owner ON personal_access_tokens(owner_id);

CREATE TABLE pat_monitor (
    id BIGINT PRIMARY KEY,
    pat_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    vault_id TEXT NOT NULL,
    object_id TEXT,
    action BIGINT NOT NULL,
    payload TEXT NOT NULL,
    created BIGINT NOT NULL
);

CREATE INDEX pat_monitor_user ON pat_monitor(pat_user_id);
