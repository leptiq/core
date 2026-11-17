-- Leptiq Assistant (Lumo clients): encrypted conversation storage.
-- Assistant migrations use versions 4000+. `encrypted` columns and keys are
-- client ciphertext; tags are client IDs used in the encryption AD.

CREATE TABLE lumo_master_keys (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    master_key TEXT NOT NULL,
    version BIGINT NOT NULL,
    created BIGINT NOT NULL
);
CREATE INDEX lumo_master_keys_user ON lumo_master_keys(user_id);

CREATE TABLE lumo_spaces (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    space_type BIGINT NOT NULL DEFAULT 0,
    space_key TEXT NOT NULL,
    tag TEXT NOT NULL,
    encrypted TEXT,
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL,
    UNIQUE (user_id, tag)
);

CREATE TABLE lumo_conversations (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    space_id TEXT NOT NULL REFERENCES lumo_spaces(id) ON DELETE CASCADE,
    is_starred BIGINT NOT NULL DEFAULT 0,
    tag TEXT NOT NULL,
    encrypted TEXT,
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL,
    UNIQUE (user_id, tag)
);
CREATE INDEX lumo_conversations_space ON lumo_conversations(space_id);

CREATE TABLE lumo_messages (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conversation_id TEXT NOT NULL REFERENCES lumo_conversations(id) ON DELETE CASCADE,
    role BIGINT NOT NULL,
    status BIGINT,
    parent_id TEXT,
    tag TEXT NOT NULL,
    encrypted TEXT,
    created BIGINT NOT NULL,
    UNIQUE (user_id, tag)
);
CREATE INDEX lumo_messages_conversation ON lumo_messages(conversation_id);

CREATE TABLE lumo_assets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    space_id TEXT NOT NULL REFERENCES lumo_spaces(id) ON DELETE CASCADE,
    asset_type BIGINT,
    tag TEXT NOT NULL,
    encrypted TEXT,
    created BIGINT NOT NULL,
    UNIQUE (user_id, tag)
);

CREATE TABLE lumo_settings (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    encrypted TEXT,
    created BIGINT NOT NULL,
    updated BIGINT NOT NULL
);

-- Per-user change log for the Lumo event loop.
CREATE TABLE lumo_events (
    user_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,                   -- LumoSpaces, LumoConversations, ...
    item_id TEXT NOT NULL,
    action BIGINT NOT NULL,               -- 0 delete, 1 create, 2 update
    created BIGINT NOT NULL,
    PRIMARY KEY (user_id, seq)
);
