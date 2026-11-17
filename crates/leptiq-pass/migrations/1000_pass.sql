-- Leptiq Pass: vaults, shares, items, folders, invites and files.
-- Pass migrations use versions 1000+ (core uses 1-999).

-- Proton Pass core: vaults, shares, keys, items, folders.

CREATE TABLE vaults (
    id TEXT PRIMARY KEY,
    content TEXT NOT NULL,
    content_format_version BIGINT NOT NULL,
    content_key_rotation BIGINT NOT NULL,
    current_rotation BIGINT NOT NULL DEFAULT 1,
    owner_user_id TEXT NOT NULL,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);

CREATE TABLE shares (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address_id TEXT NOT NULL,
    target_type BIGINT NOT NULL,          -- 1 vault, 2 item
    target_id TEXT NOT NULL,
    share_role_id TEXT NOT NULL,          -- '1' manager, '2' write, '3' read
    owner BIGINT NOT NULL DEFAULT 0,
    is_primary BIGINT NOT NULL DEFAULT 0,
    flags BIGINT NOT NULL DEFAULT 0,
    expire_time BIGINT,
    deleted BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL
);

CREATE INDEX shares_user ON shares(user_id);

CREATE INDEX shares_vault ON shares(vault_id);

CREATE TABLE share_keys (
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    key_rotation BIGINT NOT NULL,
    key TEXT NOT NULL,
    user_key_id TEXT NOT NULL,
    created BIGINT NOT NULL,
    PRIMARY KEY (share_id, key_rotation)
);

CREATE TABLE folders (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    parent_id TEXT,
    key_rotation BIGINT NOT NULL,
    folder_key TEXT NOT NULL,
    content_format_version BIGINT NOT NULL,
    content TEXT NOT NULL,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);

CREATE INDEX folders_vault ON folders(vault_id);

CREATE TABLE items (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    folder_id TEXT,
    revision BIGINT NOT NULL,
    content_format_version BIGINT NOT NULL,
    content TEXT NOT NULL,
    key_rotation BIGINT NOT NULL,
    state BIGINT NOT NULL DEFAULT 1,      -- 1 active, 2 trashed
    flags BIGINT NOT NULL DEFAULT 0,
    alias_email TEXT,
    create_time BIGINT NOT NULL,
    modify_time BIGINT NOT NULL,
    revision_time BIGINT NOT NULL,
    last_use_time BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX items_vault ON items(vault_id);

CREATE INDEX items_alias ON items(alias_email);

CREATE TABLE item_keys (
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    key_rotation BIGINT NOT NULL,
    key TEXT NOT NULL,
    PRIMARY KEY (item_id, key_rotation)
);

CREATE TABLE item_revisions (
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    content_format_version BIGINT NOT NULL,
    content TEXT NOT NULL,
    key_rotation BIGINT NOT NULL,
    state BIGINT NOT NULL,
    flags BIGINT NOT NULL,
    modify_time BIGINT NOT NULL,
    revision_time BIGINT NOT NULL,
    PRIMARY KEY (item_id, revision)
);

CREATE TABLE item_pins (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    pin_time BIGINT NOT NULL,
    PRIMARY KEY (user_id, item_id)
);

CREATE TABLE item_reads (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    read_time BIGINT NOT NULL,
    PRIMARY KEY (user_id, item_id)
);

CREATE TABLE pass_user (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    default_share_id TEXT,
    monitor_proton BIGINT NOT NULL DEFAULT 1,
    monitor_aliases BIGINT NOT NULL DEFAULT 1,
    inapp_notifications_disabled BIGINT NOT NULL DEFAULT 0,
    activation_time BIGINT NOT NULL
);

-- Sharing: invites to existing users and to not-yet-registered emails.
CREATE TABLE invites (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    inviter_share_id TEXT NOT NULL,
    inviter_user_id TEXT NOT NULL,
    inviter_email TEXT NOT NULL,
    invitee_email TEXT NOT NULL,
    invitee_user_id TEXT,
    target_type BIGINT NOT NULL,
    target_id TEXT NOT NULL,
    share_role_id TEXT NOT NULL,
    keys TEXT NOT NULL,                   -- JSON [{KeyRotation, Key}]
    from_new_user BIGINT NOT NULL DEFAULT 0,
    expiration_time BIGINT,
    reminders_sent BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);

CREATE INDEX invites_invitee ON invites(invitee_email);

CREATE INDEX invites_vault ON invites(vault_id);

CREATE TABLE new_user_invites (
    id TEXT PRIMARY KEY,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    inviter_share_id TEXT NOT NULL,
    inviter_user_id TEXT NOT NULL,
    inviter_email TEXT NOT NULL,
    invitee_email TEXT NOT NULL,
    target_type BIGINT NOT NULL,
    target_id TEXT NOT NULL,
    share_role_id TEXT NOT NULL,
    signature TEXT NOT NULL,
    state BIGINT NOT NULL DEFAULT 1,      -- 1 waiting for signup, 2 ready for keys
    expiration_time BIGINT,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);

CREATE INDEX new_user_invites_email ON new_user_invites(invitee_email);

-- Attachments.
CREATE TABLE files (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    metadata TEXT NOT NULL DEFAULT '',
    chunk_count BIGINT NOT NULL,
    total_size BIGINT NOT NULL,
    encryption_version BIGINT NOT NULL DEFAULT 1,
    uploaded_chunks BIGINT NOT NULL DEFAULT 0,
    linked BIGINT NOT NULL DEFAULT 0,
    orphaned BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);

CREATE TABLE file_chunks (
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    chunk_index BIGINT NOT NULL,
    chunk_id TEXT NOT NULL,
    size BIGINT NOT NULL,
    PRIMARY KEY (file_id, chunk_index)
);

CREATE TABLE item_files (
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    file_key TEXT NOT NULL,
    key_rotation BIGINT NOT NULL,
    revision_added BIGINT NOT NULL,
    revision_removed BIGINT,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL,
    PRIMARY KEY (item_id, file_id)
);
