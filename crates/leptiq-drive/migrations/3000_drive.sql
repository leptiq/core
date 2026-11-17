-- Leptiq Drive: volumes, shares, links (files and folders), revisions and
-- their encrypted blocks. Drive migrations use versions 3000+.
-- Everything except hashes, sizes and states is client ciphertext.

CREATE TABLE drive_volumes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    volume_type BIGINT NOT NULL,          -- 1 regular, 2 photos
    share_id TEXT NOT NULL,
    root_link_id TEXT NOT NULL,
    used_space BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);
CREATE INDEX drive_volumes_user ON drive_volumes(user_id);

CREATE TABLE drive_shares (
    id TEXT PRIMARY KEY,
    volume_id TEXT NOT NULL REFERENCES drive_volumes(id) ON DELETE CASCADE,
    share_type BIGINT NOT NULL,           -- 1 main, 4 photos
    link_id TEXT NOT NULL,
    address_id TEXT NOT NULL,
    address_key_id TEXT NOT NULL,
    creator_email TEXT NOT NULL,
    share_key TEXT NOT NULL,
    passphrase TEXT NOT NULL,
    passphrase_signature TEXT NOT NULL,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL
);

CREATE TABLE drive_links (
    id TEXT PRIMARY KEY,
    volume_id TEXT NOT NULL REFERENCES drive_volumes(id) ON DELETE CASCADE,
    parent_id TEXT,                       -- NULL for a volume's root folder
    link_type BIGINT NOT NULL,            -- 1 folder, 2 file
    state BIGINT NOT NULL,                -- 0 draft, 1 active, 2 trashed
    name TEXT NOT NULL,
    name_hash TEXT,
    node_key TEXT NOT NULL,
    node_passphrase TEXT NOT NULL,
    node_passphrase_signature TEXT NOT NULL,
    node_hash_key TEXT,                   -- folders
    xattr TEXT,                           -- folders
    signature_email TEXT,
    name_signature_email TEXT,
    mime_type TEXT,                       -- files
    content_key_packet TEXT,              -- files
    content_key_packet_signature TEXT,    -- files
    active_revision_id TEXT,              -- files
    client_uid TEXT,
    created BIGINT NOT NULL,
    modified BIGINT NOT NULL,
    trash_time BIGINT
);
CREATE INDEX drive_links_parent ON drive_links(volume_id, parent_id);

CREATE TABLE drive_revisions (
    id TEXT PRIMARY KEY,
    link_id TEXT NOT NULL REFERENCES drive_links(id) ON DELETE CASCADE,
    state BIGINT NOT NULL,                -- 0 draft, 1 active, 2 obsolete
    size BIGINT NOT NULL DEFAULT 0,       -- encrypted bytes (blocks + thumbnails)
    manifest_signature TEXT,
    xattr TEXT,
    signature_email TEXT,
    checksum_verified BIGINT NOT NULL DEFAULT 0,
    client_uid TEXT,
    verification_code TEXT NOT NULL,
    created BIGINT NOT NULL
);
CREATE INDEX drive_revisions_link ON drive_revisions(link_id);

CREATE TABLE drive_blocks (
    revision_id TEXT NOT NULL REFERENCES drive_revisions(id) ON DELETE CASCADE,
    idx BIGINT NOT NULL,
    hash TEXT NOT NULL,                   -- base64 sha256 of the encrypted block
    size BIGINT NOT NULL,
    enc_signature TEXT,
    blob_id TEXT NOT NULL,
    PRIMARY KEY (revision_id, idx)
);

CREATE TABLE drive_thumbnails (
    id TEXT PRIMARY KEY,
    revision_id TEXT NOT NULL REFERENCES drive_revisions(id) ON DELETE CASCADE,
    thumb_type BIGINT NOT NULL,
    hash TEXT NOT NULL,
    size BIGINT NOT NULL,
    blob_id TEXT NOT NULL
);
CREATE INDEX drive_thumbnails_revision ON drive_thumbnails(revision_id);

-- Short-lived storage tokens for block/thumbnail upload and download URLs.
CREATE TABLE drive_storage_tokens (
    token TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                   -- 'block_up', 'thumb_up', 'download'
    volume_id TEXT NOT NULL,
    revision_id TEXT,
    idx BIGINT,                           -- block index / thumbnail type
    enc_signature TEXT,
    blob_id TEXT,
    expires BIGINT NOT NULL
);

-- Per-volume change log polled by clients.
CREATE TABLE drive_events (
    volume_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    event_type BIGINT NOT NULL,           -- 0 delete, 1 create, 2 update
    link_id TEXT NOT NULL,
    parent_id TEXT,
    is_trashed BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL,
    PRIMARY KEY (volume_id, seq)
);

CREATE TABLE drive_settings (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    settings TEXT NOT NULL                -- JSON
);
