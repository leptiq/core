-- Keys rotated by another member, encrypted to this member's address key,
-- waiting to be re-encrypted ("promoted") to their user key.
CREATE TABLE pending_share_keys (
    id TEXT PRIMARY KEY,
    share_id TEXT NOT NULL REFERENCES shares(id) ON DELETE CASCADE,
    address_id TEXT NOT NULL,
    rotator_address_id TEXT NOT NULL,
    key_rotation BIGINT NOT NULL,
    encrypted_key TEXT NOT NULL,
    created BIGINT NOT NULL
);
CREATE INDEX pending_share_keys_share ON pending_share_keys(share_id);

-- Public (secure) links to a single item.
CREATE TABLE public_links (
    id TEXT PRIMARY KEY,
    token TEXT NOT NULL UNIQUE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    share_id TEXT NOT NULL,
    vault_id TEXT NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
    item_id TEXT NOT NULL REFERENCES items(id) ON DELETE CASCADE,
    revision BIGINT NOT NULL,
    encrypted_item_key TEXT NOT NULL,
    encrypted_link_key TEXT NOT NULL,
    link_key_share_key_rotation BIGINT NOT NULL,
    link_key_encrypted_with_item_key BIGINT NOT NULL DEFAULT 0,
    max_read_count BIGINT,
    read_count BIGINT NOT NULL DEFAULT 0,
    expiration_time BIGINT NOT NULL,
    created BIGINT NOT NULL
);
CREATE INDEX public_links_user ON public_links(user_id);
