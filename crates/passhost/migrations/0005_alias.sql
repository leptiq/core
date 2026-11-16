-- Email aliases (SimpleLogin-style forwarding).

CREATE TABLE alias_mailboxes (
    id BIGINT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    pending_email TEXT,
    verified BIGINT NOT NULL DEFAULT 0,
    verification_code TEXT,
    is_default BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL
);
CREATE INDEX alias_mailboxes_user ON alias_mailboxes(user_id);

CREATE TABLE aliases (
    email TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id TEXT,
    enabled BIGINT NOT NULL DEFAULT 1,
    name TEXT,
    note TEXT,
    forwarded BIGINT NOT NULL DEFAULT 0,
    replied BIGINT NOT NULL DEFAULT 0,
    blocked BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL
);
CREATE INDEX aliases_user ON aliases(user_id);
CREATE INDEX aliases_item ON aliases(item_id);

CREATE TABLE alias_mailbox_links (
    alias_email TEXT NOT NULL REFERENCES aliases(email) ON DELETE CASCADE,
    mailbox_id BIGINT NOT NULL REFERENCES alias_mailboxes(id) ON DELETE CASCADE,
    PRIMARY KEY (alias_email, mailbox_id)
);

CREATE TABLE alias_contacts (
    id BIGINT PRIMARY KEY,
    alias_email TEXT NOT NULL REFERENCES aliases(email) ON DELETE CASCADE,
    email TEXT NOT NULL,
    name TEXT,
    reverse_alias TEXT NOT NULL UNIQUE,
    blocked BIGINT NOT NULL DEFAULT 0,
    forwarded BIGINT NOT NULL DEFAULT 0,
    replied BIGINT NOT NULL DEFAULT 0,
    blocked_count BIGINT NOT NULL DEFAULT 0,
    created BIGINT NOT NULL
);
CREATE INDEX alias_contacts_alias ON alias_contacts(alias_email);

CREATE TABLE alias_settings (
    user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    default_domain TEXT,
    default_mailbox_id BIGINT
);

CREATE TABLE custom_domains (
    id BIGINT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    domain TEXT NOT NULL UNIQUE,
    verification_token TEXT NOT NULL,
    ownership_verified BIGINT NOT NULL DEFAULT 0,
    mx_verified BIGINT NOT NULL DEFAULT 0,
    spf_verified BIGINT NOT NULL DEFAULT 0,
    dkim_verified BIGINT NOT NULL DEFAULT 0,
    dmarc_verified BIGINT NOT NULL DEFAULT 0,
    catch_all BIGINT NOT NULL DEFAULT 0,
    random_prefix BIGINT NOT NULL DEFAULT 0,
    default_display_name TEXT,
    created BIGINT NOT NULL
);

CREATE TABLE custom_domain_mailboxes (
    domain_id BIGINT NOT NULL REFERENCES custom_domains(id) ON DELETE CASCADE,
    mailbox_id BIGINT NOT NULL REFERENCES alias_mailboxes(id) ON DELETE CASCADE,
    PRIMARY KEY (domain_id, mailbox_id)
);
