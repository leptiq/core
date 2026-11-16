-- Atomic counters (UPSERT ... RETURNING works on SQLite >= 3.35 and Postgres).
-- The row lock taken by the upsert is held until commit, which also keeps
-- per-user event sequence numbers in commit order.
CREATE TABLE counters (
    name TEXT PRIMARY KEY,
    value BIGINT NOT NULL
);
INSERT INTO counters (name, value) SELECT 'alias_mailboxes', COALESCE(MAX(id), 0) FROM alias_mailboxes;
INSERT INTO counters (name, value) SELECT 'alias_contacts', COALESCE(MAX(id), 0) FROM alias_contacts;
INSERT INTO counters (name, value) SELECT 'custom_domains', COALESCE(MAX(id), 0) FROM custom_domains;

CREATE TABLE event_counters (
    user_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL
);
INSERT INTO event_counters (user_id, seq) SELECT user_id, MAX(seq) FROM events GROUP BY user_id;
