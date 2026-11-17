-- Leptiq core: per-user event log, atomic counters and key/value settings.

-- Append-only per-user event log. Event IDs handed to clients encode seq.
CREATE TABLE events (
    user_id TEXT NOT NULL,
    seq BIGINT NOT NULL,
    kind TEXT NOT NULL,
    share_id TEXT,
    target_id TEXT,
    data TEXT,
    created BIGINT NOT NULL,
    PRIMARY KEY (user_id, seq)
);

CREATE TABLE kv (
    k TEXT PRIMARY KEY,
    v TEXT NOT NULL
);

-- Atomic counters (UPSERT ... RETURNING works on SQLite >= 3.35 and Postgres).
-- The row lock taken by the upsert is held until commit, which also keeps
-- per-user event sequence numbers in commit order.
CREATE TABLE counters (
    name TEXT PRIMARY KEY,
    value BIGINT NOT NULL
);

CREATE TABLE event_counters (
    user_id TEXT PRIMARY KEY,
    seq BIGINT NOT NULL
);
