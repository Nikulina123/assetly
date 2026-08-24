-- Fixed-window rate limiting.
--
-- APPLY WITH psql --single-transaction (-1), like 006 and 007.
--
-- Postgres rather than Redis because this deploys to Vercel: every warm
-- instance has its own memory and instances come and go, so an in-process
-- counter enforces nothing. There is no Redis in this stack and adding one
-- for four counters is not warranted.
--
-- Fixed windows rather than sliding: a sliding window costs a range scan on
-- every request. The worst case here is a 2x burst across a window boundary,
-- which is an acceptable trade for a control whose job is stopping credential
-- stuffing and cost amplification, not precise traffic shaping.
--
-- No RLS: this table holds no tenant data. Bucket keys for per-account limits
-- are hashed (see app/rate_limit.py) precisely so this table cannot be read
-- as a list of admin email addresses.

CREATE TABLE rate_limit_hits (
    bucket_key   TEXT        NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    count        INTEGER     NOT NULL DEFAULT 0,
    PRIMARY KEY (bucket_key, window_start)
);

-- Supports the opportunistic prune in app/rate_limit.py.
CREATE INDEX idx_rate_limit_hits_window ON rate_limit_hits (window_start);

GRANT SELECT, INSERT, UPDATE, DELETE ON rate_limit_hits TO assetly;

-- Supabase exposes a PostgREST API keyed on `anon` / `authenticated` roles.
-- On this project those roles currently hold no grants on any public table
-- (verified 2026-08-24), so they cannot reach this table -- but that is a
-- project setting somebody could change later, not a property of the schema.
-- RLS plus an explicit policy for the application role makes the guarantee
-- local to this table instead of depending on a dashboard setting staying put.
--
-- The policy is required, not decorative: the table is owned by the migrating
-- role (postgres/admin), NOT by `assetly`, so with RLS on and no policy the
-- application would be denied outright and every guarded endpoint would 500.
--
-- The REVOKE is guarded because `anon` / `authenticated` are Supabase-created
-- roles that do not exist on a local development database -- same guarded
-- pattern as 008's role rename.

ALTER TABLE rate_limit_hits ENABLE ROW LEVEL SECURITY;

CREATE POLICY rate_limit_hits_app ON rate_limit_hits
    FOR ALL TO assetly USING (true) WITH CHECK (true);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON rate_limit_hits FROM anon';
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON rate_limit_hits FROM authenticated';
    END IF;
END
$$;
