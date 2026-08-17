-- Upper bound on the check-in schedule, completing 010's CHECK.
--
-- 010 bounded both columns below but not above. The columns are INTEGER
-- (int4), so a value past ~2.1 billion cannot be stored at all: asyncpg
-- rejects it client-side with DataError before Postgres sees the statement,
-- which is not the ValueError the portal reports form errors through, so it
-- surfaced as a 500. The app-layer cap in app/schedule.py
-- (MAX_INTERVAL_SECONDS) is what an admin actually meets; this constraint is
-- the backstop against direct DB edits, exactly as 010's floor is -- it must
-- never be what reports a user error.
--
-- 157680000 seconds = 5 years (365-day years), matching MAX_INTERVAL_SECONDS.
--
-- Postgres has no ALTER CONSTRAINT for a CHECK expression, so the existing
-- constraint is dropped and recreated with both bounds rather than a second
-- constraint being added alongside it -- one named invariant, one place to
-- read it.
ALTER TABLE companies DROP CONSTRAINT checkin_schedule_sane;

ALTER TABLE companies ADD CONSTRAINT checkin_schedule_sane CHECK (
    checkin_interval_seconds BETWEEN 3600 AND 157680000
    AND cancel_retry_seconds BETWEEN 3600 AND checkin_interval_seconds
);
