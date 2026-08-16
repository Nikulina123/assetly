-- Per-company check-in recurrence, replacing the agents' hardcoded 6 months.
--
-- Columns on companies rather than rows in company_fields: that table models
-- form FIELDS (keyed by field_key, with a field_type vocabulary of
-- project/hardware/custom) and resolve_field_config reads it as a flat field
-- namespace. A schedule is not a field -- it would need a fourth field_type
-- whose label/enabled/required/options columns are all meaningless.
-- 005_notification_email.sql set the precedent for plain company-level columns.
--
-- Defaults reproduce today's behaviour exactly (180 days ~ the agents'
-- INTERVAL_MONTHS = 6, and the 24 h cancel retry), so no existing company
-- changes behaviour until an admin edits the setting.
--
-- No GRANT needed: 001_init.sql already grants SELECT, INSERT, UPDATE on
-- companies at table level, which covers columns added later.
ALTER TABLE companies
    ADD COLUMN checkin_interval_seconds INTEGER NOT NULL DEFAULT 15552000,
    ADD COLUMN cancel_retry_seconds     INTEGER NOT NULL DEFAULT 86400;

-- The floor matches MIN_INTERVAL_SECONDS in app/schedule.py: agents wake
-- hourly, so a shorter interval could not be honoured. The upper bound on the
-- retry rules out the incoherent "prompt every 12 h, snooze a cancel for 24 h",
-- where the snooze would outlast the cycle it belongs to.
ALTER TABLE companies ADD CONSTRAINT checkin_schedule_sane CHECK (
    checkin_interval_seconds >= 3600
    AND cancel_retry_seconds BETWEEN 3600 AND checkin_interval_seconds
);
