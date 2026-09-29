-- Memory and disk detail the agents collect from 2.3.0 on: DIMM type, the
-- speed the memory is actually running at, slot occupancy ("2/4"), and how
-- the system disk is attached ("NVMe SSD", "SATA HDD", ...).
--
-- Separate columns rather than folded into ram/storage: those two are what
-- the computers list shows in a narrow column, and "16 GB" has to stay "16 GB"
-- there. The detail belongs on the device page.
--
-- All nullable, and they stay NULL for agents older than 2.3.0 -- those do
-- not send them, and a company that switched RAM or storage off in the
-- portal gets neither the summary nor the detail.
--
-- No GRANT needed: 001_init.sql grants SELECT, INSERT, UPDATE on both tables
-- at table level, which covers columns added later.
--
-- APPLY WITH psql --single-transaction (-1), as the `admin` role, BEFORE
-- deploying the code that writes these columns. The check-in INSERT names
-- them, so the new code against the old schema fails every check-in from
-- every agent, old and new alike.

ALTER TABLE device_checkins
    ADD COLUMN ram_type     TEXT,
    ADD COLUMN ram_speed    TEXT,
    ADD COLUMN ram_slots    TEXT,
    ADD COLUMN storage_type TEXT;

ALTER TABLE devices
    ADD COLUMN ram_type     TEXT,
    ADD COLUMN ram_speed    TEXT,
    ADD COLUMN ram_slots    TEXT,
    ADD COLUMN storage_type TEXT;
