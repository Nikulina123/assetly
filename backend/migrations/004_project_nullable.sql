-- project became a toggleable field in 003_field_config.sql (resolve_field_config
-- can omit it per company), but the column was still NOT NULL, so any company
-- with project disabled would get every checkin rejected with 422/constraint
-- violation. Matches the treatment of the other toggleable fields (cpu/ram/
-- storage/ip_address), which are already nullable.
ALTER TABLE device_checkins ALTER COLUMN project DROP NOT NULL;
