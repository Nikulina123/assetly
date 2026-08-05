-- APPLY WITH psql --single-transaction (-1). psql is autocommit by default, so
-- without it each statement commits on its own: if the ADD CONSTRAINT at the
-- bottom failed, the DROP CONSTRAINT above it would already be committed and
-- company_fields would be left with no field_type constraint at all. Postgres
-- DDL is transactional, so -1 makes the whole rename all-or-nothing.
--
-- Renames the per-device "project" field to "department", matching the Assetly
-- design system's vocabulary (device.dept, "Department Overview" reports).
-- The column was already made nullable in 004_project_nullable.sql, and
-- devices.project never had NOT NULL, so no nullability change is needed here.
ALTER TABLE device_checkins RENAME COLUMN project TO department;
ALTER TABLE devices         RENAME COLUMN project TO department;

ALTER INDEX idx_checkins_company_project RENAME TO idx_checkins_company_department;

-- field_type's CHECK is auto-named by Postgres; it must be dropped and
-- recreated rather than altered in place.
--
-- ORDER MATTERS. ADD CONSTRAINT validates existing rows immediately (it is not
-- NOT VALID), so the backfill must run while no constraint is in force. Adding
-- the new CHECK first would abort the migration on any database where a company
-- had configured the project field, because those rows still read
-- field_type = 'project'. An empty database hides this entirely.
ALTER TABLE company_fields DROP CONSTRAINT company_fields_field_type_check;

-- Existing per-company override rows carry the old key in both columns.
UPDATE company_fields
   SET field_key = 'department', field_type = 'department'
 WHERE field_key = 'project';

ALTER TABLE company_fields ADD  CONSTRAINT company_fields_field_type_check
    CHECK (field_type IN ('department', 'hardware', 'custom'));

-- NOTE: the webiz_app role keeps its name deliberately. Renaming it requires an
-- ALTER ROLE that must land in lockstep with a DATABASE_URL change on every
-- deployed instance, or the application loses database access on deploy. It is
-- an internal identifier no user ever sees. Same reasoning applies to the
-- webiz_checkin / webiz_checkin_test database names.
