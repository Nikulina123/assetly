-- Normalise device_credentials.serial_number to match the lookup key used by
-- app code, and resolve any pre-existing case-only duplicates.
--
-- APPLY WITH psql --single-transaction (-1), like 006, 007, and 013.
--
-- BACKGROUND: enroll_device, revoke_device_credential, and portal.py's
-- device_detail were changed to normalise serial_number with
-- `.strip().casefold()` before comparing or upserting (see app/enrollment.py
-- and app/routers/portal.py). That is self-consistent for rows written AFTER
-- the change -- new rows are inserted already casefolded, so every later
-- lookup matches.
--
-- It is NOT consistent for rows written BEFORE the change. Those rows hold
-- whatever casing the enrolling installer originally reported, e.g.
-- 'ABC-123'. Once the code above ships, every lookup against such a row
-- normalises its search key to 'abc-123', which no longer equals the stored
-- 'ABC-123':
--
--   * revoke_device_credential's UPDATE ... WHERE serial_number = $2 matches
--     zero rows. It raises nothing and returns success, so an admin who
--     clicks "Revoke" on a pre-existing device is told it worked while the
--     credential stays live indefinitely. This is a silent security
--     regression, not just a UX bug.
--   * device_detail's comparison also fails, so the portal renders the
--     device as having "no active credential" and hides its revoke control
--     -- an operator can no longer even find the row to deal with it
--     manually.
--   * enroll_device's existing-row probe and its
--     ON CONFLICT (company_id, serial_number) target both use the
--     normalised value, so re-enrolling 'ABC-123' finds no existing row,
--     INSERTs a second credential for the same machine, and consumes an
--     extra max_devices slot -- while the original, un-revokable row is
--     still active.
--
-- This migration closes that gap by normalising serial_number at rest to
-- lower(btrim(...)) -- the same transform the application performs -- so
-- every row, old or new, is comparable against a casefolded lookup key.
-- devices.serial_number (and device_checkins.serial_number) are deliberately
-- left with their real casing: those tables are user-facing display data and
-- check-in binding already normalises both sides of that comparison in code
-- (see app/enrollment.py), so there is no fleet-outage risk there -- this is
-- purely a device_credentials data-consistency and revocability fix.
--
-- DEPLOY ORDER: this migration MUST run BEFORE the code that normalises
-- lookups (the enrollment.py / portal.py change described above) is
-- deployed. If the code deploys first and this migration runs later, every
-- revoke against a still-un-normalised row silently no-ops for the entire
-- window between the two -- exactly the bug this migration exists to fix.
--
-- COLLISION HANDLING: device_credentials has UNIQUE (company_id,
-- serial_number), and that constraint applies regardless of revoked_at --
-- Postgres does not know or care that one of two colliding rows is dead. So
-- if a company somehow holds both 'ABC-123' and 'abc-123' (e.g. two
-- independent enrollments before this fix existed), we cannot simply
-- normalise both rows' casing and mark the loser revoked in two separate
-- steps: the moment the loser's serial_number is written as 'abc-123', it
-- collides with the winner's row, which already holds (or is about to hold)
-- that exact value -- revoked or not. A naive UPDATE ... SET serial_number =
-- lower(btrim(serial_number)) hits this and aborts the whole migration.
--
-- We resolve it by keeping only the most recently enrolled row (by
-- enrolled_at, breaking ties by id for a stable, deterministic pick) as the
-- live, normalised credential for that (company_id, normalised serial) pair.
-- Every other colliding row is revoked (revoked_at = NOW(), if not already)
-- rather than deleted -- deleting would destroy the audit trail of what
-- credentials existed -- but its serial_number is ALSO given a
-- '~superseded-<id>' suffix, so it no longer collides with the winner's
-- clean normalised value under the unique constraint. The id suffix keeps
-- the value unique even across more than two colliding rows, and the
-- 'abc-123~superseded-<uuid>' prefix keeps the original serial legible to
-- anyone reading the row later.
--
-- This is a single UPDATE (not two passes) precisely so the winner and every
-- loser in a group are rewritten together -- there is no intermediate state
-- where two rows in the same group both hold the clean normalised value.

WITH ranked AS (
    SELECT
        id,
        serial_number,
        revoked_at,
        row_number() OVER (
            PARTITION BY company_id, lower(btrim(serial_number))
            ORDER BY enrolled_at DESC NULLS LAST, id DESC
        ) AS rn
    FROM device_credentials
)
UPDATE device_credentials dc
SET
    serial_number = CASE
        WHEN ranked.rn = 1 THEN lower(btrim(dc.serial_number))
        ELSE lower(btrim(dc.serial_number)) || '~superseded-' || dc.id
    END,
    revoked_at = CASE
        WHEN ranked.rn = 1 THEN dc.revoked_at
        ELSE COALESCE(dc.revoked_at, NOW())
    END
FROM ranked
WHERE dc.id = ranked.id
  AND (
        (ranked.rn = 1 AND dc.serial_number <> lower(btrim(dc.serial_number)))
        OR (
            ranked.rn > 1
            AND (
                dc.serial_number <> lower(btrim(dc.serial_number)) || '~superseded-' || dc.id
                OR dc.revoked_at IS NULL
            )
        )
      );

-- No new grants: device_credentials already grants SELECT, INSERT, UPDATE to
-- assetly (see 007, renamed from webiz_app in 008), which covers this
-- migration's UPDATE statements too.
