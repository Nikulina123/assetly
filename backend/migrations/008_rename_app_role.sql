-- Renames the application role webiz_app -> assetly, finishing the rebrand that
-- 006 deliberately stopped short of.
--
-- 006's closing note argued the rename wasn't worth it: an ALTER ROLE has to
-- land in lockstep with a DATABASE_URL change on every deployed instance, or
-- the application loses database access on deploy. That constraint no longer
-- holds -- there is no deployed instance yet, and the production DATABASE_URL
-- is being written for the first time as part of this deployment. After the
-- first agent is enrolled this stops being free again, so it happens now.
--
-- Object privileges and table ownership are tracked by the role's OID, not its
-- name, so every GRANT issued in 001/002/003/007 survives untouched. Nothing
-- needs re-granting, and the RLS policies (which key off app.company_id, not
-- the role) are equally unaffected.
--
-- Set this role's password AFTER applying this migration, never before: an
-- md5-encoded password hash embeds the role name, so Postgres invalidates it on
-- rename. SCRAM hashes survive, but ordering it this way is correct either way.
DO $$
BEGIN
    -- Guarded rather than a bare ALTER so this is a no-op on a database where
    -- the rename already happened, instead of erroring on a missing role.
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'webiz_app') THEN
        ALTER ROLE webiz_app RENAME TO assetly;
    END IF;
END
$$;
