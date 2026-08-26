-- Admin MFA, role separation, per-company scoping, and privileged-action
-- audit logging. Closes findings H-2 and H-4 of the 2026-08-20 assessment.
--
-- APPLY WITH psql --single-transaction (-1), like 013 and 014.
-- APPLY THIS BEFORE DEPLOYING THE CODE THAT USES IT. Unlike the rate limiter
-- (013), there is no fail-open path here: the login flow reads admins.role and
-- admins.mfa_secret on every request, so code deployed against a database
-- without this migration breaks admin login outright. The ordering IS the
-- control -- see BACKEND_API_PLAN.md's deploy-ordering block.
--
-- Three things land together because they share one table:
--
-- 1. MFA. Password alone protected a console that can rotate any company's API
--    key and mint enrollment tokens for any tenant, so one leaked password was
--    the whole customer base. TOTP because it needs no vendor, no SMS, and no
--    per-user cost.
-- 2. Roles. `support` is read-only, so routine work stops requiring the
--    credential that can mint tokens (least privilege, TSC CC6.3).
-- 3. Per-company scoping. `company_id NULL` means global -- which is every
--    admin that exists today, so this is behaviour-preserving on application.
--    The column lands now rather than being retrofitted onto a table that
--    other features have since grown to assume is global.

ALTER TABLE admins
    ADD COLUMN mfa_secret      TEXT,
    ADD COLUMN mfa_enrolled_at TIMESTAMPTZ,
    ADD COLUMN role            TEXT NOT NULL DEFAULT 'admin'
                               CHECK (role IN ('admin', 'support')),
    -- ON DELETE RESTRICT, not CASCADE or SET NULL: companies are revoked
    -- (companies.revoked_at), never deleted. If a delete path is ever added,
    -- it must not silently promote a scoped admin to global by nulling this.
    ADD COLUMN company_id      UUID REFERENCES companies(id) ON DELETE RESTRICT;

-- mfa_secret holds a Fernet-encrypted TOTP seed, never the raw base32 -- a
-- TOTP seed is a live credential (read it once, generate valid codes forever,
-- silently), unlike a bcrypt password hash which is useless to a reader. The
-- key is derived from SESSION_SECRET_KEY and lives in the environment, not in
-- this database, so a stolen dump or backup does not carry the second factor
-- with it. See backend/app/mfa.py.

-- 002 granted only SELECT on admins, because accounts were seeded by an
-- operator and the app never wrote to this table. Enrollment changes that --
-- but only for the two MFA columns. Column-level deliberately: the app can
-- enroll MFA and nothing else, so even a privilege-escalation bug in the admin
-- router cannot grant a role or move an admin's scope, because the role the
-- application connects as has no grant to do so. Role and scope assignment is
-- an operator action via backend/scripts/set_admin_role.py, run as `admin`.
GRANT UPDATE (mfa_secret, mfa_enrolled_at) ON admins TO assetly;

-- Single-use recovery codes, so losing a phone is not an account loss that
-- ends in manual SQL against production.
--
-- bcrypt rather than the SHA-256 used for API keys and enrollment tokens:
-- those are 256-bit random secrets where a fast hash is fine, whereas a
-- recovery code is short enough to be worth attacking offline, and bcrypt's
-- work factor is the entire point. Verification therefore costs one bcrypt
-- comparison per unused code -- bounded at 10, only on the recovery path, and
-- rate-limited (app/routers/admin.py).
CREATE TABLE admin_recovery_codes (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    admin_id   UUID NOT NULL REFERENCES admins(id),
    code_hash  TEXT NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_admin_recovery_codes_admin ON admin_recovery_codes (admin_id);

-- UPDATE to mark a code used; DELETE to replace a whole set on regeneration.
GRANT SELECT, INSERT, UPDATE, DELETE ON admin_recovery_codes TO assetly;

-- Append-only record of privileged admin actions. Before this, the only
-- durable trace of admin activity was the mutated row itself, which carries no
-- actor and often no timestamp -- so after a suspected admin compromise there
-- was no way to establish what was changed, or by whom (TSC CC7.2/CC7.3).
--
-- actor_admin_id deliberately has NO foreign key to admins. A foreign key
-- would give row deletion power over this log: CASCADE erases an actor's
-- history, SET NULL rewrites it, RESTRICT lets the log block an unrelated
-- operation. An append-only record must not be mutable by a referential
-- action. The cost -- an actor UUID whose join may find nothing -- is correct
-- for a log that outlives the accounts it describes.
--
-- target_id is TEXT, not UUID: targets include enrollment-token UUIDs, device
-- serial numbers, and custom field keys.
CREATE TABLE audit_log (
    id                BIGSERIAL PRIMARY KEY,
    actor_admin_id    UUID,
    action            TEXT        NOT NULL,
    target_company_id UUID,
    target_id         TEXT,
    ip_address        TEXT,
    user_agent        TEXT,
    occurred_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metadata          JSONB       NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX idx_audit_log_occurred ON audit_log (occurred_at DESC);
CREATE INDEX idx_audit_log_company  ON audit_log (target_company_id, occurred_at DESC);
CREATE INDEX idx_audit_log_actor    ON audit_log (actor_admin_id, occurred_at DESC);

-- SELECT and INSERT only. No UPDATE, no DELETE, deliberately and permanently:
-- "append-only" is a property of the grant, not a convention in application
-- code that the next refactor can forget. This is also why retention is
-- indefinite -- the application cannot prune even if it wanted to. Any future
-- pruning is an operator action run as `admin`. See BACKEND_API_PLAN.md.
GRANT SELECT, INSERT ON audit_log TO assetly;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO assetly;

-- Supabase exposes a PostgREST API keyed on `anon` / `authenticated` roles.
-- On this project those roles currently hold no grants on any public table,
-- so they cannot reach these tables -- but that is a project setting somebody
-- could change later, not a property of the schema. RLS plus an explicit
-- policy for the application role makes the guarantee local to these tables
-- instead of depending on a dashboard setting staying put.
--
-- The policy is required, not decorative: these tables are owned by the
-- migrating role (postgres/admin), NOT by `assetly`, so with RLS on and no
-- policy the application would be denied outright and every guarded endpoint
-- would 500.
--
-- The REVOKE is guarded because `anon` / `authenticated` are Supabase-created
-- roles that do not exist on a local development database -- same guarded
-- pattern as 008's role rename and 014.
ALTER TABLE admin_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log            ENABLE ROW LEVEL SECURITY;

CREATE POLICY admin_recovery_codes_app ON admin_recovery_codes
    FOR ALL TO assetly USING (true) WITH CHECK (true);
CREATE POLICY audit_log_app ON audit_log
    FOR ALL TO assetly USING (true) WITH CHECK (true);

DO $$
BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'anon') THEN
        EXECUTE 'REVOKE ALL ON admin_recovery_codes, audit_log FROM anon';
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'authenticated') THEN
        EXECUTE 'REVOKE ALL ON admin_recovery_codes, audit_log FROM authenticated';
    END IF;
END
$$;
