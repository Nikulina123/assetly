DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'webiz_app') THEN
        CREATE ROLE webiz_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
    END IF;
END
$$;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- No RLS on companies: api-key lookup must happen before company_id is known.
-- Tenant isolation for this table is enforced entirely in application code.
CREATE TABLE companies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    api_key_hash    TEXT UNIQUE NOT NULL,
    api_key_prefix  TEXT NOT NULL,
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    revoked_at      TIMESTAMPTZ
);

CREATE TABLE device_checkins (
    id               SERIAL PRIMARY KEY,
    company_id       UUID NOT NULL REFERENCES companies(id),
    checkin_id       UUID NOT NULL,
    received_at      TIMESTAMPTZ DEFAULT NOW(),
    timestamp        TIMESTAMPTZ NOT NULL,

    first_name       TEXT NOT NULL,
    last_name        TEXT NOT NULL,
    email            TEXT NOT NULL,
    project          TEXT NOT NULL,

    serial_number    TEXT NOT NULL,
    hostname         TEXT NOT NULL,
    brand            TEXT NOT NULL,
    model            TEXT NOT NULL,

    cpu              TEXT,
    ram              TEXT,
    storage          TEXT,
    ip_address       TEXT,

    os               TEXT NOT NULL,
    os_version       TEXT,
    platform         TEXT,

    agent_version    TEXT,
    submission_type  TEXT DEFAULT 'online',

    UNIQUE (company_id, checkin_id)
);

CREATE TABLE devices (
    company_id       UUID NOT NULL REFERENCES companies(id),
    serial_number    TEXT NOT NULL,
    last_seen_at     TIMESTAMPTZ,
    hostname         TEXT,
    brand            TEXT,
    model            TEXT,
    cpu              TEXT,
    ram              TEXT,
    storage          TEXT,
    os               TEXT,
    os_version       TEXT,
    platform         TEXT,
    owner_email      TEXT,
    project           TEXT,
    PRIMARY KEY (company_id, serial_number)
);

ALTER TABLE device_checkins ENABLE ROW LEVEL SECURITY;
-- FORCE ensures even the table owner (admin/migration role) respects tenant isolation, not just webiz_app
ALTER TABLE device_checkins FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_checkins ON device_checkins
    USING (company_id = current_setting('app.company_id')::uuid);

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
-- FORCE ensures even the table owner (admin/migration role) respects tenant isolation, not just webiz_app
ALTER TABLE devices FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_devices ON devices
    USING (company_id = current_setting('app.company_id')::uuid);

CREATE INDEX idx_checkins_company_serial   ON device_checkins (company_id, serial_number);
CREATE INDEX idx_checkins_company_email    ON device_checkins (company_id, email);
CREATE INDEX idx_checkins_company_project  ON device_checkins (company_id, project);
CREATE INDEX idx_checkins_company_platform ON device_checkins (company_id, platform);
CREATE INDEX idx_checkins_company_received ON device_checkins (company_id, received_at DESC);

GRANT SELECT, INSERT, UPDATE ON companies, device_checkins, devices TO webiz_app;
GRANT USAGE, SELECT ON SEQUENCE device_checkins_id_seq TO webiz_app;
