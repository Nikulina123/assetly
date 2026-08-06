-- Per-device credentials, replacing the single shared company API key.
--
-- APPLY WITH psql --single-transaction (-1), like 006: psql is autocommit by
-- default, so a failure partway would leave half these objects created.

CREATE TABLE enrollment_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id   UUID NOT NULL REFERENCES companies(id),
    token_hash   TEXT UNIQUE NOT NULL,
    token_prefix TEXT NOT NULL,
    label        TEXT,
    created_at   TIMESTAMPTZ DEFAULT NOW(),
    expires_at   TIMESTAMPTZ NOT NULL,
    max_devices  INTEGER,
    used_count   INTEGER NOT NULL DEFAULT 0,
    revoked_at   TIMESTAMPTZ
);

CREATE TABLE device_credentials (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    company_id      UUID NOT NULL REFERENCES companies(id),
    credential_hash TEXT UNIQUE NOT NULL,
    serial_number   TEXT NOT NULL,
    hostname        TEXT,
    enrolled_at     TIMESTAMPTZ DEFAULT NOW(),
    last_used_at    TIMESTAMPTZ,
    revoked_at      TIMESTAMPTZ,
    enrolled_via    UUID REFERENCES enrollment_tokens(id),
    -- Idempotency: re-running an installer on an already-enrolled machine must
    -- replace that machine's credential, never add a second row. Without this,
    -- every reinstall would inflate the company's device count.
    UNIQUE (company_id, serial_number)
);

ALTER TABLE enrollment_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrollment_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_enrollment_tokens ON enrollment_tokens
    USING (company_id = current_setting('app.company_id')::uuid);

ALTER TABLE device_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_credentials FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_device_credentials ON device_credentials
    USING (company_id = current_setting('app.company_id')::uuid);

CREATE INDEX idx_enrollment_tokens_company ON enrollment_tokens (company_id, created_at DESC);
CREATE INDEX idx_device_credentials_company ON device_credentials (company_id, enrolled_at DESC);

GRANT SELECT, INSERT, UPDATE ON enrollment_tokens, device_credentials TO webiz_app;
