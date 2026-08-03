CREATE TABLE company_fields (
    id          SERIAL PRIMARY KEY,
    company_id  UUID NOT NULL REFERENCES companies(id),
    field_key   TEXT NOT NULL,   -- 'project', a hardware field name, or a custom field's slug
    field_type  TEXT NOT NULL,   -- 'project' | 'hardware' | 'custom'
    label       TEXT NOT NULL,   -- display label (meaningful for 'custom'; fixed for the others)
    enabled     BOOLEAN NOT NULL DEFAULT true,
    required    BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (company_id, field_key)
);

-- Same tenant-isolation pattern as device_checkins/devices (see 001_init.sql):
-- FORCE so even the table owner respects it, non-superuser webiz_app role
-- enforces it for real.
ALTER TABLE company_fields ENABLE ROW LEVEL SECURITY;
ALTER TABLE company_fields FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_company_fields ON company_fields
    USING (company_id = current_setting('app.company_id')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON company_fields TO webiz_app;
GRANT USAGE, SELECT ON SEQUENCE company_fields_id_seq TO webiz_app;

ALTER TABLE device_checkins ADD COLUMN custom_fields JSONB NOT NULL DEFAULT '{}';
