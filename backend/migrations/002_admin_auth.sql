-- No RLS on admins: this table isn't tenant-scoped (no company_id column) —
-- every admin can see and manage every company by design (single global
-- admin tier, no per-company admin role).
CREATE TABLE admins (
    id             UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email          TEXT UNIQUE NOT NULL,
    password_hash  TEXT NOT NULL,  -- bcrypt hash, see backend/app/admin_auth.py
    created_at     TIMESTAMPTZ DEFAULT NOW()
);

-- webiz_app only needs to read admins to verify a login attempt. Admin
-- accounts are seeded via backend/scripts/seed_admin.py run as the `admin`
-- superuser role, not created through the app itself (no self-registration).
GRANT SELECT ON admins TO webiz_app;
