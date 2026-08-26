"""Schema assertions for migration 016.

These exist because two of the properties this migration establishes are
invisible in application code and only fail in production: the column-level
UPDATE grant on admins (which is what stops the app from writing its own role)
and the absence of UPDATE/DELETE on audit_log (which is what makes the log
append-only). A test is the only thing that notices if a later migration
grants them back.
"""
import pytest

pytestmark = pytest.mark.asyncio


async def test_admins_has_mfa_role_and_scope_columns(db_pool):
    async with db_pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT column_name, is_nullable, column_default FROM information_schema.columns "
            "WHERE table_name = 'admins'"
        )
    cols = {r["column_name"]: r for r in rows}
    assert "mfa_secret" in cols and cols["mfa_secret"]["is_nullable"] == "YES"
    assert "mfa_enrolled_at" in cols and cols["mfa_enrolled_at"]["is_nullable"] == "YES"
    assert "company_id" in cols and cols["company_id"]["is_nullable"] == "YES"
    assert cols["role"]["is_nullable"] == "NO"
    assert "admin" in cols["role"]["column_default"]


async def test_role_check_constraint_rejects_unknown_roles(db_pool):
    """Inserted via the admin-role connection, not db_pool/assetly: assetly
    has no INSERT grant on admins at all (see migrations/002_admin_auth.sql --
    accounts are seeded by an operator, never by the app), so an insert
    attempted as assetly fails with InsufficientPrivilegeError regardless of
    the CHECK constraint. Using the admin role isolates the assertion this
    test is actually about."""
    import asyncpg
    from tests.conftest import ADMIN_TEST_DATABASE_URL
    conn = await asyncpg.connect(ADMIN_TEST_DATABASE_URL)
    try:
        with pytest.raises(asyncpg.CheckViolationError):
            await conn.execute(
                "INSERT INTO admins (email, password_hash, role) VALUES ($1, $2, $3)",
                "bad-role@example.com", "x", "superuser",
            )
    finally:
        await conn.close()


async def test_app_role_cannot_update_password_hash_or_role(db_pool, admin):
    """The column-level grant is the control that stops a router bug from
    escalating privilege. If this test fails, the app can write its own role."""
    import asyncpg
    admin_id, _email, _password = admin
    async with db_pool.acquire() as conn:
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "UPDATE admins SET role = 'admin' WHERE id = $1", admin_id
            )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute(
                "UPDATE admins SET password_hash = 'x' WHERE id = $1", admin_id
            )


async def test_app_role_can_update_mfa_columns(db_pool, admin):
    admin_id, _email, _password = admin
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE admins SET mfa_secret = $1, mfa_enrolled_at = NOW() WHERE id = $2",
            "encrypted-blob", admin_id,
        )
        stored = await conn.fetchval("SELECT mfa_secret FROM admins WHERE id = $1", admin_id)
    assert stored == "encrypted-blob"


async def test_audit_log_is_append_only_for_the_app_role(db_pool):
    """No UPDATE and no DELETE grant -- this is what 'append-only' actually
    means here, and it is enforced by Postgres rather than by convention."""
    import asyncpg
    async with db_pool.acquire() as conn:
        row_id = await conn.fetchval(
            "INSERT INTO audit_log (action) VALUES ('test.action') RETURNING id"
        )
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("UPDATE audit_log SET action = 'tampered' WHERE id = $1", row_id)
        with pytest.raises(asyncpg.InsufficientPrivilegeError):
            await conn.execute("DELETE FROM audit_log WHERE id = $1", row_id)


async def test_audit_log_actor_has_no_foreign_key(db_pool):
    """A deleted admin must not be able to erase or rewrite its own history."""
    async with db_pool.acquire() as conn:
        count = await conn.fetchval(
            """
            SELECT COUNT(*) FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
            WHERE tc.table_name = 'audit_log'
              AND tc.constraint_type = 'FOREIGN KEY'
              AND kcu.column_name = 'actor_admin_id'
            """
        )
    assert count == 0


async def test_new_tables_have_rls_with_an_app_policy(db_pool):
    """RLS with no policy denies the owning application outright. 013/014 both
    carry an explicit policy for exactly this reason."""
    async with db_pool.acquire() as conn:
        for table in ("admin_recovery_codes", "audit_log"):
            enabled = await conn.fetchval(
                "SELECT relrowsecurity FROM pg_class WHERE relname = $1", table
            )
            assert enabled is True, f"{table} has no RLS"
            policies = await conn.fetchval(
                "SELECT COUNT(*) FROM pg_policies WHERE tablename = $1", table
            )
            assert policies >= 1, f"{table} has RLS but no policy -- the app will be denied"
