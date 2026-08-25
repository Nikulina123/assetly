import pytest

from app.admin_auth import hash_password, resolve_admin, verify_password

pytestmark = pytest.mark.asyncio


async def test_hash_password_produces_a_bcrypt_hash():
    password_hash = hash_password("correct-horse-battery-staple")
    assert password_hash.startswith("$2b$")
    assert password_hash != "correct-horse-battery-staple"


async def test_verify_password_accepts_the_correct_password():
    password_hash = hash_password("correct-horse-battery-staple")
    assert verify_password("correct-horse-battery-staple", password_hash) is True


async def test_verify_password_rejects_the_wrong_password():
    password_hash = hash_password("correct-horse-battery-staple")
    assert verify_password("wrong-password", password_hash) is False


async def test_resolve_admin_returns_id_for_correct_credentials(db_pool, admin):
    admin_id, email, password = admin
    resolved = await resolve_admin(db_pool, email, password)
    assert resolved == admin_id


async def test_resolve_admin_returns_none_for_wrong_password(db_pool, admin):
    _, email, _ = admin
    resolved = await resolve_admin(db_pool, email, "wrong-password")
    assert resolved is None


async def test_resolve_admin_returns_none_for_unknown_email(db_pool):
    resolved = await resolve_admin(db_pool, "nobody@example.com", "whatever")
    assert resolved is None


async def test_load_admin_context_defaults_for_a_pre_migration_admin(db_pool, admin):
    """The rollout case: a row that existed before 016 is a full, global,
    un-enrolled admin. If this ever changes, existing operators lose access."""
    from app.admin_auth import load_admin_context

    admin_id, email, _password = admin
    ctx = await load_admin_context(db_pool, admin_id)
    assert ctx is not None
    assert ctx.id == admin_id
    assert ctx.email == email
    assert ctx.role == "admin"
    assert ctx.company_id is None
    assert ctx.mfa_enrolled is False
    assert ctx.is_full_admin is True
    assert ctx.is_global is True


async def test_load_admin_context_returns_none_for_an_unknown_id(db_pool):
    """A signed cookie naming a deleted admin must not authenticate anyone."""
    from app.admin_auth import load_admin_context

    assert await load_admin_context(db_pool, "00000000-0000-0000-0000-000000000000") is None


async def test_load_admin_context_reads_role_and_scope(db_pool, support_admin):
    from app.admin_auth import load_admin_context

    admin_id, email, _password, _secret = support_admin
    ctx = await load_admin_context(db_pool, admin_id)
    assert ctx.role == "support"
    assert ctx.is_full_admin is False
    assert ctx.mfa_enrolled is True


async def test_set_and_get_mfa_secret_round_trip(db_pool, admin):
    from app.admin_auth import get_mfa_secret, set_mfa_secret
    from app import mfa

    admin_id, _email, _password = admin
    secret = mfa.generate_secret()
    async with db_pool.acquire() as conn:
        await set_mfa_secret(conn, admin_id, secret)
        stored = await conn.fetchval("SELECT mfa_secret FROM admins WHERE id = $1", admin_id)
        enrolled_at = await conn.fetchval(
            "SELECT mfa_enrolled_at FROM admins WHERE id = $1", admin_id
        )
    assert stored != secret, "the raw seed must never be written to the column"
    assert enrolled_at is not None
    assert await get_mfa_secret(db_pool, admin_id) == secret


async def test_get_mfa_secret_returns_none_when_the_stored_blob_is_unreadable(db_pool, admin):
    """A key rotation must force re-enrollment, not a 500 and not free access."""
    from app.admin_auth import get_mfa_secret

    admin_id, _email, _password = admin
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE admins SET mfa_secret = 'garbage', mfa_enrolled_at = NOW() WHERE id = $1",
            admin_id,
        )
    assert await get_mfa_secret(db_pool, admin_id) is None


async def test_recovery_codes_are_replaced_not_appended(db_pool, admin):
    from app.admin_auth import count_unused_recovery_codes, replace_recovery_codes
    from app import mfa

    admin_id, _email, _password = admin
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, mfa.generate_recovery_codes())
        await replace_recovery_codes(conn, admin_id, mfa.generate_recovery_codes())
    assert await count_unused_recovery_codes(db_pool, admin_id) == 10


async def test_a_recovery_code_works_exactly_once(db_pool, admin):
    from app.admin_auth import consume_recovery_code, count_unused_recovery_codes, replace_recovery_codes
    from app import mfa

    admin_id, _email, _password = admin
    codes = mfa.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, codes)
        assert await consume_recovery_code(conn, admin_id, codes[0]) is True
        assert await consume_recovery_code(conn, admin_id, codes[0]) is False
    assert await count_unused_recovery_codes(db_pool, admin_id) == 9


async def test_consume_recovery_code_rejects_an_unknown_code(db_pool, admin):
    from app.admin_auth import consume_recovery_code, replace_recovery_codes
    from app import mfa

    admin_id, _email, _password = admin
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, mfa.generate_recovery_codes())
        assert await consume_recovery_code(conn, admin_id, "aaaaa-bbbbb") is False


async def test_one_admins_recovery_code_does_not_work_for_another(db_pool, admin, support_admin):
    from app.admin_auth import consume_recovery_code, replace_recovery_codes
    from app import mfa

    admin_id, _e, _p = admin
    other_id, _e2, _p2, _s2 = support_admin
    codes = mfa.generate_recovery_codes()
    async with db_pool.acquire() as conn:
        await replace_recovery_codes(conn, admin_id, codes)
        assert await consume_recovery_code(conn, other_id, codes[0]) is False
