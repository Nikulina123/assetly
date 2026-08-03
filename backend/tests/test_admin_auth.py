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
