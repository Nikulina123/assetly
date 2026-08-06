import pytest
from app.auth import generate_api_key, hash_api_key, resolve_company_id

pytestmark = pytest.mark.asyncio


async def test_generate_api_key_has_expected_prefix_and_length():
    key = generate_api_key()
    assert key.startswith("as_live_")
    assert len(key) == len("as_live_") + 64  # 32 bytes hex-encoded


async def test_hash_api_key_is_deterministic_sha256():
    key = "as_live_abc123"
    assert hash_api_key(key) == hash_api_key(key)
    assert len(hash_api_key(key)) == 64


async def test_resolve_company_id_returns_id_for_valid_key(db_pool, company):
    company_id, api_key = company
    resolved = await resolve_company_id(db_pool, api_key)
    assert resolved == company_id


async def test_resolve_company_id_returns_none_for_unknown_key(db_pool):
    resolved = await resolve_company_id(db_pool, "as_live_doesnotexist")
    assert resolved is None


async def test_resolve_company_id_returns_none_for_revoked_key(db_pool, company):
    company_id, api_key = company
    async with db_pool.acquire() as conn:
        await conn.execute(
            "UPDATE companies SET revoked_at = NOW() WHERE id = $1", company_id
        )
    resolved = await resolve_company_id(db_pool, api_key)
    assert resolved is None
