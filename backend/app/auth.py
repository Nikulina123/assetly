import hashlib
import secrets

import asyncpg


def generate_api_key() -> str:
    return "wz_live_" + secrets.token_hex(32)


def hash_api_key(api_key: str) -> str:
    return hashlib.sha256(api_key.encode()).hexdigest()


async def resolve_company_id(pool: asyncpg.Pool, api_key: str) -> str | None:
    key_hash = hash_api_key(api_key)
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id FROM companies WHERE api_key_hash = $1 AND revoked_at IS NULL",
            key_hash,
        )
    return str(row["id"]) if row else None
