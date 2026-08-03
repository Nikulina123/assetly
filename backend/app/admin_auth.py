import bcrypt
import asyncpg


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode(), password_hash.encode())


async def resolve_admin(pool: asyncpg.Pool, email: str, password: str) -> str | None:
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id, password_hash FROM admins WHERE email = $1", email
        )
    if row is None:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return str(row["id"])
