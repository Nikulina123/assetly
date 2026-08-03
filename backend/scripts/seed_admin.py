"""One-off script to create the first admin account.

Usage:
    cd backend && source venv/bin/activate
    python3 -m scripts.seed_admin --email admin@webiz.com --password 'a-strong-password'

(Must be run as `-m scripts.seed_admin`, not `scripts/seed_admin.py` directly —
the latter puts scripts/ rather than backend/ on sys.path, so `from app...`
fails with ModuleNotFoundError. `-m` runs from the current directory instead,
which is backend/, where the `app` package actually lives.)

Connects as the `admin` superuser role (not webiz_app — webiz_app only has
SELECT on the admins table, per migrations/002_admin_auth.sql), since account
creation is an operator action, not something the running app does itself.
"""
import argparse
import asyncio
import sys

import asyncpg

from app.admin_auth import hash_password


async def create_admin(database_url: str, email: str, password: str) -> None:
    conn = await asyncpg.connect(database_url)
    try:
        await conn.execute(
            "INSERT INTO admins (email, password_hash) VALUES ($1, $2)",
            email, hash_password(password),
        )
    except asyncpg.UniqueViolationError:
        print(f"An admin with email {email!r} already exists.", file=sys.stderr)
        sys.exit(1)
    finally:
        await conn.close()
    print(f"Created admin account: {email}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    parser.add_argument("--password", required=True)
    parser.add_argument(
        "--database-url",
        default="postgresql://admin@localhost:5432/webiz_checkin",
        help="Defaults to the local dev database via the admin superuser role.",
    )
    args = parser.parse_args()
    asyncio.run(create_admin(args.database_url, args.email, args.password))
