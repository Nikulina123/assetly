"""Operator script to assign an admin's role and company scope.

Usage:
    cd backend && source venv/bin/activate
    python3 -m scripts.set_admin_role --email admin@assetly.com --role admin --company-id global
    python3 -m scripts.set_admin_role --email support@assetly.com --role support --company-id 3c84ac54-f814-4124-880f-2bf3cfc05d3b

(Must be run as `-m scripts.set_admin_role`, not `scripts/set_admin_role.py`
directly — the latter puts scripts/ rather than backend/ on sys.path, so
`from app...` fails with ModuleNotFoundError. `-m` runs from the current
directory instead, which is backend/, where the `app` package actually
lives.)

Connects as the `admin` superuser role (not assetly — per migrations/016
the assetly app role holds only SELECT on admins plus a column-level UPDATE
grant on (mfa_secret, mfa_enrolled_at); it cannot write `role` or
`company_id`), since role and scope assignment is an operator action, not
something the running app does itself.

This is deliberate and load-bearing: THERE IS NO UI FOR THIS. Role and
company_id are the two columns that decide what an admin account can see and
do, so granting them only through an operator script run against the
database directly means a bug in the admin router -- a missing dependency,
a mis-wired form field -- can never be used to escalate an account's own
privileges. The admin console can display role and scope, but it can never
change them.
"""
import argparse
import asyncio
import sys
import uuid

import asyncpg

ROLE_CHOICES = ("admin", "support")


async def set_admin_role(
    database_url: str, email: str, role: str, company_id: str | None
) -> None:
    parsed_company_id = uuid.UUID(company_id) if company_id is not None else None
    conn = await asyncpg.connect(database_url)
    try:
        row = await conn.fetchrow(
            "UPDATE admins SET role = $1, company_id = $2 WHERE email = $3 "
            "RETURNING id, email, role, company_id",
            role, parsed_company_id, email,
        )
    finally:
        await conn.close()
    if row is None:
        print(f"No admin with email {email!r} exists.", file=sys.stderr)
        sys.exit(1)
    scope = row["company_id"] or "global"
    print(f"Set {row['email']}: role={row['role']} company_id={scope}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    parser.add_argument("--role", required=True, choices=ROLE_CHOICES)
    parser.add_argument(
        "--company-id",
        required=True,
        help='A company UUID to scope this admin to one tenant, or the literal '
             '"global" for company_id = NULL (sees every company).',
    )
    parser.add_argument(
        "--database-url",
        default="postgresql://admin@localhost:5432/webiz_checkin",
        help="Defaults to the local dev database via the admin superuser role.",
    )
    args = parser.parse_args()
    company_id = None if args.company_id == "global" else args.company_id
    asyncio.run(
        set_admin_role(args.database_url, args.email, args.role, company_id)
    )
