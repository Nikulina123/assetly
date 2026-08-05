import re
import uuid

import asyncpg

HARDWARE_FIELD_KEYS = ["cpu", "ram", "storage", "ip_address"]


async def resolve_field_config(pool: asyncpg.Pool, company_id: str) -> dict:
    """Resolves the effective, agent-facing field configuration for a company.

    Absence of a company_fields row for a given key means "default enabled".
    'department' additionally defaults to NOT required.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            rows = await conn.fetch(
                "SELECT field_key, field_type, label, enabled, required "
                "FROM company_fields WHERE company_id = $1 ORDER BY id",
                uuid.UUID(company_id),
            )

    # Flat by field_key across all field_type values — relies on add_custom_field
    # (below) rejecting any slug that collides with 'department' or a hardware key.
    # Nothing in this function itself prevents that collision.
    overrides = {row["field_key"]: row for row in rows}

    user_fields = [
        {"key": "first_name", "label": "First Name", "required": True, "locked": True},
        {"key": "last_name", "label": "Last Name", "required": True, "locked": True},
        {"key": "email", "label": "Email", "required": True, "locked": True},
    ]

    department_override = overrides.get("department")
    department_enabled = department_override["enabled"] if department_override else True
    if department_enabled:
        user_fields.append({
            "key": "department",
            "label": "Department",
            # Defaults to optional. Absence of an override row used to mean
            # "required" for the old project field; department is opt-in.
            "required": department_override["required"] if department_override else False,
            "locked": False,
        })

    for field_key, row in overrides.items():
        if row["field_type"] == "custom" and row["enabled"]:
            user_fields.append({
                "key": field_key,
                "label": row["label"],
                "required": row["required"],
                "locked": False,
            })

    hardware_fields = [
        key for key in HARDWARE_FIELD_KEYS
        if key not in overrides or overrides[key]["enabled"]
    ]

    return {"user_fields": user_fields, "hardware_fields": hardware_fields}


def slugify(label: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", label.strip().lower()).strip("_")


async def set_hardware_field_enabled(pool: asyncpg.Pool, company_id: str, field_key: str, enabled: bool) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                """
                INSERT INTO company_fields (company_id, field_key, field_type, label, enabled)
                VALUES ($1, $2, 'hardware', $2, $3)
                ON CONFLICT (company_id, field_key) DO UPDATE SET enabled = EXCLUDED.enabled
                """,
                uuid.UUID(company_id), field_key, enabled,
            )


async def set_department_config(pool: asyncpg.Pool, company_id: str, enabled: bool, required: bool) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                """
                INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required)
                VALUES ($1, 'department', 'department', 'Department', $2, $3)
                ON CONFLICT (company_id, field_key) DO UPDATE SET enabled = EXCLUDED.enabled, required = EXCLUDED.required
                """,
                uuid.UUID(company_id), enabled, required,
            )


_RESERVED_FIELD_KEYS = {"department"} | set(HARDWARE_FIELD_KEYS)


async def add_custom_field(pool: asyncpg.Pool, company_id: str, label: str, required: bool) -> str:
    field_key = slugify(label)
    if not field_key:
        # slugify only keeps [a-z0-9] — punctuation-only or non-Latin-script
        # labels (e.g. Georgian) collapse to "". Without this check the first
        # such label would silently insert field_key="", and a second would
        # hit the DB's UNIQUE constraint as an unhandled 500 instead of a
        # clean validation error.
        raise ValueError(f"{label!r} does not contain any usable characters for a field name")
    if field_key in _RESERVED_FIELD_KEYS:
        raise ValueError(
            f"{label!r} is a reserved field name (conflicts with a built-in or hardware field key)"
        )
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                """
                INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required)
                VALUES ($1, $2, 'custom', $3, true, $4)
                """,
                uuid.UUID(company_id), field_key, label, required,
            )
    return field_key


async def remove_custom_field(pool: asyncpg.Pool, company_id: str, field_key: str) -> None:
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "DELETE FROM company_fields WHERE company_id = $1 AND field_key = $2 AND field_type = 'custom'",
                uuid.UUID(company_id), field_key,
            )


async def resolve_field_settings_for_admin(pool: asyncpg.Pool, company_id: str) -> dict:
    """Admin-UI-friendly shape (distinct from the agent-facing resolve_field_config):
    hardware fields as {key, label, enabled} options, department as separate
    enabled/required flags, custom fields as a plain list."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            rows = await conn.fetch(
                "SELECT field_key, field_type, label, enabled, required "
                "FROM company_fields WHERE company_id = $1 ORDER BY id",
                uuid.UUID(company_id),
            )

    overrides = {row["field_key"]: row for row in rows}

    hardware_field_options = [
        {
            "key": key,
            "label": key.replace("_", " ").upper() if key == "ip_address" else key.upper(),
            "enabled": overrides[key]["enabled"] if key in overrides else True,
        }
        for key in HARDWARE_FIELD_KEYS
    ]

    department_override = overrides.get("department")
    department_enabled = department_override["enabled"] if department_override else True
    department_required = department_override["required"] if department_override else False

    custom_fields = [
        {"key": row["field_key"], "label": row["label"], "required": row["required"]}
        for row in rows
        if row["field_type"] == "custom"
    ]

    return {
        "hardware_field_options": hardware_field_options,
        "department_enabled": department_enabled,
        "department_required": department_required,
        "custom_fields": custom_fields,
    }
