import re
import uuid

import asyncpg

HARDWARE_FIELD_KEYS = ["cpu", "ram", "storage", "ip_address"]


def _department_override(rows: list) -> asyncpg.Record | None:
    """The built-in department setting, if the company configured one.

    Matches on field_type too, not just field_key: a *custom* field whose label
    slugged to 'department' (possible before 'department' became reserved) must
    never be mistaken for the built-in setting.
    """
    return next(
        (r for r in rows if r["field_key"] == "department" and r["field_type"] == "department"),
        None,
    )


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

    # Flat by field_key across all field_type values. add_custom_field (below)
    # rejects any slug that collides with 'department' or a hardware key for
    # rows created from now on, but legacy rows created before 'department' was
    # reserved can still have field_key='department' with field_type='custom'.
    # _department_override() and the reserved-key skip in the loop below both
    # guard against mistaking such a row for the built-in department setting.
    overrides = {row["field_key"]: row for row in rows}

    user_fields = [
        {"key": "first_name", "label": "First Name", "required": True, "locked": True},
        {"key": "last_name", "label": "Last Name", "required": True, "locked": True},
        {"key": "email", "label": "Email", "required": True, "locked": True},
    ]

    department_override = _department_override(rows)
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
            if field_key in _RESERVED_FIELD_KEYS:
                # Legacy data only: a custom field can only have a reserved
                # field_key if it was created before that key was reserved
                # (e.g. 'department' before this rename). The built-in field
                # wins here; an admin can clear the stray row via the existing
                # custom-field-remove endpoint.
                continue
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

    department_override = _department_override(rows)
    department_enabled = department_override["enabled"] if department_override else True
    department_required = department_override["required"] if department_override else False

    custom_fields = [
        {"key": row["field_key"], "label": row["label"], "required": row["required"]}
        for row in rows
        # Excludes legacy rows only: a custom field can only have a reserved
        # field_key (e.g. 'department') if it was created before that key was
        # reserved. The built-in field wins; an admin can clear the stray row
        # via the existing custom-field-remove endpoint.
        if row["field_type"] == "custom" and row["field_key"] not in _RESERVED_FIELD_KEYS
    ]

    return {
        "hardware_field_options": hardware_field_options,
        "department_enabled": department_enabled,
        "department_required": department_required,
        "custom_fields": custom_fields,
    }
