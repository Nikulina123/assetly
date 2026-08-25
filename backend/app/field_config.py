import re
import uuid

import asyncpg

HARDWARE_FIELD_KEYS = ["cpu", "ram", "storage", "ip_address"]

# What the department dropdown offers when a company has never edited the list.
# Kept byte-for-byte in sync with DEFAULT_DEPARTMENT_OPTIONS in
# inventory_agent.py and $DefaultDepartments in AssetlyAgent_Windows.ps1, which
# are the fallbacks each agent uses when it cannot reach this endpoint.
#
# One neutral value on purpose. This list used to hold one early customer's
# real department names, so every company that had never opened the field
# editor served that customer's org chart to its own employees. A company that
# wants real options sets them in the portal; nothing is leaked in the meantime.
# Never empty: a required department field with no options cannot be submitted.
DEFAULT_DEPARTMENT_OPTIONS = ["Other"]


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


def _department_options(department_override: asyncpg.Record | None) -> list[str]:
    """The configured dropdown values, or the built-in list.

    NULL (never configured) and an empty array are treated alike on purpose:
    set_department_config refuses to store an empty list, but a row could still
    hold one from a direct DB edit, and a dropdown an employee cannot pick any
    value from would block check-in entirely on a required field.
    """
    if department_override is None:
        return list(DEFAULT_DEPARTMENT_OPTIONS)
    return list(department_override["options"] or DEFAULT_DEPARTMENT_OPTIONS)


async def resolve_field_config(pool: asyncpg.Pool, company_id: str) -> dict:
    """Resolves the effective, agent-facing field configuration for a company.

    Absence of a company_fields row for a given key means "default enabled".
    'department' additionally defaults to NOT required.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            rows = await conn.fetch(
                "SELECT field_key, field_type, label, enabled, required, options "
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
            # Only the department entry carries this. A custom field with an
            # "options" key would read to an agent as a dropdown with nothing
            # in it, so the loop below deliberately never adds one.
            "options": _department_options(department_override),
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


async def set_hardware_field_enabled(
    pool: asyncpg.Pool, company_id: str, field_key: str, enabled: bool, conn=None
) -> None:
    """`conn`, when given, is used directly instead of acquiring a new one --
    see app/enrollment.py's create_enrollment_token for why."""
    async def _write(c):
        await c.execute("SELECT set_config('app.company_id', $1, true)", company_id)
        await c.execute(
            """
            INSERT INTO company_fields (company_id, field_key, field_type, label, enabled)
            VALUES ($1, $2, 'hardware', $2, $3)
            ON CONFLICT (company_id, field_key) DO UPDATE SET enabled = EXCLUDED.enabled
            """,
            uuid.UUID(company_id), field_key, enabled,
        )

    if conn is not None:
        await _write(conn)
    else:
        async with pool.acquire() as acquired:
            async with acquired.transaction():
                await _write(acquired)


def normalize_department_options(options: list[str]) -> list[str]:
    """Trims, drops blanks, and de-duplicates while preserving order.

    The portal collects these as free text, one per line, so trailing spaces
    and accidental repeats are ordinary input rather than an error worth
    rejecting a whole form over. Order is preserved because it is the order the
    dropdown shows, which admins set deliberately (commonest department first).
    """
    seen: dict[str, None] = {}
    for option in options:
        cleaned = option.strip()
        if cleaned:
            seen.setdefault(cleaned, None)
    return list(seen)


async def set_department_config(
    pool: asyncpg.Pool,
    company_id: str,
    enabled: bool,
    required: bool,
    options: list[str] | None = None,
    conn=None,
) -> None:
    """Writes the department settings. `options=None` means "leave the saved
    list alone", which is not the same as an empty list: the enabled/required
    checkboxes are edited through the same form, so a caller that has nothing
    to say about the options must not silently reset them. An empty list, by
    contrast, is an explicit clear, and stores NULL so the built-in defaults
    apply again (see _department_options).

    `conn`, when given, is used directly instead of acquiring a new one --
    see app/enrollment.py's create_enrollment_token for why."""
    stored_options = normalize_department_options(options) if options is not None else None

    async def _write(c):
        await c.execute("SELECT set_config('app.company_id', $1, true)", company_id)
        await c.execute(
            """
            INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required, options)
            VALUES ($1, 'department', 'department', 'Department', $2, $3, $4)
            ON CONFLICT (company_id, field_key) DO UPDATE SET
                enabled  = EXCLUDED.enabled,
                required = EXCLUDED.required,
                -- Not COALESCE: that cannot tell "caller passed nothing"
                -- from "caller cleared the list", and the two have to
                -- write different values here.
                options  = CASE WHEN $5 THEN EXCLUDED.options ELSE company_fields.options END
            """,
            uuid.UUID(company_id), enabled, required,
            stored_options or None, options is not None,
        )

    if conn is not None:
        await _write(conn)
    else:
        async with pool.acquire() as acquired:
            async with acquired.transaction():
                await _write(acquired)


_RESERVED_FIELD_KEYS = {"department"} | set(HARDWARE_FIELD_KEYS)


async def add_custom_field(
    pool: asyncpg.Pool, company_id: str, label: str, required: bool, conn=None
) -> str:
    """`conn`, when given, is used directly instead of acquiring a new one --
    see app/enrollment.py's create_enrollment_token for why."""
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

    async def _write(c):
        await c.execute("SELECT set_config('app.company_id', $1, true)", company_id)
        await c.execute(
            """
            INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required)
            VALUES ($1, $2, 'custom', $3, true, $4)
            """,
            uuid.UUID(company_id), field_key, label, required,
        )

    if conn is not None:
        await _write(conn)
    else:
        async with pool.acquire() as acquired:
            async with acquired.transaction():
                await _write(acquired)
    return field_key


async def remove_custom_field(
    pool: asyncpg.Pool, company_id: str, field_key: str, conn=None
) -> None:
    """`conn`, when given, is used directly instead of acquiring a new one --
    see app/enrollment.py's create_enrollment_token for why."""
    async def _write(c):
        await c.execute("SELECT set_config('app.company_id', $1, true)", company_id)
        await c.execute(
            "DELETE FROM company_fields WHERE company_id = $1 AND field_key = $2 AND field_type = 'custom'",
            uuid.UUID(company_id), field_key,
        )

    if conn is not None:
        await _write(conn)
    else:
        async with pool.acquire() as acquired:
            async with acquired.transaction():
                await _write(acquired)


async def resolve_field_settings_for_admin(pool: asyncpg.Pool, company_id: str) -> dict:
    """Admin-UI-friendly shape (distinct from the agent-facing resolve_field_config):
    hardware fields as {key, label, enabled} options, department as separate
    enabled/required flags, custom fields as a plain list."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            rows = await conn.fetch(
                "SELECT field_key, field_type, label, enabled, required, options "
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
        "department_options": _department_options(department_override),
        "custom_fields": custom_fields,
    }
