import uuid

import asyncpg

HARDWARE_FIELD_KEYS = ["cpu", "ram", "storage", "ip_address"]


async def resolve_field_config(pool: asyncpg.Pool, company_id: str) -> dict:
    """Resolves the effective, agent-facing field configuration for a company.

    Absence of a company_fields row for a given key means "default enabled"
    (and, for 'project', also "default required") — see design doc for why.
    """
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            rows = await conn.fetch(
                "SELECT field_key, field_type, label, enabled, required "
                "FROM company_fields WHERE company_id = $1 ORDER BY id",
                uuid.UUID(company_id),
            )

    overrides = {row["field_key"]: row for row in rows}

    user_fields = [
        {"key": "first_name", "label": "First Name", "required": True, "locked": True},
        {"key": "last_name", "label": "Last Name", "required": True, "locked": True},
        {"key": "email", "label": "Email", "required": True, "locked": True},
    ]

    project_override = overrides.get("project")
    project_enabled = project_override["enabled"] if project_override else True
    if project_enabled:
        user_fields.append({
            "key": "project",
            "label": "Project",
            "required": project_override["required"] if project_override else True,
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
