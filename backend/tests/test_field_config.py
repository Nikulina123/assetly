import pytest

from app.field_config import resolve_field_config
from app.field_config import (
    add_custom_field,
    remove_custom_field,
    resolve_field_settings_for_admin,
    set_department_config,
    set_hardware_field_enabled,
    slugify,
)

pytestmark = pytest.mark.asyncio


async def test_fresh_company_gets_all_defaults(db_pool, company):
    company_id, _ = company
    config = await resolve_field_config(db_pool, company_id)

    keys = [f["key"] for f in config["user_fields"]]
    assert keys == ["first_name", "last_name", "email", "department"]
    assert all(f["required"] for f in config["user_fields"][:3])
    assert config["user_fields"][3]["required"] is False  # department defaults to optional
    assert config["user_fields"][0]["locked"] is True
    assert config["user_fields"][3]["locked"] is False  # department is toggleable

    assert config["hardware_fields"] == ["cpu", "ram", "storage", "ip_address"]


async def test_disabled_hardware_field_is_excluded(db_pool, company):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled) "
                "VALUES ($1, 'cpu', 'hardware', 'cpu', false)",
                company_id,
            )
    config = await resolve_field_config(db_pool, company_id)
    assert "cpu" not in config["hardware_fields"]
    assert config["hardware_fields"] == ["ram", "storage", "ip_address"]


async def test_department_disabled_is_excluded_from_user_fields(db_pool, company):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'department', 'department', 'Department', false, false)",
                company_id,
            )
    config = await resolve_field_config(db_pool, company_id)
    keys = [f["key"] for f in config["user_fields"]]
    assert "department" not in keys


async def test_department_defaults_to_optional(db_pool, company):
    """With no company_fields override row, department is offered but not
    required. This is a deliberate change from the old project default."""
    company_id, _ = company
    config = await resolve_field_config(db_pool, company_id)
    department = next(f for f in config["user_fields"] if f["key"] == "department")
    assert department["label"] == "Department"
    assert department["required"] is False


async def test_department_required_when_configured(db_pool, company):
    company_id, _ = company
    await set_department_config(db_pool, company_id, enabled=True, required=True)
    config = await resolve_field_config(db_pool, company_id)
    department = next(f for f in config["user_fields"] if f["key"] == "department")
    assert department["required"] is True


async def test_legacy_custom_department_field_does_not_duplicate_builtin(db_pool, company):
    """Before 'department' was reserved, add_custom_field would happily create
    a *custom* field whose label slugged to 'department' (field_type='custom').
    That row can no longer be created through add_custom_field (it's the whole
    point of reserving the key), but existing rows from before this rename can
    still be sitting in the table. resolve_field_config must not surface that
    legacy row as a second 'department' entry alongside the built-in one, and
    resolve_field_settings_for_admin must not list it under custom_fields."""
    company_id, _ = company
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'department', 'custom', 'Legacy Dept', true, true)",
                company_id,
            )

    config = await resolve_field_config(db_pool, company_id)
    department_entries = [f for f in config["user_fields"] if f["key"] == "department"]
    assert len(department_entries) == 1
    assert department_entries[0]["label"] == "Department"
    assert department_entries[0]["required"] is False

    settings = await resolve_field_settings_for_admin(db_pool, company_id)
    assert "department" not in [f["key"] for f in settings["custom_fields"]]


async def test_enabled_custom_field_is_included_in_order(db_pool, company):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'cost_center', 'custom', 'Cost Center', true, true)",
                company_id,
            )
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'asset_tag', 'custom', 'Asset Tag', true, false)",
                company_id,
            )
    config = await resolve_field_config(db_pool, company_id)
    custom = [f for f in config["user_fields"] if f["key"] in ("cost_center", "asset_tag")]
    assert custom == [
        {"key": "cost_center", "label": "Cost Center", "required": True, "locked": False},
        {"key": "asset_tag", "label": "Asset Tag", "required": False, "locked": False},
    ]


def test_slugify_lowercases_and_replaces_non_alnum():
    assert slugify("Department") == "department"
    assert slugify("Asset Tag #") == "asset_tag"
    assert slugify("  Cost Center  ") == "cost_center"


async def test_set_hardware_field_enabled_persists(db_pool, company):
    company_id, _ = company
    await set_hardware_field_enabled(db_pool, company_id, "cpu", False)
    config = await resolve_field_config(db_pool, company_id)
    assert "cpu" not in config["hardware_fields"]

    await set_hardware_field_enabled(db_pool, company_id, "cpu", True)
    config = await resolve_field_config(db_pool, company_id)
    assert "cpu" in config["hardware_fields"]


async def test_set_department_config_persists(db_pool, company):
    company_id, _ = company
    await set_department_config(db_pool, company_id, enabled=True, required=False)
    config = await resolve_field_config(db_pool, company_id)
    department = next(f for f in config["user_fields"] if f["key"] == "department")
    assert department["required"] is False

    await set_department_config(db_pool, company_id, enabled=False, required=False)
    config = await resolve_field_config(db_pool, company_id)
    assert "department" not in [f["key"] for f in config["user_fields"]]


async def test_add_and_remove_custom_field(db_pool, company):
    company_id, _ = company
    field_key = await add_custom_field(db_pool, company_id, "Cost Center", required=True)
    assert field_key == "cost_center"

    config = await resolve_field_config(db_pool, company_id)
    assert "cost_center" in [f["key"] for f in config["user_fields"]]

    await remove_custom_field(db_pool, company_id, field_key)
    config = await resolve_field_config(db_pool, company_id)
    assert "cost_center" not in [f["key"] for f in config["user_fields"]]


async def test_add_custom_field_duplicate_label_raises_unique_violation(db_pool, company):
    import asyncpg

    company_id, _ = company
    await add_custom_field(db_pool, company_id, "Cost Center", required=True)
    with pytest.raises(asyncpg.UniqueViolationError):
        await add_custom_field(db_pool, company_id, "Cost Center", required=False)


async def test_add_custom_field_rejects_reserved_key(db_pool, company):
    company_id, _ = company
    with pytest.raises(ValueError, match="reserved"):
        await add_custom_field(db_pool, company_id, "CPU", required=False)
    with pytest.raises(ValueError, match="reserved"):
        await add_custom_field(db_pool, company_id, "Department", required=False)


async def test_resolve_field_settings_for_admin_shape(db_pool, company):
    company_id, _ = company
    await set_hardware_field_enabled(db_pool, company_id, "cpu", False)
    await add_custom_field(db_pool, company_id, "Cost Center", required=True)

    settings = await resolve_field_settings_for_admin(db_pool, company_id)
    hw_by_key = {f["key"]: f for f in settings["hardware_field_options"]}
    assert hw_by_key["cpu"]["enabled"] is False
    assert hw_by_key["ram"]["enabled"] is True
    assert settings["department_enabled"] is True
    assert settings["department_required"] is False
    assert settings["custom_fields"] == [
        {"key": "cost_center", "label": "Cost Center", "required": True}
    ]


def test_slugify_punctuation_only_label_produces_empty_string():
    assert slugify("???") == ""
    assert slugify("   ") == ""
    assert slugify("ąćę") == ""  # non a-z0-9 script collapses to nothing


async def test_add_custom_field_rejects_unusable_label(db_pool, company):
    company_id, _ = company
    with pytest.raises(ValueError, match="usable characters"):
        await add_custom_field(db_pool, company_id, "???", required=False)
    with pytest.raises(ValueError, match="usable characters"):
        await add_custom_field(db_pool, company_id, "ąćę", required=False)
