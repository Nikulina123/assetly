import pytest

from app.field_config import resolve_field_config
from app.field_config import (
    add_custom_field,
    remove_custom_field,
    resolve_field_settings_for_admin,
    set_hardware_field_enabled,
    set_project_config,
    slugify,
)

pytestmark = pytest.mark.asyncio


async def test_fresh_company_gets_all_defaults(db_pool, company):
    company_id, _ = company
    config = await resolve_field_config(db_pool, company_id)

    keys = [f["key"] for f in config["user_fields"]]
    assert keys == ["first_name", "last_name", "email", "project"]
    assert all(f["required"] for f in config["user_fields"])
    assert config["user_fields"][0]["locked"] is True
    assert config["user_fields"][3]["locked"] is False  # project is toggleable

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


async def test_project_disabled_is_excluded_from_user_fields(db_pool, company):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'project', 'project', 'Project', false, false)",
                company_id,
            )
    config = await resolve_field_config(db_pool, company_id)
    keys = [f["key"] for f in config["user_fields"]]
    assert "project" not in keys


async def test_enabled_custom_field_is_included_in_order(db_pool, company):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'department', 'custom', 'Department', true, true)",
                company_id,
            )
            await conn.execute(
                "INSERT INTO company_fields (company_id, field_key, field_type, label, enabled, required) "
                "VALUES ($1, 'asset_tag', 'custom', 'Asset Tag', true, false)",
                company_id,
            )
    config = await resolve_field_config(db_pool, company_id)
    custom = [f for f in config["user_fields"] if f["key"] in ("department", "asset_tag")]
    assert custom == [
        {"key": "department", "label": "Department", "required": True, "locked": False},
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


async def test_set_project_config_persists(db_pool, company):
    company_id, _ = company
    await set_project_config(db_pool, company_id, enabled=True, required=False)
    config = await resolve_field_config(db_pool, company_id)
    project = next(f for f in config["user_fields"] if f["key"] == "project")
    assert project["required"] is False

    await set_project_config(db_pool, company_id, enabled=False, required=False)
    config = await resolve_field_config(db_pool, company_id)
    assert "project" not in [f["key"] for f in config["user_fields"]]


async def test_add_and_remove_custom_field(db_pool, company):
    company_id, _ = company
    field_key = await add_custom_field(db_pool, company_id, "Department", required=True)
    assert field_key == "department"

    config = await resolve_field_config(db_pool, company_id)
    assert "department" in [f["key"] for f in config["user_fields"]]

    await remove_custom_field(db_pool, company_id, field_key)
    config = await resolve_field_config(db_pool, company_id)
    assert "department" not in [f["key"] for f in config["user_fields"]]


async def test_add_custom_field_duplicate_label_raises_unique_violation(db_pool, company):
    import asyncpg

    company_id, _ = company
    await add_custom_field(db_pool, company_id, "Department", required=True)
    with pytest.raises(asyncpg.UniqueViolationError):
        await add_custom_field(db_pool, company_id, "Department", required=False)


async def test_add_custom_field_rejects_reserved_key(db_pool, company):
    company_id, _ = company
    with pytest.raises(ValueError, match="reserved"):
        await add_custom_field(db_pool, company_id, "CPU", required=False)
    with pytest.raises(ValueError, match="reserved"):
        await add_custom_field(db_pool, company_id, "Project", required=False)


async def test_resolve_field_settings_for_admin_shape(db_pool, company):
    company_id, _ = company
    await set_hardware_field_enabled(db_pool, company_id, "cpu", False)
    await add_custom_field(db_pool, company_id, "Department", required=True)

    settings = await resolve_field_settings_for_admin(db_pool, company_id)
    hw_by_key = {f["key"]: f for f in settings["hardware_field_options"]}
    assert hw_by_key["cpu"]["enabled"] is False
    assert hw_by_key["ram"]["enabled"] is True
    assert settings["project_enabled"] is True
    assert settings["project_required"] is True
    assert settings["custom_fields"] == [
        {"key": "department", "label": "Department", "required": True}
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
