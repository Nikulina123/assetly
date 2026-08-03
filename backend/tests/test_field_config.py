import pytest

from app.field_config import resolve_field_config

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
