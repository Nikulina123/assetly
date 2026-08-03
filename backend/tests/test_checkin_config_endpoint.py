import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.main import app

pytestmark = pytest.mark.asyncio


@pytest_asyncio.fixture(autouse=True)
async def _reset_app_pool():
    yield
    await db_module.close_pool()


async def _client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


async def test_config_requires_auth():
    async with await _client() as client:
        resp = await client.get("/api/v1/inventory/config")
    assert resp.status_code == 401


async def test_config_returns_defaults_for_fresh_company(company):
    _, api_key = company
    async with await _client() as client:
        resp = await client.get(
            "/api/v1/inventory/config", headers={"Authorization": f"Bearer {api_key}"}
        )
    assert resp.status_code == 200
    body = resp.json()
    assert [f["key"] for f in body["user_fields"]] == ["first_name", "last_name", "email", "project"]
    assert body["hardware_fields"] == ["cpu", "ram", "storage", "ip_address"]
