import re

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


async def _logged_in_client(email, password):
    client = await _client()
    await client.post("/admin/login", data={"email": email, "password": password})
    return client


async def _get_csrf_token(client, company_id):
    resp = await client.get(f"/admin/companies/{company_id}")
    return resp.text.split('name="csrf_token" value="')[1].split('"')[0]


async def test_download_macos_requires_login(company):
    company_id, _ = company
    async with await _client() as client:
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": "irrelevant"},
            follow_redirects=False,
        )
    assert resp.status_code == 303


async def test_download_macos_rotates_key_and_embeds_new_one(admin, company, db_pool):
    from app.auth import resolve_company_id

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")
    body = resp.text
    assert "APPS_SCRIPT_URL" not in body
    assert 'CHECKIN_API_URL="https://api.example.com/api/v1/inventory/checkin"' in body

    match = re.search(r'COMPANY_API_KEY="(as_live_[a-f0-9]+)"', body)
    assert match is not None, "no COMPANY_API_KEY found in downloaded script"
    new_api_key = match.group(1)
    assert new_api_key != old_api_key

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved is None
    new_resolved = await resolve_company_id(db_pool, new_api_key)
    assert new_resolved == company_id


async def test_download_linux_contains_a_fresh_key(admin, company, db_pool):
    from app.auth import resolve_company_id

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/linux",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    body = resp.text
    assert "APPS_SCRIPT_URL" not in body
    match = re.search(r'COMPANY_API_KEY="(as_live_[a-f0-9]+)"', body)
    assert match is not None
    new_api_key = match.group(1)
    assert new_api_key != old_api_key

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved is None
    new_resolved = await resolve_company_id(db_pool, new_api_key)
    assert new_resolved == company_id


async def test_download_blocked_for_revoked_company(admin, company, db_pool):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        # Fetch the CSRF token BEFORE revoking, so this test isolates "is the
        # download blocked for a revoked company" from any side effect of
        # revocation on CSRF/detail-page rendering.
        csrf_token = await _get_csrf_token(client, company_id)

        async with db_pool.acquire() as conn:
            await conn.execute("UPDATE companies SET revoked_at = NOW() WHERE id = $1", company_id)

        resp = await client.post(
            f"/admin/companies/{company_id}/download/macos",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 404


async def test_download_without_csrf_token_is_rejected(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.post(f"/admin/companies/{company_id}/download/macos", data={})
    finally:
        await client.aclose()
    assert resp.status_code == 422


async def test_download_windows_without_exe_returns_clear_error(admin, company, monkeypatch):
    from pathlib import Path

    import app.routers.admin as admin_module

    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", Path("/nonexistent/AssetlyAgent_Windows.exe"))

    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 503


async def test_download_windows_zips_placeholder_exe_and_config(admin, company, db_pool, tmp_path, monkeypatch):
    import io
    import json
    import zipfile

    import app.routers.admin as admin_module
    from app.auth import resolve_company_id

    placeholder = tmp_path / "AssetlyAgent_Windows.exe"
    placeholder.write_bytes(b"PLACEHOLDER-EXE-BYTES-NOT-A-REAL-BINARY")
    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", placeholder)

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert "attachment" in resp.headers.get("content-disposition", "")

    zf = zipfile.ZipFile(io.BytesIO(resp.content))
    names = zf.namelist()
    assert "AssetlyAgent_Windows.exe" in names
    assert "config.json" in names
    assert zf.read("AssetlyAgent_Windows.exe") == b"PLACEHOLDER-EXE-BYTES-NOT-A-REAL-BINARY"

    config = json.loads(zf.read("config.json"))
    new_api_key = config["company_api_key"]
    assert new_api_key.startswith("as_live_")
    assert new_api_key != old_api_key
    assert config["checkin_api_url"] == "https://api.example.com/api/v1/inventory/checkin"

    old_resolved = await resolve_company_id(db_pool, old_api_key)
    assert old_resolved is None
    new_resolved = await resolve_company_id(db_pool, new_api_key)
    assert new_resolved == company_id


async def test_download_windows_does_not_rotate_key_when_exe_missing(admin, company, db_pool, monkeypatch):
    """The exe-missing check must happen BEFORE key rotation -- verify the
    old key still resolves after a 503, proving nothing was rotated."""
    from pathlib import Path

    import app.routers.admin as admin_module
    from app.auth import resolve_company_id

    monkeypatch.setattr(admin_module, "WINDOWS_EXE_PATH", Path("/nonexistent/AssetlyAgent_Windows.exe"))

    _, email, password = admin
    company_id, old_api_key = company
    client = await _logged_in_client(email, password)
    try:
        csrf_token = await _get_csrf_token(client, company_id)
        resp = await client.post(
            f"/admin/companies/{company_id}/download/windows",
            data={"csrf_token": csrf_token},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 503

    resolved = await resolve_company_id(db_pool, old_api_key)
    assert resolved == company_id


async def test_company_detail_shows_download_buttons(admin, company):
    _, email, password = admin
    company_id, _ = company
    client = await _logged_in_client(email, password)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Download for macOS" in resp.content
    assert b"Download for Linux" in resp.content
    assert b"Download for Windows" in resp.content
    assert b"Not yet available" not in resp.content
    assert b"generates a new API key" in resp.content.lower() or b"invalidat" in resp.content.lower()
