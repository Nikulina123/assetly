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


async def _logged_in_client(login_as, admin_tuple):
    client = await _client()
    await login_as(client, admin_tuple)
    return client


async def test_company_detail_shows_check_in_fields_section(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Check-in fields" in resp.content
    assert b"Coming soon" not in resp.content


async def test_update_hardware_fields_persists(login_as, enrolled_admin, company, db_pool):
    from app.field_config import resolve_field_config

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        # Submit with only "ram", "storage", "ip_address" checked (cpu unchecked)
        # and department left unchecked -> disabled.
        resp = await client.post(
            f"/admin/companies/{company_id}/fields/hardware",
            data={
                "csrf_token": csrf_token,
                "ram": "on",
                "storage": "on",
                "ip_address": "on",
            },
        )
    finally:
        await client.aclose()
    assert resp.status_code == 303

    config = await resolve_field_config(db_pool, company_id)
    assert config["hardware_fields"] == ["ram", "storage", "ip_address"]
    assert "department" not in [f["key"] for f in config["user_fields"]]


async def test_add_and_remove_custom_field_via_admin(login_as, enrolled_admin, company, db_pool):
    from app.field_config import resolve_field_config

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        add_resp = await client.post(
            f"/admin/companies/{company_id}/fields/custom",
            data={"csrf_token": csrf_token, "label": "Cost Center", "required": "on"},
        )
        assert add_resp.status_code == 303

        config = await resolve_field_config(db_pool, company_id)
        assert "cost_center" in [f["key"] for f in config["user_fields"]]

        remove_resp = await client.post(
            f"/admin/companies/{company_id}/fields/custom/cost_center/remove",
            data={"csrf_token": csrf_token},
        )
        assert remove_resp.status_code == 303
    finally:
        await client.aclose()

    config = await resolve_field_config(db_pool, company_id)
    assert "cost_center" not in [f["key"] for f in config["user_fields"]]


async def test_department_form_round_trips_through_admin_ui(login_as, enrolled_admin, company, db_pool):
    """Regression test for a silent-disable failure mode: the admin.py Form
    parameter names and the company_detail.html checkbox `name` attributes
    must match exactly (FastAPI binds form fields by name). If either side
    drifts -- e.g. the handler still expects "project_enabled" while the
    template posts "department_enabled" -- the handler silently receives
    None for both fields, treats that as unchecked, and every save disables
    the department field for that company with no error raised anywhere.

    This test also asserts on the rendered HTML of the company detail page,
    since a Jinja `field_settings['department_enabled']` key mismatch
    resolves to Undefined (falsy) rather than raising -- also silent.
    """
    from app.field_config import resolve_field_settings_for_admin

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        # Both department checkboxes checked.
        resp = await client.post(
            f"/admin/companies/{company_id}/fields/hardware",
            data={
                "csrf_token": csrf_token,
                "cpu": "on",
                "ram": "on",
                "storage": "on",
                "ip_address": "on",
                "department_enabled": "on",
                "department_required": "on",
            },
        )
        assert resp.status_code == 303

        settings = await resolve_field_settings_for_admin(db_pool, company_id)
        assert settings["department_enabled"] is True
        assert settings["department_required"] is True

        # The rendered page must post to the same names the handler reads,
        # and must reflect the enabled/required state as checked.
        detail_resp = await client.get(f"/admin/companies/{company_id}")
        detail_html = detail_resp.text
        assert 'name="department_enabled"' in detail_html
        assert 'name="department_required"' in detail_html
        dept_enabled_snippet = detail_html.split('name="department_enabled"')[1].split(">")[0]
        dept_required_snippet = detail_html.split('name="department_required"')[1].split(">")[0]
        assert "checked" in dept_enabled_snippet
        assert "checked" in dept_required_snippet

        # Both department checkboxes omitted (as a browser would send when unchecked).
        csrf_token = detail_html.split('name="csrf_token" value="')[1].split('"')[0]
        resp = await client.post(
            f"/admin/companies/{company_id}/fields/hardware",
            data={
                "csrf_token": csrf_token,
                "cpu": "on",
                "ram": "on",
                "storage": "on",
                "ip_address": "on",
            },
        )
        assert resp.status_code == 303
    finally:
        await client.aclose()

    settings = await resolve_field_settings_for_admin(db_pool, company_id)
    assert settings["department_enabled"] is False
    assert settings["department_required"] is False


async def test_department_options_round_trip_through_admin_ui(login_as, enrolled_admin, company, db_pool):
    """Same silent-drift risk as the checkboxes above: the textarea's `name`
    and admin.py's Form parameter must match, and the rendered page has to
    show the saved list back or an admin editing it would wipe it."""
    from app.field_config import DEFAULT_DEPARTMENT_OPTIONS, resolve_field_config

    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        assert 'name="department_options"' in get_resp.text
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            f"/admin/companies/{company_id}/fields/hardware",
            data={
                "csrf_token": csrf_token,
                "cpu": "on", "ram": "on", "storage": "on", "ip_address": "on",
                "department_enabled": "on",
                # Blank lines and stray whitespace are ordinary textarea input.
                "department_options": "Support\n  Engineering  \n\nFinance\n",
            },
        )
        assert resp.status_code == 303

        config = await resolve_field_config(db_pool, company_id)
        department = next(f for f in config["user_fields"] if f["key"] == "department")
        assert department["options"] == ["Support", "Engineering", "Finance"]

        # The saved list has to render back into the textarea.
        detail_html = (await client.get(f"/admin/companies/{company_id}")).text
        textarea_body = detail_html.split('name="department_options"')[1].split(">", 1)[1].split("</textarea>")[0]
        assert textarea_body.strip().splitlines() == ["Support", "Engineering", "Finance"]

        # Clearing the textarea restores the built-in list.
        csrf_token = detail_html.split('name="csrf_token" value="')[1].split('"')[0]
        resp = await client.post(
            f"/admin/companies/{company_id}/fields/hardware",
            data={
                "csrf_token": csrf_token,
                "cpu": "on", "ram": "on", "storage": "on", "ip_address": "on",
                "department_enabled": "on",
                "department_options": "",
            },
        )
        assert resp.status_code == 303
    finally:
        await client.aclose()

    config = await resolve_field_config(db_pool, company_id)
    department = next(f for f in config["user_fields"] if f["key"] == "department")
    assert department["options"] == DEFAULT_DEPARTMENT_OPTIONS


async def test_add_custom_field_with_reserved_label_shows_error(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        get_resp = await client.get(f"/admin/companies/{company_id}")
        csrf_token = get_resp.text.split('name="csrf_token" value="')[1].split('"')[0]

        resp = await client.post(
            f"/admin/companies/{company_id}/fields/custom",
            data={"csrf_token": csrf_token, "label": "CPU"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"reserved" in resp.content
