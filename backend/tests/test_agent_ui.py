import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

import app.db as db_module
from app.agent_ui import (
    DEFAULT_AGENT_UI,
    _CONTRAST_PAIRS,
    contrast_ratio,
    resolve_agent_ui,
    set_agent_ui,
    validate_agent_ui,
)
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


# ── Pure validation (no database) ─────────────────────────────────────────────

def test_the_shipped_defaults_satisfy_the_rules_they_enforce():
    """The defaults have to pass their own validator, or the very first save of
    an unchanged form would be rejected -- and every contrast pair would be
    asserting something the product itself violates."""
    assert validate_agent_ui(dict(DEFAULT_AGENT_UI)) == {}
    for fg, bg, minimum, description in _CONTRAST_PAIRS:
        ratio = contrast_ratio(DEFAULT_AGENT_UI[fg], DEFAULT_AGENT_UI[bg])
        assert ratio >= minimum, f"{description}: {ratio:.2f} < {minimum}"


def test_contrast_ratio_matches_the_wcag_reference_values():
    assert contrast_ratio("#FFFFFF", "#000000") == pytest.approx(21.0)
    assert contrast_ratio("#FFFFFF", "#FFFFFF") == pytest.approx(1.0)
    # Order must not matter: the pairs are declared foreground-first for
    # readability, not because the maths is directional.
    assert contrast_ratio("#1866F2", "#0B1120") == pytest.approx(
        contrast_ratio("#0B1120", "#1866F2")
    )


def test_only_the_differences_from_the_defaults_are_stored():
    """A company that never touched the heading must keep tracking the built-in
    rather than freezing a copy of whatever it was the day they first saved."""
    stored = validate_agent_ui({**DEFAULT_AGENT_UI, "heading": "Who is on this laptop?"})
    assert stored == {"heading": "Who is on this laptop?"}


def test_blank_means_restore_the_default_not_show_nothing():
    assert validate_agent_ui({"heading": "", "submit_label": "   "}) == {}


def test_hex_colours_are_normalised_to_upper_case():
    # Browsers submit #rrggbb lower-case from a colour picker; without this the
    # same colour would look like a change on every save.
    assert validate_agent_ui({"teal": "#00c2a8"}) == {}
    assert validate_agent_ui({"teal": "#00c2a9"}) == {"teal": "#00C2A9"}


def test_unreadable_combinations_are_refused_with_a_reason():
    with pytest.raises(ValueError) as exc:
        validate_agent_ui({"navy": "#FFFFFF"})
    message = str(exc.value)
    # The admin has to be able to tell WHICH pairing failed; a bare "invalid
    # colours" would leave them guessing across eleven inputs.
    assert "heading and input text on the window background" in message
    assert "#F4F7FF on #FFFFFF" in message


def test_contrast_is_checked_against_the_merged_palette():
    """Changing only the background still has to re-check every text colour
    that sits on it, none of which the admin touched."""
    with pytest.raises(ValueError):
        validate_agent_ui({"navy_sidebar": "#A4B3CC"})


@pytest.mark.parametrize("bad", [
    {"blue": "#FFF"},
    {"blue": "1866F2"},
    {"blue": "#1866F2FF"},
    {"blue": "rebeccapurple"},
])
def test_only_six_digit_hex_is_accepted(bad):
    # The agents parse these into GDI+/Tk colour types that have no alpha
    # channel here, so an 8-digit value would silently lose its transparency.
    with pytest.raises(ValueError, match="must be a colour like"):
        validate_agent_ui(bad)


def test_unknown_placeholders_are_refused():
    with pytest.raises(ValueError, match=r"\{name\}"):
        validate_agent_ui({"heading": "Hello {name}"})
    with pytest.raises(ValueError, match="unmatched"):
        validate_agent_ui({"heading": "Hello {name"})


def test_supported_placeholders_are_accepted_where_they_belong():
    assert validate_agent_ui({"subheading": "Just {count} to go."}) == {
        "subheading": "Just {count} to go."
    }
    # ...and refused where they do not: {count} means nothing in a message
    # shown after the form has already closed.
    with pytest.raises(ValueError, match=r"\{count\}"):
        validate_agent_ui({"success_message": "Done, {count}"})


def test_copy_too_long_for_the_window_is_refused():
    with pytest.raises(ValueError, match="room for 24"):
        validate_agent_ui({"submit_label": "x" * 25})


def test_unknown_keys_are_refused():
    with pytest.raises(ValueError, match="Unknown appearance setting"):
        validate_agent_ui({"font_size": "48"})


# ── Persistence ───────────────────────────────────────────────────────────────

async def test_an_unconfigured_company_resolves_to_the_defaults(db_pool, company):
    company_id, _ = company
    assert await resolve_agent_ui(db_pool, company_id) == DEFAULT_AGENT_UI


async def test_overrides_layer_over_the_defaults(db_pool, company):
    company_id, _ = company
    await set_agent_ui(db_pool, company_id, {"heading": "Whose Mac is this?", "teal": "#FF8A00"})
    resolved = await resolve_agent_ui(db_pool, company_id)
    assert resolved["heading"] == "Whose Mac is this?"
    assert resolved["teal"] == "#FF8A00"
    # Untouched keys still come from the built-ins, and the palette is always
    # complete so no agent ever has to merge.
    assert resolved["submit_label"] == DEFAULT_AGENT_UI["submit_label"]
    assert set(resolved) == set(DEFAULT_AGENT_UI)


async def test_saving_is_a_replace_so_a_cleared_box_reverts(db_pool, company):
    company_id, _ = company
    await set_agent_ui(db_pool, company_id, {"heading": "First"})
    await set_agent_ui(db_pool, company_id, {"cancel_label": "Not now"})
    resolved = await resolve_agent_ui(db_pool, company_id)
    assert resolved["heading"] == DEFAULT_AGENT_UI["heading"]
    assert resolved["cancel_label"] == "Not now"


async def test_a_rejected_save_stores_nothing(db_pool, company):
    company_id, _ = company
    await set_agent_ui(db_pool, company_id, {"heading": "Kept"})
    with pytest.raises(ValueError):
        await set_agent_ui(db_pool, company_id, {"heading": "Lost", "navy": "#FFFFFF"})
    assert (await resolve_agent_ui(db_pool, company_id))["heading"] == "Kept"


async def test_appearance_is_per_company(db_pool, company, admin):
    company_id, _ = company
    async with db_pool.acquire() as conn:
        other = await conn.fetchval(
            "INSERT INTO companies (name, api_key_hash, api_key_prefix, notification_email) "
            "VALUES ('Other', 'h', 'p', 'o@example.com') RETURNING id"
        )
    await set_agent_ui(db_pool, company_id, {"heading": "Only mine"})
    assert (await resolve_agent_ui(db_pool, str(other)))["heading"] == DEFAULT_AGENT_UI["heading"]


# ── The agent-facing endpoint ─────────────────────────────────────────────────

async def test_config_endpoint_serves_the_palette(db_pool, company):
    company_id, api_key = company
    await set_agent_ui(db_pool, company_id, {"heading": "Who is on this laptop?"})
    client = await _client()
    try:
        resp = await client.get(
            "/api/v1/inventory/config", headers={"Authorization": f"Bearer {api_key}"}
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    ui = resp.json()["ui"]
    assert ui["heading"] == "Who is on this laptop?"
    # Complete, not just the overrides -- an agent must never have to merge.
    assert set(ui) == set(DEFAULT_AGENT_UI)
    # Still the same single call that carries the fields and the schedule.
    assert "user_fields" in resp.json() and "schedule" in resp.json()


# ── The portal form ───────────────────────────────────────────────────────────

async def test_company_detail_shows_the_appearance_card(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.get(f"/admin/companies/{company_id}")
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"Agent window appearance" in resp.content
    assert b"no new download needed" in resp.content


async def test_saving_appearance_from_the_portal_reaches_the_agent(login_as, enrolled_admin, company, db_pool):
    company_id, api_key = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        detail = await client.get(f"/admin/companies/{company_id}")
        csrf_token = detail.text.split('name="csrf_token" value="')[1].split('"')[0]
        resp = await client.post(
            f"/admin/companies/{company_id}/appearance",
            # A purple that clears both bars this colour has to meet: 4.5:1
            # behind the button's white label and 3:1 as a focus ring on navy.
            # #7A1FA2 passes the first (7.7) and fails the second (2.3), which
            # is the kind of near-miss the validator exists to catch.
            data={"csrf_token": csrf_token, "heading": "Whose laptop?", "blue": "#9C3FBF"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        agent_view = await client.get(
            "/api/v1/inventory/config", headers={"Authorization": f"Bearer {api_key}"}
        )
    finally:
        await client.aclose()
    assert agent_view.json()["ui"]["heading"] == "Whose laptop?"
    assert agent_view.json()["ui"]["blue"] == "#9C3FBF"


async def test_a_rejected_palette_is_re_rendered_in_place_with_the_typed_values(login_as, enrolled_admin, company):
    """The admin's other nineteen hand-picked values must survive the error, or
    fixing one bad colour means retyping the whole palette."""
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        detail = await client.get(f"/admin/companies/{company_id}")
        csrf_token = detail.text.split('name="csrf_token" value="')[1].split('"')[0]
        resp = await client.post(
            f"/admin/companies/{company_id}/appearance",
            data={
                "csrf_token": csrf_token,
                "heading": "Kept in the form",
                "navy": "#FFFFFF",
            },
        )
    finally:
        await client.aclose()
    assert resp.status_code == 200
    assert b"hard or impossible to read" in resp.content
    assert b"Kept in the form" in resp.content
    assert b'value="#FFFFFF"' in resp.content


async def test_appearance_requires_a_valid_csrf_token(login_as, enrolled_admin, company):
    company_id, _ = company
    client = await _logged_in_client(login_as, enrolled_admin)
    try:
        resp = await client.post(
            f"/admin/companies/{company_id}/appearance",
            data={"csrf_token": "not-the-token", "heading": "Nope"},
        )
    finally:
        await client.aclose()
    assert resp.status_code == 403
