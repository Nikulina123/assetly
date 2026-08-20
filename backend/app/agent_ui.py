"""Per-company appearance for the agent check-in window.

Copy and colours only. Layout metrics are deliberately not configurable: the
agents' row/column arithmetic is interdependent, so a bad value there produces
overlapping or clipped controls rather than a merely ugly window, and unlike a
colour there is no cheap machine check for "this still fits".

The parsing/validation half is free of database access so it is testable
without a fixture -- the same split app/schedule.py and app/device_status.py
use. Only resolve_agent_ui/set_agent_ui touch Postgres.

WHY CONTRAST IS ENFORCED HERE, ON THE WRITE PATH
An admin picking colours in a portal form cannot see the result until an
employee's machine next checks in, and that employee has no way to undo it.
Unreadable text therefore has to be impossible to save, not merely
discouraged -- so validate_agent_ui rejects the whole submission rather than
clamping values, which would silently save something other than what the admin
typed. The agents re-check shape (never trusting a 200 OK) but deliberately do
not re-check contrast: that would put the WCAG maths in three codebases where
only this one can report the failure to whoever caused it.
"""

import re
import uuid

import asyncpg

# ── Built-in appearance ───────────────────────────────────────────────────────
# The single authority for "what the window looks like unconfigured". Mirrored
# as each agent's offline fallback ($DefaultAgentUi in AssetlyAgent_Windows.ps1,
# DEFAULT_AGENT_UI in inventory_agent.py) for when this endpoint is
# unreachable. Keep the three in sync when editing.
DEFAULT_AGENT_UI = {
    # Copy. {count} and {first_name} below are the only placeholders allowed;
    # see _PLACEHOLDERS.
    "window_title": "Assetly Inventory Agent",
    "heading": "Who's using this computer?",
    "subheading": "{count} fields, then you're done.",
    # A separate key rather than a plural rule: the agents would each need
    # their own copy of that rule, and it is wrong in most languages anyway.
    "subheading_one": "{count} field, then you're done.",
    "rail_title": "THIS DEVICE",
    "rail_footnote": "Sent to your IT team along with the answers on the right.",
    "submit_label": "Send check-in",
    "cancel_label": "Cancel",
    "success_message": "Thank you, {first_name}!\n\nYour device has been registered.",

    # Colours. Every value is #RRGGBB -- no shorthand, no alpha: the agents
    # parse these into platform colour types (GDI+ / Tk) that have no alpha
    # channel here, so accepting one would silently drop it.
    "navy": "#0B1120",           # window background
    "navy_sidebar": "#080E1A",   # device rail background
    "navy_mid": "#0F1829",       # input fill
    "blue": "#1866F2",           # primary button, focus ring
    "blue_hover": "#1560E6",
    "teal": "#00C2A8",           # accent: rail title, required marker
    "slate": "#A4B3CC",          # secondary text
    "label": "#92A3BE",          # field labels, rail keys
    "white": "#F4F7FF",          # primary text
    "border_md": "#5A6E99",      # secondary button outline
    "border_input": "#526691",   # input outline at rest
}

COPY_KEYS = {
    "window_title": 60,
    "heading": 80,
    "subheading": 90,
    "subheading_one": 90,
    "rail_title": 24,
    "rail_footnote": 140,
    "submit_label": 24,
    "cancel_label": 24,
    "success_message": 200,
}

COLOR_KEYS = [k for k in DEFAULT_AGENT_UI if k not in COPY_KEYS]

# Which placeholder each copy key may contain. Anything else in braces is
# rejected: inventory_agent.py substitutes with str.format, which raises
# KeyError on an unknown name and would take the whole window down, and the
# PowerShell agent does a literal replace, which would show the employee a raw
# "{whatever}". Neither failure is visible to the admin who caused it.
_PLACEHOLDERS = {
    "subheading": {"count"},
    "subheading_one": {"count"},
    "success_message": {"first_name"},
}

# What the portal calls each key. Kept here rather than in the template so the
# validation messages above and the form labels cannot drift apart.
KEY_LABELS = {
    "window_title": "Window title",
    "heading": "Heading",
    "subheading": "Sub-heading",
    "subheading_one": "Sub-heading (when only one field is enabled)",
    "rail_title": "Device panel title",
    "rail_footnote": "Device panel footnote",
    "submit_label": "Submit button",
    "cancel_label": "Cancel button",
    "success_message": "Message after a successful check-in",
    "navy": "Window background",
    "navy_sidebar": "Device panel background",
    "navy_mid": "Input background",
    "blue": "Primary button / focus ring",
    "blue_hover": "Primary button (hovered)",
    "teal": "Accent (panel title, required marker)",
    "slate": "Secondary text",
    "label": "Field labels",
    "white": "Primary text",
    "border_md": "Cancel button outline",
    "border_input": "Input outline",
}

_HEX_RE = re.compile(r"^#[0-9A-Fa-f]{6}$")
_BRACE_RE = re.compile(r"\{([^{}]*)\}")

# ── Contrast rules ────────────────────────────────────────────────────────────
# WCAG 2.1: 4.5:1 for body text (1.4.3), 3:1 for the boundary of a UI component
# that carries meaning (1.4.11). The window's text is 8-14pt, none of it large
# enough for the 3:1 large-text allowance, so every text pair is held to 4.5.
TEXT_MIN = 4.5
COMPONENT_MIN = 3.0

# (foreground, background, minimum, what an admin would call it). Every pair
# the window actually paints; a colour that appears on more than one background
# is checked against each, because passing on one proves nothing about the
# other.
_CONTRAST_PAIRS = [
    ("white", "navy", TEXT_MIN, "heading and input text on the window background"),
    ("white", "navy_sidebar", TEXT_MIN, "device values on the rail"),
    ("white", "navy_mid", TEXT_MIN, "text typed into an input"),
    ("white", "blue", TEXT_MIN, "the submit button's label"),
    ("white", "blue_hover", TEXT_MIN, "the submit button's label while hovered"),
    ("label", "navy", TEXT_MIN, "field labels"),
    ("label", "navy_sidebar", TEXT_MIN, "device labels on the rail"),
    ("slate", "navy", TEXT_MIN, "the sub-heading"),
    ("slate", "navy_sidebar", TEXT_MIN, "the rail footnote"),
    ("teal", "navy", TEXT_MIN, "the required-field marker"),
    ("teal", "navy_sidebar", TEXT_MIN, "the rail title"),
    ("border_input", "navy_mid", COMPONENT_MIN, "the outline of an input box"),
    ("border_md", "navy_mid", COMPONENT_MIN, "the outline of the cancel button"),
    ("blue", "navy", COMPONENT_MIN, "the focus ring on the input you are typing in"),
]


def _relative_luminance(hex_color: str) -> float:
    """WCAG 2.1 relative luminance. Assumes _HEX_RE has already matched."""
    raw = hex_color.lstrip("#")
    channels = []
    for offset in (0, 2, 4):
        value = int(raw[offset:offset + 2], 16) / 255
        channels.append(value / 12.92 if value <= 0.03928 else ((value + 0.055) / 1.055) ** 2.4)
    return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2]


def contrast_ratio(a: str, b: str) -> float:
    """WCAG 2.1 contrast ratio, 1.0 (identical) to 21.0 (black on white)."""
    la, lb = _relative_luminance(a), _relative_luminance(b)
    lighter, darker = max(la, lb), min(la, lb)
    return (lighter + 0.05) / (darker + 0.05)


def validate_agent_ui(values: dict) -> dict:
    """Cleans and checks an admin submission, returning only the keys that
    actually differ from the built-in defaults.

    Storing just the differences is what makes DEFAULT_AGENT_UI editable later:
    a company that never touched the heading keeps getting the current default
    rather than a frozen copy of whatever it was on the day they first saved
    the form. It is also why the column defaults to '{}'.

    Raises ValueError with a message meant to be shown to the admin verbatim.
    """
    unknown = set(values) - set(DEFAULT_AGENT_UI)
    if unknown:
        raise ValueError(f"Unknown appearance setting(s): {', '.join(sorted(unknown))}")

    cleaned: dict[str, str] = {}

    for key, max_length in COPY_KEYS.items():
        if key not in values or values[key] is None:
            continue
        text = str(values[key]).strip()
        if not text:
            # An empty box means "use the default", not "show nothing" -- a
            # blank heading or an unlabelled submit button is never what an
            # admin meant, and leaving the key out restores the built-in.
            continue
        if len(text) > max_length:
            raise ValueError(
                f"{key.replace('_', ' ').capitalize()} is {len(text)} characters; "
                f"the window has room for {max_length}."
            )
        allowed = _PLACEHOLDERS.get(key, set())
        used = set(_BRACE_RE.findall(text))
        if "{" in _BRACE_RE.sub("", text) or "}" in _BRACE_RE.sub("", text):
            raise ValueError(
                f"{key.replace('_', ' ').capitalize()} has an unmatched {{ or }}."
            )
        bad = used - allowed
        if bad:
            expected = (
                f"only {', '.join('{' + p + '}' for p in sorted(allowed))}"
                if allowed else "no placeholders"
            )
            raise ValueError(
                f"{key.replace('_', ' ').capitalize()} uses "
                f"{', '.join('{' + b + '}' for b in sorted(bad))}, but supports {expected}."
            )
        cleaned[key] = text

    for key in COLOR_KEYS:
        if key not in values or values[key] is None:
            continue
        color = str(values[key]).strip()
        if not color:
            continue
        if not _HEX_RE.match(color):
            raise ValueError(
                f"{key.replace('_', ' ').capitalize()} must be a colour like #1866F2 "
                f"(six hex digits, no transparency); got {color!r}."
            )
        cleaned[key] = "#" + color.lstrip("#").upper()

    # Contrast is checked against the *effective* palette -- defaults merged
    # with the submission -- because an admin who changes only the background
    # has still changed every text pair that sits on it.
    effective = {**DEFAULT_AGENT_UI, **cleaned}
    failures = []
    for fg, bg, minimum, description in _CONTRAST_PAIRS:
        ratio = contrast_ratio(effective[fg], effective[bg])
        if ratio < minimum:
            failures.append(
                f"{description} would be {ratio:.1f}:1 "
                f"({effective[fg]} on {effective[bg]}); {minimum}:1 is the minimum"
            )
    if failures:
        raise ValueError(
            "These colours would be hard or impossible to read on an employee's "
            "screen, so they have not been saved:\n  - " + "\n  - ".join(failures)
        )

    # Only the differences, for the reason in the docstring.
    return {k: v for k, v in cleaned.items() if v != DEFAULT_AGENT_UI[k]}


async def resolve_agent_ui(pool: asyncpg.Pool, company_id: str) -> dict:
    """The effective, agent-facing appearance: built-ins under the company's
    overrides. Always a complete palette, so an agent never has to merge."""
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            stored = await conn.fetchval(
                "SELECT agent_ui FROM companies WHERE id = $1", uuid.UUID(company_id)
            )

    # asyncpg hands back JSONB as a str unless a codec is registered; both
    # shapes are handled so this does not depend on pool setup elsewhere.
    if isinstance(stored, str):
        import json
        try:
            stored = json.loads(stored)
        except ValueError:
            stored = None
    if not isinstance(stored, dict):
        stored = {}

    # Overrides are filtered against the known keys on read as well as on
    # write. A key retired from a future DEFAULT_AGENT_UI would otherwise keep
    # being served to agents out of rows saved before it was removed.
    return {**DEFAULT_AGENT_UI, **{k: v for k, v in stored.items() if k in DEFAULT_AGENT_UI}}


async def set_agent_ui(pool: asyncpg.Pool, company_id: str, values: dict) -> None:
    """Validates then replaces the company's appearance overrides.

    A whole-object replace, not a merge: the portal edits every key on one
    form, so a key the admin cleared has to go back to its default rather than
    keep its previous override.
    """
    import json

    overrides = validate_agent_ui(values)
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            await conn.execute(
                "UPDATE companies SET agent_ui = $2::jsonb WHERE id = $1",
                uuid.UUID(company_id), json.dumps(overrides),
            )


async def resolve_agent_ui_for_admin(pool: asyncpg.Pool, company_id: str) -> dict:
    """Admin-UI shape: the effective values to prefill the form with, plus the
    built-ins so the form can show what "reset" would give and mark which
    values are actually customised (distinct from the agent-facing
    resolve_agent_ui, which is a flat palette)."""
    effective = await resolve_agent_ui(pool, company_id)
    return {
        "effective": effective,
        "defaults": dict(DEFAULT_AGENT_UI),
        "customised": sorted(k for k in DEFAULT_AGENT_UI if effective[k] != DEFAULT_AGENT_UI[k]),
        "copy_keys": dict(COPY_KEYS),
        "color_keys": list(COLOR_KEYS),
        "labels": dict(KEY_LABELS),
        "placeholders": {k: sorted(v) for k, v in _PLACEHOLDERS.items()},
    }
