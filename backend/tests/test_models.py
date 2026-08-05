import uuid

from app.models import CheckinRequest


def _payload(**overrides):
    """Minimal payload dict for model testing."""
    base = {
        "checkin_id": str(uuid.uuid4()),
        "timestamp": "2026-07-30T10:00:00",
        "first_name": "Nino",
        "last_name": "Nikoladze",
        "email": "nino@example.com",
        "project": "Webiz ERP",
        "serial_number": "SN-001",
        "hostname": "nino-macbook",
        "brand": "Apple",
        "model": "MacBook Pro",
        "os": "macOS 14.4.1",
    }
    base.update(overrides)
    return base


def test_department_accepts_legacy_project_key():
    """Agents deployed before the rename submit 'project'. Because department is
    optional, an ignored key would silently drop the value instead of erroring."""
    payload = _payload()
    payload["project"] = "Finance"
    payload.pop("department", None)
    assert CheckinRequest(**payload).department == "Finance"


def test_department_accepts_new_key():
    payload = _payload()
    payload.pop("project", None)
    payload["department"] = "Engineering"
    assert CheckinRequest(**payload).department == "Engineering"


def test_department_wins_when_both_keys_present():
    """AliasChoices resolves in listed order, so 'department' beats the legacy
    'project'. Pinned deliberately: reordering the choices would silently let a
    stale agent's value override the current one."""
    payload = _payload()
    payload["department"] = "Engineering"
    payload["project"] = "Finance"
    assert CheckinRequest(**payload).department == "Engineering"


def test_department_defaults_to_none_when_absent():
    """department is optional. This default is why the legacy alias matters --
    without it, a payload carrying only 'project' would validate cleanly and
    drop the value with no error."""
    payload = _payload()
    payload.pop("department", None)
    payload.pop("project", None)
    assert CheckinRequest(**payload).department is None
