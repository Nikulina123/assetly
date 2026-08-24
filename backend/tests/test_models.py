import uuid

import pytest
from pydantic import ValidationError

from app.models import MAX_FIELD_LENGTH, CheckinRequest, EnrollRequest


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


def _valid_payload(**overrides):
    payload = {
        "checkin_id": "11111111-1111-1111-1111-111111111111",
        "timestamp": "2026-08-20T10:00:00Z",
        "first_name": "Ann",
        "last_name": "Lee",
        "email": "ann@example.com",
        "serial_number": "SER123",
        "hostname": "host-1",
        "brand": "Apple",
        "model": "MacBook Pro",
        "os": "macOS 15.0",
    }
    payload.update(overrides)
    return payload


def test_rejects_oversized_string_field():
    with pytest.raises(ValidationError):
        CheckinRequest(**_valid_payload(hostname="h" * 257))


def test_accepts_string_field_at_the_limit():
    model = CheckinRequest(**_valid_payload(hostname="h" * 256))
    assert len(model.hostname) == 256


def test_rejects_too_many_custom_fields():
    with pytest.raises(ValidationError):
        CheckinRequest(**_valid_payload(custom_fields={f"k{i}": "v" for i in range(33)}))


def test_rejects_oversized_custom_field_value():
    with pytest.raises(ValidationError):
        CheckinRequest(**_valid_payload(custom_fields={"k": "v" * 513}))


def test_rejects_oversized_custom_field_key():
    with pytest.raises(ValidationError):
        CheckinRequest(**_valid_payload(custom_fields={"k" * 65: "v"}))


def test_accepts_custom_fields_at_the_limits():
    model = CheckinRequest(
        **_valid_payload(custom_fields={f"k{i}": "v" * 512 for i in range(32)})
    )
    assert len(model.custom_fields) == 32


def test_enroll_request_rejects_oversized_serial_number():
    """An unbounded serial_number on EnrollRequest let a device enroll with a
    serial its own CheckinRequest (capped at MAX_FIELD_LENGTH) could never
    carry -- permanently rejecting that device's check-ins with a 409."""
    with pytest.raises(ValidationError):
        EnrollRequest(serial_number="S" * (MAX_FIELD_LENGTH + 1))


def test_enroll_request_rejects_oversized_hostname():
    with pytest.raises(ValidationError):
        EnrollRequest(serial_number="SN-001", hostname="H" * (MAX_FIELD_LENGTH + 1))


def test_enroll_request_accepts_serial_number_and_hostname_at_the_limit():
    model = EnrollRequest(
        serial_number="S" * MAX_FIELD_LENGTH, hostname="H" * MAX_FIELD_LENGTH
    )
    assert len(model.serial_number) == MAX_FIELD_LENGTH
    assert len(model.hostname) == MAX_FIELD_LENGTH
