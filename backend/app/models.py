import datetime
import uuid

from pydantic import AliasChoices, BaseModel, Field


class CheckinRequest(BaseModel):
    checkin_id: uuid.UUID
    timestamp: datetime.datetime

    first_name: str
    last_name: str
    email: str
    # AliasChoices keeps the field settable by its own name AND by the legacy
    # "project" key that agents deployed before the rename still send. Remove
    # the "project" choice once no such agent remains in the field.
    department: str | None = Field(
        default=None,
        validation_alias=AliasChoices("department", "project"),
    )

    serial_number: str
    hostname: str
    brand: str
    model: str

    cpu: str | None = None
    ram: str | None = None
    storage: str | None = None
    ip_address: str | None = None

    os: str
    agent_version: str | None = None
    submission_type: str = "online"
    # Deliberately not cross-validated against the company's configured custom
    # fields (see app/field_config.py) -- the agent builds its form from the
    # same GET /config this endpoint's values come from, so it shouldn't send
    # anything the config doesn't call for. Not enforced server-side by design.
    custom_fields: dict[str, str] = {}


class CheckinResponse(BaseModel):
    status: str
    id: uuid.UUID


class EnrollRequest(BaseModel):
    serial_number: str
    hostname: str | None = None


class EnrollResponse(BaseModel):
    credential: str
