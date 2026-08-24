import datetime
import uuid

from pydantic import AliasChoices, BaseModel, Field, field_validator

# Generous for every hardware and identity string the agent collects; a value
# longer than this is a bug or an attempt to inflate storage, not a real
# machine. The columns are TEXT with no length constraint, so this model is
# the only bound that exists. Vercel enforces a fixed, non-configurable 4.5 MB
# request body cap platform-wide (no vercel.json key controls it), so these
# per-field limits are the only real size enforcement for this payload.
MAX_FIELD_LENGTH = 256
MAX_OS_LENGTH = 512
MAX_CUSTOM_FIELDS = 32
MAX_CUSTOM_KEY_LENGTH = 64
MAX_CUSTOM_VALUE_LENGTH = 512


class CheckinRequest(BaseModel):
    checkin_id: uuid.UUID
    timestamp: datetime.datetime

    first_name: str = Field(max_length=MAX_FIELD_LENGTH)
    last_name: str = Field(max_length=MAX_FIELD_LENGTH)
    email: str = Field(max_length=MAX_FIELD_LENGTH)
    # AliasChoices keeps the field settable by its own name AND by the legacy
    # "project" key that agents deployed before the rename still send. Remove
    # the "project" choice once no such agent remains in the field.
    department: str | None = Field(
        default=None,
        max_length=MAX_FIELD_LENGTH,
        validation_alias=AliasChoices("department", "project"),
    )

    serial_number: str = Field(max_length=MAX_FIELD_LENGTH)
    hostname: str = Field(max_length=MAX_FIELD_LENGTH)
    brand: str = Field(max_length=MAX_FIELD_LENGTH)
    model: str = Field(max_length=MAX_FIELD_LENGTH)

    cpu: str | None = Field(default=None, max_length=MAX_FIELD_LENGTH)
    ram: str | None = Field(default=None, max_length=MAX_FIELD_LENGTH)
    storage: str | None = Field(default=None, max_length=MAX_FIELD_LENGTH)
    ip_address: str | None = Field(default=None, max_length=MAX_FIELD_LENGTH)

    os: str = Field(max_length=MAX_OS_LENGTH)
    agent_version: str | None = Field(default=None, max_length=MAX_FIELD_LENGTH)
    submission_type: str = Field(default="online", max_length=MAX_FIELD_LENGTH)
    # Deliberately not cross-validated against the company's configured custom
    # fields (see app/field_config.py) -- the agent builds its form from the
    # same GET /config this endpoint's values come from, so it shouldn't send
    # anything the config doesn't call for. Not enforced server-side by design.
    # The caps below are size bounds only, not schema validation.
    custom_fields: dict[str, str] = {}

    @field_validator("custom_fields")
    @classmethod
    def _bound_custom_fields(cls, value: dict[str, str]) -> dict[str, str]:
        # Rejects the whole submission rather than truncating, matching how
        # agent_ui.py handles an out-of-range appearance value: a silently
        # clamped inventory record is worse than a visible failure.
        if len(value) > MAX_CUSTOM_FIELDS:
            raise ValueError(f"custom_fields accepts at most {MAX_CUSTOM_FIELDS} keys")
        for key, item in value.items():
            if len(key) > MAX_CUSTOM_KEY_LENGTH:
                raise ValueError(
                    f"custom_fields key exceeds {MAX_CUSTOM_KEY_LENGTH} characters"
                )
            if len(item) > MAX_CUSTOM_VALUE_LENGTH:
                raise ValueError(
                    f"custom_fields value for {key!r} exceeds "
                    f"{MAX_CUSTOM_VALUE_LENGTH} characters"
                )
        return value


class CheckinResponse(BaseModel):
    status: str
    id: uuid.UUID


class EnrollRequest(BaseModel):
    serial_number: str = Field(max_length=MAX_FIELD_LENGTH)
    hostname: str | None = Field(default=None, max_length=MAX_FIELD_LENGTH)


class EnrollResponse(BaseModel):
    credential: str
