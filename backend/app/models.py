import datetime
import uuid

from pydantic import BaseModel


class CheckinRequest(BaseModel):
    checkin_id: uuid.UUID
    timestamp: datetime.datetime

    first_name: str
    last_name: str
    email: str
    project: str

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
    custom_fields: dict[str, str] = {}


class CheckinResponse(BaseModel):
    status: str
    id: uuid.UUID
