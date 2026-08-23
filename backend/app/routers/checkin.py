import json
import uuid

import asyncpg
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.agent_ui import resolve_agent_ui
from app.auth import resolve_credential
from app.db import get_pool
from app.field_config import resolve_field_config
from app.hardware import normalize_os
from app.models import CheckinRequest, CheckinResponse
from app.notifications import notify_auth_failure, notify_checkin_success
from app.schedule import resolve_schedule

router = APIRouter(tags=["checkin"])


async def get_current_company_id(
    request: Request,
    background_tasks: BackgroundTasks,
    authorization: str | None = Header(default=None),
) -> str:
    # Stashed on request.state so app.main's HTTPException handler can still
    # run/attach these tasks when this dependency raises below: FastAPI only
    # auto-attaches a BackgroundTasks instance to the response on the normal
    # successful-return path (see fastapi.routing's response serialization) --
    # a dependency that raises HTTPException never reaches that code, and the
    # exception-handling path builds a brand new Response with no background
    # tasks on it, so tasks queued here would otherwise be silently dropped.
    # Confirmed empirically: without this, test_checkin_auth_failure_triggers_
    # notification failed (0 calls recorded) even though the task was queued.
    request.state.background_tasks = background_tasks
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    api_key = authorization.removeprefix("Bearer ").strip()
    pool = await get_pool()
    result = await resolve_credential(pool, api_key)
    if result is None:
        # Only a present-but-invalid key triggers this -- a missing header
        # entirely (the branch above) is far more common (unconfigured
        # devices, generic bot traffic) and much less actionable, so it's
        # deliberately not notified on, to keep this signal meaningful.
        background_tasks.add_task(notify_auth_failure, api_key[:16] + "...")
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    company_id, credential_id, enrolled_serial = result
    request.state.credential_id = credential_id
    request.state.enrolled_serial = enrolled_serial
    return company_id


@router.get("/api/v1/inventory/config")
async def get_config(company_id: str = Depends(get_current_company_id)):
    pool = await get_pool()
    config = await resolve_field_config(pool, company_id)
    # Additive: agents that predate this key ignore it and keep their built-in
    # interval, so this can ship ahead of any agent release.
    config["schedule"] = await resolve_schedule(pool, company_id)
    # Same additive contract as schedule above: an agent built before this key
    # existed ignores it and keeps its built-in appearance.
    config["ui"] = await resolve_agent_ui(pool, company_id)
    return config


@router.post("/api/v1/inventory/checkin", response_model=CheckinResponse)
async def checkin(
    payload: CheckinRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    company_id: str = Depends(get_current_company_id),
):
    platform_name, os_version = normalize_os(payload.os)

    # M-1: a credential may only speak for the machine it was enrolled for.
    # Without this, any one compromised endpoint -- or anyone holding a leaked
    # enrollment token -- can submit a check-in claiming any serial, and the
    # ON CONFLICT DO UPDATE below silently overwrites that machine's record.
    # For an asset-inventory product that is an attack on the integrity of the
    # thing the product exists to produce.
    #
    # enrolled_serial is None only on the legacy company-key path, which is
    # exempt by design: a company key is not issued for a serial. That
    # exemption ends when ALLOW_LEGACY_COMPANY_KEY_CHECKIN is flipped to false.
    enrolled_serial = getattr(request.state, "enrolled_serial", None)
    if enrolled_serial is not None and payload.serial_number != enrolled_serial:
        raise HTTPException(
            status_code=409,
            detail=(
                "Payload serial number does not match the serial this credential "
                "was enrolled for. Re-enroll the device from the admin portal if "
                "its hardware was replaced."
            ),
        )

    pool = await get_pool()

    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            try:
                await conn.execute(
                    """
                    INSERT INTO device_checkins (
                        company_id, checkin_id, timestamp,
                        first_name, last_name, email, department,
                        serial_number, hostname, brand, model,
                        cpu, ram, storage, ip_address,
                        os, os_version, platform,
                        agent_version, submission_type, custom_fields
                    ) VALUES (
                        $1, $2, $3,
                        $4, $5, $6, $7,
                        $8, $9, $10, $11,
                        $12, $13, $14, $15,
                        $16, $17, $18,
                        $19, $20, $21::jsonb
                    )
                    """,
                    uuid.UUID(company_id), payload.checkin_id, payload.timestamp,
                    payload.first_name, payload.last_name, payload.email, payload.department,
                    payload.serial_number, payload.hostname, payload.brand, payload.model,
                    payload.cpu, payload.ram, payload.storage, payload.ip_address,
                    payload.os, os_version, platform_name,
                    payload.agent_version, payload.submission_type, json.dumps(payload.custom_fields),
                )
            except asyncpg.UniqueViolationError:
                # Returning here still exits `async with conn.transaction()` normally, which
                # issues COMMIT — but since the INSERT already aborted the transaction server-side,
                # Postgres silently downgrades that COMMIT to a no-op/rollback. No partial state persists.
                return JSONResponse(status_code=409, content={"status": "duplicate"})

            await conn.execute(
                """
                INSERT INTO devices (
                    company_id, serial_number, last_seen_at, hostname, brand, model,
                    cpu, ram, storage, os, os_version, platform, owner_email, department
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
                ON CONFLICT (company_id, serial_number) DO UPDATE SET
                    last_seen_at = EXCLUDED.last_seen_at,
                    hostname = EXCLUDED.hostname,
                    brand = EXCLUDED.brand,
                    model = EXCLUDED.model,
                    cpu = EXCLUDED.cpu,
                    ram = EXCLUDED.ram,
                    storage = EXCLUDED.storage,
                    os = EXCLUDED.os,
                    os_version = EXCLUDED.os_version,
                    platform = EXCLUDED.platform,
                    owner_email = EXCLUDED.owner_email,
                    department = EXCLUDED.department
                """,
                uuid.UUID(company_id), payload.serial_number, payload.timestamp,
                payload.hostname, payload.brand, payload.model,
                payload.cpu, payload.ram, payload.storage,
                payload.os, os_version, platform_name,
                payload.email, payload.department,
            )

            credential_id = getattr(request.state, "credential_id", None)
            if credential_id is not None:
                await conn.execute(
                    "UPDATE device_credentials SET last_used_at = NOW() WHERE id = $1",
                    uuid.UUID(credential_id),
                )

        notification_email = await conn.fetchval(
            "SELECT notification_email FROM companies WHERE id = $1", uuid.UUID(company_id)
        )

    background_tasks.add_task(
        notify_checkin_success,
        notification_email,
        payload.hostname,
        f"{payload.first_name} {payload.last_name}",
        payload.department,
        payload.custom_fields,
    )

    return {"status": "ok", "id": str(payload.checkin_id)}
