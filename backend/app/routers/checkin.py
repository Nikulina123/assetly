import json
import uuid

import asyncpg
from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app.auth import resolve_company_id
from app.db import get_pool
from app.field_config import resolve_field_config
from app.hardware import normalize_os
from app.models import CheckinRequest, CheckinResponse
from app.notifications import notify_auth_failure, notify_checkin_success

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
    company_id = await resolve_company_id(pool, api_key)
    if company_id is None:
        # Only a present-but-invalid key triggers this -- a missing header
        # entirely (the branch above) is far more common (unconfigured
        # devices, generic bot traffic) and much less actionable, so it's
        # deliberately not notified on, to keep this signal meaningful.
        background_tasks.add_task(notify_auth_failure, api_key[:16] + "...")
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return company_id


@router.get("/api/v1/inventory/config")
async def get_config(company_id: str = Depends(get_current_company_id)):
    pool = await get_pool()
    return await resolve_field_config(pool, company_id)


@router.post("/api/v1/inventory/checkin", response_model=CheckinResponse)
async def checkin(
    payload: CheckinRequest,
    background_tasks: BackgroundTasks,
    company_id: str = Depends(get_current_company_id),
):
    platform_name, os_version = normalize_os(payload.os)
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
