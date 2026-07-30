import uuid

import asyncpg
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from app.auth import resolve_company_id
from app.db import get_pool
from app.hardware import normalize_os
from app.models import CheckinRequest, CheckinResponse

app = FastAPI(title="Webiz Inventory Check-in API")


async def get_current_company_id(
    authorization: str | None = Header(default=None),
) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    api_key = authorization.removeprefix("Bearer ").strip()
    pool = await get_pool()
    company_id = await resolve_company_id(pool, api_key)
    if company_id is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")
    return company_id


@app.post("/api/v1/inventory/checkin", response_model=CheckinResponse)
async def checkin(
    payload: CheckinRequest,
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
                        first_name, last_name, email, project,
                        serial_number, hostname, brand, model,
                        cpu, ram, storage, ip_address,
                        os, os_version, platform,
                        agent_version, submission_type
                    ) VALUES (
                        $1, $2, $3,
                        $4, $5, $6, $7,
                        $8, $9, $10, $11,
                        $12, $13, $14, $15,
                        $16, $17, $18,
                        $19, $20
                    )
                    """,
                    uuid.UUID(company_id), payload.checkin_id, payload.timestamp,
                    payload.first_name, payload.last_name, payload.email, payload.project,
                    payload.serial_number, payload.hostname, payload.brand, payload.model,
                    payload.cpu, payload.ram, payload.storage, payload.ip_address,
                    payload.os, os_version, platform_name,
                    payload.agent_version, payload.submission_type,
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
                    cpu, ram, storage, os, os_version, platform, owner_email, project
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
                    project = EXCLUDED.project
                """,
                uuid.UUID(company_id), payload.serial_number, payload.timestamp,
                payload.hostname, payload.brand, payload.model,
                payload.cpu, payload.ram, payload.storage,
                payload.os, os_version, platform_name,
                payload.email, payload.project,
            )

    return {"status": "ok", "id": str(payload.checkin_id)}
