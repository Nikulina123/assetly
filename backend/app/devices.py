"""Device reads for the tenant portal.

Every query sets app.company_id inside its transaction so Postgres RLS enforces
tenant isolation (see migrations/001_init.sql). These are the first routes where
a URL path segment selects a tenant, so isolation must not depend on the query
author remembering a WHERE clause.

Status is derived in Python via device_status.derive_status, never in SQL, so
there is exactly one definition of it.
"""
import datetime
import json
import uuid
from collections import Counter

import asyncpg

from app.device_status import derive_status
from app.enrollment import list_device_credentials
from app.schedule import resolve_schedule

_DEVICE_COLUMNS = (
    "serial_number, last_seen_at, hostname, brand, model, cpu, ram, storage, "
    "os, os_version, platform, owner_email, department"
)


async def _fetch(pool: asyncpg.Pool, company_id: str, query: str, *args) -> list:
    # Both the RLS setting and the WHERE clause's $1 are derived from this same
    # company_id argument, deliberately -- they cannot desync. Postgres ANDs the
    # RLS policy with the WHERE clause, so if a future refactor ever sourced them
    # from two different values, a mismatch would silently return [] (an "empty
    # state") rather than raise an error, unlike the missing-set_config case
    # below which errors loudly. Keep them derived from one argument.
    async with pool.acquire() as conn:
        async with conn.transaction():
            await conn.execute("SELECT set_config('app.company_id', $1, true)", company_id)
            return await conn.fetch(query, uuid.UUID(company_id), *args)


def _with_status(row: asyncpg.Record, now: datetime.datetime, interval_seconds: int) -> dict:
    device = dict(row)
    device["status"] = derive_status(device["last_seen_at"], now, interval_seconds)
    return device


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _decode_checkin(row: asyncpg.Record) -> dict:
    checkin = dict(row)
    # asyncpg returns JSONB as raw text unless a codec is registered, and none
    # is. Decode here so consumers get a dict rather than each having to know.
    raw = checkin.get("custom_fields")
    checkin["custom_fields"] = json.loads(raw) if isinstance(raw, str) else (raw or {})
    return checkin


async def list_devices(pool: asyncpg.Pool, company_id: str) -> list[dict]:
    rows = await _fetch(
        pool, company_id,
        f"SELECT {_DEVICE_COLUMNS} FROM devices WHERE company_id = $1 "
        "ORDER BY last_seen_at DESC NULLS LAST",
    )
    # Resolved once per call, not once per row. dashboard_stats needs no
    # change of its own -- it counts the statuses this function already
    # returned.
    interval = (await resolve_schedule(pool, company_id))["checkin_interval_seconds"]
    now = _now()
    return [_with_status(row, now, interval) for row in rows]


async def legacy_key_conversion(pool: asyncpg.Pool, company_id: str) -> dict:
    """Per-company L-1 measurement: how many devices still authenticate with
    the shared legacy company key versus a per-device credential.

    No new column, no hot-path write. A device counts as "converted" if it
    has an active (non-revoked) device_credentials row -- device_credentials
    has no RLS, but every read of it here filters company_id explicitly
    (list_device_credentials already does this). Everything else is "legacy",
    and because checkin.py's M-1 binding check refuses a device-credential
    check-in for any serial other than the one that credential was enrolled
    for, an unconverted device's last_seen_at can ONLY have come from a
    legacy-key check-in -- no ambiguity for that subset.

    Known blind spot, documented here because it belongs next to the query
    that has it: a device that already has an active credential but is
    misconfigured to still present the old shared key would be counted as
    "converted" even though a legacy check-in is landing for it. Not the
    normal migration path (an agent update replaces its config atomically,
    it doesn't leave both credentials live), so accepted as an
    approximation -- these numbers are a FLOOR on legacy usage, never a
    ceiling.
    """
    devices = await list_devices(pool, company_id)
    credentials = await list_device_credentials(pool, company_id)
    active_serials = {
        c["serial_number"] for c in credentials if c["revoked_at"] is None
    }
    legacy_devices = [
        {"serial_number": d["serial_number"], "last_seen_at": d["last_seen_at"]}
        for d in devices
        if d["serial_number"].strip().casefold() not in active_serials
    ]
    # Newest first, NULLs (never checked in) sorted last.
    legacy_devices.sort(
        key=lambda d: d["last_seen_at"] or datetime.datetime.min.replace(
            tzinfo=datetime.timezone.utc
        ),
        reverse=True,
    )
    last_legacy_checkin = max(
        (d["last_seen_at"] for d in legacy_devices if d["last_seen_at"] is not None),
        default=None,
    )
    return {
        "total": len(devices),
        "converted": len(devices) - len(legacy_devices),
        "legacy": len(legacy_devices),
        "last_legacy_checkin": last_legacy_checkin,
        "legacy_devices": legacy_devices,
    }


async def get_device(pool: asyncpg.Pool, company_id: str, serial_number: str) -> dict | None:
    rows = await _fetch(
        pool, company_id,
        f"SELECT {_DEVICE_COLUMNS} FROM devices WHERE company_id = $1 AND serial_number = $2",
        serial_number,
    )
    if not rows:
        return None
    interval = (await resolve_schedule(pool, company_id))["checkin_interval_seconds"]
    return _with_status(rows[0], _now(), interval)


async def get_checkin_history(pool: asyncpg.Pool, company_id: str, serial_number: str) -> list[dict]:
    rows = await _fetch(
        pool, company_id,
        "SELECT received_at, timestamp, first_name, last_name, email, department, "
        "hostname, ip_address, agent_version, submission_type, custom_fields "
        "FROM device_checkins WHERE company_id = $1 AND serial_number = $2 "
        "ORDER BY received_at DESC",
        serial_number,
    )
    return [_decode_checkin(row) for row in rows]


async def dashboard_stats(pool: asyncpg.Pool, company_id: str) -> dict:
    devices = await list_devices(pool, company_id)
    by_status = Counter(d["status"] for d in devices)
    by_os = Counter(d["os"] or "Unknown" for d in devices)
    return {
        "total": len(devices),
        "by_status": {
            "online": by_status.get("online", 0),
            "pending": by_status.get("pending", 0),
            "offline": by_status.get("offline", 0),
        },
        "by_os": by_os.most_common(),
    }
