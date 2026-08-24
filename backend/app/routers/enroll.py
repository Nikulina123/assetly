"""Device enrollment.

Separate from checkin.py: this is the one endpoint an agent calls before it has
any device identity, so its auth rules differ from every other route.
"""
from fastapi import APIRouter, Header, HTTPException, Request

from app.auth import resolve_company_id
from app.config import RATE_LIMIT_ENROLL_IP, RATE_LIMIT_ENROLL_TOKEN
from app.db import get_pool
from app.enrollment import (
    EnrollmentError,
    UnknownTokenError,
    create_enrollment_token,
    enroll_device,
)
from app.models import EnrollRequest, EnrollResponse
from app.rate_limit import client_ip, enforce_rate_limit, hashed_bucket

router = APIRouter(tags=["enroll"])


@router.post("/api/v1/enroll", response_model=EnrollResponse)
async def enroll(
    payload: EnrollRequest,
    request: Request,
    authorization: str | None = Header(default=None),
):
    pool = await get_pool()

    # The bearer parse -- and the 401 for a missing/malformed header -- comes
    # BEFORE any rate limiting. A bad header is rejected on essentially free
    # work (no DB call, no enrollment logic reached), so there is no unbounded
    # work for a limiter to guard here; the limiter's job starts once there is
    # a token to bucket on.
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    bearer = authorization.removeprefix("Bearer ").strip()

    # Primary limit: keyed on the presented bearer, not client_ip. Task 12
    # moved enrollment to install time, so a single site's MDM/GPO rollout
    # pushes installers for every seat from one egress IP -- an IP-keyed limit
    # alone would exhaust at 30 enrollments and push the rest onto the
    # on-disk-token fallback path, exactly the outcome C-2 exists to close.
    # The real per-token ceiling is max_devices, enforced in enroll_device;
    # this bucket only needs to stop pathological abuse of one token.
    token_limit, token_window = RATE_LIMIT_ENROLL_TOKEN
    await enforce_rate_limit(
        pool, hashed_bucket("enroll:token", bearer), token_limit, token_window
    )
    # Secondary, coarser per-IP limit: still useful against a flood of
    # different (unknown/bogus) tokens from one address, which the per-token
    # bucket alone wouldn't catch since each bogus token gets its own bucket.
    ip_limit, ip_window = RATE_LIMIT_ENROLL_IP
    await enforce_rate_limit(pool, f"enroll:ip:{client_ip(request)}", ip_limit, ip_window)

    try:
        credential = await enroll_device(pool, bearer, payload.serial_number, payload.hostname)
        return {"credential": credential}
    except UnknownTokenError:
        # Fall through to the legacy company-key path below. Distinguished from
        # every other EnrollmentError by type, not by string-matching the
        # message -- a reworded message must never silently change which HTTP
        # status a caller gets, or turn a genuine 403 into a fall-through here.
        #
        # This fall-through is deliberately NOT gated by
        # ALLOW_LEGACY_COMPANY_KEY_CHECKIN: that flag ends legacy CHECK-INS,
        # but a straggler agent holding only the company key still needs this
        # path to migrate itself, or flipping the flag strands exactly the
        # machines it is meant to flush out.
        pass
    except EnrollmentError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    company_id = await resolve_company_id(pool, bearer)
    if company_id is None:
        raise HTTPException(status_code=401, detail="Invalid or revoked credential")

    token = await create_enrollment_token(
        pool, company_id, label=f"self-migration: {payload.serial_number}", max_devices=1
    )
    credential = await enroll_device(pool, token, payload.serial_number, payload.hostname)
    return {"credential": credential}
