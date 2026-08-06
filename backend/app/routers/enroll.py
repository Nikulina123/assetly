"""Device enrollment.

Separate from checkin.py: this is the one endpoint an agent calls before it has
any device identity, so its auth rules differ from every other route.
"""
from fastapi import APIRouter, Header, HTTPException

from app.auth import resolve_company_id
from app.db import get_pool
from app.enrollment import (
    EnrollmentError,
    UnknownTokenError,
    create_enrollment_token,
    enroll_device,
)
from app.models import EnrollRequest, EnrollResponse

router = APIRouter(tags=["enroll"])


@router.post("/api/v1/enroll", response_model=EnrollResponse)
async def enroll(payload: EnrollRequest, authorization: str | None = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or malformed Authorization header")
    bearer = authorization.removeprefix("Bearer ").strip()
    pool = await get_pool()

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
