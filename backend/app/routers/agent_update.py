"""The signed agent-update manifest endpoint.

Authenticated with the device credential, so we can see which tenants are
updating and can stage a rollout later. The ARTIFACTS themselves stay on the
unauthenticated /static mount: their integrity comes from the signed SHA-256
in the manifest, so authenticating the download would add nothing.
"""
from fastapi import APIRouter, Depends, HTTPException

from app.routers.checkin import get_current_company_id
from app.update_manifest import load_manifest

router = APIRouter(tags=["agent-update"])


@router.get("/api/v1/agent/manifest")
async def agent_manifest(company_id: str = Depends(get_current_company_id)):
    try:
        manifest_bytes, signature = load_manifest()
    except FileNotFoundError:
        # No release has been signed. An agent treats this exactly like "no
        # update available" and carries on -- an unsigned deployment must
        # never be a reason for an agent to fall back to anything.
        raise HTTPException(status_code=404, detail="No signed release available")

    # Returned as an opaque string, deliberately. The signature covers these
    # exact bytes; handing back a parsed object would let FastAPI re-serialise
    # it into something the signature does not cover.
    return {"manifest": manifest_bytes.decode(), "signature": signature}
