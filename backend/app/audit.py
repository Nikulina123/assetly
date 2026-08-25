"""Append-only audit logging of privileged admin actions (finding H-4).

WHY A CONTEXT MANAGER RATHER THAN A DECORATOR OR MIDDLEWARE
The audit requires the log write to happen inside the same transaction as the
mutation it describes. A decorator runs around the handler and a middleware
runs around the response, so both can only write after the handler's own
transaction has already committed -- which permits exactly the two states this
control exists to prevent: a mutation with no record, and a record of a
mutation that rolled back. A context manager is the only one of the three that
can hand the route the connection the mutation runs on.

WHY THIS FAILS CLOSED
An audit insert that fails takes the request -- and, being in the same
transaction, the mutation -- down with it. This is the deliberate opposite of
app/rate_limit.py's documented fail-OPEN, and the reasoning inverts with the
stakes: there, failing closed takes the entire API down over a counter, so
allowing an unlimited request is the lesser harm. Here, failing open means a
privileged change to a customer's tenant happens with no record of who made
it, which is the whole finding. A privileged change that cannot be recorded
must not happen. The table is created by the same migration as this code and
BACKEND_API_PLAN.md requires it applied first, so "the table is missing" is a
deploy-ordering error to be surfaced loudly, not absorbed.
"""
import contextlib
import json
import uuid as _uuid

from app.rate_limit import client_ip

# Bounds on attacker-controlled strings. A user-agent is arbitrary caller input
# and this table is not the place to store a kilobyte of it per request.
_MAX_USER_AGENT = 500
_MAX_TARGET_ID = 255

_INSERT = """
    INSERT INTO audit_log (
        actor_admin_id, action, target_company_id, target_id,
        ip_address, user_agent, metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb)
"""


class AuditScope:
    """What `audited` yields: the connection the mutation must run on, plus a
    metadata dict the route may enrich with what actually happened before the
    row is written."""

    def __init__(self, conn, metadata: dict):
        self.conn = conn
        self.metadata = metadata


def _actor_id(actor) -> str | None:
    """Accepts an AdminContext, a bare id string, or None (an unauthenticated
    event such as a failed login, where there is no established actor)."""
    if actor is None:
        return None
    return getattr(actor, "id", actor)


def _request_fields(request) -> tuple[str | None, str | None]:
    if request is None:
        return None, None
    user_agent = (request.headers.get("user-agent") or "")[:_MAX_USER_AGENT] or None
    return client_ip(request), user_agent


async def _insert(conn, actor, action, target_company_id, target_id, request, metadata):
    ip_address, user_agent = _request_fields(request)
    actor_id = _actor_id(actor)
    await conn.execute(
        _INSERT,
        _uuid.UUID(str(actor_id)) if actor_id else None,
        action,
        _uuid.UUID(str(target_company_id)) if target_company_id else None,
        str(target_id)[:_MAX_TARGET_ID] if target_id is not None else None,
        ip_address,
        user_agent,
        json.dumps(metadata or {}),
    )


@contextlib.asynccontextmanager
async def audited(
    pool, request, actor, action, *,
    target_company_id=None, target_id=None, metadata=None,
):
    """Runs a privileged mutation and its audit record in one transaction.

    The route MUST use `scope.conn` for its mutation -- acquiring a second
    connection inside the block puts the mutation in a different transaction
    and silently forfeits the guarantee this exists to provide.
    """
    scope_metadata = dict(metadata or {})
    async with pool.acquire() as conn:
        async with conn.transaction():
            scope = AuditScope(conn, scope_metadata)
            yield scope
            await _insert(
                conn, actor, action, target_company_id, target_id,
                request, scope.metadata,
            )


async def record_audit(
    pool, request, actor, action, *,
    target_company_id=None, target_id=None, metadata=None,
):
    """Standalone form, for events with no mutation to join: login success,
    login failure, logout, diagnostics views."""
    async with pool.acquire() as conn:
        await _insert(
            conn, actor, action, target_company_id, target_id, request, metadata
        )
