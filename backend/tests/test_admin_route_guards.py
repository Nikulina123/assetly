"""Structural guard: every privileged POST route on the admin router must
require `require_full_admin` or `require_global_admin` (H-2 drift check).

`test_admin_roles.py` and `test_audit_log.py` both check the authorization
and audit properties against a HAND-WRITTEN list of routes. That protects
against regressions on routes already in the list, but does nothing for a
route that doesn't exist yet: a new `@router.post` added to `admin.py` with
no role guard passes every existing test, because nothing walks the router
itself.

This test walks `router.routes` and, for every POST route, recursively walks
its `Dependant` tree (each `APIRoute.dependant` has `.dependencies`, each of
which has its own `.call` and its own `.dependencies`) looking for
`require_full_admin` or `require_global_admin` among the `.call` targets.
"""
import pytest

from app.routers.admin import (
    regenerate_recovery_codes,
    require_admin,
    require_full_admin,
    require_global_admin,
    router,
)

pytestmark = pytest.mark.asyncio

# Routes that legitimately have no role guard (or a weaker one), and WHY.
# Adding a route here must be a deliberate, visible act in a diff -- a new
# privileged route must NOT be added to this allowlist just to make the test
# pass. Every entry needs the same kind of justification as the ones below.
ALLOWLISTED_ROUTES = {
    # Auth routes: there is no admin identity yet (or the identity is being
    # established/destroyed), so a role dependency isn't meaningful.
    ("POST", "/admin/login"),
    ("POST", "/admin/logout"),
    ("POST", "/admin/mfa/setup"),
    ("POST", "/admin/mfa/verify"),
    # Recovery codes are the admin's OWN credentials, not a privileged action
    # against a tenant -- deliberately gated by plain `require_admin` so any
    # logged-in admin (support included) can manage their own MFA recovery
    # codes without needing a full-admin role.
    ("POST", "/admin/mfa/recovery-codes"),
}


def _dependency_calls(dependant, seen=None):
    """Recursively collect every `.call` target in a Dependant tree."""
    if seen is None:
        seen = set()
    if id(dependant) in seen:
        return
    seen.add(id(dependant))
    if dependant.call is not None:
        yield dependant.call
    for sub in dependant.dependencies:
        yield from _dependency_calls(sub, seen)


def _admin_post_routes():
    for route in router.routes:
        methods = getattr(route, "methods", None) or set()
        if "POST" in methods:
            yield route


async def test_every_admin_post_route_requires_full_or_global_admin():
    unguarded = []
    for route in _admin_post_routes():
        key = ("POST", route.path)
        if key in ALLOWLISTED_ROUTES:
            continue
        calls = set(_dependency_calls(route.dependant))
        if require_full_admin not in calls and require_global_admin not in calls:
            unguarded.append(route.path)

    assert not unguarded, (
        "The following admin POST routes have no require_full_admin or "
        "require_global_admin dependency, and are not in the named "
        f"ALLOWLISTED_ROUTES: {unguarded}. If this route is genuinely "
        "unprivileged, add it to ALLOWLISTED_ROUTES with a comment "
        "explaining why -- do not add a privileged route to make this pass."
    )


async def test_allowlisted_routes_still_exist_and_are_posts():
    """Guards the allowlist itself against rot: if a route is renamed or
    removed, this fails loudly instead of the allowlist silently covering
    nothing."""
    actual = {("POST", route.path) for route in _admin_post_routes()}
    missing = ALLOWLISTED_ROUTES - actual
    assert not missing, f"Allowlisted routes no longer exist as POST routes: {missing}"


async def test_recovery_codes_route_uses_plain_require_admin_not_stronger():
    """Documents the deliberate choice: recovery-codes is gated by
    require_admin, not require_full_admin/require_global_admin -- if someone
    "fixes" this by adding a stronger guard, they've broken support's ability
    to manage their own recovery codes for no security benefit (they're
    already gated to the admin's own identity)."""
    route = next(
        r for r in _admin_post_routes() if r.path == "/admin/mfa/recovery-codes"
    )
    assert route.endpoint is regenerate_recovery_codes
    calls = set(_dependency_calls(route.dependant))
    assert require_admin in calls
    assert require_full_admin not in calls
    assert require_global_admin not in calls
