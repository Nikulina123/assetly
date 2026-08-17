"""Tests for inventory_agent.py's due-check guard.

The agent must stay a single self-contained file (self_update() replaces
exactly one file), so the guard cannot be extracted into an importable module.
Instead HOME is redirected to a tmp dir *before* import, which contains the
module-level STATE_DIR.mkdir() and log-file handler the agent sets up at import
time. Verified: with HOME redirected, STATE_DIR lands under the tmp path.
"""
import datetime
import importlib
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def agent(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.syspath_prepend(str(REPO_ROOT))
    sys.modules.pop("inventory_agent", None)
    module = importlib.import_module("inventory_agent")
    yield module
    sys.modules.pop("inventory_agent", None)


def _iso(**delta):
    return (datetime.datetime.now() - datetime.timedelta(**delta)).isoformat()


SCHEDULE = {"checkin_interval_seconds": 43200, "cancel_retry_seconds": 3600}


def test_no_state_means_due(agent):
    assert agent.should_show_form({}, SCHEDULE) is True


def test_inside_interval_is_not_due(agent):
    assert agent.should_show_form({"last_run": _iso(hours=1)}, SCHEDULE) is False


def test_past_interval_is_due(agent):
    assert agent.should_show_form({"last_run": _iso(hours=13)}, SCHEDULE) is True


def test_inside_cancel_window_is_not_due(agent):
    state = {"last_run": _iso(hours=13), "cancelled_at": _iso(minutes=10)}
    assert agent.should_show_form(state, SCHEDULE) is False


def test_past_cancel_window_is_due(agent):
    state = {"last_run": _iso(hours=13), "cancelled_at": _iso(hours=2)}
    assert agent.should_show_form(state, SCHEDULE) is True


def test_future_last_run_is_treated_as_due(agent):
    """Clock moved backwards. Treating it as due is the safe direction: the
    alternative parks the machine until its clock catches up, possibly
    forever, and silently."""
    future = (datetime.datetime.now() + datetime.timedelta(days=400)).isoformat()
    assert agent.should_show_form({"last_run": future}, SCHEDULE) is True


def test_schedule_prefers_server_value(agent):
    config = {"schedule": {"checkin_interval_seconds": 43200, "cancel_retry_seconds": 3600}}
    resolved = agent.resolve_schedule_from(config, {})
    assert resolved["checkin_interval_seconds"] == 43200


def test_schedule_falls_back_to_cached_value(agent):
    """An offline laptop keeps its configured cadence instead of silently
    reverting to the 6-month default -- the worst failure mode, because it is
    invisible and long-lived."""
    cached = {"checkin_interval_seconds": 86400, "cancel_retry_seconds": 3600}
    resolved = agent.resolve_schedule_from({}, {"schedule": cached})
    assert resolved == cached


def test_schedule_falls_back_to_default_when_nothing_known(agent):
    assert agent.resolve_schedule_from({}, {}) == agent.DEFAULT_SCHEDULE


def test_malformed_server_schedule_is_rejected(agent):
    cached = {"checkin_interval_seconds": 86400, "cancel_retry_seconds": 3600}
    bad = {"schedule": {"checkin_interval_seconds": "soon"}}
    assert agent.resolve_schedule_from(bad, {"schedule": cached}) == cached


def test_retry_longer_than_interval_is_rejected(agent):
    bad = {"schedule": {"checkin_interval_seconds": 3600, "cancel_retry_seconds": 86400}}
    assert agent.resolve_schedule_from(bad, {}) == agent.DEFAULT_SCHEDULE
