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
    """Fresh beats cached. The cached value must be a DIFFERENT valid schedule,
    or this asserts nothing about ordering -- against an empty state a
    cache-first implementation passes this test too.
    """
    fresh = {"checkin_interval_seconds": 43200, "cancel_retry_seconds": 3600}
    cached = {"checkin_interval_seconds": 86400, "cancel_retry_seconds": 7200}
    resolved = agent.resolve_schedule_from({"schedule": fresh}, {"schedule": cached})
    assert resolved == fresh


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


def test_bool_schedule_values_are_rejected(agent):
    """bool subclasses int, so True would otherwise pass as a 1-second
    interval -- a check-in prompt every second on every laptop in the fleet.
    """
    bad = {"schedule": {"checkin_interval_seconds": True, "cancel_retry_seconds": True}}
    assert agent.resolve_schedule_from(bad, {}) == agent.DEFAULT_SCHEDULE


def test_non_positive_schedule_values_are_rejected(agent):
    for interval, retry in ((0, 0), (-1, -1), (43200, 0)):
        bad = {
            "schedule": {
                "checkin_interval_seconds": interval,
                "cancel_retry_seconds": retry,
            }
        }
        assert agent.resolve_schedule_from(bad, {}) == agent.DEFAULT_SCHEDULE, (interval, retry)


@pytest.mark.parametrize(
    "seconds,expected",
    [
        (3600, "1 hour"),
        (14400, "4 hours"),
        (43200, "12 hours"),
        (86400, "1 day"),
        (259200, "3 days"),
        (604800, "7 days"),
        # Not a whole number of days -> hours, rounded, never below 1.
        (90000, "25 hours"),
        (5400, "2 hours"),
        (60, "1 hour"),
    ],
)
def test_humanize_seconds(agent, seconds, expected):
    """Pins the wording the cancel dialog shows. Format-Duration in
    AssetlyAgent_Windows.ps1 implements the same two rules; nothing in this
    suite can execute the PowerShell, so this is the spec both sides mirror."""
    assert agent._humanize_seconds(seconds) == expected


SERVER_CONFIG = {
    "user_fields": [],
    "hardware_fields": [],
    "schedule": {"checkin_interval_seconds": 43200, "cancel_retry_seconds": 3600},
}


def _stub_main_preamble(agent, monkeypatch, calls, state):
    """Neutralises everything main() does before the guard, so these tests
    observe only the fetch/guard ordering."""
    monkeypatch.setattr(agent.time, "sleep", lambda _s: None)
    monkeypatch.setattr(agent, "resolve_credential", lambda cfg: "cred")
    monkeypatch.setattr(agent, "self_update", lambda: None)
    monkeypatch.setattr(agent, "flush_queue", lambda: None)
    monkeypatch.setattr(agent, "load_state", lambda: state)
    monkeypatch.setattr(agent, "save_state", lambda s: None)

    def fake_fetch():
        calls.append("fetch")
        return SERVER_CONFIG

    monkeypatch.setattr(agent, "fetch_config", fake_fetch)


def test_not_due_run_fetches_exactly_once_before_the_guard(agent, monkeypatch):
    """The reorder's core property: config is fetched before the guard decides,
    exactly once, and the guard still stops a run that is not due without
    clobbering the state it was given."""
    calls = []
    recent = datetime.datetime.now().isoformat()
    state = {"last_run": recent}
    _stub_main_preamble(agent, monkeypatch, calls, state)
    monkeypatch.setattr(
        agent, "collect_hardware", lambda: pytest.fail("guard did not stop the run")
    )
    monkeypatch.setattr(sys, "argv", ["inventory_agent.py"])

    with pytest.raises(SystemExit) as exc:
        agent.main()

    assert exc.value.code == 0
    assert calls == ["fetch"]
    assert state["schedule"] == SERVER_CONFIG["schedule"]
    assert state["last_run"] == recent


def test_force_reaches_the_form_with_the_same_fetched_config(agent, monkeypatch):
    """--force bypasses the guard, and the form is built from the SAME response
    object the schedule came from -- the `is` check is what proves one fetch
    serves both, rather than a second call sneaking back in."""
    calls = []
    state = {"last_run": datetime.datetime.now().isoformat()}
    _stub_main_preamble(agent, monkeypatch, calls, state)
    monkeypatch.setattr(agent, "collect_hardware", lambda: {"serial_number": "S"})
    seen = {}

    class FakeForm:
        def __init__(self, hw, field_config, schedule, ui):
            seen["config"] = field_config
            seen["schedule"] = schedule
            seen["ui"] = ui
            self.submitted = False

        def mainloop(self):
            pass

    monkeypatch.setattr(agent, "InventoryForm", FakeForm)
    monkeypatch.setattr(sys, "argv", ["inventory_agent.py", "--force"])

    with pytest.raises(SystemExit) as exc:
        agent.main()

    assert exc.value.code == 0
    assert calls == ["fetch"]
    assert seen["config"] is SERVER_CONFIG
    # The form is also handed the resolved schedule, which is what lets the
    # cancel dialog name this company's retry instead of a hardcoded 24 hours.
    assert seen["schedule"] == SERVER_CONFIG["schedule"]
    # Same for the appearance: it rides on the same response, so a company that
    # customised its window gets that window on this run rather than one run
    # late. SERVER_CONFIG carries no "ui" key, which is the pre-appearance
    # server's response -- the built-in defaults are the correct outcome.
    assert seen["ui"] == agent.DEFAULT_AGENT_UI
    assert "cancelled_at" in state
