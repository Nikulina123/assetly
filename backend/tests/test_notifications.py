import json

import pytest

from app.notifications import send_email


class _FakeResponse:
    def __init__(self, body: bytes = b'{"id": "abc", "status": "queued"}'):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_send_email_posts_correct_request_shape(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["url"] = req.full_url
        captured["method"] = req.get_method()
        captured["headers"] = {k.lower(): v for k, v in req.headers.items()}
        captured["body"] = json.loads(req.data.decode())
        return _FakeResponse()

    monkeypatch.setattr("app.notifications.urllib.request.urlopen", fake_urlopen)
    monkeypatch.setattr("app.notifications.SENDLY_API_KEY", "sk_live_test123")
    monkeypatch.setattr("app.notifications.NOTIFICATION_FROM_EMAIL", "noreply@assetly.ge")

    send_email("customer@example.com", "Test Subject", "<p>Hello</p>", text="Hello")

    assert captured["url"] == "https://app.sendly.ge/api/v1/email/send"
    assert captured["method"] == "POST"
    assert captured["headers"]["authorization"] == "Bearer sk_live_test123"
    assert captured["headers"]["content-type"] == "application/json"
    assert captured["body"] == {
        "from": "noreply@assetly.ge",
        "to": "customer@example.com",
        "subject": "Test Subject",
        "html": "<p>Hello</p>",
        "text": "Hello",
    }


def test_send_email_omits_text_field_when_not_given(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured["body"] = json.loads(req.data.decode())
        return _FakeResponse()

    monkeypatch.setattr("app.notifications.urllib.request.urlopen", fake_urlopen)

    send_email("customer@example.com", "Subject", "<p>Hi</p>")

    assert "text" not in captured["body"]


def test_send_email_raises_on_http_error(monkeypatch):
    import urllib.error

    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)

    monkeypatch.setattr("app.notifications.urllib.request.urlopen", fake_urlopen)

    with pytest.raises(urllib.error.HTTPError):
        send_email("customer@example.com", "Subject", "<p>Hi</p>")


from app.notifications import notify_auth_failure, notify_checkin_success


def test_notify_checkin_success_sends_with_correct_content(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "app.notifications.send_email",
        lambda to, subject, html, text=None: captured.update(to=to, subject=subject, html=html),
    )

    notify_checkin_success(
        "owner@example.com", "my-laptop", "Nino Test", "Webiz ERP", {"department": "Engineering"}
    )

    assert captured["to"] == "owner@example.com"
    assert "my-laptop" in captured["subject"]
    assert "Webiz ERP" in captured["html"]
    assert "Department" in captured["html"]
    assert "Engineering" in captured["html"]


def test_notify_checkin_success_escapes_html_in_user_input(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "app.notifications.send_email",
        lambda to, subject, html, text=None: captured.update(to=to, subject=subject, html=html),
    )

    notify_checkin_success(
        "owner@example.com",
        "<script>alert('host')</script>",
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(2)>",
        {"<b>dept</b>": "<i>Eng</i>"},
    )

    assert "<script>alert(1)</script>" not in captured["html"]
    assert "<script>alert('host')</script>" not in captured["html"]
    assert "<img src=x onerror=alert(2)>" not in captured["html"]
    assert "&lt;script&gt;" in captured["html"]
    assert "&lt;img src=x onerror=alert(2)&gt;" in captured["html"]
    assert "<b>" not in captured["html"] and "</b>" not in captured["html"]
    assert "&lt;i&gt;Eng&lt;/i&gt;" in captured["html"]


def test_notify_checkin_success_noops_without_recipient(monkeypatch):
    called = []
    monkeypatch.setattr("app.notifications.send_email", lambda *a, **kw: called.append(1))

    notify_checkin_success(None, "my-laptop", "Nino Test", "Webiz ERP", {})

    assert called == []


def test_notify_checkin_success_does_not_raise_when_send_email_fails(monkeypatch):
    def failing_send(*a, **kw):
        raise ConnectionError("network down")

    monkeypatch.setattr("app.notifications.send_email", failing_send)

    notify_checkin_success("owner@example.com", "my-laptop", "Nino Test", None, {})  # must not raise


def test_notify_auth_failure_sends_to_ops_email(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "app.notifications.send_email",
        lambda to, subject, html, text=None: captured.update(to=to, subject=subject),
    )
    monkeypatch.setattr("app.notifications.OPS_ALERT_EMAIL", "ops@webiz.example")

    notify_auth_failure("wz_live_abc12345")

    assert captured["to"] == "ops@webiz.example"
    assert "Auth failure" in captured["subject"]


def test_notify_auth_failure_noops_without_ops_email(monkeypatch):
    called = []
    monkeypatch.setattr("app.notifications.send_email", lambda *a, **kw: called.append(1))
    monkeypatch.setattr("app.notifications.OPS_ALERT_EMAIL", "")

    notify_auth_failure("wz_live_abc12345")

    assert called == []
