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
