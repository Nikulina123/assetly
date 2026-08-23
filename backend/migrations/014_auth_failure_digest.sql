-- Auth-failure aggregation.
--
-- APPLY WITH psql --single-transaction (-1).
--
-- Replaces a per-event outbound email. Previously any request presenting a
-- syntactically valid but unrecognised bearer caused a background task to send
-- mail via Sendly -- with no valid credential required. That is unbounded
-- outbound email at our expense: quota exhaustion (which also suppresses the
-- legitimate check-in notifications customers rely on), sender-reputation
-- damage, and alert fatigue hiding a real incident.
--
-- An INSERT here is cheap and, unlike an email, cannot be amplified.

CREATE TABLE auth_failure_events (
    id          BIGSERIAL PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    key_prefix  TEXT NOT NULL,
    ip_address  TEXT
);

CREATE INDEX idx_auth_failure_events_time ON auth_failure_events (occurred_at);

-- Single-row table holding digest send state. The guard against two warm
-- serverless instances both sending is the conditional UPDATE in
-- app/notifications.py, not application-level coordination.
CREATE TABLE notification_state (
    id                  BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    last_digest_sent_at TIMESTAMPTZ,
    digests_sent_today  INTEGER NOT NULL DEFAULT 0,
    digest_day          DATE
);

INSERT INTO notification_state (id) VALUES (TRUE);

GRANT SELECT, INSERT, DELETE ON auth_failure_events TO assetly;
GRANT USAGE ON SEQUENCE auth_failure_events_id_seq TO assetly;
GRANT SELECT, UPDATE ON notification_state TO assetly;
