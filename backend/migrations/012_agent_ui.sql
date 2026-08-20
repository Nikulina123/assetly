-- Per-company appearance for the agent check-in window (copy + colours),
-- replacing values the agents each hardcoded. Same motivation as
-- 003_field_config.sql: an admin edit has to reach every already-installed
-- agent on its next run, with no rebuild and no re-download.
--
-- One JSONB column rather than the ~20 plain columns 010_checkin_schedule.sql
-- used. The schedule is two integers with a meaningful cross-column CHECK, so
-- columns bought real database-level validation. This is an open-ended
-- presentation blob: every key is optional-with-fallback, the validation that
-- matters (hex syntax, text-vs-background contrast, placeholder safety) is a
-- cross-key computation Postgres cannot express usefully, and adding a colour
-- later should not mean a migration against a live table. app/agent_ui.py owns
-- validation on the write path and is the only writer.
--
-- Default '{}' means "every key falls back to the built-in", so no existing
-- company changes appearance until an admin saves the form. The built-in
-- values live in DEFAULT_AGENT_UI (app/agent_ui.py) and are mirrored as each
-- agent's offline fallback -- deliberately NOT duplicated here, so there is
-- one authority per layer rather than a third copy that can drift silently.
--
-- No GRANT needed: 001_init.sql already grants SELECT, INSERT, UPDATE on
-- companies at table level, which covers columns added later.
ALTER TABLE companies
    ADD COLUMN agent_ui JSONB NOT NULL DEFAULT '{}'::jsonb;

-- Cheap backstop against a direct DB edit storing a scalar or an array, which
-- would make resolve_agent_ui's dict merge raise rather than fall back. The
-- key-level checks stay in Python where the error messages can be actionable.
ALTER TABLE companies ADD CONSTRAINT agent_ui_is_object CHECK (
    jsonb_typeof(agent_ui) = 'object'
);
