-- Nullable, not NOT NULL: existing companies (created before this feature)
-- have no value yet. New companies get one required by the admin UI form
-- (app-layer requirement, not a DB constraint) -- notify_checkin_success
-- simply skips sending if a company's notification_email is empty/NULL.
ALTER TABLE companies ADD COLUMN notification_email TEXT;
