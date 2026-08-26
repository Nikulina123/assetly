# Security posture: encryption, backups, and disaster recovery

This document exists to close a documentation gap identified in an internal
security audit (SECURITY_AUDIT.md, finding L-4): nothing in this repository
previously stated the platform's encryption, backup, or recovery posture,
no backup restoration had ever been evidenced, and no RTO/RPO was
documented. Every claim below is explicitly tagged as either verified
against Supabase's public documentation, or not yet confirmed. Nothing here
is assumed.

## Database platform

This product's database is managed PostgreSQL hosted on Supabase, on the
**Free tier** (confirmed with the product owner, 2026-08-26).

## Encryption at rest

Confirmed -- Supabase documentation, retrieved 2026-08-26: Supabase's
security page (supabase.com/security) states "All customer data is
encrypted at rest with AES-256 and in transit via TLS." Supporting
secondary sources (e.g. Supabase's data-encryption docs) describe this as
provided by the underlying cloud infrastructure, always enabled, requiring
no configuration, and not something that can be disabled. The primary
Supabase security page does not explicitly break this statement out by
plan tier -- it is presented as a general platform capability rather than
a paid add-on, but this project has not independently verified the
encryption-at-rest setting inside its own Supabase project dashboard. To
be confirmed: check the Supabase dashboard for this specific project
(Settings) to verify the setting directly rather than relying solely on
the general platform statement.

## Encryption in transit

Confirmed -- Supabase documentation, retrieved 2026-08-26: the same
Supabase security page states data is encrypted "in transit via TLS."
Supabase's default connection strings require SSL/TLS. To be confirmed:
this project's actual database connection configuration (`DATABASE_URL`
and any pooler configuration) has not been independently inspected in
this task to verify that SSL/TLS enforcement has not been disabled or
downgraded (e.g. via an `sslmode=disable` override) at the application
level.

## Backups

- **Frequency and retention on the Free tier:** Confirmed -- Supabase
  documentation, retrieved 2026-08-26 (supabase.com/docs/guides/platform/backups):
  automatic daily backups apply only to Pro, Team, and Enterprise plan
  projects. The Free plan has **no automatic backups at all**. Supabase's
  own guidance for Free tier projects is to regularly export data
  manually using the Supabase CLI `db dump` command and maintain
  off-site backups. As of this document's writing, no evidence has been
  found that this project performs such manual exports -- this should be
  treated as an open gap, not merely a documentation gap.
- **Point-in-time recovery (PITR):** Confirmed -- Supabase documentation,
  retrieved 2026-08-26 (supabase.com/docs/guides/platform/backups and
  supabase.com/docs/guides/platform/manage-your-usage/point-in-time-recovery):
  PITR is available only as an add-on on Pro, Team, and Enterprise plan
  projects. It is **not available on the Free tier** at any price.
- **Has a restore ever been tested for this project?** No. See "Restore
  test procedure" below -- this section is a procedure, not a record of a
  test that has happened. An untested backup is not a backup. Given the
  above, on the Free tier there is presently no automated backup to
  restore from at all unless manual `db dump` exports have been
  established separately.

## RTO / RPO

**Not yet defined.** These are business decisions for the product owner to
set, not values this document invents. Template:

- Recovery Time Objective (RTO): ___________ (target time to restore
  service after a database loss)
- Recovery Point Objective (RPO): ___________ (maximum acceptable data
  loss, e.g. "up to the last daily backup" given the Free tier's backup
  frequency from above -- note that on the Free tier this would currently
  have to read "up to the last manual export," since there is no
  automatic backup to fall back on)

## Restore test procedure

**No restore has been performed as of this document's last edit.** This
section is a runnable procedure, not a record of a test that happened. The
table below stays empty until it is actually run.

1. Create a new, separate scratch Supabase project (do NOT restore into or
   overwrite the production project).
2. In the Supabase dashboard for the PRODUCTION project, locate the most
   recent automated backup (Settings -> Database -> Backups). Note: per
   the "Backups" section above, the Free tier has no automated backups --
   if this project is still on the Free tier when this procedure is run,
   this step may instead need to restore from a manual `db dump` export,
   or the project may first need to be upgraded to a paid tier to have
   an automated backup available at all. Confirm the current backup
   situation before proceeding.
3. Follow Supabase's documented restore flow to restore that backup into
   the scratch project created in step 1. (Consult Supabase's current
   documentation for the exact restore flow at the time this is run --
   dashboard UIs change.)
4. Once restored, verify data integrity against the production project
   without writing to production:
   - Compare row counts for `companies`, `devices`, `device_checkins`,
     `device_credentials`, `admins` between the scratch (restored) project
     and production.
   - Spot-check one known row (e.g. a specific company's `name` and
     `notification_email`) matches between the two.
5. Record the outcome in the table below.
6. Tear down the scratch project (delete it) once verification is
   complete -- it holds a full copy of production data and should not be
   left running.

| Date run | Operator | Outcome | Notes |
|----------|----------|---------|-------|
| _(none yet)_ | | | |

## GDPR — data protection gaps

This product processes employee personal data (names, work email
addresses, department). The following are currently MISSING and are
flagged here, not drafted here -- they require legal counsel, not this
document:

- [ ] **Data processing agreement (DPA)** -- none currently in place
      between this product's operator and its customers (the companies
      whose employee data is processed). Needs legal counsel.
- [ ] **Documented lawful basis** for processing employee personal data --
      not currently documented. Needs legal counsel / the product owner.
- [ ] **Documented retention period** for employee personal data -- not
      currently documented. (Note: `device_checkins` and `devices` have no
      automatic expiry in the current schema -- confirm whether that is
      intentional once a retention period is decided.)
- [ ] **Subject-rights request process** (access, deletion, correction) --
      no documented process for an employee to request their data be
      corrected or deleted. Needs a decision on who owns this process
      operationally.

## Change log

| Date | Change |
|------|--------|
| 2026-08-26 | Document created, closing SECURITY_AUDIT.md L-4's documentation gap. Encryption/backup claims tagged per source. No restore test performed yet. RTO/RPO and GDPR items flagged as open, not resolved. |
