# Assetly — Pre-Launch Security Assessment

**Product:** Assetly Inventory Check-in (multi-tenant SaaS + Windows/macOS/Linux endpoint agents)
**Repository:** `Nikulina123/assetly`
**Assessment date:** 2026-08-20
**Scope:** Source-code review of the FastAPI backend (`backend/`), database schema and RLS policies (`backend/migrations/`), the admin/tenant portal, the three endpoint agents (`inventory_agent.py`, `AssetlyAgent_Windows.ps1`, installer scripts), CI (`.github/workflows/`), and deployment configuration (`vercel.json`).
**Method:** Manual static review against the AICPA Trust Services Criteria (Security / Availability / Confidentiality / Privacy) and the OWASP Top 10 (2021). No dynamic testing, no penetration test, no infrastructure or cloud-account review was performed.

> **Assessment type.** This is an internal engineering security review, not a SOC 1 or SOC 2 audit. SOC reports can only be issued by a licensed CPA firm and attest to *operating* controls over a period of time (Type II) — not to code. This document is designed to be the technical input to that process: it maps findings to Trust Services Criteria so the gaps a future auditor will raise are known and closed first.

---

## 1. Executive summary

Assetly is a well-engineered codebase. Tenant isolation is enforced at the database layer with PostgreSQL Row-Level Security (including `FORCE ROW LEVEL SECURITY`, so even the owning role is constrained), all secrets are stored as SHA-256 or bcrypt hashes rather than plaintext, every SQL statement is parameterised, CSRF tokens are enforced on state-changing admin forms, admin login is deliberately hardened against user enumeration via a constant-cost dummy bcrypt comparison, and templates autoescape. The engineering rationale is documented inline to an unusually high standard, which materially helps auditability.

However, **the product is not ready to launch as-is.** Three issues are launch-blocking, all of them on the endpoint-agent side rather than in the backend:

1. **Unsigned, unverified remote self-update.** Every agent, on every run, downloads a script or executable from a public GitHub raw URL and overwrites and re-executes itself with no signature check and no publisher verification. A compromise of one GitHub account yields remote code execution on every managed endpoint in every customer's fleet.
2. **Company-wide enrollment token written world-readable on macOS.** `chmod 644` on a shared config file exposes a 90-day, unlimited-use fleet credential to every local user on the machine.
3. **No rate limiting anywhere**, including on admin login (credential stuffing) and on an unauthenticated endpoint that triggers outbound email (abuse/amplification).

A further set of medium findings — absence of MFA on the admin tier, no audit logging, no session expiry, unbounded input fields, and a device credential that is not bound to the device it was issued for — would each be raised as a control gap in a SOC 2 Type II examination.

### Findings summary

| # | Finding | Severity | TSC |
|---|---|---|---|
| C-1 | Unsigned remote self-update → fleet-wide RCE | **Critical** | CC6.8, CC7.1, CC8.1 |
| C-2 | Enrollment token world-readable on macOS (`chmod 644`) | **Critical** | CC6.1, CC6.7 |
| H-1 | No rate limiting or lockout on admin login | **High** | CC6.1 |
| H-2 | No MFA on the admin tier; every admin sees every tenant | **High** | CC6.1, CC6.3 |
| H-3 | Unauthenticated email trigger (`notify_auth_failure`) | **High** | CC6.6, A1.2 |
| H-4 | No audit logging of privileged actions | **High** | CC7.2, CC7.3 |
| M-1 | Device credential not bound to its serial number | Medium | CC6.1 |
| M-2 | Enrollment tokens: unlimited devices, 90-day life, reusable | Medium | CC6.2 |
| M-3 | No session expiry, no rotation on login, no server-side revocation | Medium | CC6.1 |
| M-4 | Unbounded string inputs on the check-in payload | Medium | CC6.8, A1.1 |
| M-5 | No HTTP security headers (HSTS/CSP/X-Frame-Options) | Medium | CC6.6 |
| M-6 | Installers and Windows executable are not code-signed | Medium | CC6.8 |
| M-7 | Passwordless `sudo` rule installed on Linux endpoints | Medium | CC6.3 |
| M-8 | `python-multipart==0.0.9` carries a known DoS CVE; no dependency scanning | Medium | CC7.1 |
| L-1 | Legacy shared company key still accepted for check-in | Low | CC6.1 |
| L-2 | Partial API key material emailed on auth failure | Low | CC6.7 |
| L-3 | `/admin/diagnostics` discloses server filesystem paths | Low | CC6.6 |
| L-4 | No encryption-at-rest or backup/DR position documented | Low | CC6.7, A1.2 |

---

## 2. What is already correct

These are strengths worth stating explicitly, because they are what a client questionnaire will ask about and what an auditor will test first.

**Tenant isolation (CC6.1).** `device_checkins`, `devices`, and `company_fields` all carry `ENABLE ROW LEVEL SECURITY` + `FORCE ROW LEVEL SECURITY` with a policy keyed on `current_setting('app.company_id')`. `FORCE` is the important part: it means isolation holds even for the table-owning role, not just the low-privilege application role. Every read path in `backend/app/devices.py` sets `app.company_id` inside the same transaction as the query, and derives both the RLS setting and the `WHERE` clause from a single argument so the two cannot desynchronise. There is a dedicated regression test (`backend/tests/test_isolation.py`) proving company A cannot read company B's rows.

The two tables without RLS — `companies` and `device_credentials`/`enrollment_tokens` — are correctly reasoned: the lookup that *identifies* the tenant necessarily runs before the tenant is known. Isolation there is enforced in application code, and every list/revoke query filters on `company_id` explicitly.

**Credential storage (CC6.1).** No secret is ever stored in plaintext. API keys, enrollment tokens, and device credentials are stored as SHA-256 hashes; only a short non-secret prefix is retained for display. Admin passwords use bcrypt with per-password salts. Plaintext keys are returned exactly once at creation and never again.

**Credential generation.** All tokens use `secrets.token_hex(32)` — 256 bits of cryptographically secure randomness. This is well above any brute-force concern.

**SQL injection (OWASP A03).** Every query in the codebase uses asyncpg positional parameters. No string interpolation into SQL was found. The one dynamically-composed fragment (`_DEVICE_COLUMNS`) is a module-level constant containing no user input.

**Cross-site scripting (OWASP A03).** Jinja2 autoescaping is active for `.html` templates. Email bodies in `notifications.py` explicitly `html.escape()` every interpolated value, including keys and values of the free-form `custom_fields` dictionary.

**CSRF (OWASP A01).** Every state-changing admin route requires a session-bound CSRF token. The tenant portal is deliberately read-only and adds no new CSRF surface.

**User enumeration (CC6.1).** `resolve_admin` performs a bcrypt verification against a fixed dummy hash when the email does not exist, so a nonexistent account and a wrong password take comparable time.

**Session cookies.** `SessionMiddleware` is configured with `same_site="lax"` and `https_only` driven by `SESSION_COOKIE_SECURE`. **Action required: confirm `SESSION_COOKIE_SECURE=true` is set in the production environment** — it defaults to `false`, and left unset the session cookie will be transmittable over plaintext HTTP.

**Secret hygiene in version control.** `backend/.env` is correctly excluded by `.gitignore` and is not tracked. Only `.env.example` is committed.

**Health endpoint.** `/healthz` deliberately queries `SELECT 1` rather than any application table, so it proves database reachability without exposing tenant data to an unauthenticated caller.

**Input validation on the admin write path.** `agent_ui.py` validates hex-colour syntax, copy length, and placeholder safety, and rejects the whole submission rather than silently clamping. The schedule has both application-layer bounds and a database `CHECK` constraint as a backstop.

---

## 3. Critical findings

### C-1 — Unsigned remote self-update gives fleet-wide remote code execution

**Severity: Critical.** `inventory_agent.py:364` (`self_update`), `AssetlyAgent_Windows.ps1:500` (`Invoke-SelfUpdateExe`) and `:558` (`Invoke-SelfUpdate`).

Every agent, on every run, fetches its own replacement from a hardcoded public GitHub raw URL:

```
https://raw.githubusercontent.com/Nikulina123/Check-in_Agent/main/inventory_agent.py
https://raw.githubusercontent.com/Nikulina123/Check-in_agent/refs/heads/main/backend/static/AssetlyAgent_Windows.exe
```

It then compares a SHA-256 of the downloaded bytes against its own, and if they differ, **overwrites itself with the downloaded content and re-executes it.** The hash comparison is a change-detection mechanism, not an integrity control — it compares the new file to the old file, never to a known-good value. There is no code signature, no publisher pinning, no manifest, and no server-side authorisation of the update.

The Windows path adds a partial sanity check (rejects anything under 10 KB or lacking an `MZ` header), which defends against a captive-portal login page but not against an attacker-supplied valid PE.

**Attack paths, any one of which is sufficient:**

- Compromise of, or malicious insider access to, the `Nikulina123` GitHub account or a token with write access to that repository → arbitrary code executed on every endpoint in every customer fleet, on the next agent run. On macOS and Linux this runs as the logged-in user; the update is written into a user-writable path.
- Any local user or process able to write to `~/.assetly_inventory/config.json` (macOS/Linux) or `%LOCALAPPDATA%\AssetlyInventory\config.json` (Windows) can set `github_raw_url` to an attacker-controlled host and obtain persistent code execution under that account, re-established on every run.
- The update is fetched over TLS to a third party outside the customer's and Assetly's trust boundary. GitHub availability and integrity become a direct dependency of every customer endpoint.

**Why this is launch-blocking.** This is the single control most likely to end a security review by an enterprise client, and it is the finding most likely to be characterised as a supply-chain risk. It also fails CC8.1 (change management): agent code reaches production endpoints on a path with no approval gate, no release record, and no rollback.

**Remediation:**

1. **Short term — disable it.** Ship with self-update off (`github_raw_url` absent, `$GitHubRawUrl`/`$GitHubExeUrl` empty). Both agents already no-op cleanly when the URL is unset. Distribute updates through the existing portal download / MDM / GPO path, which is authenticated and admin-controlled.
2. **Medium term — sign the payload.** Publish updates from Assetly's own authenticated API (not GitHub raw), served as a signed manifest: version, SHA-256, and an Ed25519 or RSA signature over that manifest. Embed the public key in the agent at build time and verify the signature *before* writing anything to disk. Reject on any verification failure and log it.
3. **Additionally,** code-sign the Windows executable (Authenticode) and the macOS package (Developer ID + notarisation) — see M-6. Verify the signature of the downloaded artifact as a second, OS-enforced check.
4. Treat the agent's config file as security-relevant: on Windows, set an ACL restricting write access to the owning user and Administrators; on macOS/Linux the existing `chmod 600` is adequate once C-2 is fixed.

---

### C-2 — Company-wide enrollment token is world-readable on every Mac

**Severity: Critical.** `AssetlyAgent_macOS_postinstall.sh:141`.

The installer writes the shared seed config to `/Library/Application Support/Assetly/config.json` and explicitly sets `chmod 644`. That file contains `enrollment_token` — a credential that is valid for **90 days**, is **reusable an unlimited number of times**, and is scoped to the **entire company**.

The inline comment states this is "world-readable on purpose", because every account on the Mac must be able to seed its own copy at login. The mechanism is necessary; the permission is not the only way to achieve it.

**Impact.** Any local user, any unprivileged process, any piece of commodity malware, and any backup or MDM inventory collection that reads that path obtains a fleet-wide enrollment credential. With it, an attacker can:

- Enroll arbitrary fake devices into the customer's tenant, obtaining valid per-device credentials;
- Combined with M-1 (no serial binding), submit check-ins that overwrite the inventory records of *real* devices in that tenant — corrupting the asset register the product exists to provide;
- Continue doing so for up to 90 days, with no per-device limit and no signal that the token has leaked.

The same token is also embedded, in cleartext, in the Linux installer script (`AssetlyAgent_Linux.sh:160`) and in the trailing config block of the downloadable Windows `.exe` — both of which are distributed by email, file share, GPO, and MDM in normal use. Each of those is a credential-distribution channel with no protection.

**Remediation:**

1. **Immediately:** change the seed file to `chmod 600` root-owned, and have the per-user launcher — which already runs privileged logic at install time — seed each user's copy through a root-owned helper, or pre-create the per-user config at first login via a `LaunchDaemon`. The requirement is "each user gets a copy", not "every user can read the master".
2. **Set a device cap and a short life on installer-minted tokens.** `create_enrollment_token` already accepts `max_devices`; the three download routes in `backend/app/routers/admin.py` pass `None` (unlimited). Have the admin specify an expected device count at download time, and default the installer token life to days, not 90 days (see M-2).
3. **Give admins visibility.** Surface `used_count` against `max_devices` in the portal with an alert when a token is used at an unexpected rate — the only currently available detection for a leaked token.
4. Document token handling for customers: an installer is a credential, and should be distributed through MDM/GPO rather than email.

---

## 4. High findings

### H-1 — No rate limiting or account lockout on admin login

`backend/app/routers/admin.py:92`. `POST /admin/login` accepts unlimited attempts. There is no per-IP throttle, no per-account lockout, no exponential backoff, no CAPTCHA, and no alerting on repeated failures. bcrypt's work factor slows an attacker but does not stop credential stuffing against a known admin email.

No endpoint in the application is rate limited. `/api/v1/inventory/checkin`, `/api/v1/inventory/config`, and `/api/v1/enroll` are equally unbounded, which is also an availability concern on a serverless deployment where volume translates directly into cost.

**Remediation.** Add per-IP and per-account throttling on `/admin/login` with progressive delay and temporary lockout, plus an alert on N consecutive failures. Add coarse rate limits to the three agent endpoints. On Vercel, a platform WAF/rate-limit rule is the fastest path; `slowapi` or a small Postgres/Redis-backed counter works on any deployment.

### H-2 — No MFA on the admin tier, and every admin sees every tenant

`backend/migrations/002_admin_auth.sql`. There is a single global admin tier: any authenticated admin can read and modify **every** company's data, rotate their API keys, mint enrollment tokens, and download configured installers for them. Authentication is a password alone.

This is a documented design decision, and it is reasonable for a small internal operations team. It will still be raised in every enterprise security review and in a SOC 2 examination, on two counts: absence of MFA (CC6.1) and absence of least privilege / role separation (CC6.3). Compromise of one admin password is compromise of the entire customer base.

**Remediation.** (a) Enforce MFA — TOTP is sufficient and cheap to add to the existing bcrypt login. (b) Introduce roles (at minimum: read-only support vs. full admin) so routine work does not require the credential that can mint tokens. (c) Longer term, if customers are to administer their own tenants, add per-company admin scoping — the `admins` table has no `company_id`, so this is a schema change to plan for now rather than retrofit later.

### H-3 — Unauthenticated request can trigger outbound email

`backend/app/routers/checkin.py:44` and `backend/app/notifications.py:62`. Any request presenting a syntactically valid but unrecognised `Bearer` token causes a background task to send an email to `OPS_ALERT_EMAIL` via Sendly. This requires no valid credential.

An attacker can therefore generate unbounded outbound email at Assetly's expense: mailbox flooding, Sendly quota exhaustion (which would also suppress the *legitimate* check-in notifications customers rely on), sender-reputation damage, and alert fatigue that hides a real incident. Combined with the absence of rate limiting (H-1), this is trivially exploitable.

**Remediation.** Replace per-event email with aggregation: count auth failures and send at most one digest per interval (e.g. hourly), with a hard daily cap. Better, route this to a logging/metrics pipeline with alerting thresholds rather than to email at all.

### H-4 — No audit logging of privileged actions

There is no audit trail for: admin login (successful or failed), API key rotation, company revocation, enrollment-token creation or revocation, device-credential revocation, installer downloads, or field/schedule/appearance changes. The only durable records of privileged activity are the mutated rows themselves, which carry no actor and, in several cases, no timestamp.

This is a direct SOC 2 gap (CC7.2 monitoring, CC7.3 evaluation of security events) and makes incident response effectively impossible: after a suspected admin-account compromise there would be no way to determine what was accessed or changed, or by whom.

**Remediation.** Add an append-only `audit_log` table (`actor_admin_id`, `action`, `target_company_id`, `target_id`, `ip_address`, `user_agent`, `occurred_at`, `metadata JSONB`), written inside the same transaction as each privileged mutation. Grant the application `INSERT` only, never `UPDATE`/`DELETE`. Ship logs to a retained, tamper-evident store. Define and document a retention period.

---

## 5. Medium findings

### M-1 — A device credential is not bound to the device it was issued for

`backend/app/routers/checkin.py`. `device_credentials` records the `serial_number` a credential was enrolled for, but the check-in handler never compares `payload.serial_number` against it. Any valid device credential can submit a check-in claiming **any serial number**, and the `ON CONFLICT ... DO UPDATE` on `devices` will overwrite that device's record.

Consequently a single compromised endpoint — or anyone who obtained an enrollment token via C-2 — can rewrite the entire tenant's asset register: change owners, departments, hardware specs, and last-seen timestamps for machines they have no relationship to. For an asset-inventory product this is a direct attack on the integrity of the core deliverable.

**Remediation.** Reject a check-in whose `serial_number` does not match the enrolled serial for the presented credential (with a documented, admin-initiated re-enrollment path for legitimate hardware replacement). Keep the legacy company-key path exempt only for as long as L-1 remains open.

### M-2 — Enrollment tokens are long-lived, reusable, and uncapped

`backend/app/config.py` (`ENROLLMENT_TOKEN_DAYS = 90`) and the three download routes, which pass no `max_devices`. Reusability is a deliberate and correct choice for bulk GPO/MDM deployment. Unlimited devices for 90 days is not — it makes a leaked token maximally valuable and gives no natural expiry pressure.

**Remediation.** Prompt for an expected device count at installer-download time and set `max_devices` accordingly with modest headroom. Default installer tokens to 7–14 days. Keep 90 days available only as an explicit admin choice. Alert when `used_count` approaches or exceeds the cap.

### M-3 — Session management

`backend/app/main.py`. `SessionMiddleware` is used without `max_age`, so admin sessions live for Starlette's 14-day default. The session identifier is not rotated on login (`request.session["admin_id"]` is written into the pre-existing session), and because sessions are client-side signed cookies there is **no server-side revocation** — logging out, deleting an admin, or responding to a compromise cannot invalidate an already-issued cookie before it expires. `SESSION_SECRET_KEY` has no documented rotation procedure.

**Remediation.** Set an explicit `max_age` (8 hours is typical for an admin console) plus an idle timeout. Call `request.session.clear()` before writing `admin_id` on login. For genuine revocation, move to server-side sessions (a `sessions` table keyed by an opaque ID) — this also gives the "active sessions / sign out everywhere" control enterprise clients ask for. Document secret rotation.

### M-4 — Unbounded string inputs

`backend/app/models.py`. `CheckinRequest` declares `str` fields with no `max_length`, and `custom_fields: dict[str, str]` has no cap on key count, key length, or value length — and is explicitly not validated against the company's configured fields. The underlying columns are `TEXT`/`JSONB` with no length constraint.

Any holder of a device credential can therefore write megabytes per check-in, inflating storage cost and degrading portal queries. It is a storage-exhaustion and cost vector rather than an injection one (parameterised SQL and template autoescaping hold).

**Remediation.** Add `max_length` to every string field (256 is generous for hardware fields), cap `custom_fields` at a sane key count and per-value length, and add a request body size limit at the edge.

### M-5 — No HTTP security headers

No `Strict-Transport-Security`, `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`/`frame-ancestors`, or `Referrer-Policy` is set on portal responses. The portal is server-rendered with autoescaping, so the immediate XSS risk is low, but clickjacking of the admin console is currently unmitigated and there is no defence-in-depth if a template escaping gap is ever introduced.

**Remediation.** Add a small middleware setting all five. A strict CSP is achievable here because the templates carry no third-party script dependencies.

### M-6 — Installers and the Windows executable are not code-signed

The CI workflow compiles `AssetlyAgent_Windows.exe` with ps2exe and commits it; no Authenticode signature is applied. The macOS `.pkg` is assembled in-process by `backend/app/macos_pkg.py` and is neither signed nor notarised.

Practical consequences: SmartScreen and Gatekeeper will warn or block, driving customers to teach staff to bypass those warnings — a habit with security cost well beyond this product. It also means an endpoint has no OS-level way to distinguish a genuine Assetly agent from a substitute, which is what makes C-1 as severe as it is.

**Remediation.** Obtain an EV or OV code-signing certificate and sign in CI; obtain an Apple Developer ID, and sign and notarise the package. This is a prerequisite for any credible enterprise rollout.

### M-7 — Passwordless `sudo` rule installed on Linux endpoints

`AssetlyAgent_Linux.sh:87` writes `/etc/sudoers.d/assetly-inventory` granting the installing user `NOPASSWD: /usr/sbin/dmidecode`. The rule is correctly narrow (one absolute binary path, no wildcard, no argument freedom) and `dmidecode` is a read-only hardware query, so this is not a direct privilege escalation. It is nevertheless a persistent modification to the host's privilege configuration that customers must know about and consent to, and it will appear in their own endpoint-hardening audits.

**Remediation.** Document it prominently in deployment documentation and in the security FAQ. Consider reading `/sys/class/dmi/id/product_serial` where available, or falling back gracefully to `N/A`, to avoid needing the rule at all on modern systems.

### M-8 — Known-vulnerable dependency; no dependency scanning

`python-multipart==0.0.9` is affected by CVE-2024-53981 (resource exhaustion / excessive logging when parsing malformed multipart input), fixed in 0.0.18. The application accepts multipart form data on every admin POST route. There is no automated dependency scanning (Dependabot, `pip-audit`, or equivalent) in CI, so nothing in the pipeline would flag this or the next one.

**Remediation.** Upgrade `python-multipart` to ≥ 0.0.18 and review `fastapi`/`starlette` pins against current advisories. Enable Dependabot or add `pip-audit` as a CI gate. A documented patch SLA (e.g. critical within 7 days) is something enterprise questionnaires ask for directly.

---

## 6. Low findings

**L-1 — Legacy shared company key still accepted for check-in.** `ALLOW_LEGACY_COMPANY_KEY_CHECKIN` defaults to `true`, so a single shared, non-rotating, fleet-wide key remains a valid check-in credential. The reasoning (agents migrate only on their next run, up to six months out) is sound, but the flag needs an owner and a date. Track fleet conversion in the portal and set a target date to flip it to `false`.

**L-2 — Partial key material in alert emails.** `notify_auth_failure` emails the first 16 characters of the rejected bearer. For a token of the form `as_live_` + hex, that discloses 8 hex characters of secret material to a third-party email service. Truncate to the non-secret prefix (`as_live_`) plus a hash fragment instead.

**L-3 — `/admin/diagnostics` discloses server internals.** Absolute filesystem paths, directory listings, and artifact hashes. It is correctly authenticated; the concern is only that it widens what a compromised admin session yields. Consider restricting it to a subset of admins once roles exist (H-2).

**L-4 — Encryption at rest, backups, and DR are undocumented.** The database is managed (Supabase/Postgres, per the pooler notes) and almost certainly encrypted at rest with automated backups — but nothing in the repository states this, no backup restoration has been evidenced, and there is no documented RTO/RPO. Clients will ask; auditors will require evidence. Document the provider's encryption posture, backup frequency and retention, and perform and record a restore test.

**Also worth noting:** `backend/static/AssetlyAgent_Windows.exe` is committed to the repository and auto-committed by CI with `contents: write`. This is a reasonable trade-off given the portal reads it from disk, but a binary artifact in version control with an automated write path deserves branch protection on `main` and required review, so that neither the workflow nor a token can push agent code unreviewed.

---

## 7. Prioritised remediation plan

**Before launch (blocking)**

1. Disable agent self-update, or gate it behind signature verification — C-1
2. Fix macOS seed config permissions to `600` — C-2
3. Set `max_devices` and short expiry on installer-minted enrollment tokens — C-2 / M-2
4. Add rate limiting on `/admin/login` and the three agent endpoints — H-1
5. Replace per-event auth-failure email with a rate-capped digest — H-3
6. Confirm `SESSION_COOKIE_SECURE=true` in production; set session `max_age` and rotate on login — M-3
7. Upgrade `python-multipart`; enable dependency scanning in CI — M-8
8. Add `max_length` to all check-in fields and cap `custom_fields` — M-4
9. Bind device credentials to their enrolled serial number — M-1

**Within 30 days of launch**

10. MFA on the admin tier — H-2
11. Audit logging of all privileged actions — H-4
12. HTTP security headers middleware — M-5
13. Code-sign the Windows executable; sign and notarise the macOS package — M-6
14. Document encryption at rest, backups, and DR; perform and record a restore test — L-4
15. Branch protection and required review on `main`

**Within 90 days (SOC 2 readiness)**

16. Role separation for admins (read-only vs. full) — H-2
17. Server-side sessions with revocation — M-3
18. Signed update channel served from Assetly's own API — C-1
19. Written security policies: access control, incident response, change management, vendor management, secure SDLC
20. Formal vulnerability disclosure process and patch SLA
21. Independent penetration test (annual; clients will ask for the most recent report)
22. Engage a CPA firm; select a Type II observation window (typically 3–12 months)

---

## 8. Client security questionnaire — prepared answers

The answers below are accurate as of this assessment. **Items marked ⚠ depend on the blocking remediation above and must not be given to a client until that work has shipped.**

**Do you have a SOC 2 report?**
Not yet. We have completed an internal security assessment against the Trust Services Criteria and are executing a remediation plan toward SOC 2 Type II. This assessment and the remediation plan are available under NDA. We can commit to a target date for the observation window.

**How is customer data isolated in your multi-tenant system?**
Isolation is enforced at the database layer using PostgreSQL Row-Level Security with `FORCE ROW LEVEL SECURITY`, so the policy applies even to the table-owning role rather than relying solely on application query correctness. Every tenant-scoped query sets the tenant identifier within the same transaction as the query. We maintain automated regression tests that assert one tenant cannot read another's data.

**How are API keys and credentials stored?**
Never in plaintext. API keys, enrollment tokens, and device credentials are stored as SHA-256 hashes; only a short non-secret prefix is retained for display. Administrator passwords use bcrypt with per-password salts. Plaintext credentials are shown once at creation and cannot be retrieved afterwards. All credentials are generated from a cryptographically secure random source with 256 bits of entropy.

**Is data encrypted in transit and at rest?**
In transit: all API and portal traffic is HTTPS/TLS. At rest: the database is a managed PostgreSQL service with provider-managed encryption at rest — *[insert provider and specific attestation before sending]*.

**What data does the agent collect?**
Device hardware inventory (serial number, hostname, manufacturer, model, CPU, RAM, storage, OS and version, local IP address) and employee-provided identification (first name, last name, email address, department, plus any custom fields the customer's own administrator configures). The agent does not collect file contents, browsing history, keystrokes, screenshots, or application usage. Collection is periodic on a customer-configured interval, not continuous.

**Can the agent execute code on our machines?**
⚠ *After C-1 is remediated:* The agent runs as a scheduled task under the logged-in user account (not as root or SYSTEM) and communicates only with your tenant's Assetly API endpoint. Agent updates are distributed exclusively through the authenticated administrator portal or your own MDM/GPO tooling. *[If the signed update channel has shipped, add: automatic updates are cryptographically signed and verified before installation.]* On Linux, the installer adds a narrowly scoped passwordless `sudo` rule permitting only `/usr/sbin/dmidecode`, a read-only hardware query required to read the chassis serial number.

**Is the agent code-signed?**
⚠ Not currently; Authenticode signing for Windows and Developer ID signing with notarisation for macOS are scheduled — *[insert date]*.

**How do you authenticate administrators? Do you support SSO/MFA?**
Administrators authenticate with email and password (bcrypt). ⚠ MFA is on the near-term roadmap — *[insert date]*. SAML/OIDC SSO is not currently supported; we can discuss it as a roadmap item.

**Do you log administrative access?**
⚠ Comprehensive audit logging of privileged actions is in active development — *[insert date]*. Do not claim audit logging until H-4 has shipped.

**What is your vulnerability management process?**
Dependencies are pinned and reviewed; automated dependency scanning is being added to CI with a defined patch SLA (critical within 7 days, high within 30). ⚠ An independent penetration test is planned — *[insert date]*; we will share the executive summary under NDA once complete.

**What happens if a device or credential is compromised?**
Each enrolled device holds its own credential, which an administrator can revoke individually from the portal without affecting any other device. Company-level API keys can be rotated or revoked at any time. Enrollment tokens can be revoked, which blocks new enrollments while leaving already-enrolled devices operational.

**What are your backup and disaster recovery commitments?**
⚠ *[Complete after L-4 is addressed: state provider, backup frequency, retention period, RTO/RPO, and the date of the most recent tested restore.]*

**Do you have a documented incident response process?**
⚠ *[Complete after item 19. Do not answer affirmatively until the policy exists in writing.]*

**Where is data hosted?**
Application compute runs in the EU (Frankfurt, `fra1`). *[Confirm and state the database region — it must be verified, not assumed, particularly for GDPR-relevant customers.]* Note that the product processes employee personal data (names, work email addresses, department), so a GDPR data processing agreement and a documented lawful basis, retention period, and subject-rights process should be prepared before selling into the EU.

---

## 9. Scope limitations

This review is source-code analysis only, performed on the repository as of 2026-08-20. It did **not** include: dynamic or authenticated application testing; penetration testing; review of the production Vercel or database configuration, IAM, network controls, or logging; review of the actual production environment variables; GitHub organisation and access-control review; social engineering or physical security; or review of the Sendly email vendor's security posture. Absence of a finding here is not evidence that a control is effective in production — a SOC 2 Type II examination requires exactly that operational evidence, which code review cannot supply.
