# conductor: design

`conductor` is the web administrator and self-service portal for Samba
Active Directory, and `conductor-helper` is the small root process that
performs the few operations needing root on the domain controller. Users
sign in with their own AD account; every read and write goes to AD over
LDAPS with that user's Kerberos ticket, so AD's ACLs decide what happens
and conductor's roles are an additional layer. Every write is previewed,
confirmed and recorded in a hash-chained audit log. The cross-cutting
design is in
[architecture.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/architecture.md),
packaging in
[packaging.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/packaging.md),
and the AD access layer in the
[ad library design](https://github.com/openbasalt/samba-conductor-ad/blob/main/docs/design.md).

## Sign-in with the user's own identity

- The password is used once for a Kerberos AS exchange through `ad`; the
  session keeps only the ticket, in memory. A restart of conductor means
  signing in again. No service account is used for anything a user does.
- LDAP simple bind over TLS is an opt-in fallback
  (`simple_bind_fallback`) for when no KDC is reachable; the password is
  then kept sealed in memory under a per-process key for the session.
- Every AD bind sub-code is handled. An expired or must-change password,
  which AD proves right, leads to a change page that asks for the old
  password again (never an administrator reset). Locked, disabled and
  expired accounts get a clear message; everything else is "wrong
  username or password".
- Rate limits per client address (30 per minute) and per account (5
  failures in 15 minutes) apply to sign-in, second factor and password
  forms. The per-account limit sits below the domain lockout threshold,
  so conductor stops before AD locks the account. Both are in memory
  (one instance per host).

## Second factor

- TOTP (RFC 6238) with single-use recovery codes, and WebAuthn security
  keys and platform authenticators. Replayed TOTP codes are refused.
- Administrators always need a second factor; helpdesk and auditors do by
  default (`delegated_roles_required`); everyone else follows `policy`
  (`off`, `optional`, `required`).
- An administrator without a second factor enrolls only through a
  one-time link (24 h, bound to the username), made with
  `conductor enroll-link`, `conductor setup --first-admin` or by another
  administrator. With plain first-sign-in enrollment a stolen
  administrator password would be enough to register the thief's
  authenticator.
- `webauthn.admin_required` makes keys mandatory for administrators: TOTP
  is then refused for them and recovery codes remain the emergency path.
  Removing the last second factor of a user who must have one is refused.
  A signature counter regression (a possible clone) is refused.
- WebAuthn challenges live in the server-side session, bound to their
  purpose and single use. The user handle is a hash of the user's SID.
- TOTP secrets are sealed with AES-256-GCM (additional data: the user's
  SID) under a key from systemd `LoadCredential`.
- conductor-idp can use this second factor instead of its own (`[idp]
  mfa_socket`): a local socket only conductor-idp's user may use
  (SO_PEERCRED) answers whether a user is enrolled and must use a second
  factor (from the user's group SIDs, mapped to conductor's roles exactly
  as at sign-in), verifies codes (refusing TOTP when a key is mandatory)
  and runs WebAuthn assertions for the IdP's page (ceremonies kept here,
  single use, five minutes). Wrong codes count against the same per-user
  limit as conductor's sign-in; every verification is audited.

## Roles

| Role | Default group | May |
|---|---|---|
| admin | Domain Admins (RID 512) | everything |
| helpdesk | configured | view users, reset passwords, unlock, enable and disable, where AD delegates it |
| auditor | configured | read-only administration views, audit log |
| everyone | | self-service |

- Roles are configured as group SIDs and matched by SID, never by name or
  DN. They are read from the user's `tokenGroups` with the user's own
  ticket (fallback: an in-chain membership search plus the primary group)
  and re-checked on every privileged request, cached at most 60 s. A
  failed re-check ends the session instead of using stale roles.
- Protected accounts and groups: the configured administrator groups plus
  the well-known privileged groups (Domain, Enterprise and Schema Admins,
  Domain Controllers, GP Creator Owners, Administrators, Account, Server,
  Print and Backup Operators). Helpdesk is refused on them; administrators
  re-authenticate for any write to a protected account or to the
  membership of a protected group.
- Each route declares its permission; a table-driven test enumerates
  every route and role.

## Sessions and re-authentication

- Server-side sessions: metadata in SQLite (the session ID stored hashed),
  the ticket in memory. Cookie `__Host-conductor` (HttpOnly, Secure,
  SameSite=Strict). Idle timeout 15 minutes, absolute 8 hours (also bounded
  by the ticket), a new session ID after the second factor, "sign out
  everywhere".
- Re-authentication (password plus a fresh second factor) is required for
  writes to protected objects, password and lockout policy changes, CSV
  imports and bulk deletes, backup, sync and file server changes, and
  similar sensitive actions. It is a fresh Kerberos sign-in whose ticket
  then replaces the session's.
- The session remembers when it last passed a second factor (the sign-in,
  an enrollment or a re-authentication). The connected-accounts actions
  ask for the password and a second factor again only when that was more
  than five minutes ago (step-up), and are refused to a session that never
  passed one.

## Web hardening

- Server-rendered `html/template` pages, no single-page application, all
  assets embedded, no third-party assets.
- No JavaScript except one self-hosted script on the second-factor pages
  (WebAuthn needs the browser API) and on the page that shows a generated
  password once (a copy button, hidden without the script), loaded with a
  per-response CSP nonce and Subresource Integrity, with `connect-src
  'none'` (it fills a form field and submits, or writes to the clipboard).
  Every other page has `script-src 'none'`. Styles and
  images from the same origin only, `frame-ancestors 'none'`, HSTS,
  `Referrer-Policy: no-referrer`, same-origin opener and resource
  policies. Theme and language switch through links; confirmations are
  their own pages.
- CSRF: a token on every POST plus Fetch metadata and `Origin` checks; the
  sign-in form uses a double-submit pre-session cookie.
- Errors never show LDAP or samba-tool output; details go to the journal
  without secrets.
- Internationalized (English and Brazilian Portuguese), mobile-first,
  `data-e2e` attributes on interactive elements.

## Previews and plan, then apply

- Every write is built into an `ad.Operation` and kept in the server-side
  session as a pending operation (10 minutes, single use). The preview
  page shows its exact LDIF (secrets redacted); confirming applies that
  same object, with the permission re-checked. Nothing is rebuilt from the
  confirming request, and passwords never travel back to the browser in
  hidden fields.
- Integrations that act elsewhere use plans bound to a digest:
  conductor-sync and conductor-files re-plan at apply time and refuse to
  run unless the digest of the fresh plan equals the reviewed one.

## Audit log

- An append-only SQLite table. Triggers refuse UPDATE and DELETE; each row
  stores the SHA-256 of the previous row's hash and its own canonical
  content. `conductor audit verify` checks the chain; the viewer filters
  and exports JSON lines.
- Each entry records the actor (SID and name), action, target, the
  preview or helper request, result, source address, user agent and time.
- The log is local; forwarding to syslog or object storage is not
  implemented.

## State and credentials

- SQLite through a pure-Go driver (CGO off), WAL, one connection,
  embedded migrations, at `/var/lib/conductor/conductor.db` (0600):
  session metadata, second-factor secrets and keys, enrollment links,
  bulk job reports, backup results, audit log. AD stays the source of
  truth; no copy of the directory is kept.
- The TOTP key comes from systemd `LoadCredential` (or a 0600 key file).
- Configuration in `/etc/conductor/conductor.toml`; unknown keys and
  invalid values stop the start, so a typo never falls back to a default.
- conductor listens on 8443 by default so its unit keeps an empty
  capability set; port 443 through socket activation or a reverse proxy
  on loopback. Plain HTTP only on loopback behind a proxy.

## conductor-helper

- The only root process. It listens on `/run/conductor-helper/helper.sock`
  (root:conductor, 0660) and checks every connection with `SO_PEERCRED`
  against the conductor UID. The protocol (typed requests, strict
  decoding, allowlist) is defined in the `ad` library's `helper` package.
- Enabled for conductor: ping, domain functional levels, FSMO roles, the
  DC list and, with backups configured, backup status, "back up now" or
  "run drill now" requests and the backup policy. Operations in the
  protocol but not enabled for a peer are refused.
- With backups on, a second socket (`backup.sock`, root:conductor-backup)
  admits only conductor-backup and serves only the online backup.
- samba-tool runs with typed operations, no secrets in argv; its output
  stays in the helper's journal. Every call is logged by the helper and
  audited by conductor with the caller.
- The helper unit keeps only the file capabilities it needs and may reach
  localhost only.

## First password and reset by e-mail

Every other write in conductor uses the signed-in user's own identity.
An invitation or a reset by e-mail has no signed-in user with the right
to set the password, so that right lives in a separate service,
conductor-provisioner, with a delegated account limited to the managed OUs
(Reset Password, `lockoutTime`, `pwdLastSet`, `userAccountControl`, nothing
else). conductor asks it over a local socket; it checks every request on
its own: the target is a user below a managed OU, read fresh from AD by
SID, and not privileged (membership of the administrative and operator
groups or conductor's role groups, `adminCount`, or an access entry that
grants more than read on the domain, an OU, AdminSDHolder or a Group
Policy object). Hourly ceilings bound what a compromised conductor could
do.

- Token model: 32 random bytes, single use, bound to the account's SID,
  objectGUID and `pwdLastSet` at issue (a password set elsewhere voids
  it), stored by conductor-provisioner as a hash. conductor never stores
  it: the raw token is in the sealed mail queue until the relay accepts
  the message, and in a link record's memory, sealed, during the flow.
  conductor keeps its own expiry next to the token's id, and the shorter
  of the two lifetimes wins.
- Opening a link only validates it (a mail scanner consumes nothing); the
  button moves the token into a `__Host-` cookie and a server-side record
  (10 minutes), so it leaves the address bar and the history. The link
  pages run on that record only, never on a signed-in session, and send no
  Referer.
- Uniform answers: every unusable link gets the same page with the same
  status after the same check; the reset form answers before doing
  anything, the lookup and the message run in the background, and the
  audit log keeps a hash of what was typed.
- Second factor at reset: a user who has one must use it before the new
  password is accepted (optionally, resets need one). This is what
  separates reading the mailbox from owning the account. Five wrong
  answers revoke the link.
- An invitation enables the account only at the end, after the password
  and, when the policy requires it, the enrollment of a second factor; an
  abandoned flow leaves it disabled. conductor-provisioner enables only an
  account that was disabled when the invitation was issued, so it never
  re-enables an account an administrator disabled.
- After a reset every conductor session of the user ends. Any password
  change is followed by a notice to the account's address and the
  verified recovery address, with no link.
- Privileged accounts are never invited or reset by e-mail; their
  passwords are changed by an administrator, as before.

## Areas

- Users, groups, OUs, computers: server-side sorted search and
  pagination, create, edit an attribute allowlist, enable and disable,
  unlock, reset password, move, rename, delete (never recursive), group
  membership with nested views, 2FA reset and enrollment links. Domain
  controllers are protected.
- Self-service: profile, editing the attributes Samba's default SELF
  rights allow (phones, office, address, web page), password change with
  the old password, own second factors and sessions.
- Connected accounts (self-service, when the sync section is enabled): the
  user's own account on each directory conductor-sync provisions to, with
  the actions that target declares and its policy allows: activate it
  (on-demand provisioning) and set a new password, generated by
  conductor-sync and shown once (kept in the session's memory only until
  that page is opened) or typed by the user. conductor knows nothing of a
  particular target: it renders the state, reason codes, capabilities and
  password rules conductor-sync returns, and conductor-sync acts only on
  the signed-in user (by SID). Each action is confirmed, needs a recent
  second factor, is rate limited by conductor-sync and audited in both
  logs without the password
  ([self-service.md](https://github.com/openbasalt/samba-conductor-sync/blob/main/docs/self-service.md)).
- DNS: AD-integrated zones and records over LDAP with the user's
  credentials, paging and search, zone create and delete. The AD zones and
  the records AD manages are read-only; DCs are discovered, never named.
- Group Policy: GPOs and their links; link, unlink, enable, enforce, link
  order (GPMC semantics), block inheritance as LDAP writes. GPO create and
  delete also write SYSVOL, so conductor runs `samba-tool gpo` itself with
  the user's ticket in a private, temporary credential cache (no password,
  no root). Editing settings inside a GPO stays with RSAT or GPMC.
- Password policies: the domain policy (a warning and a suggested value
  when the lockout threshold is 0), PSOs and their targets, the effective
  policy of a user.
- Lockouts across DCs: lockout state and bad-password counters read from
  every DC (they are not replicated), an unreachable DC reported. Unlock
  writes `lockoutTime = 0` on every writable DC with the user's
  connection, reporting each DC in the preview, the result and the audit.
- Account health: expiring and expired passwords, never signed in, stale,
  disabled; CSV export with spreadsheet formulas neutralized.
- Bulk: CSV import with a strict template and actions on selected
  accounts. Every row is validated and built first (one invalid row
  rejects the file), the full preview (also as LDIF) is confirmed, then
  rows apply in the background with the user's ticket, each audited, with
  a report and retry of failed rows. Passwords are never in a CSV:
  generated passwords are shown once to the creating session. A restart
  interrupts a running job, which is reported as such.
- Security keys: see "Second factor".
- File servers: managed through
  [conductor-files](https://github.com/openbasalt/samba-conductor-files/blob/main/docs/design.md)
  agents on member servers, over mutually pinned TLS; administrators
  write, auditors read.
- Backups: the status, policy and drill results of
  [conductor-backup](https://github.com/openbasalt/samba-conductor-backup/blob/main/docs/design.md),
  read through the helper; "back up now", "run drill now" and policy
  changes are previewed and re-authenticated. Destinations, credentials
  and recipients are host configuration only. A dashboard banner warns
  about stale backups, failures and a stopped conductor-backup.
- Google Workspace sync (administrators only): settings, key, plans and
  applies of
  [conductor-sync](https://github.com/openbasalt/samba-conductor-sync/blob/main/docs/design.md)
  through its local management API. An apply requires typing a
  confirmation containing the start of the plan digest plus a fresh second
  factor.
  For a company whose AD starts empty while its people use Google, an
  import creates the AD users and groups once from the Google directory:
  conductor-sync reads Google with its read-only scopes
  ([import-from-google.md](https://github.com/openbasalt/samba-conductor-sync/blob/main/docs/import-from-google.md)),
  conductor writes AD as a bulk job (mail = the Google address, a random
  password nobody sees, change at next logon), and the sync then adopts
  the Google accounts by address.

- Single sign-on (administrators only): the applications, signing keys,
  settings and activity of
  [conductor-idp](https://github.com/openbasalt/samba-conductor-idp/blob/main/docs/design.md)
  through its local management API. OpenID Connect clients and SAML
  service providers are added from guided presets (Google Workspace,
  Grafana, Nextcloud, GitLab, generic) or SAML metadata (URL, file or
  text); allowed groups are picked from the directory by SID; a preview
  shows the claims or the assertion a real user would get, which also
  validates the draft. Every change is previewed and confirmed with a
  fresh second factor; a client secret is shown once and kept nowhere.
- Branding (administrators only, Settings > Branding): the organization's
  name, logos, favicon, colors, texts per language, support contact and
  links on the self-service pages here and on conductor-idp's sign-in
  pages. An edit is previewed in the light and the dark theme, then saved
  as a new version with the password and a fresh second factor and pushed
  to conductor-idp; any kept version can be restored the same way.
  Template overrides read from a directory can replace the header, the
  footer and the self-service home. Admin pages keep the product look
  ([branding.md](branding.md)).

## Decisions

- No JavaScript outside the second-factor pages and the one page that
  shows a generated password (its copy button): the CSP can then be
  `script-src 'none'` everywhere else, which removes script injection as a
  class.
- Pending operations kept server-side and applied as shown: what the
  administrator confirmed is exactly what runs.
- Enrollment by one-time link for administrators: a password alone must
  never be enough to take over an administrator's second factor.
- Roles from `tokenGroups` by SID, re-checked and failing closed: names
  and DNs can be renamed or spoofed; SIDs cannot.
- Rate limits below the domain lockout threshold: conductor must not
  become a tool to lock accounts out.
- Self-service allowlist taken from Samba's actual SELF rights (verified
  against a real domain), not from what would be convenient.
- DNS over LDAP rather than DNS RPC: same identity, ACLs and previews as
  every other write, and no subprocess.
- Unlock on every DC: `lockoutTime` replicates with a delay, and the
  lockouts page reads every DC.
- Port 8443 by default: no capability needed to bind it.
- Two helper sockets rather than adding conductor-backup to the conductor
  group, which would let it read conductor's TLS key.
- Import from Google split by privilege (2026-10-05): conductor-sync, which
  can write Google, only reads it for the import; conductor, which already
  writes AD with the administrator's identity and audits it, creates the
  objects. New accounts are enabled by default: with a password nobody
  knows they are as unusable as disabled ones, and only an enabled AD user
  adopts its Google account; disabled is an option per import.
- Branding without weakening the pages (2026-10-05): colors are CSS
  custom properties in a generated same-origin stylesheet and images are
  served from this origin with their checked type, so the CSP stays
  `script-src 'none'` and `style-src 'self'`; only `[branding]
  allowed_origins` can add image and font origins, on branded pages only.
  SVG is refused rather than sanitized (no sanitizer is shipped and a
  raster logo covers the need). A primary color below 4.5:1 on the light
  background is refused, an accent below 3:1 is a warning. Admin pages
  never take the branding, so an administrator always recognizes the
  product's own pages. Every save and restore is a new version (the
  history is append-only, the newest 50 kept) and needs a fresh second
  factor; conductor-idp keeps its own copy, pushed through its management
  API, so its sign-in pages keep their look while conductor is down. The
  consent note stays a single sign-on setting, shown on the Branding page
  with a link, so it is edited in one place.
- Policy editable from the web, destinations and recipients not: a
  compromised web process must not be able to redirect future backups to
  a new key or bucket.
