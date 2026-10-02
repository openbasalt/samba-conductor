# Samba Conductor v2 — architecture

Status: design, 2026-10-01. Replaces the Meteor/MongoDB v1
(`github.com/edimarlnx/samba-conductor`, archived when v2 reaches its first
release). v1's analysis is the reason for this rewrite: security is the first
requirement, real time is not.

## 1. Goals

- **The web administrator for Samba Active Directory**: users, groups, OUs,
  computers, DNS, GPO links, service accounts, password policy, lockouts, plus
  a self-service portal for every user.
- **Integration components, separately deployable**: an OAuth2/OIDC identity
  provider backed by AD, a provisioning sync from AD to other directories
  (Google Workspace first; Microsoft Entra ID, SCIM 2.0, GitHub later), and
  domain backup/restore.
- **Runs as native services on the DC's VM** (systemd), Docker optional.
- **Security over convenience**: least privilege, no stored passwords, every
  change audited, every destructive operation previewed and confirmed.

Non-goals: shipping or packaging Samba itself (the distribution does), real
time UI, multi-domain forests in the first releases, being a terminal tool
(that is `tui-dc` in the tui-tools family; both share the AD library, §8).

## 2. Supported platforms (owner delegated the choice)

| Platform | Samba | Status |
|---|---|---|
| Debian 13 (trixie) | 4.22 (4.24 via backports) | primary, CI-tested |
| Ubuntu 26.04 LTS | distribution package | primary, CI-tested |
| Ubuntu 24.04 LTS | 4.19 | best effort |
| Other systemd distributions with Samba ≥ 4.19 | | community |

Minimum Samba 4.19, functional level 2016. amd64 and arm64 packages.

## 3. Components

One repository, one Go module, several binaries; each runs as its own systemd
unit with its own user and sandbox.

| Binary | Role | AD identity | Root |
|---|---|---|---|
| `conductor` | Admin web UI + self-service + API | **the signed-in user's own credentials** (AD ACLs apply) | no |
| `conductor-helper` | The few operations that need root on the DC (domain backup, local `samba-tool` tasks that have no network path) | root, local only | yes, narrow |
| `conductor-idp` | OAuth2 / OIDC provider (SAML later) | read-only service account | no |
| `conductor-sync` | Provisioning AD → Google Workspace (then Entra ID, SCIM, GitHub) | read-only service account | no |
| `conductor-backup` | Scheduled encrypted domain backups to S3-compatible storage, restore tooling, restore drills | via helper | no (helper does) |

Only `conductor` is required; the others are optional and can run on the same
VM or elsewhere (idp and sync need only LDAPS to a DC).

## 4. How AD is accessed

- **Reads and writes go over LDAPS (636) to the DC with the user's identity**:
  at sign-in the user's password is used once to obtain a Kerberos TGT
  (`gokrb5`); subsequent LDAP operations use GSSAPI with that ticket, so the
  password is never retained. Fallback when Kerberos is unavailable: LDAP simple
  bind over TLS with the password held encrypted in memory for the session's
  short TTL only. In both cases AD enforces what the user may do; the app's own
  role check is an additional layer, not the only one.
- **No root access to `sam.ldb` from the web process.** Operations that only
  `samba-tool` offers locally go through `conductor-helper`: a separate
  process on a Unix socket, an allowlist of typed operations (no free-form
  arguments), arguments validated, credentials passed via file descriptor or
  auth file (never argv), `--` before user values, output parsed into
  structured results, every call audited with the caller.
- **LDAP hygiene**: paged results (RFC 2696) everywhere, filter escaping
  (RFC 4515) and DN escaping (RFC 4514) in one library, CA pinning for LDAPS,
  server-side search and pagination in the UI.
- DNS management uses the DC's DNS RPC/`samba-tool dns` with the user's
  credentials; no hardcoded DC names (multi-DC aware: discover DCs from DNS
  SRV records, prefer the local one, fail over to others).

## 5. Security model

- **Sign-in**: AD username + password, then TOTP or WebAuthn second factor.
  **2FA mandatory for administrators; configurable (optional or required)
  for everyone else** (owner decision). Second-factor secrets stored encrypted
  in local state; WebAuthn credentials registered per user.
- **Administrator** = member of a configured AD group, matched by **SID**
  (default: Domain Admins, RID 512), re-checked against AD on every privileged
  request (cached ≤ 60 s). Delegated roles (helpdesk: reset passwords, unlock;
  read-only auditor) map to other AD groups by SID.
- **Sessions**: server-side, opaque cookie (`__Host-`, HttpOnly, Secure,
  SameSite=Strict), idle timeout 15 min, absolute 8 h, re-authentication for
  sensitive actions (password resets of admins, group membership of admin
  groups, settings).
- **Web hardening**: server-rendered HTML (Go templates, progressive
  enhancement with htmx at most), strict CSP without inline scripts, CSRF
  tokens on every form, `frame-ancestors 'none'`, HSTS, no third-party assets.
- **Rate limiting and lockout awareness**: per IP and per account for sign-in
  and self-service; surfaces AD lockout state; recommends a lockout policy if
  the domain has none.
- **Audit log**: append-only, hash-chained, every change with actor, target,
  before/after, source IP; exportable; optional forwarding to syslog/S3.
- **Previews**: every write shows exactly what will change (attributes, group
  memberships, or the helper operation) before confirmation, in the spirit of
  the tui-tools family.
- **State**: SQLite (WAL) in `/var/lib/conductor`, holding sessions, settings,
  second-factor secrets (encrypted with a key from systemd credentials /
  `LoadCredential`), audit log, and job history. AD stays the source of truth;
  no copy of the directory is kept.
- **systemd sandboxing** for every unit: dedicated user, `ProtectSystem=strict`,
  `NoNewPrivileges`, empty `CapabilityBoundingSet` (except the helper),
  `PrivateTmp`, `RestrictAddressFamilies`, `SystemCallFilter=@system-service`.
- **Supply chain**: reproducible builds, signed release artifacts and SBOM,
  Dependabot, `govulncheck` in CI, OpenSSF Scorecard (same practice as
  tui-tools).

## 6. Integration components

### conductor-idp
- OIDC provider (Authorization Code + PKCE only; discovery, JWKS with key
  rotation, userinfo, revocation), clients registered by admins, per-client
  allowed AD groups (by SID), `groups` claim with group names or SIDs, consent
  screen for third-party clients, refresh token rotation, tokens stored hashed.
- Authenticates users against AD (same Kerberos/LDAP path) and applies the
  same 2FA policy. SAML 2.0 IdP is a later phase (needed for Google Workspace
  SSO).

### conductor-sync (first connector: Google Workspace)
- One-way AD → Google via the Directory API (service account with domain-wide
  delegation): users, groups, memberships, suspension.
- **Plan, then apply**: every run computes a diff and shows it; scheduled runs
  apply only changes inside configured safety limits (e.g. at most N
  suspensions per run), otherwise stop and alert.
- Never deletes: removal from scope suspends; deletion is a manual,
  separately confirmed action.
- Scope by OU and/or AD group; attribute mapping configurable; dry-run mode
  first by default.
- Passwords are not synchronized; Google sign-in through `conductor-idp`
  (SAML) later, or users keep Google passwords until then.

### conductor-backup
- `samba-tool domain backup online` with proper credentials (via helper),
  encrypted with `age` before leaving the host, uploaded to S3-compatible
  storage, retention policy, alert on failure or missed schedule.
- Restore runbook and tooling (`samba-tool domain backup restore`), and a
  scheduled **restore drill** into an isolated container that verifies the
  restored domain answers LDAP and Kerberos.

## 7. Packaging and operation

- `.deb` packages (Debian/Ubuntu) and a tarball with systemd units; Docker
  image optional (for idp/sync anywhere; `conductor` itself on the DC host).
- `conductor setup`: interactive first-run (detect Samba, create the
  read-only service account with minimal rights, trust the domain CA, set the
  admin group SID, enroll the first admin's 2FA).
- TLS: built-in ACME or behind a reverse proxy; HTTP never served publicly.
- Health endpoints per unit; metrics behind authentication.
- Upgrades: database migrations embedded, configuration in
  `/etc/conductor/*.toml`, no state inside the package.

## 8. Shared AD library with tui-dc

The AD access layer (LDAP with paging and escaping, Kerberos, typed
`samba-tool` operations with an exact command preview) is written as a
standalone Go package so `tui-dc` (tui-tools) can use it too. It lives in this
repository first (`pkg/ad`), published as its own module once stable.

## 9. Phases

| Phase | Deliverable |
|---|---|
| P0 | Repo, CI (tests, govulncheck, lint), `pkg/ad` core (LDAP paging/escaping, Kerberos sign-in, typed helper protocol), Debian 13 + Samba test lab in CI |
| P1 | `conductor`: sign-in + mandatory admin 2FA, users/groups/OUs/computers, self-service (password change with old password, profile allowlist), audit log, previews, delegated roles |
| P2 | DNS, GPO links, service accounts, password policy and fine-grained policies, lockout view/unlock, bulk operations (CSV) |
| P3 | `conductor-backup` + helper: encrypted backups, restore tooling, restore drill in CI |
| P4 | `conductor-idp` (OIDC), then SAML |
| P5 | `conductor-sync` with the Google Workspace connector; then Entra ID, SCIM, GitHub |
| P6 | Packages (.deb, arm64), docs site, v1 archived with a pointer to v2 |
