# conductor

Web administrator and self-service portal for Samba Active Directory
(`conductor`), plus the privileged local helper (`conductor-helper`). Part of
Samba Conductor v2; design in `../planning/docs/architecture.md`, phase spec
in `../planning/docs/p1-spec.md`.

Status: **P1 complete** (2026-10-02). Validated end to end in the two-DC
server-home lab, desktop and mobile: [`docs/usage-p1.md`](docs/usage-p1.md).

| | |
|---|---|
| ![Dashboard](docs/screenshots/desktop/03-dashboard.png) | ![Preview with re-authentication](docs/screenshots/desktop/04-preview-reauth.png) |
| ![Users on a phone](docs/screenshots/mobile/03-users.png) | ![Sign-in, pt-BR, dark](docs/screenshots/desktop/01-signin-pt-br.png) |

## What it does

- **Sign-in with the user's own AD account**: Kerberos through the `ad`
  library (LDAP simple bind only when configured). The ticket stays in
  memory for the session; no service account is used for anything the user
  does, so AD's own ACLs apply to every read and write.
- **Every bind sub-code handled**: an expired or must-change password (which
  AD proves right) leads to a change page that asks for the old password
  again; locked, disabled and expired accounts get a clear message;
  everything else is "wrong username or password".
- **2FA (TOTP + recovery codes)**: mandatory for administrators (and by
  default for helpdesk and auditors), `off` / `optional` / `required` for
  everyone else. Administrators without 2FA enroll only through a one-time
  link, so a stolen administrator password is not enough to register a
  device.
- **Roles by AD group SID**, re-checked against AD (tokenGroups) on every
  privileged request, cached at most 60 s:

  | Role | Group (configurable) | May |
  |---|---|---|
  | admin | Domain Admins (RID 512) | everything below |
  | helpdesk | e.g. `Helpdesk` | search/view users, reset password, unlock, enable/disable (where AD delegates it; never on privileged accounts) |
  | auditor | e.g. `Auditors` | read-only admin views, audit log, domain info |
  | everyone | | self-service |

- **Administration**: dashboard; users (server-side sorted search and
  pagination, create, edit, enable/disable, unlock, reset password, move,
  delete, group membership, 2FA reset and enrollment links); groups
  (members with paging, nesting, create, delete, add/remove members); OUs
  (tree, create, rename, move, delete when empty); computers (enable/
  disable, move, delete; domain controllers protected).
- **Preview before every write**: the exact LDAP changes (passwords
  redacted) are shown and applied only after confirmation; changes to
  administrator accounts and privileged groups need password + TOTP again.
- **Self-service**: profile, edit of the attributes Samba lets users write
  on themselves (phones, office, address, web page), password change,
  2FA, sessions and "sign out everywhere".
- **Audit log**: append-only SQLite table, hash-chained; viewer with
  filters, JSON lines export, `conductor audit verify`.
- **conductor-helper**: the only root process, on a Unix socket only the
  `conductor` user may use (SO_PEERCRED); P1 serves read-only domain
  information (functional levels, FSMO roles, DCs), every call logged and
  audited.

## Security notes

- No JavaScript at all: CSP `script-src 'none'`, styles and images from the
  same origin only, `frame-ancestors 'none'`, HSTS, `Referrer-Policy:
  no-referrer`.
- CSRF token on every POST plus Fetch-metadata/Origin checks; the sign-in
  form uses a double-submit pre-session cookie.
- Session cookie `__Host-conductor` (HttpOnly, Secure, SameSite=Strict),
  server-side sessions, idle 15 min, absolute 8 h, new ID after 2FA.
- Rate limits per client address and per account on sign-in, 2FA and
  password pages; the per-account limit stops before AD would lock the
  account.
- Errors never show LDAP or samba-tool output; details go to the journal
  without secrets.
- TOTP secrets sealed with AES-256-GCM under a key from systemd credentials,
  bound to the user's SID; replayed codes are refused.
- systemd sandboxing: `conductor` runs with no capabilities and
  `ProtectSystem=strict`; the helper keeps only the file capabilities it
  needs and no network beyond localhost.

## Documentation

- [Install (Debian 13 / Ubuntu 26.04)](docs/install.md)
- [Configuration reference](docs/config.md)
- [P1 lab run (e2e transcript)](docs/usage-p1.md) and [screenshots](docs/screenshots/)

## Development

```sh
make check       # gofmt, go vet, staticcheck, govulncheck, go test -race
make build       # bin/conductor, bin/conductor-helper (CGO off, static)
scripts/lab-deploy.sh [--snapshot]   # build on server-home, install on the lab's dc1
e2e/run-lab.sh [--no-deploy] [desktop|mobile]   # Playwright suite on server-home
```

The module uses `replace github.com/samba-conductor/ad => ../ad` until the
family has a public home. Layout:

| Path | What |
|---|---|
| `cmd/conductor` | `serve`, `setup`, `enroll-link`, `audit verify|export`, `version` |
| `cmd/conductor-helper` | the privileged helper |
| `internal/web` | HTTP server, routes and guard, sessions, pages, templates, CSS |
| `internal/store` | SQLite state, embedded migrations, audit hash chain |
| `internal/directory` | sign-in and connections through `ad` |
| `internal/totp`, `internal/secret` | RFC 6238, recovery codes, AES-GCM sealing |
| `internal/i18n` | message catalogs (`en`, `pt-BR`) |
| `internal/helperd` | helper socket server |
| `deploy/systemd` | units |
| `e2e` | Playwright suite |

License: MIT.
