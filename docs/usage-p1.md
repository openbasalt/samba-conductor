# P1 lab run

Transcript of `e2e/run-lab.sh` against the lab
([testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md)), run on 2026-10-02 from commit `1eef13d`. No
secrets appear: passwords reach the Playwright container only through a
temporary 0600 env file on the lab host, the tests never log them, and this
transcript was checked against the lab's secrets file before committing.
Screenshots mask TOTP secrets, QR codes and recovery codes (the lab's 2FA
enrollments are destroyed by the next `reset.sh` anyway).

What happens (spec [design.md](design.md) §4):

1. `scripts/lab-deploy.sh --snapshot`: rsync to the lab host, build both
   binaries there (CGO off), reset the lab to `seeded`, install on dc1 with
   `lab/conductor-install.sh` exactly as [install.md](install.md)
   describes (system user, directories, units, `conductor setup
   --non-interactive`: CA pinned, Helpdesk/Auditors resolved to SIDs, TOTP
   key generated), start both units, snapshot both DCs as `conductor-p1`.
2. Per project (`desktop` 1366×900, `mobile` Pixel 7): `reset.sh
   conductor-p1`, `conductor enroll-link --user lab.admin` on dc1, the
   suite in `mcr.microsoft.com/playwright:v1.62.1-noble`, then
   `conductor audit verify` on dc1.

| Spec | Covers |
|---|---|
| `01-anonymous` | security headers, theme and language, `__Host-` cookie flags; anonymous access only to sign-in and static assets; CSRF-less POSTs refused (403); wrong password, unknown user, locked (775), disabled (533), expired account (701) messages; admin without enrollment link refused; per-account rate limit stops before AD lockout |
| `02-expired-password` | `must.change` (773) and `expired.password` (532): change page that asks for the old password (wrong one refused), then sign-in with the new one |
| `03-admin` | forced admin 2FA enrollment through the one-time link (nothing reachable before it), recovery codes, sign-in with TOTP; dashboard counts and locked accounts; users search, paging, status filter; domain levels, DCs and FSMO roles through conductor-helper |
| `04-admin-cycle` | create OU, child OU, user, group with previews; edit attributes; add to group; Domain Admins membership add/remove with re-authentication (wrong password refused first); disable/enable; move; rename OU; computer disable/enable/move/delete, DC protected; non-empty OU not deletable; delete everything; all of it in the audit log |
| `05-helpdesk` | helpdesk enrolls 2FA at first sign-in; reset (must change by default, password redacted in the preview) and unlock inside OU=People; AD refuses outside the delegated OU; conductor refuses on a Domain Admin; other roles' pages 403 |
| `06-auditor` | read-only views (no write controls), nested group view, forged write with a valid CSRF token refused by role (403), audit filter and JSON lines export with hashes, domain page |
| `07-selfservice` | regular user has no admin access; edit of SELF-writable attributes with preview; password change needs the current password; optional 2FA enroll, sign-in with it, disable with password + code; sign out everywhere |

Every test also fails on any CSP violation or page error.

```text
=== project desktop

Running 14 tests using 1 worker

  ✓   1 [desktop] › tests/01-anonymous.spec.ts:4:7 › anonymous visitor and sign-in failures › sign-in page, theme, language and security headers (1.1s)
  ✓   2 [desktop] › tests/01-anonymous.spec.ts:30:7 › anonymous visitor and sign-in failures › anonymous access is limited to sign-in and static assets (790ms)
  ✓   3 [desktop] › tests/01-anonymous.spec.ts:43:7 › anonymous visitor and sign-in failures › refused sign-ins get the right message (1.8s)
  ✓   4 [desktop] › tests/01-anonymous.spec.ts:59:7 › anonymous visitor and sign-in failures › an administrator without 2FA needs an enrollment link (654ms)
  ✓   5 [desktop] › tests/01-anonymous.spec.ts:66:7 › anonymous visitor and sign-in failures › per-account rate limit stops before AD locks the account (2.3s)
  ✓   6 [desktop] › tests/02-expired-password.spec.ts:6:7 › must.change changes the password with the old one (2.2s)
  ✓   7 [desktop] › tests/02-expired-password.spec.ts:6:7 › expired.password changes the password with the old one (2.0s)
  ✓   8 [desktop] › tests/03-admin.spec.ts:4:7 › administrator › forced 2FA enrollment through the one-time link (3.3s)
  ✓   9 [desktop] › tests/03-admin.spec.ts:26:7 › administrator › dashboard, users with server-side search and paging (30.2s)
  ✓  10 [desktop] › tests/03-admin.spec.ts:52:7 › administrator › domain information through conductor-helper (26.8s)
  ✓  11 [desktop] › tests/04-admin-cycle.spec.ts:5:5 › create, edit, move and delete with previews (1.7m)
  ✓  12 [desktop] › tests/05-helpdesk.spec.ts:3:5 › helpdesk resets and unlocks in its OU, never on an administrator (8.1s)
  ✓  13 [desktop] › tests/06-auditor.spec.ts:4:5 › auditor sees everything and changes nothing (9.1s)
  ✓  14 [desktop] › tests/07-selfservice.spec.ts:3:5 › self-service profile, password and optional 2FA (56.2s)

  14 passed (4.2m)
=== audit chain on dc1 after the desktop run
audit chain OK: 89 rows, head 3152abd3cd448b50cce104cf6d948300857fd06a3b669d3f568105f6de6745d9
=== project mobile

Running 14 tests using 1 worker

  ✓   1 [mobile] › tests/01-anonymous.spec.ts:4:7 › anonymous visitor and sign-in failures › sign-in page, theme, language and security headers (1.4s)
  ✓   2 [mobile] › tests/01-anonymous.spec.ts:30:7 › anonymous visitor and sign-in failures › anonymous access is limited to sign-in and static assets (886ms)
  ✓   3 [mobile] › tests/01-anonymous.spec.ts:43:7 › anonymous visitor and sign-in failures › refused sign-ins get the right message (2.0s)
  ✓   4 [mobile] › tests/01-anonymous.spec.ts:59:7 › anonymous visitor and sign-in failures › an administrator without 2FA needs an enrollment link (541ms)
  ✓   5 [mobile] › tests/01-anonymous.spec.ts:66:7 › anonymous visitor and sign-in failures › per-account rate limit stops before AD locks the account (2.3s)
  ✓   6 [mobile] › tests/02-expired-password.spec.ts:6:7 › must.change changes the password with the old one (2.1s)
  ✓   7 [mobile] › tests/02-expired-password.spec.ts:6:7 › expired.password changes the password with the old one (1.8s)
  ✓   8 [mobile] › tests/03-admin.spec.ts:4:7 › administrator › forced 2FA enrollment through the one-time link (3.9s)
  ✓   9 [mobile] › tests/03-admin.spec.ts:26:7 › administrator › dashboard, users with server-side search and paging (33.8s)
  ✓  10 [mobile] › tests/03-admin.spec.ts:52:7 › administrator › domain information through conductor-helper (25.2s)
  ✓  11 [mobile] › tests/04-admin-cycle.spec.ts:5:5 › create, edit, move and delete with previews (1.7m)
  ✓  12 [mobile] › tests/05-helpdesk.spec.ts:3:5 › helpdesk resets and unlocks in its OU, never on an administrator (7.8s)
  ✓  13 [mobile] › tests/06-auditor.spec.ts:4:5 › auditor sees everything and changes nothing (10.0s)
  ✓  14 [mobile] › tests/07-selfservice.spec.ts:3:5 › self-service profile, password and optional 2FA (57.6s)

  14 passed (4.2m)
=== audit chain on dc1 after the mobile run
audit chain OK: 89 rows, head bca708e5be3316d19ed41e97783f56c279a9582895622429975f432d570f4701
```

The audit chain verified after each run (89 rows each). Unit and security
tests (`go test ./...`, same commit; `make check` also runs them with the race
detector, plus gofmt, go vet, staticcheck and govulncheck, all clean):

```text
ok  	github.com/openbasalt/samba-conductor/internal/config	0.004s
ok  	github.com/openbasalt/samba-conductor/internal/directory	0.003s
ok  	github.com/openbasalt/samba-conductor/internal/helperd	0.008s
ok  	github.com/openbasalt/samba-conductor/internal/i18n	0.002s
ok  	github.com/openbasalt/samba-conductor/internal/ratelimit	0.002s
ok  	github.com/openbasalt/samba-conductor/internal/secret	0.002s
ok  	github.com/openbasalt/samba-conductor/internal/store	0.007s
ok  	github.com/openbasalt/samba-conductor/internal/totp	0.001s
ok  	github.com/openbasalt/samba-conductor/internal/web	0.150s
```

Security tests in `internal/web`: `TestRouteGuards` walks every route of
the route table as anonymous, each sign-in stage and each role, and checks
who reaches the handler (refusals are 303 to sign-in or 403, and audited);
`TestCSRF` (missing, wrong, other session's token, cross-site Fetch
metadata, foreign Origin, sign-in without the pre-session cookie);
`TestAnonymousSurfaceAndHeaders`; `TestSigninRateLimits` (per account,
per address); `TestAdminWithoutMFAIsRefused`; `TestRoleRecheck` (group
removal effective after the 60 s cache, failed re-check signs out);
`TestAdminEnrollmentLinkAndTOTP` (link bound to the user, session ID
rotation, TOTP replay refused, recovery code single use, sign-in ends after
5 wrong codes); `TestSessionTimeoutsAndSignoutEverywhere`. `internal/store`
detects edited and re-hashed audit rows; `internal/helperd` refuses a peer
with another UID and operations outside the P1 allowlist.

Screenshots: [desktop](screenshots/desktop/) and [mobile](screenshots/mobile/).
