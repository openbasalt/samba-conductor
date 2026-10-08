# P2 lab run

Transcript of `e2e/run-lab.sh` against the lab
([testing.md](https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md)), run on 2026-10-02 from commit `b766779`. No
secrets appear: passwords reach the Playwright container only through a
temporary 0600 env file on the lab host, the tests never log them, and this
transcript was checked against the lab's secrets file before committing.
Screenshots mask TOTP secrets, QR codes and recovery codes; the generated
passwords shown in `11-job-passwords` and `12-bulk-result` belong to
throwaway lab accounts that the next `reset.sh` destroys.

What happens (spec [design.md](design.md) §7):

1. `scripts/lab-deploy.sh --snapshot`: rsync to the lab host, build both
   binaries there, reset the lab to `seeded` (the P2 seed: DNS zones
   `apps.conductor.test` and `0.93.10.in-addr.arpa`, four lab GPOs with
   links and a blocked OU, the 20-day PSO `lab-staff-20d`, accounts
   expiring soon, `stale.user`), install on dc1 with
   `lab/conductor-install.sh` (`conductor setup` now also writes
   `[webauthn] rp_id = "dc1.lab.conductor.test"`), snapshot both DCs as
   `conductor-p2` (`conductor-p1` is kept as it was).
2. Per project (`desktop` 1366×900, `mobile` Pixel 7): `reset.sh
   conductor-p2`, an enrollment link for `lab.admin`, the suite in
   `mcr.microsoft.com/playwright:v1.63.0-noble`, then `conductor audit
   verify` on dc1.

| Spec | Covers |
|---|---|
| `01`-`07` | the P1 suite, unchanged (see [usage-p1.md](usage-p1.md)) |
| `08-dns` | zones of both partitions; DCs listed as discovered; the AD zones without a delete control; `_ldap._tcp` and the DC records AD-managed (no edit/delete), `intranet` editable; paging of a 65-name zone; zone create with the dNSProperty values and SOA/NS naming the connected DC; A record add (decoded record and SOA serial 1 → 2 in the preview), edit (old value deleted by its exact bytes), MX/TXT/CNAME/SRV adds, invalid data refused, record delete, zone delete with typed name, tree-delete control and re-authentication; reverse zone from `198.51.100.0/24` with a PTR |
| `09-gpo` | GPO list with links, enforced and disabled links, unlinked GPO; GPO view with the RSAT note and no delete while linked; link to an OU (assertion `(!(gPLink=*))`), second link at the lowest precedence, move up, enforce, disable, block and allow inheritance, unlink; GPO create and delete through `samba-tool` with the user's ticket (command in the preview, re-authentication for the delete) |
| `10-policy` | domain policy with the lockout values; min length 7 → 8 with re-authentication and back; threshold 0 shows the "never lock out" warning (cancelled); effective policy of `user0101` = `lab-staff-20d` with its expiry; PSO create (precedence 5, length 14), apply to `user0301`, its effective policy, unapply, delete |
| `11-health` | lockouts from dc1 and dc2 (per-DC bad-password counters: 3 on the DC that saw the attempts), unlock of a selected account through a job (preview, apply, report); expiring/expired, stale, disabled, never-signed-in lists; CSV export header; random password reset of two selected accounts, passwords shown once, downloaded once, then gone (410); delete of a selected account with the typed count and re-authentication |
| `12-bulk` | strict template: wrong header refused; unknown OU, unknown group and a duplicate reported together and nothing written; create 3 users with group membership (full preview, re-authentication, 3 applied, report CSV, 3 passwords downloaded once); update (title, `(clear)`, disable, group remove, move); cleanup by a selected delete |
| `13-webauthn` | a user registers a security key (the page alone loads the script; recovery codes issued), signs in with it; an administrator registers a key, re-authenticates a privileged-group change with it, removes it re-authenticating with the key; an authenticator without the credential is refused and the recovery code still works |
| `14-roles-p2` | auditor: every P2 page read-only (no write controls, PSOs not visible to it, as AD intends), forged writes with a valid CSRF token refused (403), write pages 403; helpdesk: lockouts and health with only the helpdesk actions, DNS/GPO/policy/bulk 403, write actions on selections 403, a protected account refused before AD is asked |

Every test also fails on any CSP violation or page error (the WebAuthn
pages included: their script runs under its nonce and SRI hash).

```text
=== project desktop

Running 34 tests using 1 worker

  ✓   1 [desktop] › tests/01-anonymous.spec.ts:4:7 › anonymous visitor and sign-in failures › sign-in page, theme, language and security headers (1.2s)
  ✓   2 [desktop] › tests/01-anonymous.spec.ts:30:7 › anonymous visitor and sign-in failures › anonymous access is limited to sign-in and static assets (843ms)
  ✓   3 [desktop] › tests/01-anonymous.spec.ts:43:7 › anonymous visitor and sign-in failures › refused sign-ins get the right message (2.2s)
  ✓   4 [desktop] › tests/01-anonymous.spec.ts:59:7 › anonymous visitor and sign-in failures › an administrator without 2FA needs an enrollment link (641ms)
  ✓   5 [desktop] › tests/01-anonymous.spec.ts:66:7 › anonymous visitor and sign-in failures › per-account rate limit stops before AD locks the account (2.5s)
  ✓   6 [desktop] › tests/02-expired-password.spec.ts:6:7 › must.change changes the password with the old one (2.5s)
  ✓   7 [desktop] › tests/02-expired-password.spec.ts:6:7 › expired.password changes the password with the old one (2.0s)
  ✓   8 [desktop] › tests/03-admin.spec.ts:4:7 › administrator › forced 2FA enrollment through the one-time link (3.3s)
  ✓   9 [desktop] › tests/03-admin.spec.ts:26:7 › administrator › dashboard, users with server-side search and paging (7.1s)
  ✓  10 [desktop] › tests/03-admin.spec.ts:59:7 › administrator › domain information through conductor-helper (25.9s)
  ✓  11 [desktop] › tests/04-admin-cycle.spec.ts:5:5 › create, edit, move and delete with previews (1.7m)
  ✓  12 [desktop] › tests/05-helpdesk.spec.ts:3:5 › helpdesk resets and unlocks in its OU, never on an administrator (8.1s)
  ✓  13 [desktop] › tests/06-auditor.spec.ts:4:5 › auditor sees everything and changes nothing (9.6s)
  ✓  14 [desktop] › tests/07-selfservice.spec.ts:3:5 › self-service profile, password and optional 2FA (57.4s)
  ✓  15 [desktop] › tests/08-dns.spec.ts:4:7 › DNS › zones and records; AD records are read-only (4.8s)
  ✓  16 [desktop] › tests/08-dns.spec.ts:42:7 › DNS › create a zone, add/edit/delete records, delete the zone (55.3s)
  ✓  17 [desktop] › tests/08-dns.spec.ts:113:7 › DNS › a reverse zone from a network, with a PTR record (59.1s)
  ✓  18 [desktop] › tests/09-gpo.spec.ts:4:7 › Group Policy › GPOs and links; settings editing is out of scope (32.0s)
  ✓  19 [desktop] › tests/09-gpo.spec.ts:20:7 › Group Policy › link, enforce, disable, reorder, unlink, block inheritance (34.7s)
  ✓  20 [desktop] › tests/09-gpo.spec.ts:64:7 › Group Policy › create and delete a GPO with the user own ticket (54.6s)
  ✓  21 [desktop] › tests/10-policy.spec.ts:6:7 › password policy › domain policy: view, change with re-authentication, lockout warning (1.5m)
  ✓  22 [desktop] › tests/10-policy.spec.ts:40:7 › password policy › fine-grained policy: create, apply, effective policy, remove (2.5m)
  ✓  23 [desktop] › tests/11-health.spec.ts:5:7 › lockouts and account health › lockouts across both DCs; unlock selected (35.3s)
  ✓  24 [desktop] › tests/11-health.spec.ts:36:7 › lockouts and account health › health lists, CSV export and a password reset of selected accounts (49.0s)
  ✓  25 [desktop] › tests/11-health.spec.ts:89:7 › lockouts and account health › deleting selected accounts needs the typed count and re-authentication (38.0s)
  ✓  26 [desktop] › tests/12-bulk.spec.ts:25:7 › bulk operations › invalid files are rejected as a whole, nothing applied (30.6s)
  ✓  27 [desktop] › tests/12-bulk.spec.ts:45:7 › bulk operations › create users from CSV: full preview, apply, report, passwords once (59.8s)
  ✓  28 [desktop] › tests/12-bulk.spec.ts:67:7 › bulk operations › update users from CSV: attributes, disable, group, move (1.0m)
  ✓  29 [desktop] › tests/12-bulk.spec.ts:88:7 › bulk operations › clean up: delete the created users (selected, typed count) (59.6s)
  ✓  30 [desktop] › tests/13-webauthn.spec.ts:17:7 › security keys (WebAuthn) › a user registers a key, then signs in with it (2.7s)
  ✓  31 [desktop] › tests/13-webauthn.spec.ts:55:7 › security keys (WebAuthn) › an administrator re-authenticates a protected change with a key (55.6s)
  ✓  32 [desktop] › tests/13-webauthn.spec.ts:95:7 › security keys (WebAuthn) › a wrong key or a cancelled ceremony is refused (840ms)
  ✓  33 [desktop] › tests/14-roles-p2.spec.ts:7:7 › roles on the P2 pages › auditor: read-only DNS, GPO, policy, lockouts, health (13.9s)
  ✓  34 [desktop] › tests/14-roles-p2.spec.ts:56:7 › roles on the P2 pages › helpdesk: lockouts and health with actions; no DNS, GPO, policy, bulk (22.1s)

  34 passed (18.9m)
=== audit chain on dc1 after the desktop run
audit chain OK: 224 rows, head 04ecbc73ad81e1a3f04496adcf19d02f26fed99b650d096b6db1f4e9d3df70d5
=== project mobile

Running 34 tests using 1 worker

  ✓   1 [mobile] › tests/01-anonymous.spec.ts:4:7 › anonymous visitor and sign-in failures › sign-in page, theme, language and security headers (1.4s)
  ✓   2 [mobile] › tests/01-anonymous.spec.ts:30:7 › anonymous visitor and sign-in failures › anonymous access is limited to sign-in and static assets (854ms)
  ✓   3 [mobile] › tests/01-anonymous.spec.ts:43:7 › anonymous visitor and sign-in failures › refused sign-ins get the right message (1.9s)
  ✓   4 [mobile] › tests/01-anonymous.spec.ts:59:7 › anonymous visitor and sign-in failures › an administrator without 2FA needs an enrollment link (617ms)
  ✓   5 [mobile] › tests/01-anonymous.spec.ts:66:7 › anonymous visitor and sign-in failures › per-account rate limit stops before AD locks the account (2.3s)
  ✓   6 [mobile] › tests/02-expired-password.spec.ts:6:7 › must.change changes the password with the old one (2.1s)
  ✓   7 [mobile] › tests/02-expired-password.spec.ts:6:7 › expired.password changes the password with the old one (2.1s)
  ✓   8 [mobile] › tests/03-admin.spec.ts:4:7 › administrator › forced 2FA enrollment through the one-time link (3.5s)
  ✓   9 [mobile] › tests/03-admin.spec.ts:26:7 › administrator › dashboard, users with server-side search and paging (25.5s)
  ✓  10 [mobile] › tests/03-admin.spec.ts:59:7 › administrator › domain information through conductor-helper (23.9s)
  ✓  11 [mobile] › tests/04-admin-cycle.spec.ts:5:5 › create, edit, move and delete with previews (1.7m)
  ✓  12 [mobile] › tests/05-helpdesk.spec.ts:3:5 › helpdesk resets and unlocks in its OU, never on an administrator (8.2s)
  ✓  13 [mobile] › tests/06-auditor.spec.ts:4:5 › auditor sees everything and changes nothing (11.7s)
  ✓  14 [mobile] › tests/07-selfservice.spec.ts:3:5 › self-service profile, password and optional 2FA (53.9s)
  ✓  15 [mobile] › tests/08-dns.spec.ts:4:7 › DNS › zones and records; AD records are read-only (4.6s)
  ✓  16 [mobile] › tests/08-dns.spec.ts:42:7 › DNS › create a zone, add/edit/delete records, delete the zone (55.3s)
  ✓  17 [mobile] › tests/08-dns.spec.ts:113:7 › DNS › a reverse zone from a network, with a PTR record (1.0m)
  ✓  18 [mobile] › tests/09-gpo.spec.ts:4:7 › Group Policy › GPOs and links; settings editing is out of scope (32.4s)
  ✓  19 [mobile] › tests/09-gpo.spec.ts:20:7 › Group Policy › link, enforce, disable, reorder, unlink, block inheritance (34.7s)
  ✓  20 [mobile] › tests/09-gpo.spec.ts:64:7 › Group Policy › create and delete a GPO with the user own ticket (53.3s)
  ✓  21 [mobile] › tests/10-policy.spec.ts:6:7 › password policy › domain policy: view, change with re-authentication, lockout warning (1.5m)
  ✓  22 [mobile] › tests/10-policy.spec.ts:40:7 › password policy › fine-grained policy: create, apply, effective policy, remove (2.5m)
  ✓  23 [mobile] › tests/11-health.spec.ts:5:7 › lockouts and account health › lockouts across both DCs; unlock selected (35.9s)
  ✓  24 [mobile] › tests/11-health.spec.ts:36:7 › lockouts and account health › health lists, CSV export and a password reset of selected accounts (49.8s)
  ✓  25 [mobile] › tests/11-health.spec.ts:89:7 › lockouts and account health › deleting selected accounts needs the typed count and re-authentication (36.1s)
  ✓  26 [mobile] › tests/12-bulk.spec.ts:25:7 › bulk operations › invalid files are rejected as a whole, nothing applied (30.7s)
  ✓  27 [mobile] › tests/12-bulk.spec.ts:45:7 › bulk operations › create users from CSV: full preview, apply, report, passwords once (1.0m)
  ✓  28 [mobile] › tests/12-bulk.spec.ts:67:7 › bulk operations › update users from CSV: attributes, disable, group, move (59.7s)
  ✓  29 [mobile] › tests/12-bulk.spec.ts:88:7 › bulk operations › clean up: delete the created users (selected, typed count) (59.7s)
  ✓  30 [mobile] › tests/13-webauthn.spec.ts:17:7 › security keys (WebAuthn) › a user registers a key, then signs in with it (3.0s)
  ✓  31 [mobile] › tests/13-webauthn.spec.ts:55:7 › security keys (WebAuthn) › an administrator re-authenticates a protected change with a key (55.5s)
  ✓  32 [mobile] › tests/13-webauthn.spec.ts:95:7 › security keys (WebAuthn) › a wrong key or a cancelled ceremony is refused (843ms)
  ✓  33 [mobile] › tests/14-roles-p2.spec.ts:7:7 › roles on the P2 pages › auditor: read-only DNS, GPO, policy, lockouts, health (16.0s)
  ✓  34 [mobile] › tests/14-roles-p2.spec.ts:56:7 › roles on the P2 pages › helpdesk: lockouts and health with actions; no DNS, GPO, policy, bulk (23.9s)

  34 passed (19.3m)
=== audit chain on dc1 after the mobile run
audit chain OK: 224 rows, head 32494e5342f6e3c6418a14ad4c9def8bfead2a3736b61a61be43c64b4d286cc7
```

Unit and security tests (`make check` in both repositories: gofmt, go vet,
staticcheck, govulncheck, `go test -race`, all clean; govulncheck still lists
GO-2026-5932 in `golang.org/x/crypto` as present in a required module but not
reachable). New in `internal/web`:

- `TestRouteGuards` now walks the P2 routes too (anonymous, each sign-in
  stage, each role).
- `TestCSPScriptOnlyOnSecondFactorPages`: every GET page rendered; the six
  second-factor routes carry `script-src 'nonce-…'` with the matching
  `<script … nonce integrity>` and `connect-src 'none'`; every other page
  has `script-src 'none'` and no `<script>`; the served script matches its
  SRI hash and has no `fetch`, `XMLHttpRequest`, `eval` or `innerHTML`.
- `TestWebAuthnEnrollAndSignIn`: a software authenticator (ES256, "none"
  attestation) enrolls a key-only administrator through the one-time link,
  signs in; TOTP refused when keys are required; foreign and replayed
  assertions refused; the last key cannot be removed.
- `TestBulkJobLifecycle` (owner-only jobs, every row failed and audited when
  AD is unreachable, report CSV, interrupted after a restart),
  `TestSelectedActionPermissions`, `TestParseCSV`, `TestNewPasswordComplexity`,
  `TestCSVCellNeutralizesFormulas`, `TestZoneNameFromNetwork`.

The `ad` library's lab tests (`make lab-test`): `TestLabDNSReadSeeded`,
`TestLabDNSZoneLifecycle` (the DC's DNS answers right after each LDAP write;
a stale SOA is a conflict), `TestLabGPOLinks` (a stale gPLink is a
conflict), `TestLabPasswordPolicies` (a stale domain policy is a conflict;
PSO precedence and effective policy), `TestLabDomainControllersAndPerDCState`
and, as root on dc1, `TestLabGPOWithUserCCache` (samba-tool with only the
user's exported ticket).

Results (2026-10-02, full deploy): desktop 34 passed (18.9 min), mobile 34
passed (19.3 min), nothing failed or skipped; `conductor audit verify` on dc1
after each project reports the chain intact (lines in the transcript).
The unlock of a selected account is written on every DC (see
[design.md](design.md)): the lockouts test asserts the per-DC report
(`dc1...: applied`, `dc2...: applied`) and then that the lockouts page no
longer lists the account, with no waiting. The navigation is the grouped
sidebar (a native `<details>` "Menu" on phones); `03-dashboard` shows it.

Screenshots: [desktop](screenshots/desktop/) and [mobile](screenshots/mobile/)
(`08-*` … `14-*` are P2).
