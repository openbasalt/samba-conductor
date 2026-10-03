# P3 lab run: encrypted backups, restore drills, a full-forest restore

Run on 2026-10-03 in the server-home lab (`../../planning/docs/lab.md`):
two Samba 4.22 DCs on Debian 13 (`lab.conductor.test`, 2,517 users, P2
seed), conductor and conductor-helper on dc1, conductor-backup on dc1, a
drill host VM on its own network, MinIO and mailpit in containers. Builds
from the committed code of `ad`, `conductor` and `conductor-backup`. No
secret appears below; every value that is one stayed in
`~/conductor-lab/` on server-home.

Spec: `../../planning/docs/p3-spec.md`. Choices: `../../planning/docs/decisions.md` (P3).

## 1. Setting it up

```sh
scripts/lab-deploy.sh --snapshot      # build on server-home, planning/lab/p3-snapshot.sh
```

`p3-snapshot.sh` follows the READMEs: `backup-infra.sh` (drill network,
MinIO and mailpit with TLS from the lab CA, the bucket and two
least-privilege S3 users, the lab's age keys), `drill-up.sh` (the drill
VM; it **cannot reach dc1:389** and can reach MinIO, both checked),
`reset.sh seeded`, conductor's install, `remote/seed-p3.sh` (the backup
account with only the three replication rights on the five naming
contexts, and the drill's probe account), `backup-install.sh` (each host
generates its own signing key; only public keys move), a first backup, a
first drill, the snapshot `conductor-p3`.

On dc1 after the install:

```
srw-rw---- 1 root conductor-backup 0 backup.sock
srw-rw---- 1 root conductor        0 helper.sock
drwx--x--x root conductor /run/conductor-helper
drwx------ conductor-backup conductor-backup /var/lib/conductor-backup        (state.json, private.json 0600)
```

The helper's journal never contains the backup account's password; the
spool is empty after each run; the helper's private `/tmp` holds no
plaintext after a backup.

## 2. A backup and a drill

```
$ conductor-backup status
realm LAB.CONDUCTOR.TEST, dc dc1, last run 2026-10-03T02:05:07Z, next due 2026-10-03T02:30:00Z
policy: 02:30 UTC every 24h; keep 7 daily, 4 weekly, 12 monthly; stale after 26h; drill every 7 days
RPO: last good backup 20261003T020507Z-dc1, 0s ago
BACKUP                STATUS  TRIGGER    SIZE     USERS  DESTINATIONS
20261003T020507Z-dc1  ok      scheduled  9105354  2517   minio:ok local:ok
```

samba-tool takes about 21 s for this domain; the whole run (facts, backup,
conductor state snapshot, encryption, two uploads, two read-back
verifications) about 25 s. The archive (8.7 MiB of age ciphertext) holds
the samba-tool backup, conductor's database without sessions, `smb.conf`,
`krb5.conf`, the conductor/helper/backup configurations, `chrony.conf` and
the DC's TLS files, plus metadata (counts, sample SIDs, versions).

The DC posted a signed drill request (the policy wants one every 7 days and
there was none); the drill host picked it up:

```
drill 20261003T020532Z-drill of 20261003T020507Z-dc1: passed, RTO 17s
  ok   integrity sha256 50088d9c3559e931…
  ok   ldap rootDSE drill.lab.conductor.test
  ok   dns:_ldap._tcp.lab.conductor.test drill.lab.conductor.test:389
  ok   dns:_kerberos._tcp.lab.conductor.test drill.lab.conductor.test:88
  ok   dns:_ldap._tcp.dc._msdcs.lab.conductor.test drill.lab.conductor.test:389
  ok   kerberos TGT for svc-drill-probe
  ok   users 2517 users
  ok   sid:Administrator S-1-5-21-…-500
  ok   sid:expired.password S-1-5-21-…-1104
  ok   sid:user0001 … sid:user0004
  ok   sid:Domain Admins S-1-5-21-…-512
  ok   sid:Domain Users S-1-5-21-…-513
  phases (ms): download 43, verify 60, decrypt 37, restore 9262, checks 7547
```

The restored DC ran in the sandbox (new network/mount/PID/UTS/IPC
namespaces, loopback and a dummy interface only); everything was shredded
afterwards. The DC's next run read the signed report; conductor's poller
recorded it (`backup_results`) and audited it (`backup.drill_result`,
actor `drill:drill`). Later drills in the same session measured 15-17 s.

## 3. Failure tests (`planning/lab/backup-failure-tests.sh`)

```
[lab] wrong key: restore with an identity that is not a recipient
  integrity: SHA-256 matches the signed manifest
  conductor-backup: archive: the identity does not match any recipient of this backup
  rc=1   (nothing restored)
[test] PASS wrong key refused, nothing restored

[lab] tamper: flipping one byte of domain/lab.conductor.test/20261003T031710Z-dc1.tar.age in MinIO
  minio: 20261003T031710Z-dc1: FAILED: stored archive does not match the manifest (size or SHA-256)
  drill 20261003T032521Z-drill of 20261003T031710Z-dc1: FAILED, RTO 0s
  conductor-backup: restore drill failed: the downloaded archive does not match its signed manifest (SHA-256)
  mail: [conductor-backup] LAB.CONDUCTOR.TEST: restore drill failed (20261003T031710Z-dc1)
[test] PASS tampered archive refused by verify and by the drill
  (original object back: verify ok; the next drill passed, RTO 15 s)

[lab] bucket down: MinIO stopped during a backup
  20261003T032547Z-dc1  partial  manual  9102282  2517   minio:failed local:ok
  mail: [conductor-backup] LAB.CONDUCTOR.TEST: backup failed (dc1)
[test] PASS partial backup, archive kept in the spool, alert e-mail sent
[lab] MinIO back: the next run uploads the spooled archive
  20261003T032547Z-dc1  ok  manual  9102282  2517   minio:ok local:ok
[test] PASS spooled archive uploaded and verified after the bucket came back

[lab] prune --dry-run: the last good backup is kept
  minio: keep 6 (… 20261003T032547Z-dc1); would delete 0 []; incomplete []
  local: keep 2 (20261003T025404Z-dc1 20261003T032547Z-dc1); would delete 0 []
[test] PASS prune keeps the last good backup (20261003T032547Z-dc1) at every destination
```

All backups were younger than 24 h, so the lab's prune only shows the
rule that the newest good backup is always kept; the retention selection
over months and the "two years without a good backup" case are covered by
unit tests (`internal/retention`, `internal/runner`).

The drill host's watchdog also sent "no recent backup (seen from the drill
host)" once, at its very first check, before dc1 had taken any backup.

Missed schedule (a dead scheduler): `stale-setup` stops
`conductor-backup.timer` and `.path` and sets an hourly schedule with a
1-hour alert threshold; an hour after the last good backup:

```
[lab] stale check: conductor-backup check with the scheduler stopped
  ALERT stale since 2026-10-03T04:28:43Z: last good backup 20261003T032843Z-dc1 is 1h17m0s old
  mail: [conductor-backup] LAB.CONDUCTOR.TEST: no recent backup (dc1)
[test] PASS missed schedule detected: check exits 1, alert e-mail sent
```

The dashboard shows the banner (`16-backups-stale.spec.ts`, run with
`E2E_NO_RESET=1 E2E_STALE=1`), from the status conductor's poller reads
every minute: ![banner](screenshots/desktop/16-dashboard-backup-banner.png)
A policy whose threshold is below its interval is invalid; conductor-backup
then keeps the default policy (the web form refuses it, the helper too).
conductor also flags conductor-backup itself when it has not run for more
than 2 h 15 min, and the drill host alerts on its own when the newest backup
in the bucket is too old.

## 4. Full-forest restore exercise (`planning/lab/restore-exercise.sh`)

From `conductor-p3`: a marker user `restore.marker` is created and a
backup requested (`conductor-backup request backup --wait`); the facts are
recorded; both DCs are powered off. A fresh VM `dc3` (10.93.0.12) gets the
Samba packages and, with the operator's identity copied in for the
operation and shredded after it:

```
$ conductor-backup restore latest --config restore.toml --identity operator-age.key \
    --target /var/lib/samba-restored --newservername DC3
backup 20261003T031710Z-dc1 from minio (9108938 bytes, sha256 c29f9752…)
integrity: SHA-256 matches the signed manifest
decrypted: LAB.CONDUCTOR.TEST, taken on dc1 at 2026-10-03T03:17:10Z, 2518-2518 users
running: /usr/bin/samba-tool domain backup restore --backup-file=… --targetdir=/var/lib/samba-restored/samba --newservername=DC3
Restored backup 20261003T031710Z-dc1 … into /var/lib/samba-restored/samba as DC DC3, in 9s.
(next steps follow; restore.md section 4)
```

Then the printed steps (smb.conf, krb5.conf, the certificate for dc3,
resolver, chrony, start), conductor installed on dc3 with its restored
configuration (pointed at dc3), TOTP key and database, and a fresh dc2
joined to the restored domain. Report:

```
backup restored: 20261003T031710Z-dc1
fresh VM + Samba packages: 101 s
conductor-backup restore + Samba started: 15 s
conductor back with its state, user signed in: 8 s
RTO (loss -> conductor working): 124 s; from a host with Samba installed: 23 s
dc2 rejoined: 136 s
users, groups, SIDs, GUID: identical          (2518 users, 50 groups; Administrator,
                                               lab.admin, normal.user, restore.marker,
                                               svc-conductor-backup, Domain Admins,
                                               Helpdesk SIDs; lab.admin's GUID)
fsmo 7                                        (every role on DC3)
dbcheck: 0 errors
audit chain OK: 5 rows                        (4 from the backup + the sign-in below)
signin normal.user: 303 https://dc3.lab.conductor.test:8443/me
dc2: 2518 users, replication healthy
```

The audit row conductor wrote after the backup was taken is the expected
loss (RPO). The exercise VMs were removed and the lab went back to
`conductor-p3`.

Two findings changed the code and the runbook:

- `samba-tool domain backup restore` creates the restored DC's account
  before it removes the old DCs: restoring under the old name fails
  (`CN=DC1,OU=Domain Controllers,… already exists`). `--newservername` is
  now required and must differ from the backup's DC; the restored DC
  needs a certificate for its new name, and conductor's `[domain]` must
  point at it.
- After a DC is rebuilt with a new signing key, its older manifests no
  longer verify. Pruning now reports such backups as "unverified" and
  never deletes them (before, they would have been removed after 48 h as
  incomplete).

## 5. Playwright (desktop and mobile)

```sh
e2e/run-lab.sh --no-deploy desktop    # 38 passed (21.8 min); audit chain OK: 271 rows
e2e/run-lab.sh --no-deploy mobile     # 38 passed (21.6 min); audit chain OK: 272 rows
```

Each project starts from a fresh `conductor-p3`. The P1 and P2 specs pass
unchanged; `15-backups.spec.ts` adds:

- administrator: the sidebar's Operations → Backups (marked current), the
  backups table, a passed drill, RTO and RPO filled, both recipients'
  fingerprints, both destinations, and no secret in the HTML (no
  `AGE-SECRET-KEY`, signing key or S3 secret); "Back up now" shows the
  helper operation (`backup.trigger`, `action: backup`), needs password +
  TOTP, then the new backup appears requested by `lab.admin`, OK in MinIO
  and in the local destination, each verified;
- administrator: "Run drill now" (re-authenticated) lists the pending drill;
  the policy form refuses an alert threshold below the interval, previews
  `retention.daily: 7 -> 8`, applies it with re-authentication, and puts it
  back;
- auditor: the page without actions; forged POSTs to run, drill and config
  get 403, the config page 403;
- helpdesk: no Backups entry in the sidebar, 403 on the pages.

Screenshots (`docs/screenshots/{desktop,mobile}/`): `15-backups.png`,
`15-backups-confirm.png` (re-authentication), `15-backups-config.png`,
`15-backups-auditor.png`.

## 6. Gates

`make check` (gofmt, go vet, staticcheck, govulncheck, `go test -race`)
passes in `ad`, `conductor` and `conductor-backup`. govulncheck: no
vulnerability in the code's call graph; it still lists one advisory in a
required module, not reachable (as in P2).
