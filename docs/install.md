# Installing conductor (Debian 13 / Ubuntu 26.04)

Manual installation on a Samba AD domain controller with systemd. Packages
(`.deb`) come in P6; until then this is the reference procedure, and the lab
install script (`../planning/lab/remote/install-conductor.sh`) runs exactly
these steps.

conductor normally runs **on a DC** (the helper needs the local Samba
database); it reaches AD over LDAPS and Kerberos like any client.

## Requirements

- Samba AD DC ≥ 4.19 (Debian 13 ships 4.22), functional level 2016.
- LDAPS on the DCs with a certificate whose SANs include the DC host name,
  issued by a CA you can pin (Samba's self-generated certificate has no SAN
  and Go refuses it). See `../planning/docs/lab.md` for an example CA.
- Time in sync (chrony with `ntp_signd`).
- The binaries `conductor` and `conductor-helper` (`make build`, static,
  CGO off) and `deploy/systemd/*.service`.
- A TLS certificate for the web address users open, or a TLS reverse proxy
  on the same host.

## 1. System user and directories

```sh
sudo useradd --system --user-group --home-dir /var/lib/conductor --no-create-home --shell /usr/sbin/nologin conductor
sudo install -m 0755 conductor conductor-helper /usr/local/bin/
sudo install -d -m 0750 -o root -g conductor /etc/conductor /etc/conductor/tls
sudo install -d -m 0700 -o root -g root /etc/conductor/credentials
sudo install -d -m 0700 -o conductor -g conductor /var/lib/conductor
```

## 2. Web certificate

```sh
sudo install -m 0644 cert.pem /etc/conductor/tls/cert.pem
sudo install -m 0640 -o root -g conductor key.pem /etc/conductor/tls/key.pem
```

The key is readable by the `conductor` group only. Behind a reverse proxy
skip this step and use `setup --behind-proxy` (conductor then listens on
`127.0.0.1:8080` and never serves plain HTTP on another address).

## 3. systemd units

```sh
sudo install -m 0644 deploy/systemd/conductor.service deploy/systemd/conductor-helper.service /etc/systemd/system/
sudo systemctl daemon-reload
```

`conductor.service` runs as `conductor` with an empty capability set,
`ProtectSystem=strict`, a private `/tmp`, `MemoryDenyWriteExecute` and a
`@system-service` syscall filter; its state is `/var/lib/conductor`
(`StateDirectory`). The TOTP encryption key reaches it through
`LoadCredential=totp-key:/etc/conductor/credentials/totp-key`.

`conductor-helper.service` runs as root with `CapabilityBoundingSet` limited
to file access, write access only to Samba's state directories,
`IPAddressAllow=localhost`, and a socket in `/run/conductor-helper`
(`RuntimeDirectory`, group `conductor`, mode 0660). Only the `conductor`
user's processes are served (SO_PEERCRED).

To listen on 443 without any capability, add a `conductor.socket` unit with
`ListenStream=443`; `conductor serve` accepts a socket passed by systemd.

## 4. First-run setup

```sh
sudo conductor setup
```

Interactive; flags exist for every question (`conductor setup -h`). It:

1. detects the realm from `/etc/samba/smb.conf` and the preferred DC (this
   host);
2. **pins the domain CA**: `--ca-file` with the CA that signed the DCs'
   LDAPS certificates, or reads the chain from the DC and asks you to
   confirm its SHA-256 fingerprint (`--ca-fingerprint` for unattended
   runs). It is written to `/etc/conductor/domain-ca.pem`;
3. signs in once with a domain account you name (`--admin-user`; the
   password is asked, or read from stdin with `--non-interactive`, and not
   stored) to **resolve the role groups by name to SIDs**: administrators
   default to Domain Admins (RID 512), plus optional helpdesk and auditor
   groups;
4. generates the TOTP key `/etc/conductor/credentials/totp-key` (0600,
   root). **Back it up**: without it every 2FA enrollment is lost;
5. writes `/etc/conductor/conductor.toml` (root:conductor 0640) after
   validating it; security keys (WebAuthn) are enabled for the host name of
   `--public-url` (or `--webauthn-rp-id NAME`), off without either;
6. optionally (`--first-admin NAME`) issues the **first administrator's
   2FA enrollment link**, created as the `conductor` user so the database
   stays owned by it.

Example (unattended, the lab's values):

```sh
printf '%s\n' "$PASSWORD" | sudo conductor setup --non-interactive \
  --realm LAB.CONDUCTOR.TEST --dc dc1.lab.conductor.test --ca-file /root/lab-ca.pem \
  --admin-user lab.admin --helpdesk-group Helpdesk --auditor-group Auditors \
  --mfa-policy optional --first-admin lab.admin --public-url https://dc1.lab.conductor.test:8443
```

Group Policy object creation and deletion run `samba-tool` (default
`/usr/bin/samba-tool`, `[tools] samba_tool`) as the `conductor` user with the
signed-in administrator's own Kerberos ticket; the Samba packages of a DC
provide it, nothing else is needed. The shipped unit's sandbox allows it
(verified on Debian 13 / Samba 4.22).

## 5. Start

```sh
sudo systemctl enable --now conductor-helper conductor
sudo systemctl status conductor conductor-helper
journalctl -u conductor -f
```

## 6. First administrator

Administrators must enroll 2FA before they reach any admin page, and only
through a one-time link (24 hours). If setup did not issue one:

```sh
sudo -u conductor conductor enroll-link --user lab.admin --base-url https://dc1.example.com:8443
```

Give the link to the administrator over a trusted channel. They open it,
sign in with their AD password, scan the QR code, confirm a code and save
the recovery codes. Later administrators get their link from an existing
administrator (user page → "Issue 2FA enrollment link").

Helpdesk and auditor accounts enroll on their first sign-in
(`delegated_roles_required = true`); regular users follow `mfa.policy`.

## Operating

- Audit chain: `sudo -u conductor conductor audit verify` (run it as the
  database owner; root would leave root-owned WAL files). Export:
  `sudo -u conductor conductor audit export > audit.jsonl`.
- Restart = everyone signs in again (Kerberos tickets live only in memory).
- Upgrade: replace the binaries, `systemctl restart conductor-helper
  conductor`. Database migrations are embedded and applied at start.
- Backups: install conductor-backup (`../../conductor-backup/README.md`):
  encrypted domain backups that include conductor's database; keep
  `/etc/conductor/credentials/totp-key` offline with the operator's age key
  (`restore.md`, section 0).
- Google Workspace sync (optional): install conductor-sync
  (`../../conductor-sync/docs/usage-p5.md`) with its API socket
  (`conductor-sync-api.socket`, group `conductor`), then `[sync] enabled =
  true` in `conductor.toml` and restart conductor (`usage-p5b.md`).
