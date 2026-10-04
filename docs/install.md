# Installing conductor (Debian 13 / Ubuntu 26.04)

Basalt OS and Fedora (RPM packages, SELinux): `install-fedora.md`.

Installation on a Samba AD domain controller with systemd, from the Debian
package (recommended) or from source. Ubuntu 24.04 (Samba 4.19) is best
effort. The lab install script (`../planning/lab/remote/install-conductor.sh`)
runs the from-source steps; the package lab (`../planning/lab/pkglab/`)
runs the package steps.

conductor normally runs **on a DC** (the helper needs the local Samba
database); it reaches AD over LDAPS and Kerberos like any client.

## Requirements

- Samba AD DC ≥ 4.19 (Debian 13 ships 4.22), functional level 2016.
- LDAPS on the DCs with a certificate whose SANs include the DC host name,
  issued by a CA you can pin (Samba's self-generated certificate has no SAN
  and Go refuses it). See `../planning/docs/lab.md` for an example CA.
- Time in sync (chrony with `ntp_signd`).
- Samba 4.19 (Ubuntu 24.04, best effort) refuses Kerberos (GSSAPI) binds
  over LDAPS that carry TLS channel bindings but no SASL signing ("Strong
  Auth Required: Sign or Seal are required"); Samba 4.20 and later accept
  them. On a 4.19 DC add `ldap server require strong auth =
  allow_sasl_over_tls` to `[global]` in `smb.conf` and restart
  `samba-ad-dc` (binds still require TLS). Verified in the package lab.
- The `conductor` package (amd64 or arm64), or for a source install the
  binaries `conductor` and `conductor-helper` (`make build`, static, CGO off)
  and `deploy/systemd/*.service`.
- A TLS certificate for the web address users open, or a TLS reverse proxy
  on the same host.

## 0. Install the package

The project's APT repository is not published yet; until it is, install the
`.deb` of a release directly (`sudo apt install ./conductor_<version>_amd64.deb`,
after checking it against the release's signed `SHA256SUMS`). Once the
repository is published:

```sh
curl -fsSLo /tmp/samba-conductor.gpg https://apt.openbasalt.org/samba-conductor/samba-conductor-archive-keyring.gpg
gpg --show-keys /tmp/samba-conductor.gpg     # must be 3601734842BD4E482D19DE4AE4EED5ECA395B302 (OpenBasalt release key)
sudo install -m 0644 /tmp/samba-conductor.gpg /usr/share/keyrings/samba-conductor-archive-keyring.gpg
printf 'Types: deb\nURIs: https://apt.openbasalt.org/samba-conductor\nSuites: stable\nComponents: main\nSigned-By: /usr/share/keyrings/samba-conductor-archive-keyring.gpg\n' |
  sudo tee /etc/apt/sources.list.d/samba-conductor.sources
sudo apt update
sudo apt install conductor
```

The package contains `conductor` and `conductor-helper` (`/usr/bin`), their
units (`/usr/lib/systemd/system`), man pages and
`/etc/conductor/helper.toml` (a conffile, backups off). It creates the
`conductor` system user, `/etc/conductor` (root:conductor 0750) with `tls/`
(0750) and `credentials/` (root 0700), and `/var/lib/conductor`. **It does
not enable or start anything.** Skip steps 1 and 3 and continue with step 2.

## 1. System user and directories (source install only)

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

## 3. systemd units (source install only)

```sh
sudo install -m 0644 deploy/systemd/conductor.service deploy/systemd/conductor-helper.service /etc/systemd/system/
sudo systemctl daemon-reload
```

The package installs the same units in `/usr/lib/systemd/system` (with
`/usr/bin` paths); change them with drop-ins (`systemctl edit conductor`),
never by editing the packaged files.

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
- Upgrade: with the package, `apt upgrade` (the running services are
  restarted; `conductor.toml`, credentials and the database are kept; an
  edited `helper.toml` is kept and the new default lands next to it as
  `helper.toml.dpkg-dist`). From source: replace the binaries, `systemctl
  restart conductor-helper conductor`. Database migrations are embedded and
  applied at start.
- Removal: `apt remove conductor` stops the services and keeps the
  configuration and the database; `apt purge conductor` also deletes
  `/etc/conductor` (with the TOTP key) and `/var/lib/conductor` (database,
  audit log): back them up first. The `conductor` user is kept.
- Backups: install conductor-backup (<https://github.com/openbasalt/samba-conductor-backup/blob/main/README.md>):
  encrypted domain backups that include conductor's database; keep
  `/etc/conductor/credentials/totp-key` offline with the operator's age key
  (`restore.md`, section 0).
- Google Workspace sync (optional): install conductor-sync
  (<https://github.com/openbasalt/samba-conductor-sync/blob/main/docs/usage-p5.md>) with its API socket
  (`conductor-sync-api.socket`, group `conductor`), then `[sync] enabled =
  true` in `conductor.toml` and restart conductor (`usage-p5b.md`).
