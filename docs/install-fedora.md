# Installing conductor on Basalt OS / Fedora

Installation on a Samba AD domain controller running **Basalt OS** (Fedora
44 based, SELinux enforcing) or **Fedora 44**, from the RPM packages. The
steps are the ones `docs/install.md` describes for Debian and Ubuntu; this
page lists what differs. The Basalt OS package lab
(`../planning/lab/basaltlab/`) runs exactly these steps, with SELinux
enforcing, and checks that the audit log holds no denial.

## Requirements

- Fedora's Samba AD DC (`samba-dc`, `samba-dc-provision`) ≥ 4.19, functional
  level 2016. Fedora builds the DC with the **MIT Kerberos KDC** (Debian and
  Ubuntu use Heimdal); see "MIT Kerberos" below for what that means here.
- LDAPS with a certificate whose SANs include the DC host name, issued by a
  CA you can pin (as on Debian).
- SELinux in enforcing mode with the targeted policy is supported and
  expected; the `conductor-selinux` package confines both services.
- The packages: `conductor` (x86_64 or aarch64) and `conductor-selinux`
  (noarch), from the `basalt-tools` repository on Basalt OS, or from the
  release assets.

## 0. Install the package

On **Basalt OS** the `basalt-tools` repository is configured by default
(metadata only; nothing is installed unless chosen):

```sh
sudo dnf install conductor
```

On **Fedora**, or before the repository carries Samba Conductor, install the
RPMs of a release after checking them against its signed `SHA256SUMS`:

```sh
sudo dnf install ./conductor-<version>-1.x86_64.rpm ./conductor-selinux-<version>-1.noarch.rpm
```

`conductor-selinux` comes with `conductor` wherever the targeted policy is
installed (`Requires: (conductor-selinux if selinux-policy-targeted)`); it
needs `selinux-policy-targeted` at least as new as the policy it was built
against, which dnf updates with it.

The package contains `conductor` and `conductor-helper` (`/usr/bin`), their
units (`/usr/lib/systemd/system`), man pages, `/etc/conductor/helper.toml`
(`%config(noreplace)`, backups off), the `sysusers.d` entry of the
`conductor` user, and owns `/etc/conductor` (root:conductor 0750) with
`tls/` (0750) and `credentials/` (root 0700), and `/var/lib/conductor`
(conductor 0700). Licenses are in `/usr/share/licenses/conductor`
(`LICENSE`, `NOTICE`, `THIRD-PARTY-LICENSES`). **Nothing is enabled or
started**: the units get the distribution's preset, which disables them.

## 1. Firewall

Basalt OS's default zone allows SSH only; a DC needs its AD services and
conductor's port:

```sh
sudo firewall-cmd --permanent --add-service=samba-dc
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload
```

## 2. Web certificate, setup, start

Exactly as `docs/install.md` steps 2, 4, 5 and 6:

```sh
sudo install -m 0644 cert.pem /etc/conductor/tls/cert.pem
sudo install -m 0640 -o root -g conductor key.pem /etc/conductor/tls/key.pem
sudo conductor setup
sudo systemctl enable --now conductor-helper conductor
sudo -u conductor conductor enroll-link --user <admin> --base-url https://dc1.example.com:8443
```

Files created in `/etc/conductor` and `/var/lib/conductor` get their
SELinux types from the policy (`conductor_conf_t`, `conductor_cred_t`,
`conductor_var_lib_t`); files copied there with `cp -a` or `mv` from
elsewhere keep their old label: run `sudo restorecon -R /etc/conductor`.

## SELinux

| Process | Domain | Can |
|---|---|---|
| `conductor` | `conductor_t` | read its configuration; manage `/var/lib/conductor`; listen on `http_port_t` (8443); LDAP(S), Kerberos, kpasswd and RPC to the DCs; the helper socket; conductor-sync's API socket; conductor-files agents (unreserved ports); run `samba-tool` with the signed-in user's ticket |
| `conductor-helper` | `conductor_helper_t` | its sockets in `/run/conductor-helper`; `samba-tool` as root on the local Samba database (`/var/lib/samba`, `/var/cache/samba`, `/run/samba`); with conductor-backup, its spool and recipients |

The credentials directory (`conductor_cred_t`) is readable by systemd only:
the services read their copy in `$CREDENTIALS_DIRECTORY`, as on Debian
(where `InaccessiblePaths=` hides it). Fedora runs the Samba AD DC itself
unconfined (`/usr/sbin/samba` has no policy of its own).

- Another listen port: `sudo semanage port -a -t http_port_t -p tcp <port>`.
- Denials: `sudo ausearch -m AVC,USER_AVC -ts recent`. To check whether
  SELinux is the cause of a problem, make one domain permissive
  (`sudo semanage permissive -a conductor_t`, `-d` to revert); please report
  any denial seen in normal use.

## MIT Kerberos

Fedora's `samba-dc` uses MIT Kerberos for the KDC and kpasswd services.
conductor's Kerberos flows were checked against it in the Basalt OS package
lab (Samba 4.24, krb5 1.22): sign-in (AS exchange with the user's password),
LDAPS binds with the user's service ticket (GSSAPI with channel bindings),
password changes through kpasswd (self-service and expired passwords),
`samba-tool` with the user's credential cache (GPO creation and deletion)
and conductor-helper's root operations. See `planning/docs/packaging.md`,
"MIT Kerberos (Fedora's samba-dc)", for the results and known differences.

## Operating

- Upgrade: `sudo dnf upgrade conductor` restarts the services that are
  running and keeps the enabled state, `conductor.toml`, the credentials and
  the database; an edited `helper.toml` is kept and the new default lands
  beside it as `helper.toml.rpmnew`.
- Removal: `sudo dnf remove conductor` stops and disables the services and
  removes the packaged files and the policy module; it keeps what was
  created after installation (`conductor.toml`, the TOTP key in
  `credentials/`, the TLS files, the database and audit log in
  `/var/lib/conductor`, an edited `helper.toml` as `helper.toml.rpmsave`)
  and the `conductor` user. Remaining files are relabeled to the system
  defaults. Delete them by hand when they are no longer needed (back up the
  TOTP key and the database first: `restore.md`).
- Everything else (audit chain, backups, sync) as in `docs/install.md`,
  "Operating".
