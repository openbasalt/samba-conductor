# Configuration reference

`/etc/conductor/conductor.toml` (TOML). `conductor setup` writes it;
[`../conductor.toml.example`](../conductor.toml.example) is a commented
template. Unknown keys are an error and conductor refuses to start on
any invalid value, so a typo never silently falls back to a default.

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `":8443"` | Address to listen on (ignored when systemd passes a socket). |
| `tls_cert`, `tls_key` | none | Built-in TLS (TLS 1.2+). Both or neither. |
| `behind_proxy` | `false` | Plain HTTP for a TLS reverse proxy on the same host. Only with a loopback `listen` address; never together with `tls_*`. Without TLS and without this, conductor refuses to start. |
| `trusted_proxies` | `[]` | CIDRs whose `X-Forwarded-For` is believed (rate limits and audit use the client address). Only with `behind_proxy`. |

conductor always sends HSTS and `__Host-` cookies, so the browser must reach
it over HTTPS (directly or through the proxy).

## `[domain]`

| Key | Default | Meaning |
|---|---|---|
| `realm` | required | Kerberos realm, e.g. `EXAMPLE.COM`. |
| `ca_file` | required | Absolute path of the PEM CA that signs the DCs' LDAPS certificates. Nothing else is trusted. |
| `preferred` | `[]` | DC host names tried first (the local DC). Kerberos service tickets go to the KDC that issued the user's TGT. |
| `dcs` | `[]` | Fixed DC list instead of DNS SRV discovery. |
| `dns_servers` | `[]` | DNS servers (IPs) for SRV discovery when the host resolver is not the domain's DNS. |
| `simple_bind_fallback` | `false` | When no KDC is reachable, sign in with an LDAP simple bind over TLS; the password is then kept sealed in memory (per-process key) for the session. |

## `[roles]`

| Key | Default | Meaning |
|---|---|---|
| `admin_groups` | `[]` | SIDs of administrator groups; empty = the domain's Domain Admins (RID 512). |
| `helpdesk_groups` | `[]` | SIDs of helpdesk groups. |
| `auditor_groups` | `[]` | SIDs of read-only auditor groups. |
| `cache_seconds` | `60` | How long a role check is reused (0-60). Roles come from the user's tokenGroups (nested membership, by SID). |

Values must be SIDs (`setup` resolves names). Membership is always checked
by SID, never by name or DN. Accounts that belong to the administrator
groups or to the well-known privileged groups (Domain/Enterprise/Schema
Admins, Domain Controllers, Administrators, Account/Server/Print/Backup
Operators) are protected: helpdesk cannot act on them, and
administrators re-authenticate (password + TOTP or a security key) to
change them or the membership of those groups.

What each role may do on the P2 pages:

| Page | admin | helpdesk | auditor |
|---|---|---|---|
| DNS zones and records | read, write | none | read |
| Group Policy (GPOs, links, inheritance) | read, write | none | read |
| Password policy, PSOs, effective policy | read, write | none | read |
| Lockouts (all DCs), account health, CSV export | read | read | read |
| Actions on selected accounts | all | unlock, enable/disable, reset password | none |
| Bulk CSV import | yes | none | none |

## `[mfa]`

| Key | Default | Meaning |
|---|---|---|
| `policy` | `"optional"` | 2FA for users without a privileged role: `off` (not offered), `optional` (self-service enrollment; once enrolled it is asked at every sign-in), `required` (enrollment forced at first sign-in). Administrators always need 2FA. |
| `delegated_roles_required` | `true` | Helpdesk and auditors need 2FA too. |
| `admin_enrollment_requires_link` | `true` | An administrator without 2FA may enroll only with a one-time link (`conductor enroll-link`, or issued by another administrator). Turning it off means whoever first knows an administrator's password can register their own authenticator. |
| `issuer` | `"Samba Conductor"` | Name shown in authenticator apps. |
| `key_file` | `""` | 32-byte key (raw or 64 hex digits, mode 0600) that encrypts TOTP secrets. Empty: `$CREDENTIALS_DIRECTORY/totp-key` from systemd `LoadCredential`. |

## `[session]`

| Key | Default | Meaning |
|---|---|---|
| `idle_minutes` | `15` | Idle timeout (1-60). |
| `absolute_hours` | `8` | Absolute lifetime (1-24); also bounded by the Kerberos ticket. |

## `[ratelimit]`

| Key | Default | Meaning |
|---|---|---|
| `per_ip_per_minute` | `30` | Attempts per client address and minute on sign-in, 2FA and password forms. |
| `account_failures` | `5` | Failed attempts per account within the window before conductor stops trying (keep it below the domain's lockout threshold). |
| `account_window_minutes` | `15` | Window of the per-account counter. |

## `[state]`

| Key | Default | Meaning |
|---|---|---|
| `database` | `"/var/lib/conductor/conductor.db"` | SQLite database (sessions metadata, 2FA secrets and security keys, enrollment links, bulk job reports, audit). Created 0600. |

## `[helper]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Use conductor-helper for the domain page and the Backups page. |
| `socket` | `"/run/conductor-helper/helper.sock"` | Its Unix socket. |

## conductor-helper: `/etc/conductor/helper.toml` (optional)

The helper's own file (root:conductor 0640, no secrets). Without it, or with
`[backup] enabled = false`, the backup operations are off and the Backups
page says so. Set up together with conductor-backup
(<https://github.com/openbasalt/samba-conductor-backup/blob/main/README.md>). Unknown keys are an error.

| `[backup]` key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Serve the backup operations and a second socket, `/run/conductor-helper/backup.sock` (root:conductor-backup 0660; the socket directory becomes 0711). |
| `peer_user` | `"conductor-backup"` | The only user admitted on the backup socket (SO_PEERCRED), and the owner of the archives. |
| `account` | (required) | AD account samba-tool backs up with: replication rights only (README). |
| `password_credential` | `"backup-account"` | systemd credential with its password (`LoadCredential=` in the conductor-backup drop-in). `password_file` instead for hosts without systemd. |
| `server` | `"127.0.0.1"` | DC to back up: this one, over loopback (the helper unit only allows localhost). |
| `dc` | host name | short name in backup IDs. |
| `recipients_file` | `"/etc/conductor-backup/recipients.txt"` | age recipients; must be owned and writable by root only (with its directory), or the backup is refused. |
| `state_dir` | `"/var/lib/conductor-backup"` | conductor-backup's state (must belong to `peer_user`; never followed through symbolic links). |
| `work_dir` | `"/tmp/conductor-backup"` | where plaintext exists while the archive is built: the unit's private `/tmp` (tmpfs on Debian 13). Shredded after each run. |
| `conductor_db` | `""` | conductor's database to include (sessions removed); set it to `/var/lib/conductor/conductor.db`. |
| `extra_files` | `[]` | more host files for the archive (absolute, at most 1 MiB each). |
| `python`, `samba` | `/usr/bin/python3`, `/usr/sbin/samba` | used to count users/groups and read versions. |

## `[ui]`

| Key | Default | Meaning |
|---|---|---|
| `default_language` | `"en"` | `en` or `pt-BR`; users switch in the footer, and `Accept-Language` is honoured. |

## `[webauthn]`

Security keys and platform authenticators (WebAuthn) as a second factor,
next to TOTP. Off while `rp_id` is empty.

| Key | Default | Meaning |
|---|---|---|
| `rp_id` | `""` | The host name users open conductor with (the WebAuthn relying party ID), e.g. `conductor.example.com`. Keys registered for one RP ID only work there: changing it invalidates every registered key. |
| `origins` | derived | Origins allowed in ceremonies, `https://host[:port]`, host = `rp_id` or below it. Default: `https://<rp_id>` plus the `listen` port when it is not 443 (behind a proxy: no port). |
| `display_name` | `"Samba Conductor"` | Name the browser shows while registering a key. |
| `admin_required` | `false` | Administrators must use a security key: TOTP codes are no longer accepted for them at sign-in and re-authentication (recovery codes are, as the emergency path). An administrator without a key registers one right after the TOTP step. |
| `related_origins` | `[]` | Extra origins on other domains that may use the same keys (WebAuthn related origins), served at `/.well-known/webauthn`. Browsers fetch that from `https://<rp_id>`, so conductor must answer on the `rp_id` host. Origins below `rp_id` (conductor-idp on `idp.example.com` with `rp_id = "example.com"`) go in `origins` instead. |

To let conductor-idp use these keys (its 2FA backend `conductor`, see
`[idp]`), the IdP's origin must be allowed: with conductor on
`conductor.example.com:8443` and the IdP on `idp.example.com:9443`, set
`rp_id = "example.com"` and `origins = ["https://conductor.example.com:8443",
"https://idp.example.com:9443"]`. Changing `rp_id` invalidates the keys
already registered.

The browser part is `/static/webauthn.js`, the only script conductor has.
It is loaded only on the second-factor pages (sign-in 2FA, enrollment,
security page, key removal, key re-authentication) with a per-response CSP
nonce and Subresource Integrity; it makes no requests of its own
(`connect-src 'none'`). Every other page keeps `script-src 'none'`.

## `[bulk]`

| Key | Default | Meaning |
|---|---|---|
| `max_rows` | `1000` | Most rows per batch: CSV import (create or update) and actions on selected accounts (1-100000). |

## `[tools]`

| Key | Default | Meaning |
|---|---|---|
| `samba_tool` | `"/usr/bin/samba-tool"` | samba-tool, run for GPO creation and deletion (they write SYSVOL as well as LDAP) with the signed-in user's own Kerberos ticket, written for the run to a private credential cache in conductor's own `/tmp` (systemd `PrivateTmp`) and removed afterwards. No password is involved. |

## `[sync]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Show the "Google Workspace sync" section (administrators only) and drive conductor-sync through its management API. Needs `conductor-sync serve` (conductor-sync's `conductor-sync-api.socket`) on this host. |
| `socket` | `"/run/conductor-sync/api.sock"` | The API socket (owner conductor-sync, group conductor, 0660; conductor-sync admits only the conductor user, SO_PEERCRED). |

## `[idp]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Show the "Single sign-on" section (administrators only) and drive conductor-idp through its management API. Needs conductor-idp on this host with `[api] enabled = true` and `conductor-idp-api.socket`. |
| `socket` | `"/run/conductor-idp/api.sock"` | The API socket (owner conductor-idp, group conductor, 0660; conductor-idp admits only the conductor user, SO_PEERCRED). |
| `mfa_socket` | `false` | Serve conductor's second factor to conductor-idp (its `mfa.backend = "conductor"`): one enrollment (TOTP, recovery codes, security keys) and conductor's policy for both. Every verification is rate limited per user and audited here (`idp.mfa_*`). |
| `mfa_socket_path` | `"/run/conductor/mfa.sock"` | Used when systemd passes no socket (`conductor-mfa.socket` passes it under the name `mfa`). |
| `mfa_socket_group` | `""` | Group of a socket conductor creates itself (the conductor-idp group; conductor's user must be a member). Unused with socket activation. |
| `mfa_allowed_users`, `mfa_allowed_uids` | `["conductor-idp"]` | Who may use the 2FA socket (SO_PEERCRED). Root and conductor are refused. |

## `[files]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Show the "File servers" section (administrators manage, auditors read) and drive the conductor-files agents on domain-member file servers. See `usage-p2b.md`. |
| `key_dir` | `"/var/lib/conductor/files"` | conductor's client key pair for the agents (`tls-key.pem` 0600, `tls-cert.pem`), generated on first start; the directory is created 0700. The agents pin this key at enrollment: replacing it means enrolling every file server again. |
| `name` | the host name | How conductor's key is labelled on the agents (`conductor-files trust list`). |

## `[branding]`

| Key | Default | Meaning |
|---|---|---|
| `templates_dir` | `""` | Directory of template overrides of the self-service pages (`header.html`, `footer.html`, `self-home.html`, an optional `custom.css`), read at startup; empty: none. Suggested: `/etc/conductor/templates`. Check it with `conductor templates check` ([branding.md](branding.md)). The organization name, logos, colors and texts are not here: they are edited in Settings > Branding. |
| `allowed_origins` | `[]` | Origins (`https://host[:port]`) the branded pages may load images and fonts from, added to `img-src` and `font-src` of those pages only. |

## Files

| Path | Owner / mode | What |
|---|---|---|
| `/etc/conductor/conductor.toml` | root:conductor 0640 | this file |
| `/etc/conductor/domain-ca.pem` | root 0644 | pinned domain CA |
| `/etc/conductor/tls/{cert,key}.pem` | key root:conductor 0640 | web certificate |
| `/etc/conductor/credentials/totp-key` | root 0600 | TOTP encryption key (systemd credential) |
| `/var/lib/conductor/conductor.db` | conductor 0600 | state |
| `/run/conductor-helper/helper.sock` | root:conductor 0660 | helper socket |
| `/etc/conductor/helper.toml` | root:conductor 0640 | helper configuration (backups) |
| `/etc/conductor/templates/` | root:conductor 0750 | template overrides (optional, `[branding] templates_dir`) |
| `/run/conductor-helper/backup.sock` | root:conductor-backup 0660 | helper socket for conductor-backup (with backups) |
| `/run/conductor-sync/api.sock` | conductor-sync:conductor 0660 | conductor-sync's management API (with `[sync]`) |
| `/var/lib/conductor/files/` | conductor 0700 | conductor's key pair for the conductor-files agents (with `[files]`) |
