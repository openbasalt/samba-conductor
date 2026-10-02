# Configuration reference

`/etc/conductor/conductor.toml` (TOML). `conductor setup` writes it;
[`../conductor.toml.example`](../conductor.toml.example) is a commented
template. **Unknown keys are an error** and conductor refuses to start on
any invalid value, so a typo never silently falls back to a default.

## `[server]`

| Key | Default | Meaning |
|---|---|---|
| `listen` | `":8443"` | Address to listen on (ignored when systemd passes a socket). |
| `tls_cert`, `tls_key` | — | Built-in TLS (TLS 1.2+). Both or neither. |
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
Operators) are **protected**: helpdesk cannot act on them, and
administrators re-authenticate (password + TOTP) to change them or the
membership of those groups.

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
| `database` | `"/var/lib/conductor/conductor.db"` | SQLite database (sessions metadata, 2FA, enrollment links, audit). Created 0600. |

## `[helper]`

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `true` | Use conductor-helper for the domain page. |
| `socket` | `"/run/conductor-helper/helper.sock"` | Its Unix socket. |

## `[ui]`

| Key | Default | Meaning |
|---|---|---|
| `default_language` | `"en"` | `en` or `pt-BR`; users switch in the footer, and `Accept-Language` is honoured. |

## Files

| Path | Owner / mode | What |
|---|---|---|
| `/etc/conductor/conductor.toml` | root:conductor 0640 | this file |
| `/etc/conductor/domain-ca.pem` | root 0644 | pinned domain CA |
| `/etc/conductor/tls/{cert,key}.pem` | key root:conductor 0640 | web certificate |
| `/etc/conductor/credentials/totp-key` | root 0600 | TOTP encryption key (systemd credential) |
| `/var/lib/conductor/conductor.db` | conductor 0600 | state |
| `/run/conductor-helper/helper.sock` | root:conductor 0660 | helper socket |
