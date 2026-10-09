# E-mail

conductor sends its messages through an SMTP relay configured in the
`[mail]` section of `conductor.toml` ([config.md](config.md#mail)). While
`host` is unset, e-mail is off: nothing is queued and nothing is sent.

## Turning it on

```toml
[mail]
host = "smtp.example.com"
port = 587
security = "starttls"
username = "conductor@example.com"
from = "Samba Conductor <no-reply@example.com>"
```

1. Put the relay password where conductor reads it (see
   [The relay password](#the-relay-password)).
2. Restart conductor (`systemctl restart conductor`). The journal shows
   `e-mail on` with the relay, never the password.
3. Send a test message from Settings > E-mail, or from the shell:

```
sudo conductor mail test --to you@example.com --password-file /etc/conductor/credentials/smtp-password
sudo -u conductor conductor mail status
```

`--password-file` is needed only when the password comes from the
systemd credential, which exists only inside the service. `conductor
mail test` talks to the relay directly and prints its answer,
so a wrong password or a certificate problem shows up at once. The test
message on the settings page goes through the queue like any other
message and its result appears in the list on that page. An
administrator may send at most 5 test messages per hour; each one is
audited as `mail.test` with the recipient's domain.

## Relay requirements

- A submission relay that accepts messages from the `from` address:
  STARTTLS on port 587 (`security = "starttls"`) or TLS from the first
  byte on port 465 (`security = "tls"`). TLS 1.2 or newer.
- A certificate valid for `host` and issued by a CA in the system store,
  or by the CA in `ca_file`. There is no option to skip the check.
- With `starttls`, the relay must offer STARTTLS. If it does not, the
  message is not sent; conductor never falls back to plain text.
- Authentication, when `username` is set, is AUTH PLAIN, and only over
  TLS. Without `username`, conductor does not authenticate (a relay that
  trusts the server's address).
- `security = "none"` is plain SMTP and is accepted only when `host` is
  a loopback address (`localhost`, `127.0.0.1`, `::1`): a mail server on
  the same machine that relays onward. Authentication over plain SMTP
  works only with one of those three names.
- SPF, DKIM and DMARC are the relay's job. conductor does not sign
  messages. Publish the records your relay documents for the domain of
  `from`, or the messages will land in spam folders or be refused.

## The relay password

The password is read once at startup from, in this order:

1. `mail.password_file`: an absolute path, one line, not readable by
   others (mode 0600 or 0640). Under the shipped unit the service can read
   files below `/etc/conductor` but not `/etc/conductor/credentials`.
2. The systemd credential `smtp-password`
   (`$CREDENTIALS_DIRECTORY/smtp-password`).

conductor refuses to start when `username` is set and neither is there.

The shipped `conductor.service` does not load the credential: on systemd
252 a `LoadCredential=` whose file is missing stops the unit from
starting, and most installations have no relay password. To use the
credential, add it with a drop-in:

```
install -d -m 0700 /etc/conductor/credentials
(umask 077; cat > /etc/conductor/credentials/smtp-password)
systemctl edit conductor
```

with these lines in the editor:

```
[Service]
LoadCredential=smtp-password:/etc/conductor/credentials/smtp-password
```

then `systemctl restart conductor`. The `cat` line reads the password
from the terminal (type it, then Enter and Ctrl-D), so it never appears
in the shell history or a process list.

The settings page and `conductor mail status` show where the password
comes from, never the password itself.

## The queue

Every message waits in the queue, in conductor's database, until the
relay accepts it.

- Kept: the recipient, the subject and both bodies, sealed with
  AES-256-GCM under the key that also seals the second-factor secrets
  (`[mfa] key_file` or the `totp-key` credential) and bound to the
  message's id, so a copy of the database does not reveal an address or
  a link. Also the kind of message, a reference (for example the id of
  the link it carries), the number of attempts and the last error.
- Retries: after a failure the next attempt comes 1, 2, 4, 8 and 16
  minutes later, then every 30 minutes.
- Expiry: every message has one. A message carrying a link expires with
  the link, a notification after 24 hours, a test message after one hour,
  and nothing waits longer than 8 days. A message that is still queued
  when it expires is deleted unsent.
- Deleted: as soon as the relay accepts the message, when it expires,
  when the relay refuses the recipient for good (a 5xx answer), or when
  it cannot be opened any more (the database was restored with another
  key).
- Ceiling: `max_per_hour` messages per hour in total. Above it messages
  wait in the queue and the journal logs a warning (at most every 10
  minutes).

The log kept next to the queue (the list on the settings page and in
`conductor mail status`) has, for each message, its kind, the recipient's
domain, the reference, the status (queued, retrying, sent, refused,
expired), the number of attempts, the times and the last error with any
address removed. It never holds the recipient's address or the content.
Rows are kept for 30 days. The journal lines carry the same fields.

## Templates

Every message has a plain text and an HTML part, in English and Brazilian
Portuguese (the recipient's language when conductor knows it, otherwise
`[ui] default_language`). The look comes from Settings > Branding: the
organization name, the light logo, the primary color, the support
contact and the help text ([branding.md](branding.md)). The logo is an
absolute URL on `server.public_url` (or the first `[webauthn] origins`
entry, or `https://` + `rp_id`), so recipients load it from conductor; it is left
out when conductor has no https address. Nothing else is loaded from
elsewhere and every style is inline.

| Template | Content |
|---|---|
| `test` | the time it was sent |
| `invitation` | the logon name, a one-time link and its expiry |
| `reset` | the logon name, a one-time link and its expiry |
| `password_changed` | the logon name, the time, and the client address or "an administrator" |
| `alternate_verify` | a verification code and how long it is valid |
| `alternate_changed` | the logon name, the time and the client address |

Messages never carry a password or the state of an account.

### Overrides

Files in `<[branding] templates_dir>/mail/` replace built-in templates one
by one, with the same names: `<template>.<language>.txt` and
`<template>.<language>.html`, for example `reset.pt-BR.html`. Start from
the built-in file:

```
conductor templates list
conductor templates show mail/reset.en.html
```

Rules:

- `.txt` files are Go text/template, `.html` files Go html/template with
  auto-escaping. Both may use `t` (a message of the catalog) and the
  shared parts of the built-in layout (`mail-top`, `mail-link` and
  `mail-bottom` for HTML, `text-bottom` for text).
- Only these fields: `.Lang`, `.Subject`, `.OrgName`, `.Logo`,
  `.Primary`, `.Support` (`.Email`, `.Phone`, `.URL`, `.Text`, `.Any`),
  `.Link`, `.Username`, `.ExpiresAt`, `.ExpiresIn`, `.When`, `.From`,
  `.ByAdministrator` and `.Code`. A field that does not exist is refused
  in every branch of the file, not only in the branch sample data reaches.
- Refused (the built-in template stays, with a finding): `<script>`,
  `javascript:` URLs, event handler attributes, a file over 64 KiB, a file
  that does not parse or does not render with sample data, an unknown
  file name.
- The subject is not part of the template: it comes from the message
  catalog (`mail.subject.<template>`).
- The files are read at startup: restart conductor after a change.

`conductor templates check` checks these files together with the page
partials, and the same findings are logged at startup.
