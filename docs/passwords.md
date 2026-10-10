# Invitations and password reset by e-mail

conductor can let people set their own password through a one-time link:

- an invitation, sent by an administrator or helpdesk, for the first
  password of an account (the account is enabled when the person finishes);
- a password reset, requested by the person on a public form;
- a notice after any password change, and an optional recovery address.

conductor itself has no right to set a password: these features go through
[conductor-provisioner](https://github.com/openbasalt/samba-conductor-provisioner),
a separate local service that holds a delegated AD account with the Reset
Password right on chosen OUs only. conductor-provisioner owns the one-time
tokens (it stores their hashes, never the tokens), enforces its own limits
and refuses any account that holds privileged rights, even when conductor
asks for it.

## What is needed

1. E-mail: the `[mail]` section ([mail.md](mail.md)).
2. conductor-provisioner installed, with its delegated account and the OUs
   it manages (its `docs/install.md` and `docs/delegation.md`), and in
   `conductor.toml`:

   ```toml
   [provisioner]
   enabled = true
   socket = "/run/conductor-provisioner/api.sock"
   ```

3. `server.public_url`: the links in the messages are built from it, never
   from a request's Host header.

Settings > Passwords says what is missing, shows conductor-provisioner's
account, its managed OUs and its use in the last hour, and holds the
settings below. Saving them is previewed (before and after) and needs the
password and a fresh second factor; it is audited as `settings.update`.

| Setting | Default | Meaning |
|---|---|---|
| Invitation link valid for | 72 hours | 1 to 168. conductor-provisioner's own limit applies when it is shorter. |
| Send a new invitation once when the first one expires unused | off | The new one is issued for the administrator who sent the first. |
| Offer the public reset form | off | Adds "Forgot your password?" to the sign-in page. |
| Reset link valid for | 30 minutes | 5 to 120. |
| Second factor at reset | required when the user has one | Or always: users without a second factor cannot reset by e-mail. |
| Clear a lockout when the password is reset | on | |
| Tell users by e-mail after any change of their password | on | |

## Invitations

On a user's page, people with the helpdesk role see "Send invitation" when
conductor-provisioner says the account is in one of its OUs, is not
privileged and has an e-mail address; otherwise the page says why. The
preview names the account, the address and the validity; on confirmation
conductor-provisioner issues the token and conductor queues the message.
The same section lists the account's links (invitation and reset) with
their state, and "Revoke" for open ones.

When creating a user, "Send an invitation instead of setting a password"
creates the account disabled with a random 32-character password nobody
sees, then issues the invitation in the same confirmation. The option
needs an e-mail address and an OU managed by conductor-provisioner.

Issuing a new invitation revokes the previous one. A person who does not
finish leaves the account disabled; send a new invitation.

## Reset by e-mail

The form at `/reset` takes a username or an e-mail address and always
answers with the same page, at once: the lookup and the message happen in
the background, so the answer does not tell whether the account exists,
can be reset or has an address. A reset link goes to the account's `mail`
attribute and to its verified recovery address. It is not sent when:

- the account is privileged, outside the managed OUs, or disabled (a
  locked account can be reset);
- it has no address;
- the second factor is set to "always" and the user has none;
- the limits are reached: 5 requests per client address in 15 minutes,
  and 3 per account per hour and 5 per day (silently), besides the e-mail
  ceiling and conductor-provisioner's own.

## The link pages

Opening a link only checks it: a mail scanner that fetches the link uses
nothing. The page shows the account and a button; the button moves the
token out of the address into a short-lived cookie (10 minutes) and a
record in conductor's memory, then the steps follow:

1. For a reset of a user with a second factor: a code from the
   authenticator, a recovery code or a security key. Five wrong answers
   revoke the link.
2. The new password, twice. The domain's password policy decides; a
   refusal is explained (too short, complexity, history, minimum age).
3. For an invitation: the enrollment of a second factor when the policy
   (`[mfa] policy`) asks for it, with "Skip for now" when it is optional.
4. A last page. An invitation enables the account at this point; a reset
   ends every conductor session of the user.

A link that is not valid any more (expired, used, revoked, or changed
because the password was set elsewhere) shows the same page in every
case. The link pages send no Referer.

## Recovery address

On the Security page, "Recovery address" lets a user add a second e-mail
address for reset links and notices. Setting it needs the password and,
when the user has one, the second factor; a 6-digit code (valid 15
minutes, 5 tries, at most 5 codes per hour) is sent to the new address.
The previous address is told about a change or a removal, and reset links
go to a new address only 72 hours after it was set.

## Notices

After an invitation is completed, a reset, a self-service change, a reset
by an administrator or helpdesk, and a reset of selected accounts, the
user gets a message at the account's address and the recovery address
with the time and the client address (or "an administrator"). It carries
no link.

## What is logged

conductor's audit log, besides conductor-provisioner's own:

| Event | When |
|---|---|
| `invite.issued`, `invite.refused`, `invite.revoked`, `invite.reissued` | an administrator's actions and the automatic re-issue |
| `invite.opened`, `invite.password_set`, `invite.enrolled`, `invite.completed` | the person's steps |
| `reset.requested` | a request on the form: a hash of what was typed, never the text |
| `reset.mailed`, `reset.refused` | the outcome, with the internal reason |
| `reset.opened`, `reset.mfa`, `reset.completed`, `reset.revoked`, `reset.password_refused` | the person's steps |
| `link.refused` | a link that could not be used, with conductor-provisioner's code |
| `self.recovery_email_code`, `self.recovery_email_set`, `self.recovery_email_removed` | the recovery address |
| `settings.update` | Settings > Passwords, before and after |

No password, token or full recipient address is logged: the e-mail log
keeps the recipient's domain only.
