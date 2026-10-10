# Google-first mode (conductor side)

In the default mode AD is the source of truth and conductor-sync
provisions Google Workspace from it. The Google-first mode is the other
direction, for the people of chosen scopes: they are created, renamed and
suspended in Google Workspace, and AD follows. It is off by default and
nothing changes for an installation that does not turn it on.

What conductor-sync does (reads, the plan, the operations, the limits and
the field ownership table) is described in conductor-sync's
`docs/google-first.md`. This page covers the section in conductor:
settings, the plan page, applying a plan, and the fields shown as
"Managed by Google".

## Who does what

- conductor-sync reads Google with read-only scopes and AD with its
  read-only account, and returns a plan of typed AD operations
  (`g2a.plan`). It never writes to Google or to AD.
- conductor shows the plan and, after review, applies its operations
  through conductor-provisioner, then reports what it applied
  (`g2a.confirm`) so conductor-sync records the links and closes the run.
- conductor-provisioner holds the delegated AD account and checks every
  operation again on its own: the account is below one of its scope OUs,
  is not privileged, carries the marker of the Google account the plan
  names, and still has the values the plan saw. It refuses anything else.

## What is needed

1. The Google Workspace sync section (`[sync]` in `conductor.toml`) with
   conductor-sync set up ([usage-p5b.md](usage-p5b.md)).
2. conductor-provisioner (`[provisioner]`), delegated on the managed OUs
   of the scopes, with the rights its `docs/delegation.md` lists for the
   plan operations ([passwords.md](passwords.md) for the installation).
3. For invitations to the accounts created: `[mail]` and
   `server.public_url`. Without them the accounts are created and stay
   disabled until an administrator sends an invitation from the user page.

The section is under Google Workspace sync > Google-first mode, for
administrators only (viewing needs `sync.read`, every change `sync.write`).
No new key in `conductor.toml`: the settings are the `[google_first]`
section of conductor-sync's settings, saved as a new settings version
through conductor-sync's API like every other sync setting.

## Turning it on

The overview states what turning the mode on means: Google administrators
become account administrators of the managed OUs (never of privileged
accounts), Google-owned fields follow Google, accounts suspended or
removed in Google are disabled and moved to the quarantine OU (never
deleted), and Google keeps its own sign-in.

The domain and the switch are saved through a preview, confirmed with the
password and a fresh second factor. Every scope starts in dry-run, so the
first plans are previews.

### Single sign-on check

Google keeps its own sign-in in this mode, so conductor-idp must not serve
Google. conductor checks it through conductor-idp's management API:

- turning the mode on, saving the settings while it is on, every plan
  request and every apply are refused while a registered SAML service
  provider or OIDC client targets Google, and the refusal names the
  application;
- the Single sign-on section refuses to register or change an application
  that targets Google, or one made from the Google Workspace preset, while
  the mode is on.

An application targets Google when its entity ID, an ACS URL, a redirect
URI or a post-logout URI has `google.com` or a host below it, or when the
identifier ends with the Google domain as a path
(`google.com/a/example.com`). Applications on the organization's own
hosts (`cloud.example.com`) are not affected. A disabled registration
counts too. When conductor-idp cannot be asked, the check fails and the
action is refused; when the single sign-on section is off in conductor,
there is nothing to check and the page says so.

## Scopes

A scope pairs a managed OU (with its groups OU and quarantine OU below it)
with a Google selection: org units, optionally the org units below them,
optionally restricted to members of named Google groups. The scope form
also sets the optional fields Google owns, the logon name template and
the limits per plan. conductor-sync validates the whole settings version
(no overlap with the AD to Google scope, org units that are not targets
of the AD to Google mapping) and the form shows what it refuses.

- The name cannot be changed later.
- An edit that changes what a scope in apply mode selects (OUs, org
  units, groups, fields, template) puts it back in dry-run. Changing only
  the limits keeps the mode.
- Removing a scope (typed name and the confirmation) leaves its accounts
  in AD as they are; their fields become AD-managed again.

## Plans

"Plan" on the overview, for every scope or one, checks single sign-on
first, then asks conductor-sync for a plan with conductor's admin,
helpdesk and auditor role groups (their members are privileged for the
plan). The plan page shows, per scope:

- the operations grouped by kind in apply order (updates, primary address
  changes, re-enables, creates, disables), with every field's value before
  and after, the target OU of a move, and whether an invitation follows;
- the privileged accounts left alone, with the reasons, so a human acts on
  them in AD; each one is also audited (`g2a.skip.privileged`);
- the other skips and the warnings;
- the limits with the plan's values; a scope over a limit is blocked and
  none of its operations can be applied (limits are not overridden here).

### Switching a scope to apply

From the latest plan only, for a scope in dry-run: type the scope name, a
space and the first 8 characters of the plan's digest, then confirm with
the password and a fresh second factor. Back to dry-run needs the
confirmation only.

### Applying

The apply form is offered on the latest plan when it is still open and at
least one of its scopes is in apply mode within its limits. Type the first
8 characters of the digest and confirm with the password and a fresh
second factor. Before anything runs, conductor reads the settings again
(a scope switched back to dry-run since the plan is left out) and checks
single sign-on again. Then:

1. The operations run in order: updates, primary address changes,
   re-enables (move back, then enable), creates (disabled, with a random
   password nobody sees), disables (disable, which also revokes the
   account's open links, then move to the quarantine OU).
2. Each one is audited as `g2a.apply.<kind>` with the run, the digest, the
   target and the values before and after. conductor-provisioner keeps its
   own audit entry with the reference `g2a run <id> op <seq>`.
3. An account created gets an invitation to set its first password when
   mail is configured (`invite.issued`); otherwise `invite.skipped` is
   audited and the account waits for an invitation from its user page.
4. A refusal of one operation (a value changed in AD since the plan, an
   account that exists already, a marker of another Google account) is
   reported and the others continue. When conductor-provisioner is
   unreachable or at its hourly ceiling, the remaining operations are
   reported as not attempted.
5. conductor reports every result to conductor-sync (`g2a.confirm`,
   audited), which records the links and closes the run as applied or
   partial. A closed plan cannot be applied again: request a new one.

## Managed by Google

An account whose `msDS-cloudExtensionAttribute1` starts with
`google-first:` follows Google for the fields Google owns: `givenName`,
`sn`, `displayName`, `mail` and `proxyAddresses` always, and `title`,
`department`, `employeeID`, `telephoneNumber` and `mobile` when its scope
lists them. In conductor:

- the user page shows the Google ID and the scope, and marks those fields
  "Managed by Google";
- the edit page shows them read only and refuses a change to them
  (`err.managed_by_google`, audited as refused);
- a bulk CSV update row that would change one of them is refused with the
  same message;
- the self-service profile shows them read only and refuses a change.

An account with a marker but no scope containing it (the scope was
removed) is AD-managed again. When conductor-sync's settings cannot be
read, every field Google may own is treated as owned until they can be.
Changes made around conductor (other tools, LDAP) are corrected by the
next applied plan.

## Audit

| Action | When |
|---|---|
| `google_first.enable`, `google_first.disable`, `google_first.settings` | the mode and the domain |
| `google_first.scope_add`, `google_first.scope_update`, `google_first.scope_remove` | scopes |
| `google_first.mode` | a scope switched to apply or back to dry-run (refused gates too) |
| `g2a.p3_refused` | a single sign-on check that failed, with the applications named |
| `g2a.plan` | a plan request, with the counts per scope and kind |
| `g2a.skip.privileged` | each privileged account a plan left alone |
| `g2a.apply` | the apply as confirmed, and refusals before it |
| `g2a.apply.<kind>` | each operation applied or refused |
| `invite.issued`, `invite.skipped` | invitations of the accounts created |
| `g2a.confirm` | the report to conductor-sync |
