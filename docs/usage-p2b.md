# P2b: File servers (shares on domain-member servers)

conductor's "File servers" section shares folders on the network from
Samba **domain-member file servers**: an administrator picks a folder below
the server's share roots, the AD groups that get read, modify or full
access, a few options, reviews the exact change the server will make and
confirms it with the second factor. Domain controllers never host these
shares.

Spec: `../../planning/docs/p2b-spec.md`; decisions:
`../../planning/docs/decisions.md` (P2b). The agent on each file server:
`../../conductor-files` (README, `docs/install.md`, `docs/usage-p2b.md`).

## How it works

```
browser --HTTPS--> conductor (DC VM, user conductor) --TLS 1.3, both keys pinned--> conductor-files (file server, root, sandboxed)
                    session, roles, 2FA                  one request per connection      net conf, sharesec, samba-tool ntacl,
                    previews, audit                      actor in every request          smbstatus, winbind; own audit log
```

- conductor never writes to a file server itself. The agent offers typed
  operations only (status, folders below the roots, shares, plan, apply,
  remove, sessions) and validates everything again.
- **Trust**: no CA. conductor's key lives in `files.key_dir`
  (`/var/lib/conductor/files`), each agent's in its state directory. A
  server is enrolled with a one-time code made on it
  (`conductor-files enroll-code` → `cfe1.<token>.<agent key>`): conductor
  pins the agent's key from the code, the agent pins conductor's key when
  the token matches. Unknown keys fail the TLS handshake on both sides.
- **Roles**: `files.read` (administrators and auditors: servers, shares,
  permissions, sessions) and `files.write` (administrators: enroll, remove,
  create, edit, remove shares). Helpdesk sees nothing. Every write asks for
  the password and a fresh second factor on the preview page.
- **Plan, then apply**: the wizard asks the agent for the plan of the
  draft; the preview shows the share and folder permissions as before/after
  lists (groups by name and SID), the registry section and the commands in
  order, and the text kept in the audit log (with the plan digest). The
  apply is bound to that digest: if the share or its folder changed in
  between, the agent refuses and asks for a new review.
- **Audit**: conductor logs `files.enroll`, `files.remove_server`,
  `files.share_create`, `files.share_update`, `files.share_remove` with the
  exact preview; the agent logs the same operations, with the AD user,
  conductor's key, the digest and the commands run, in its own hash-chained
  log (`conductor-files audit verify`).
- No JavaScript, the CSP is unchanged.

## Enabling it

1. Prepare the file server and install the agent:
   `../../conductor-files/docs/install.md` (member join with
   `include = registry` and `vfs objects = acl_xattr`, a root such as
   `/srv/shares`, the unit, TCP 7443 open to conductor's host only).
2. In `/etc/conductor/conductor.toml` (`config.md`, `[files]`):

   ```toml
   [files]
   enabled = true
   ```

   then `systemctl restart conductor`. conductor generates its key pair on
   first start and logs its fingerprint; the File servers page shows it too.
3. On the file server, as root: `conductor-files enroll-code`.
4. In conductor: **File servers → Add a file server**: the server's address
   and the code, **Review**, then confirm with password and second factor.
   The server page then shows the prerequisites (all must be OK), both
   keys and the shares.

## Using it

- **New share** (server page): three steps, kept as a draft in the session
  until applied or discarded.
  1. *Folder*: name (letters, digits, `.`, `_`, `-`; a trailing `$` hides it
     from network lists), description, and a folder: browse the roots and
     pick an existing folder, or type a new folder name (created root:root,
     0700, then given the permissions). Folders already shared, and folders
     whose parent can be written by others (e.g. inside another share), are
     not offered.
  2. *Access*: search AD groups, add each with read (read and execute),
     modify (read, write, delete) or full control. SYSTEM, Administrators
     and Domain Admins always have full control.
  3. *Options*: listed on the network (default on), hide from people
     without access (access-based enumeration), recycle bin (deleted files
     go to `.recycle/<user>`), previous versions (only when the server has a
     `[shadow_copies]` profile). **Review the change** shows the plan.
- **Edit** (share page, shares created by conductor only): access and
  options, or another existing folder; the name cannot change. Existing
  files keep their own permissions (the preview warns), but the share
  permissions apply to everyone at the next connection, so removing a group
  takes effect at once.
- **Remove share**: the share and its share permissions go; the folder and
  its files stay.
- **Sessions** (server page tab): who is connected, from where, protocol,
  signing and encryption; connections per share; open files.
- **Remove this server**: the agent drops conductor's key, conductor
  forgets the server. If the server cannot be reached, conductor forgets it
  anyway and the message gives the `conductor-files trust remove <pin>` to
  run on it.
- Shares made by hand or in `smb.conf` are listed and shown read-only.

## Verified in the lab (2026-10-03)

Lab snapshot `conductor-p2b` (dc1, dc2 and fs1, `../../planning/docs/lab.md`);
Playwright `e2e/tests/18-files.spec.ts`, desktop and mobile, each on a fresh
reset, with SMB checks run by smbclient from dc2 against fs1:

| Step | Result |
|---|---|
| Enroll fs1 with a code made on it (a malformed code refused first) | preview shows the address and the agent key, not the token; server ready, all prerequisites OK |
| Create `e2e-eng` in a new folder, Engineering modify, recycle bin | plan with `net conf import`, `samba-tool ntacl set --use-s3fs`, `sharesec --replace`; applied with re-authentication |
| `user0001` (Engineering) writes; `user0002` (Sales) lists | written; refused with `NT_STATUS_ACCESS_DENIED` at tree connect |
| A held session | listed on the sessions page with its connection to `e2e-eng` |
| Edit: Engineering read, Sales modify | Sales writes; Engineering lists but gets `NT_STATUS_ACCESS_DENIED` on write |
| Auditor / helpdesk | auditor reads every page without write controls (403 on writes); helpdesk has no entry and gets 403 |
| Remove the share, then the server | `NT_STATUS_BAD_NETWORK_NAME` afterwards, folder kept; server forgotten, agent no longer trusts conductor |

The agent's own refusals (paths outside the roots, symbolic links, parents
writable by others, unknown SIDs, users, other domains, untrusted client
keys, a share changed between plan and apply, shares not made by it) are
proven by `conductor-files`' lab tests on fs1 (`make lab-test`, its
`docs/usage-p2b.md`).

## Screenshots

`docs/screenshots/{desktop,mobile}/18-files-*.png`: servers list, enrollment
and its preview, server page, the three wizard steps, the plan preview,
share page, sessions, edit and removal previews.
