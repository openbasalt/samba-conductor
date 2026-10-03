# Restore runbook

How to recover a Samba AD domain managed with Samba Conductor, from the
encrypted backups `conductor-backup` takes (`../../conductor-backup/README.md`).
Read it before you need it, and keep a printed or offline copy with the
keys below.

## 0. What you must keep outside the domain

Keep these together, offline (password manager, a safe, a hardware token),
in at least two places:

| Item | Why | Where it comes from |
|---|---|---|
| An **operator age identity** (`AGE-SECRET-KEY-…`) | decrypts every backup; it is never on a DC | `conductor-backup keygen age --out key.txt` on a trusted machine; its public line goes into `/etc/conductor-backup/recipients.txt` |
| The DC's **public signing key** (`cbsig1:…`) | proves a manifest (and so the archive's SHA-256) was written by your DC, not by someone with write access to the bucket | `conductor-backup pubkey /etc/conductor-backup/credentials/signing-key` on the DC |
| **Bucket access**: endpoint, bucket, prefix, read credentials, the CA of the endpoint | to download | your object storage |
| conductor's **TOTP key** (`/etc/conductor/credentials/totp-key`) | 2FA enrollments in a restored conductor database are sealed with it | the conductor install |

Consequences of losing them:

- **Every operator identity and the drill identity lost**: the backups
  cannot be decrypted, by anyone. This is the price of "a compromised DC
  cannot read old backups". Keep two operator keys in two places, and treat
  the drill host's key as a recovery key too (the drill host can decrypt).
- **Signing public key lost**: `conductor-backup restore` refuses unsigned
  manifests. Use the manual path (section 6) and compare the archive's
  SHA-256 with what you recorded elsewhere (alert e-mails, the Backups page,
  `conductor-backup status`), accepting that the bucket was not tampered
  with.
- **TOTP key lost**: the restored conductor works, but nobody's TOTP
  verifies: administrators enroll again through `conductor enroll-link`,
  users from their security page. WebAuthn keys keep working (public keys
  only).

## 1. Pick the scenario

| What happened | Do |
|---|---|
| One DC is lost or broken, other DCs are healthy | **Do not restore.** Rebuild it by joining (section 2). |
| An object or a few were deleted by mistake | **Do not restore the domain.** Reanimate the tombstones (section 3). |
| Every DC is lost, corrupted or compromised (full-forest loss) | Restore the newest good backup on one new host, then join the others to it (section 4). |
| The domain database is logically corrupted everywhere | Section 4, choosing a backup from before the corruption (`conductor-backup list`). |

A restore rolls the whole forest back to the backup's time: every change
made since (passwords, new users, group changes, joined computers) is lost,
and computers whose machine password changed since then must rejoin. Never
restore while another DC of the domain is still running.

## 2. One DC lost, others alive: rejoin

1. On a healthy DC, remove the dead DC from the directory and DNS:
   `samba-tool domain demote --remove-other-dead-server=DC2 -U Administrator`.
2. If it held FSMO roles (`samba-tool fsmo show`), seize them on a healthy
   DC: `samba-tool fsmo seize --role=all -U Administrator`.
3. Build a fresh host with the same name and address, Samba installed, the
   resolver pointing at a healthy DC, time in sync, and join it:
   `samba-tool domain join example.com DC -U Administrator` (the lab's
   `planning/lab/remote/join-dc2.sh` is a worked example).
4. Check `samba-tool drs showrepl` on both sides, DNS records
   (`host -t SRV _ldap._tcp.example.com`), SYSVOL (Samba does not replicate
   it: copy `sysvol` from the DC holding the PDC role, or use your own sync).

## 3. Deleted objects: reanimate

AD keeps a deleted object as a tombstone (with its SID and GUID, most
attributes stripped) for the tombstone lifetime (180 days by default). It
can be brought back by a Domain Admin with an LDAP modify against the
deleted object: remove `isDeleted` and set its `distinguishedName` back in
place, with the "show deleted" control
(`ldbmodify -H ldap://dc1 --controls=show_deleted:1 -U Administrator …`).
The SID survives, so group memberships that point to it by SID and ACLs
work again; attributes that were stripped (and the member list of a deleted
group) must be put back by hand. When a backup newer than the change
exists, a restore drill-style sandbox (`conductor-backup restore` into a
scratch directory on a machine with no network to the DCs) shows the old
values to copy from. Automating this is out of scope for Samba Conductor.

## 4. Full-forest recovery

Measured in the lab (two DCs, 2,518 users, Samba 4.22, Debian 13;
`usage-p3.md`): 124 s from the loss to conductor working again, of which
101 s were creating a VM and installing Samba; 23 s from a host with Samba
installed (download, verification, decryption and restore 15 s, conductor
back with its state 8 s); a second DC rejoined in 136 s. Users, groups,
SIDs and GUIDs identical; every FSMO role on the restored DC; dbcheck
clean; the audit chain continuous.

1. **Isolate.** Make sure no old DC of the domain is running (power off,
   disconnect). If they were compromised, keep them off for good.
2. **A fresh host with a new DC name** (e.g. `dc3`): `samba-tool domain
   backup restore` creates the restored DC's account before it removes
   every old DC from the database, so an old DC's name cannot be reused
   for the restored one (it is free again for the DCs you join later).
   Debian 13 or Ubuntu 26.04, the distribution's `samba-ad-dc` packages
   installed, its services stopped and masked, time in sync, and a TLS
   certificate for the new name from your CA (LDAPS clients, conductor
   included, verify the host name). Clients find DCs through DNS SRV
   records, which the restored DC registers for itself; anything that
   names a DC explicitly must be updated. Serving conductor under a stable
   service name (e.g. `conductor.example.com`) keeps its URL and WebAuthn
   relying party unchanged through such a change.
3. **conductor-backup** on it (binary only) with a minimal configuration,
   e.g. `/root/restore.toml`:

   ```toml
   realm = "EXAMPLE.COM"
   backup_public_keys = ["cbsig1:…"]        # the DC's public signing key
   credentials_dir = "/root/restore-credentials"   # holds "s3" (0600)
   [[destination]]
   name = "s3"
   type = "s3"
   endpoint = "https://s3.example.com"
   bucket = "example-ad-backups"
   path_style = true
   credentials = "s3"
   ```

   `conductor-backup list --config /root/restore.toml` shows the backups
   with their manifests verified.
4. **Restore** (the operator's identity file only on this host, 0600, and
   removed afterwards):

   ```sh
   conductor-backup restore latest --config /root/restore.toml \
     --identity /root/operator-age.key --target /var/lib/samba-restored \
     --newservername DC3
   ```

   It downloads the archive, checks its SHA-256 against the signed
   manifest, decrypts it, runs `samba-tool domain backup restore` (original
   SIDs and GUIDs; every FSMO role seized; the old DCs removed from the
   restored database; krbtgt renewed twice), puts the old DC's TLS files
   back (replace them with the new name's certificate in
   `/var/lib/samba-restored/samba/private/tls/`), shreds the plaintext
   archive and prints the next steps. Add `--with-conductor-state` once
   conductor is installed (step 7).
5. **Start the DC** with the restored configuration (the printed steps):
   the restored `smb.conf` points at `/var/lib/samba-restored/samba/…`;
   link it to `/etc/samba/smb.conf`, copy its `krb5.conf` to
   `/etc/krb5.conf`, point `/etc/resolv.conf` at the host itself, unmask and
   start `samba-ad-dc`.
6. **Check**: `samba-tool dbcheck --cross-ncs`, `samba-tool fsmo show`
   (all roles on this DC), `host -t SRV _ldap._tcp.example.com 127.0.0.1`
   (`samba_dnsupdate --verbose` registers the DC's records),
   `kinit` for a user, a few SIDs (`samba-tool user show NAME
   --attributes=objectSid`) against what you know, the user count.
7. **conductor**: install it (`install.md`), put back
   `/etc/conductor/conductor.toml` from
   `/var/lib/samba-restored/files/etc/conductor/conductor.toml` with its
   `[domain] preferred`/`dcs` (and `[webauthn] rp_id` if it named the old
   DC) changed to the new DC, the TOTP key from where you keep it, then
   `conductor-backup restore … --with-conductor-state` (or copy
   `/var/lib/samba-restored/conductor/conductor.db` to
   `/var/lib/conductor/conductor.db`, owner `conductor`, mode 0600) and
   start it. `conductor audit verify` must pass: the audit chain continues
   from the backup.
8. **Backups again**: reinstall conductor-backup (README), with a **new
   signing key** (the old one was on the lost DC; the backup does not carry
   credentials). Add the new public key to the drill host's
   `backup_public_keys` and keep the old one there so older manifests still
   verify. The recipients file is in the archive
   (`files/etc/conductor-backup/recipients.txt`). Take a backup at once.
9. **Rebuild the other DCs** by joining them (section 2, step 3), never by
   restoring another copy.
10. **Clients**: computers whose machine account password changed after the
    backup was taken fail to authenticate; rejoin them. Users who changed
    their password after it use the old one.

## 5. Restore drills: proof that this works

`conductor-backup drill` on the drill host does steps 3-6 automatically
every week (or when an administrator clicks "Run drill now"), in a sandbox
with no network, and reports the measured restore time and every check to
the Backups page. A failed or overdue drill raises the dashboard banner and
an e-mail. Read its report before you trust a backup.

## 6. Manual path (no conductor-backup)

With only the `age` CLI, `tar` and `samba-tool`:

```sh
sha256sum 20261003T020000Z-dc1.tar.age        # compare with the manifest or your records
age -d -i operator-age.key 20261003T020000Z-dc1.tar.age | tar -x -C /root/restore-work
# conductor-backup.json describes the archive; samba/ holds the samba-tool file
samba-tool domain backup restore --backup-file=/root/restore-work/samba/samba-backup-….tar.bz2 \
  --newservername=DC3 --targetdir=/var/lib/samba-restored/samba
shred -u /root/restore-work/samba/*.tar.bz2
```

then continue with section 4, step 5.
