# Samba Conductor v2 — Guidelines

Go rewrite of Samba Conductor (v1 = Meteor/MongoDB, `edimarlnx/samba-conductor`,
to be archived). Web admin + self-service for Samba AD,
plus separate optional components: OIDC provider, provisioning sync
(Google Workspace first), encrypted domain backup. Design: `../planning/docs/architecture.md`.

- Security first: AD operations with the signed-in user's own identity
  (Kerberos/LDAPS); root only in `conductor-helper` (typed allowlist, no argv
  secrets); 2FA mandatory for admins, configurable for others; admin by group
  SID re-checked on AD; every change previewed and audited (hash chain).
- No MongoDB. Local state in SQLite; AD is the source of truth.
- Native systemd services on the DC VM (sandboxed units); Docker optional.
- Kept separate from tui-tools by owner decision; the AD layer is the `ad`
  module (`github.com/openbasalt/samba-conductor-ad`), shared with `tui-dc`
  later. Sibling modules are pinned in go.mod; the family go.work overrides
  them locally (CONTRIBUTING.md).
- Go: `go test ./...`, `go vet ./...`, gofmt, govulncheck. Heavy runs (Samba
  lab containers, e2e) on the lab host.
- Open source (MIT, like v1). Code comments and docs in English.
- Commit with explicit paths (never `git add -A`).
