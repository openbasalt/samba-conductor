#!/usr/bin/env bash
# Maintainer lab tooling: it needs the family checkout with the lab
# scripts (planning/lab), which are not published; the lab is described in
# https://github.com/openbasalt/samba-conductor-docs/blob/main/testing.md
# Build conductor, conductor-helper, conductor-backup, conductor-sync (with
# the lab's fake Directory API) and conductor-files on the lab host and
# install them in the lab (planning/lab/conductor-install.sh, which follows
# docs/install.md; backup-install.sh for conductor-backup; sync-install.sh
# for conductor-sync; files-install.sh for conductor-files on fs1).
#
#   scripts/lab-deploy.sh                 # build + install/upgrade on dc1 (+ drill VM, fs1)
#   scripts/lab-deploy.sh --snapshot      # rebuild the conductor-p2b snapshot from conductor-p5b
#                                         # (planning/lab/p2b-snapshot.sh: dc1, dc2 and fs1)
#   scripts/lab-deploy.sh --snapshot-p5b  # rebuild conductor-p5b from conductor-p3 (p5b-snapshot.sh)
#   scripts/lab-deploy.sh --snapshot-p3   # rebuild conductor-p3 from "seeded" (p3-snapshot.sh)
#   LAB_HOST=<ssh destination> (required)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # the family directory
LAB_HOST="${LAB_HOST:?set LAB_HOST to the SSH destination of the lab host}"
VERSION="$(git -C conductor describe --always --dirty 2>/dev/null || echo dev)"

rsync -a --delete --exclude .git/ --exclude node_modules/ --exclude /conductor/bin/ --exclude /conductor-backup/bin/ --exclude /ACESSO-AMBIENTE-TESTE.md --exclude /conductor-devenv-fake-google-key.json \
  --exclude /conductor/e2e/test-results/ --exclude /conductor/e2e/playwright-report/ --exclude /conductor-sync/bin/ --exclude /conductor-files/bin/ ./ "$LAB_HOST:samba-conductor/"
ssh -o BatchMode=yes "$LAB_HOST" bash -s -- "$VERSION" "${1:-}" <<'REMOTE'
set -euo pipefail
version="$1" snap="${2:-}"
# A Go workspace over the copied modules (planning/scripts/family-gowork.sh):
# the lab runs the local sibling modules, not the versions go.mod pins, and
# the lab host needs no access to the private repositories.
mkdir -p ~/conductor-build
(cd ~/samba-conductor && planning/scripts/family-gowork.sh -o ~/conductor-build/go.work \
  ad conductor conductor-backup conductor-sync conductor-files)
export GOWORK="$HOME/conductor-build/go.work" GOTOOLCHAIN=go1.27.0 CGO_ENABLED=0
cd ~/samba-conductor/conductor
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor ./cmd/conductor
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor-helper ./cmd/conductor-helper
cp deploy/systemd/conductor.service deploy/systemd/conductor-helper.service ~/conductor-build/
cd ~/samba-conductor/conductor-backup
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor-backup ./cmd/conductor-backup
cp deploy/systemd/conductor-backup.service deploy/systemd/conductor-backup.timer deploy/systemd/conductor-backup.path \
  deploy/systemd/conductor-backup-drill.service deploy/systemd/conductor-backup-drill.timer \
  deploy/systemd/conductor-helper.service.d/conductor-backup.conf ~/conductor-build/
cd ~/samba-conductor/conductor-sync
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor-sync ./cmd/conductor-sync
go build -trimpath -o ~/conductor-build/fakegws ./tools/fakegws
cp deploy/systemd/conductor-sync.service deploy/systemd/conductor-sync.timer deploy/systemd/conductor-sync-api.service \
  deploy/systemd/conductor-sync-api.socket ~/conductor-build/
cd ~/samba-conductor/conductor-files
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor-files ./cmd/conductor-files
cp deploy/systemd/conductor-files.service ~/conductor-build/
cd ~/samba-conductor/planning/lab
case "$snap" in
--snapshot) ./p2b-snapshot.sh ~/conductor-build ;;
--snapshot-p5b) ./p5b-snapshot.sh ~/conductor-build ;;
--snapshot-p3) ./p3-snapshot.sh ~/conductor-build ;;
*)
  ./conductor-install.sh ~/conductor-build
  ./backup-infra.sh ~/conductor-build
  ./drill-up.sh
  ./backup-install.sh ~/conductor-build both
  ./sync-install.sh ~/conductor-build
  ./files-install.sh ~/conductor-build
  ;;
esac
REMOTE
