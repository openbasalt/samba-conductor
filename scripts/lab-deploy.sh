#!/usr/bin/env bash
# Build conductor on server-home and install it on the lab's dc1
# (planning/lab/conductor-install.sh, which follows docs/install.md).
#
#   scripts/lab-deploy.sh               # build + install/upgrade on dc1
#   scripts/lab-deploy.sh --snapshot    # … and snapshot both DCs as conductor-p1
#   LAB_HOST=server-home (default)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."   # the family directory
LAB_HOST="${LAB_HOST:-server-home}"
VERSION="$(git -C conductor describe --always --dirty 2>/dev/null || echo dev)"

rsync -a --delete --exclude .git/ --exclude node_modules/ --exclude /conductor/bin/ \
  --exclude /conductor/e2e/test-results/ --exclude /conductor/e2e/playwright-report/ ./ "$LAB_HOST:samba-conductor/"
ssh -o BatchMode=yes "$LAB_HOST" bash -s -- "$VERSION" "${1:-}" <<'REMOTE'
set -euo pipefail
version="$1" snap="${2:-}"
cd ~/samba-conductor/conductor
export GOWORK=off GOTOOLCHAIN=go1.27.0 CGO_ENABLED=0
mkdir -p ~/conductor-build
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor ./cmd/conductor
go build -trimpath -ldflags "-s -w -X main.version=$version" -o ~/conductor-build/conductor-helper ./cmd/conductor-helper
cp deploy/systemd/conductor.service deploy/systemd/conductor-helper.service ~/conductor-build/
cd ~/samba-conductor/planning/lab
./conductor-install.sh ~/conductor-build $snap
REMOTE
