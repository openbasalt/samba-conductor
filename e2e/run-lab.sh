#!/usr/bin/env bash
# Run the Playwright suite on server-home against conductor on the lab's
# dc1, once per project (desktop, mobile), each on a freshly reset lab.
#
#   e2e/run-lab.sh                    # deploy + snapshot conductor-p3, run both
#   e2e/run-lab.sh --no-deploy        # reuse the conductor-p3 snapshot
#   e2e/run-lab.sh --no-deploy desktop
#   E2E_GREP='administrator|WebAuthn' e2e/run-lab.sh --no-deploy desktop   # a subset
#   E2E_NO_RESET=1 E2E_STALE=1 E2E_GREP='forced 2FA|missed schedule' e2e/run-lab.sh --no-deploy desktop
#                                     # the missed-schedule check (lab as it is)
#
# Secrets stay on server-home: they go from ~/conductor-lab/secrets.env to
# the container through a 0600 env file that is deleted afterwards. After
# each run the audit chain is verified on dc1. Screenshots and the HTML
# report are copied back to e2e/screenshots and e2e/playwright-report.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
LAB_HOST="${LAB_HOST:-server-home}"
deploy=1
projects=()
for a in "$@"; do
  case "$a" in
    --no-deploy) deploy=0 ;;
    desktop|mobile) projects+=("$a") ;;
    *) echo "unknown argument $a" >&2; exit 2 ;;
  esac
done
[ ${#projects[@]} -gt 0 ] || projects=(desktop mobile)

if [ "$deploy" = 1 ]; then
  ./scripts/lab-deploy.sh --snapshot
else
  rsync -a --delete --exclude node_modules/ --exclude test-results/ --exclude playwright-report/ --exclude screenshots/ --exclude .auth/ \
    e2e/ "$LAB_HOST:samba-conductor/conductor/e2e/"
fi

rc=0
for p in "${projects[@]}"; do
  echo "=== project $p"
  # ssh joins its arguments into one remote command line: quote the grep.
  ssh -o BatchMode=yes "$LAB_HOST" bash -s -- "$p" "$(printf '%q' "${E2E_GREP:-}")" "${E2E_NO_RESET:-0}" "${E2E_STALE:-}" <<'REMOTE' || rc=$?
set -euo pipefail
project="$1" grep="${2:-}" noreset="${3:-0}" stale="${4:-}"
LAB_HOME="$HOME/conductor-lab"
E2E="$HOME/samba-conductor/conductor/e2e"
SSH="ssh -n -i $LAB_HOME/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=$LAB_HOME/known_hosts -o LogLevel=ERROR debian@10.93.0.10"
cd "$HOME/samba-conductor/planning/lab"
[ "$noreset" = 1 ] || ./reset.sh conductor-p3 </dev/null >/dev/null 2>&1
$SSH 'for i in $(seq 90); do ss -ltn | grep -q ":8443 " && exit 0; sleep 1; done; exit 1'
link="$($SSH 'sudo -u conductor conductor enroll-link --user lab.admin --base-url https://dc1.lab.conductor.test:8443' | tail -n 1)"
spki="$(openssl x509 -in "$LAB_HOME/tls/conductor-dc1.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
rm -rf "$E2E/.auth" "$E2E/screenshots/$project" "$E2E/test-results"
install -d -m 0700 "$E2E/.auth"
install -m 0644 "$LAB_HOME/ca.pem" "$E2E/.auth/lab-ca.pem"
envf="$(mktemp)"
trap 'rm -f "$envf"' EXIT
( set -a; . "$LAB_HOME/secrets.env"; set +a
  umask 077
  printf 'E2E_USER_PASSWORD=%s\nE2E_ADMIN_PASSWORD=%s\nE2E_HELPDESK_PASSWORD=%s\nE2E_ADMIN_ENROLL_URL=%s\nE2E_CERT_SPKI=%s\nE2E_STALE=%s\n' \
    "$LAB_USER_PASSWORD" "$LAB_TESTADMIN_PASSWORD" "$LAB_HELPDESK_PASSWORD" "$link" "$spki" "$stale" >"$envf" )
docker run --rm --network host --add-host dc1.lab.conductor.test:10.93.0.10 --security-opt label=disable \
  -u "$(id -u):$(id -g)" -e HOME=/tmp -e CI=1 -e NODE_EXTRA_CA_CERTS=/work/.auth/lab-ca.pem --env-file "$envf" \
  -e E2E_GREP="$grep" -v "$E2E:/work" -w /work mcr.microsoft.com/playwright:v1.62.1-noble </dev/null \
  sh -c 'npm ci --no-audit --no-fund --loglevel=error >/dev/null && npx playwright test --project='"$project"' ${E2E_GREP:+--grep "$E2E_GREP"}' || test_rc=$?
echo "=== audit chain on dc1 after the $project run"
$SSH 'sudo -u conductor conductor audit verify'
exit "${test_rc:-0}"
REMOTE
  mkdir -p e2e/screenshots "e2e/playwright-report/$p"
  rsync -a "$LAB_HOST:samba-conductor/conductor/e2e/screenshots/" e2e/screenshots/ || true
  rsync -a --delete "$LAB_HOST:samba-conductor/conductor/e2e/playwright-report/" "e2e/playwright-report/$p/" || true
done
exit "$rc"
