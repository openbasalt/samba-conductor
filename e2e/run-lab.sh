#!/usr/bin/env bash
# Run the Playwright suite on server-home against conductor on the lab's
# dc1, once per project (desktop, mobile), each on a freshly reset lab.
#
#   e2e/run-lab.sh                    # deploy + snapshot conductor-p2b, run both
#   e2e/run-lab.sh --no-deploy        # reuse the conductor-p2b snapshot
#   e2e/run-lab.sh --no-deploy desktop
#   E2E_GREP='administrator|WebAuthn' e2e/run-lab.sh --no-deploy desktop   # a subset
#   E2E_NO_RESET=1 E2E_STALE=1 E2E_GREP='forced 2FA|missed schedule' e2e/run-lab.sh --no-deploy desktop
#                                     # the missed-schedule check (lab as it is)
#
# Secrets stay on server-home: they go from ~/conductor-lab/secrets.env to
# the container through a 0600 env file that is deleted afterwards. After
# each run the audit chain is verified on dc1 (and conductor-files' on fs1).
# Screenshots and the HTML report are copied back to e2e/screenshots and
# e2e/playwright-report.
#
# File servers (P2b): a one-time enrollment code is made on fs1
# (E2E_FILES_CODE) and an SMB watcher runs next to the suite: the files
# spec writes .auth/smb-req-<id>.json ({share, user, op}) and the watcher
# answers .auth/smb-res-<id>.json with smbclient run on dc2 against fs1 as
# that lab user (the password goes to dc2 on stdin, never into the browser
# container).
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
SSH_FS="ssh -n -i $LAB_HOME/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=$LAB_HOME/known_hosts -o LogLevel=ERROR debian@10.93.0.20"
SSH_DC2="ssh -i $LAB_HOME/id_ed25519 -o BatchMode=yes -o UserKnownHostsFile=$LAB_HOME/known_hosts -o LogLevel=ERROR debian@10.93.0.11"
[ "$noreset" = 1 ] || ./reset.sh conductor-p2b </dev/null >/dev/null 2>&1
$SSH 'for i in $(seq 90); do ss -ltn | grep -q ":8443 " && exit 0; sleep 1; done; exit 1'
link="$($SSH 'sudo -u conductor conductor enroll-link --user lab.admin --base-url https://dc1.lab.conductor.test:8443' | tail -n 1)"
spki="$(openssl x509 -in "$LAB_HOME/tls/conductor-dc1.pem" -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | base64)"
rm -rf "$E2E/.auth" "$E2E/screenshots/$project" "$E2E/test-results"
install -d -m 0700 "$E2E/.auth"
install -m 0644 "$LAB_HOME/ca.pem" "$E2E/.auth/lab-ca.pem"
# The fake Google's service account key, uploaded by the sync setup test.
$SSH 'for i in $(seq 60); do sudo test -s /var/lib/conductor-lab-fakegws/sa-key.json && exit 0; sleep 1; done; exit 1'
(umask 077; $SSH 'sudo cat /var/lib/conductor-lab-fakegws/sa-key.json' >"$E2E/.auth/fake-sa-key.json")
# A one-time enrollment code for fs1 (the files spec enrolls it).
$SSH_FS 'for i in $(seq 60); do ss -ltn | grep -q ":7443 " && exit 0; sleep 1; done; exit 1'
files_code="$($SSH_FS 'sudo conductor-files enroll-code --quiet')"
# smb_watcher answers the files spec's SMB checks (see the header).
smb_watcher() {
  local pw req id share user op out rc cmds
  pw="$(set -a; . "$LAB_HOME/secrets.env"; printf '%s' "$LAB_USER_PASSWORD")"
  while :; do
    for req in "$E2E"/.auth/smb-req-*.json; do
      [ -e "$req" ] || continue
      id="${req##*/smb-req-}"; id="${id%.json}"
      read -r share user op < <(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["share"], d["user"], d["op"])' "$req") || true
      rm -f "$req"
      out="invalid request"; rc=2; cmds=""
      if [[ "$share" =~ ^[A-Za-z0-9._-]{1,64}$ && "$user" =~ ^[a-z0-9._-]{1,32}$ ]]; then
        case "$op" in
          ls) cmds="ls" ;;
          write) cmds="ls; put /etc/hostname e2e-$user.txt; ls" ;;
          hold)
            printf '%s\n' "$pw" | $SSH_DC2 "read -r PASSWD; export PASSWD; nohup bash -c '(sleep 25; echo quit) | smbclient //fs1.lab.conductor.test/$share -U \"LAB\\\\$user\"' >/dev/null 2>&1 &" && rc=0 || rc=$?
            out="holding" ;;
        esac
        if [ -n "$cmds" ]; then
          rc=0
          out="$(printf '%s\n' "$pw" | $SSH_DC2 "read -r PASSWD; export PASSWD; smbclient //fs1.lab.conductor.test/$share -U 'LAB\\$user' -c '$cmds'" 2>&1)" || rc=$?
        fi
      fi
      python3 -c 'import json,sys; json.dump({"rc": int(sys.argv[1]), "out": sys.argv[2]}, open(sys.argv[3] + ".tmp", "w"))' "$rc" "$out" "$E2E/.auth/smb-res-$id.json"
      mv "$E2E/.auth/smb-res-$id.json.tmp" "$E2E/.auth/smb-res-$id.json"
    done
    sleep 0.3
  done
}
smb_watcher </dev/null &
watcher=$!
envf="$(mktemp)"
trap 'kill "$watcher" 2>/dev/null; rm -f "$envf"' EXIT
( set -a; . "$LAB_HOME/secrets.env"; set +a
  umask 077
  printf 'E2E_USER_PASSWORD=%s\nE2E_ADMIN_PASSWORD=%s\nE2E_HELPDESK_PASSWORD=%s\nE2E_ADMIN_ENROLL_URL=%s\nE2E_CERT_SPKI=%s\nE2E_STALE=%s\nE2E_FILES_CODE=%s\n' \
    "$LAB_USER_PASSWORD" "$LAB_TESTADMIN_PASSWORD" "$LAB_HELPDESK_PASSWORD" "$link" "$spki" "$stale" "$files_code" >"$envf" )
docker run --rm --network host --add-host dc1.lab.conductor.test:10.93.0.10 --security-opt label=disable \
  -u "$(id -u):$(id -g)" -e HOME=/tmp -e CI=1 -e NODE_EXTRA_CA_CERTS=/work/.auth/lab-ca.pem --env-file "$envf" \
  -e E2E_GREP="$grep" -v "$E2E:/work" -w /work mcr.microsoft.com/playwright:v1.62.1-noble </dev/null \
  sh -c 'npm ci --no-audit --no-fund --loglevel=error >/dev/null && npx playwright test --project='"$project"' ${E2E_GREP:+--grep "$E2E_GREP"}' || test_rc=$?
echo "=== audit chains on dc1 and fs1 after the $project run"
$SSH 'sudo -u conductor conductor audit verify'
$SSH_FS 'sudo conductor-files audit verify'
exit "${test_rc:-0}"
REMOTE
  mkdir -p e2e/screenshots "e2e/playwright-report/$p"
  rsync -a "$LAB_HOST:samba-conductor/conductor/e2e/screenshots/" e2e/screenshots/ || true
  rsync -a --delete "$LAB_HOST:samba-conductor/conductor/e2e/playwright-report/" "e2e/playwright-report/$p/" || true
done
exit "$rc"
