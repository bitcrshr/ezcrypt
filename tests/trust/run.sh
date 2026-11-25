#!/usr/bin/env bash
# End-to-end test of `ezcrypt trust` against a real sshd in a container.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
image=ezcrypt-trust-test
work=$(mktemp -d)
containers=()

cleanup() {
    for c in ${containers[@]+"${containers[@]}"}; do
        docker rm -f "$c" >/dev/null 2>&1 || true
    done
    rm -rf "$work"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR)

start_container() {
    local id
    id=$(docker run -d --rm -p 127.0.0.1::22 "$@" "$image")
    containers+=("$id")
    echo "$id"
}

wait_for_sshd() {
    local id=$1 i
    for i in $(seq 1 50); do
        docker exec "$id" test -s /run/sshd.pid 2>/dev/null && return 0
        sleep 0.2
    done
    fail "sshd did not start"
}

host_port() { docker port "$1" 22/tcp | head -n1 | sed 's/.*://'; }

echo "== building image"
docker build -q -f "$root/tests/trust/Containerfile" -t "$image" "$root" >/dev/null

echo "== generating keys"
ssh-keygen -q -t ed25519 -N '' -C ca -f "$work/ca"
ssh-keygen -q -t ed25519 -N '' -C user -f "$work/user"
ssh-keygen -q -s "$work/ca" -I test -n testuser -V +1h "$work/user.pub"
(cd "$root" && cargo run --locked -q -p ezcrypt-link --example make-reply -- "$work/ca.pub" "Test CA") >"$work/reply.txt"

echo "== trust, login, rerun"
c=$(start_container)
wait_for_sshd "$c"
port=$(host_port "$c")

login() {
    ssh "${SSH_OPTS[@]}" -i "$work/user" -o CertificateFile="$work/user-cert.pub" \
        -p "$port" testuser@127.0.0.1 true
}

if login 2>/dev/null; then fail "login worked before trust"; fi

docker cp "$work/reply.txt" "$c:/tmp/reply.txt"
docker exec "$c" ezcrypt trust --yes --from-reply /tmp/reply.txt
login || fail "login with certificate"
echo "PASS: login with certificate"

sums() { docker exec "$c" sh -c 'cat /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* /etc/ssh/ezcrypt/* 2>/dev/null | md5sum; ls -l --time-style=+%s /etc/ssh/sshd_config /etc/ssh/sshd_config.d /etc/ssh/ezcrypt | md5sum'; }
before=$(sums)
docker exec "$c" ezcrypt trust --yes --from-reply /tmp/reply.txt
after=$(sums)
[ "$before" = "$after" ] || fail "rerun changed files"
login || fail "login after rerun"
echo "PASS: rerun unchanged"

echo "== shadowed setting"
c2=$(start_container)
docker exec "$c2" sh -c 'touch /etc/ssh/other && echo "TrustedUserCAKeys /etc/ssh/other" >> /etc/ssh/sshd_config'
docker cp "$work/reply.txt" "$c2:/tmp/reply.txt"
if out=$(docker exec "$c2" ezcrypt trust --yes --from-reply /tmp/reply.txt 2>&1); then
    fail "trust succeeded despite shadowing: $out"
fi
echo "$out" | grep -q "/etc/ssh/other" || fail "error does not mention /etc/ssh/other: $out"
echo "PASS: shadowed setting refused"
