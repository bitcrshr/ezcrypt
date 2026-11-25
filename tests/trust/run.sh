#!/usr/bin/env bash
# End-to-end test of `ezcrypt trust` against a real sshd in a container.
set -euo pipefail

root=$(cd "$(dirname "$0")/../.." && pwd)
image=ezcrypt-trust-test
work=$(mktemp -d)
label=ezcrypt-trust-test-$$

cleanup() {
    docker ps -aq --filter "label=$label" | xargs docker rm -f >/dev/null 2>&1 || true
    rm -rf "$work"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    -o IdentitiesOnly=yes -o BatchMode=yes -o LogLevel=ERROR)

start_container() {
    docker run -d --label "$label" -p 127.0.0.1::22 "$@" "$image"
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

echo "== sshd not running"
# A host where sshd has never started: no daemon, no pid file, no /run/sshd.
c3=$(docker run -d --label "$label" -p 127.0.0.1::22 "$image" sleep infinity)
docker exec "$c3" sh -c 'rm -rf /run/sshd /run/sshd.pid && ssh-keygen -A'
docker cp "$work/reply.txt" "$c3:/tmp/reply.txt"
out=$(docker exec "$c3" ezcrypt trust --yes --from-reply /tmp/reply.txt 2>&1) \
    || fail "trust failed with sshd stopped: $out"
echo "$out" | grep -q "sshd isn't running" || fail "no note that sshd isn't running: $out"
docker exec "$c3" test -d /run/sshd || fail "/run/sshd was not created"
docker exec "$c3" /usr/sbin/sshd -o PidFile=/run/sshd.pid
wait_for_sshd "$c3"
port=$(host_port "$c3")
login || fail "login after starting sshd"
echo "PASS: trust with sshd stopped"
