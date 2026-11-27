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

# sshd re-execs itself on SIGHUP and briefly stops listening, so a login
# right after a reload can be refused; retry for a few seconds.
login() {
    local i
    for i in $(seq 1 10); do
        ssh "${SSH_OPTS[@]}" -i "$work/user" -o CertificateFile="$work/user-cert.pub" \
            -p "$port" testuser@127.0.0.1 true && return 0
        sleep 0.3
    done
    return 1
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

# Without --from-reply, trust would start a phone session and print a QR code;
# checks that don't need the CA key must fail before that.
no_session() {
    local id=$1 want=$2 out
    if out=$(docker exec "$id" timeout 20 ezcrypt trust </dev/null 2>&1); then
        fail "trust succeeded: $out"
    fi
    echo "$out" | grep -q "$want" || fail "error does not mention '$want': $out"
    if echo "$out" | grep -q "ezcrypt://"; then fail "a session started before the check failed: $out"; fi
}
no_session "$c2" "/etc/ssh/other"
echo "PASS: shadowed setting refused before the session"
c4=$(start_container)
docker exec "$c4" mv /usr/sbin/sshd /usr/sbin/sshd.moved
no_session "$c4" "could not find sshd"
echo "PASS: missing sshd refused before the session"

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

echo "== escalation from ~/.local/bin"
# sudo's secure_path leaves out ~/.local/bin, so `sudo ezcrypt` cannot find
# it; a plain `ezcrypt trust` must rerun itself as root by absolute path.
c5=$(start_container)
wait_for_sshd "$c5"
port=$(host_port "$c5")
docker cp "$work/reply.txt" "$c5:/tmp/reply.txt"
docker exec "$c5" sh -c 'chmod 644 /tmp/reply.txt && install -D -o admin -m 755 /usr/local/bin/ezcrypt /home/admin/.local/bin/ezcrypt && rm /usr/local/bin/ezcrypt'
userpath='PATH=/home/admin/.local/bin:/usr/bin:/bin'
if docker exec -u admin "$c5" sh -c "$userpath sudo ezcrypt --version" >/dev/null 2>&1; then
    fail "sudo found ezcrypt in ~/.local/bin; this case tests nothing"
fi
out=$(docker exec -u admin "$c5" sh -c "$userpath ezcrypt trust --yes --from-reply /tmp/reply.txt" 2>&1) \
    || fail "trust as a non-root user failed: $out"
echo "$out" | grep -q "Running it with sudo" || fail "no note about sudo: $out"
login || fail "login after escalated trust"
echo "PASS: trust escalates with sudo"
