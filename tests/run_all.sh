#!/bin/sh
# Runs every suite against a freshly started server (the brute-force IP block is in-memory,
# and one suite deliberately triggers it). PROFILE selects the build, e.g. "release" or
# "x86_64-unknown-linux-musl/release".
B=/home/claude/postwright-repo/target/${PROFILE:-release}/postwright
T=/home/claude/tests
stop() { pkill -f "postwright.* serve"; sleep 1; }
start() { stop; (RUST_LOG=info $B -c "/tmp/pwtest/$1" serve >> /tmp/pwtest/server.log 2>&1 &); sleep 1.5; }

stop
cd /tmp/pwtest && rm -f data/postwright.db data/postwright.db-wal data/postwright.db-shm server.log
C="-c /tmp/pwtest/postwright.toml"
$B $C domain add johncock.test >/dev/null; $B $C domain add poffles.test >/dev/null
$B $C user add tony@johncock.test --password 'CorrectHorse1' --quota-mb 100 >/dev/null
$B $C user add amy@poffles.test --password 'BatteryStaple2' >/dev/null
$B $C alias add hello@poffles.test amy@poffles.test >/dev/null
$B $C alias add info@poffles.test tony@johncock.test >/dev/null
$B $C domain catch-all poffles.test amy@poffles.test >/dev/null
$B $C user admin tony@johncock.test >/dev/null

start postwright.toml; echo "core:";     timeout 150 python3 -I $T/e2e.py | grep -E "FAIL|passed"
start postwright.toml; echo "dkim:";     python3 -I $T/dkim_check.py
start postwright.toml; echo "features:"; timeout 150 python3 -I $T/e2e_features.py | grep -E "FAIL|passed"
start postwright.toml; echo "admin:";    timeout 150 python3 -I $T/admin_check.py | grep -E "FAIL|passed"
# Scanner suite: real ClamAV, Rspamd and SpamAssassin must be running.
start filter.toml;     echo "filters:";  timeout 150 python3 -I $T/filter_check.py | grep -E "FAIL|passed"
stop
# Certificate push suite (uses OpenSSH's sftp client).
start filter.toml; echo "certs:"; cp /tmp/pwtest/data/tls/cert.pem /tmp/pwtest/cert.bak; cp /tmp/pwtest/data/tls/key.pem /tmp/pwtest/key.bak
timeout 200 python3 -I $T/cert_check.py | grep -E "FAIL|passed"
stop; cp /tmp/pwtest/cert.bak /tmp/pwtest/data/tls/cert.pem; cp /tmp/pwtest/key.bak /tmp/pwtest/data/tls/key.pem
# Two-step verification, app passwords, delegation, send on behalf (fresh database).
$T/run_security.sh
