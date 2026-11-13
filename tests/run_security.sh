#!/bin/sh
# Two-step verification / delegation suite. Uses a copy of the test config with a higher
# failed-login limit, because the suite deliberately makes a lot of failed sign-ins.
B=/home/claude/postwright-repo/target/${PROFILE:-release}/postwright
cd /tmp/pwtest
sed 's/^max_auth_failures = 5/max_auth_failures = 100/' postwright.toml > security.toml
pkill -f "postwright.* serve"; sleep 1
rm -f data/postwright.db data/postwright.db-wal data/postwright.db-shm server.log
C="-c /tmp/pwtest/security.toml"
$B $C domain add johncock.test >/dev/null; $B $C domain add poffles.test >/dev/null
$B $C user add tony@johncock.test --password 'CorrectHorse1' --quota-mb 100 >/dev/null
$B $C user add amy@poffles.test --password 'BatteryStaple2' >/dev/null
$B $C user admin tony@johncock.test >/dev/null
(RUST_LOG=info $B $C serve >> server.log 2>&1 &); sleep 1.5
echo "security:"; timeout 400 python3 -I /home/claude/tests/security_check.py | grep -E "FAIL|passed|Error|line "
pkill -f "postwright.* serve"
