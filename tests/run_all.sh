#!/bin/sh
# Fresh database, then each suite against a freshly started server (the IP block is in-memory).
B=/home/claude/postwright/target/${PROFILE:-debug}/postwright
cd /tmp/pwtest
start() { pkill -f "postwright serve"; sleep 1; (RUST_LOG=info $B serve >> server.log 2>&1 &); sleep 1.5; }
pkill -f "postwright serve"; sleep 1
rm -f data/postwright.db data/postwright.db-wal data/postwright.db-shm server.log
$B domain add johncock.test >/dev/null; $B domain add poffles.test >/dev/null
$B user add tony@johncock.test --password 'CorrectHorse1' --quota-mb 100 >/dev/null
$B user add amy@poffles.test --password 'BatteryStaple2' >/dev/null
$B alias add hello@poffles.test amy@poffles.test >/dev/null
$B alias add info@poffles.test tony@johncock.test >/dev/null
$B domain catch-all poffles.test amy@poffles.test >/dev/null
start; timeout 150 python3 -I /home/claude/tests/e2e.py | grep -E "FAIL|passed"
start; python3 -I /home/claude/tests/dkim_check.py
start; timeout 150 python3 -I /home/claude/tests/e2e_features.py | grep -E "FAIL|passed"
