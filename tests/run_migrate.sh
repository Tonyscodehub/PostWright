#!/bin/sh
# Migration + contacts suite (fresh database, fake cloud APIs on 9911).
B=/home/claude/postwright-repo/target/${PROFILE:-release}/postwright
cd /tmp/pwtest
pkill -f "postwright.* serve"; pkill -f fake_clouds.py; sleep 1
rm -rf data/postwright.db data/postwright.db-wal data/postwright.db-shm data/blobs server.log
C="-c /tmp/pwtest/postwright.toml"
$B $C domain add johncock.test >/dev/null; $B $C domain add poffles.test >/dev/null
$B $C user add tony@johncock.test --password 'CorrectHorse1' >/dev/null
$B $C user add amy@poffles.test --password 'BatteryStaple2' >/dev/null
$B $C alias add hello@poffles.test amy@poffles.test >/dev/null
$B $C user admin tony@johncock.test >/dev/null
(python3 -I /home/claude/tests/fake_clouds.py 9911 &)
(RUST_LOG=info $B $C serve >> server.log 2>&1 &); sleep 1.5
echo "migrate:"; PWBIN=$B timeout 600 python3 -I /home/claude/tests/migrate_check.py | grep -E "FAIL|passed|Error|line "
pkill -f "postwright.* serve"; pkill -f fake_clouds.py
