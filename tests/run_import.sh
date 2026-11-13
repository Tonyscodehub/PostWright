#!/bin/sh
# Fresh fake iRedMail -> fresh Postwright import -> verify through a live server.
B=/home/claude/postwright-repo/target/${PROFILE:-release}/postwright
pkill -f "postwright.* serve"; sleep 1
sh /home/claude/tests/fake_iredmail.sh >/dev/null
cd /tmp/imptest && rm -f data/postwright.db data/postwright.db-wal data/postwright.db-shm server.log
$B import iredmail >/dev/null && $B import iredmail | grep "already present"
(RUST_LOG=info $B serve > server.log 2>&1 &); sleep 1.5
python3 -I /home/claude/tests/import_check.py | grep -E "FAIL|passed"
