#!/bin/sh
# Starts the external services the test suites use.
service mariadb start >/dev/null 2>&1
service postgresql start >/dev/null 2>&1
mkdir -p /run/clamav /run/rspamd /var/lib/rspamd && chown _rspamd:_rspamd /run/rspamd /var/lib/rspamd
pgrep clamd >/dev/null || clamd -c /tmp/clamd.conf
pgrep rspamd >/dev/null || rspamd -u _rspamd -g _rspamd >/dev/null 2>&1
printf "PING SPAMC/1.5\r\n\r\n" | timeout 3 nc 127.0.0.1 783 | grep -q PONG || spamd -d --allow-tell -i 127.0.0.1 -p 783 >/dev/null 2>&1
sleep 8
