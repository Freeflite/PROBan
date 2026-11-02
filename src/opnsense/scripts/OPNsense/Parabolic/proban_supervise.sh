#!/bin/sh
# ProBAN engine supervisor.
#
# engine.py runs a single ban/decay/enforce cycle and exits. This loop is what
# makes it a service: run the engine, sleep, repeat. Managed by rc.d/proban via
# daemon(8), so `configctl proban start|stop|restart` controls it.
#
# A settings save does NOT restart this -- the engine re-reads config.json every
# cycle, and the API kicks an immediate one-shot `proban run`. restart is only for
# start/stop from the Services page.
INTERVAL="${PROBAN_INTERVAL:-60}"
ENGINE="/usr/local/opnsense/scripts/OPNsense/Parabolic/engine.py"
PYTHON="/usr/local/bin/python3"

mkdir -p /var/log/parabolic

# Stop promptly: run the sleep in the background and wait on it, so SIGTERM interrupts
# the wait and we exit right away. Otherwise rc.d stop blocks until the current sleep
# elapses (up to INTERVAL seconds) -- which made `proban restart`/stop take ~30s.
sleep_pid=""
term() { [ -n "$sleep_pid" ] && kill "$sleep_pid" 2>/dev/null; exit 0; }
trap term TERM INT

while :; do
    "$PYTHON" "$ENGINE" 2>&1 | logger -t proban
    sleep "$INTERVAL" &
    sleep_pid=$!
    wait "$sleep_pid"
done
