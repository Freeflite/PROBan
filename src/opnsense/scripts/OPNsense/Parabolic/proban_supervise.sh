#!/bin/sh
# ProBAN engine supervisor.
#
# daemon(8) supervises the persistent engine and forwards its output to syslog.
# PROBAN_INTERVAL controls full maintenance, not the fast detection cadence.
INTERVAL="${PROBAN_INTERVAL:-60}"
ENGINE="/usr/local/opnsense/scripts/OPNsense/Parabolic/engine.py"
PYTHON="/usr/local/bin/python3"

mkdir -p /var/log/parabolic

exec "$PYTHON" -u "$ENGINE" --daemon --interval "$INTERVAL"
