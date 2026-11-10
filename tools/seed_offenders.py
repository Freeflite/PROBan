#!/usr/bin/env python3
"""Seed synthetic offenders into a ProBAN store for dashboard/UI validation.

This is a DEVELOPMENT helper, not part of the shipped plugin (the Makefile
packages ``src/`` only). Use it to populate the offenders table with a large,
realistic-looking spread so you can exercise the dashboard by hand:

  * offenders-list pagination and the page-size picker (incl. the 500-row cap
    and the "max 500" custom entry),
  * column sorting across thousands of rows,
  * the "Active blocks" stat and the blocked/decayed split,
  * the per-offender hits modal (with --with-events N it seeds event detail for
    the first N offenders; the rest have no events, which exercises the
    "event history aged out" explainer).

All synthetic rows use the RFC 2544 benchmarking block (198.18.0.0/15) by
default: reserved, non-routable, and easy to identify and purge. Nothing in
that range can reach a real host.

The schema comes from ``proban.store.db()``, so it always matches the engine.

Examples
--------
  # Spray 5,000 offenders into the live store on an OPNsense box:
  python3 tools/seed_offenders.py --count 5000

  # Point at a specific DB, reproducible seed, 50% active, seed event detail
  # for the first 25 offenders:
  python3 tools/seed_offenders.py --db /var/log/parabolic/offenders.db \\
      --count 5000 --active-frac 0.5 --seed 1337 --with-events 25

  # Remove everything this tool added (purge the synthetic range) and exit:
  python3 tools/seed_offenders.py --purge

Run it on the firewall (python3 is part of the OPNsense base). Restart the
engine afterwards only if you want it to start decaying the synthetic rows;
the dashboard reads the DB directly, so a browser refresh is enough to see
them.
"""
import argparse
import ipaddress
import os
import random
import sys
import time

# Import the engine's store so the schema stays in lockstep with the plugin.
sys.path.insert(0, os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "src", "opnsense", "scripts", "OPNsense", "Parabolic")))
from proban import store   # noqa: E402

DEFAULT_DB = "/var/log/parabolic/offenders.db"

REASON_TEMPLATES = [
    "firewall:TCP SYN probe to {target}:{port} blocked on vtnet1; port scan: "
    "{n} distinct TCP destination ports on {target} in 60s (threshold 10)",
    "firewall:UDP probe to {target}:{port} blocked on vtnet1\n"
    "pf:{n} additional incoming packets blocked by PF while the ban is active",
    "firewall:TCP NULL/FIN/XMAS flags to {target}:{port} blocked on vtnet1",
    "suricata:ET SCAN potential SSH Scan on {target}:{port} (severity 2)",
    "suricata:ET EXPLOIT attempted login on {target}:{port} (severity 1)\n"
    "pf:{n} additional incoming packets blocked by PF while the ban is active",
    "firewall:invalid TCP flag combo to {target}:{port} blocked on vtnet1",
]
PORTS = [21, 22, 23, 80, 443, 445, 3389, 8443, 3306, 5432]


class _Cfg:
    """Minimal shim: store.db() only reads .db off the config object."""

    def __init__(self, db):
        self.db = db


def synthetic_ips(network, count):
    net = ipaddress.ip_network(network, strict=False)
    ips = []
    for host in net.hosts():
        ips.append(str(host))
        if len(ips) >= count:
            break
    return ips


def seed(connection, args):
    rng = random.Random(args.seed)
    now = int(time.time())
    ips = synthetic_ips(args.net, args.count)
    if len(ips) < args.count:
        print("WARN: %s only holds %d usable hosts; seeding that many."
              % (args.net, len(ips)))

    rows = []
    event_rows = []
    for index, ip in enumerate(ips):
        level = rng.choices([1, 2, 3, 4, 5], weights=[30, 25, 20, 15, 10])[0]
        hits = rng.randint(level * 3, level * 60)
        first_seen = now - rng.randint(3600, 30 * 86400)
        span = max(60, min(now - first_seen, 7 * 86400))
        last_seen = first_seen + rng.randint(60, span)
        if last_seen > now:
            last_seen = now - rng.randint(0, 3600)
        ban_secs = float(rng.randint(level * 300, level * 7200))
        if rng.random() < args.active_frac:
            blocked_until = now + rng.randint(120, 2 * 86400)
        else:
            blocked_until = last_seen + rng.randint(0, 6 * 3600)
        reasons = rng.choice(REASON_TEMPLATES).format(
            target="192.168.88.%d" % rng.randint(2, 200),
            port=rng.choice(PORTS),
            n=rng.randint(1, 40),
        )
        # last_calc = now so the decay pass sees dt=0 on its first run (no jump).
        rows.append((ip, hits, first_seen, last_seen, ban_secs, now,
                     blocked_until, level, reasons, 0))

        if index < args.with_events:
            for _ in range(rng.randint(2, 8)):
                source = rng.choice(["firewall", "suricata"])
                event_rows.append((
                    rng.randint(first_seen, last_seen), ip, source,
                    reasons.split("\n")[0], rng.randint(1, 5)))

    cur = connection.cursor()
    cur.executemany(
        "INSERT OR REPLACE INTO offenders"
        "(ip,hits,first_seen,last_seen,ban_secs,last_calc,blocked_until,"
        "level,reasons,blackhole_until) VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
    if event_rows:
        cur.executemany(
            "INSERT INTO events(ts,ip,source,reason,hits) VALUES(?,?,?,?,?)",
            event_rows)
    connection.commit()

    total = cur.execute("SELECT count(*) FROM offenders").fetchone()[0]
    active = cur.execute("SELECT count(*) FROM offenders WHERE blocked_until>?",
                         (now,)).fetchone()[0]
    print("seeded %d synthetic offenders in %s" % (len(rows), args.net))
    if event_rows:
        print("seeded %d events across the first %d offenders"
              % (len(event_rows), args.with_events))
    print("offenders total: %d   active blocks: %d" % (total, active))


def purge(connection, args):
    net = ipaddress.ip_network(args.net, strict=False)
    # LIKE prefix works for the common /15 and /16 test blocks; fall back to a
    # membership check for anything else so we never delete real data.
    cur = connection.cursor()
    victims = [row[0] for row in cur.execute("SELECT ip FROM offenders")
               if _in_net(row[0], net)]
    cur.executemany("DELETE FROM offenders WHERE ip=?",
                    [(ip,) for ip in victims])
    cur.executemany("DELETE FROM events WHERE ip=?", [(ip,) for ip in victims])
    connection.commit()
    print("purged %d synthetic offenders (and their events) from %s"
          % (len(victims), args.net))


def _in_net(ip, net):
    try:
        return ipaddress.ip_address(ip) in net
    except ValueError:
        return False


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Seed/purge synthetic ProBAN offenders for UI validation.")
    parser.add_argument("--db", default=DEFAULT_DB,
                        help="offenders SQLite path (default: %(default)s)")
    parser.add_argument("--count", type=int, default=5000,
                        help="how many offenders to seed (default: %(default)s)")
    parser.add_argument("--net", default="198.18.0.0/15",
                        help="synthetic source block; must be a non-routable "
                             "test range (default: %(default)s)")
    parser.add_argument("--active-frac", type=float, default=0.35,
                        help="fraction currently blocked (default: %(default)s)")
    parser.add_argument("--with-events", type=int, default=0, metavar="N",
                        help="seed event detail for the first N offenders so "
                             "the hits modal shows data (default: 0)")
    parser.add_argument("--seed", type=int, default=1337,
                        help="PRNG seed for reproducibility (default: %(default)s)")
    parser.add_argument("--no-clear", action="store_true",
                        help="keep any existing rows in --net instead of "
                             "clearing them first")
    parser.add_argument("--purge", action="store_true",
                        help="delete all offenders/events in --net and exit")
    args = parser.parse_args(argv)

    connection = store.db(_Cfg(args.db))
    if args.purge:
        purge(connection, args)
    else:
        if not args.no_clear:
            purge(connection, args)
        seed(connection, args)
    connection.close()


if __name__ == "__main__":
    main()
