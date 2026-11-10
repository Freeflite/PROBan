#!/usr/bin/env python3
"""Seed synthetic offenders into a ProBAN store for dashboard/UI validation.

This is a DEVELOPMENT helper, not part of the shipped plugin (the Makefile
packages ``src/`` only). It's a thin CLI over ``proban.demo`` -- the same
seed/purge core the gated in-UI "demo mode" uses -- so there's one
implementation and the schema always matches the engine (via ``proban.store``).

Use it to populate the offenders table with a large, realistic-looking spread
so you can exercise the dashboard by hand:

  * offenders-list pagination and the page-size picker (incl. the 500-row cap
    and the "max 500" custom entry),
  * column sorting across thousands of rows,
  * the "Active blocks" stat and the blocked/decayed split,
  * the per-offender hits modal (with --with-events N it seeds event detail for
    the first N offenders; the rest have no events, which exercises the
    "event history aged out" explainer).

All synthetic rows use the RFC 2544 benchmarking block (198.18.0.0/15) by
default: reserved, non-routable, and easy to identify and purge.

Examples
--------
  # Spray 5,000 offenders into the live store on an OPNsense box:
  python3 tools/seed_offenders.py --count 5000

  # Point at a specific DB, reproducible seed, 50% active, event detail for the
  # first 25 offenders:
  python3 tools/seed_offenders.py --db /var/log/parabolic/offenders.db \\
      --count 5000 --active-frac 0.5 --seed 1337 --with-events 25

  # Remove everything this tool added (purge the synthetic range) and exit:
  python3 tools/seed_offenders.py --purge
"""
import argparse
import os
import sys

# Import the engine's packages so the schema (store) and the seed/purge core
# (demo) stay in lockstep with the shipped plugin.
sys.path.insert(0, os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "src", "opnsense", "scripts", "OPNsense", "Parabolic")))
from proban import demo, store   # noqa: E402

DEFAULT_DB = "/var/log/parabolic/offenders.db"


class _Cfg:
    """Minimal shim: store.db() only reads .db off the config object."""

    def __init__(self, db):
        self.db = db


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Seed/purge synthetic ProBAN offenders for UI validation.")
    parser.add_argument("--db", default=DEFAULT_DB,
                        help="offenders SQLite path (default: %(default)s)")
    parser.add_argument("--count", type=int, default=5000,
                        help="how many offenders to seed (default: %(default)s)")
    parser.add_argument("--net", default=demo.DEMO_NET,
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
    try:
        if args.purge:
            removed = demo.purge(connection, net=args.net)
            print("purged %d synthetic offenders (and their events) from %s"
                  % (removed, args.net))
        else:
            result = demo.seed(
                connection, count=args.count, net=args.net,
                active_frac=args.active_frac, with_events=args.with_events,
                seed_value=args.seed, clear=not args.no_clear)
            print("seeded %d synthetic offenders in %s"
                  % (result["seeded"], args.net))
            if result["events"]:
                print("seeded %d events across the first %d offenders"
                      % (result["events"], args.with_events))
            print("offenders total: %d   active blocks: %d"
                  % (result["total"], result["active"]))
    finally:
        connection.close()


if __name__ == "__main__":
    main()
