#!/usr/local/bin/python3
"""configd entrypoint for ProBAN demo-mode seeding/purging.

Called by the DemoController via `proban demoseed` / `proban demopurge`. Loads
the engine's own config.json (next to this script) so it writes to the exact
offender DB the engine uses, then seeds or purges synthetic offenders confined
to the non-routable 198.18.0.0/15 test block.

  demo_seed.py seed  [--count N] [--with-events M] [--json]
  demo_seed.py purge [--json]

The DemoController gates `seed` behind the demo_mode setting; `purge` is always
allowed so synthetic data can be cleaned up even after demo mode is turned off.
"""
import argparse
import json
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from proban import config, demo, store   # noqa: E402


def _connect():
    cfg = config.load(BASE)          # reads BASE/config.json -> the engine's DB
    connection = store.db(cfg)
    connection.execute("PRAGMA busy_timeout=5000")   # ride out an engine write
    return connection


def main(argv=None):
    parser = argparse.ArgumentParser(description="ProBAN demo seeding/purging")
    sub = parser.add_subparsers(dest="cmd", required=True)

    seed = sub.add_parser("seed")
    seed.add_argument("--count", type=int, default=5000)
    seed.add_argument("--with-events", type=int, default=25)
    seed.add_argument("--json", action="store_true")

    purge = sub.add_parser("purge")
    purge.add_argument("--json", action="store_true")

    args = parser.parse_args(argv)
    connection = _connect()
    try:
        if args.cmd == "seed":
            result = demo.seed(connection, count=args.count,
                               with_events=args.with_events)
        else:
            removed = demo.purge(connection)
            result = {"purged": removed}
    finally:
        connection.close()

    if getattr(args, "json", False):
        print(json.dumps(result))
    else:
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
