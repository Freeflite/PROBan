"""ProBAN progressive-ban engine -- internal package.

Split into focused modules so the engine's main loop stays a thin pipeline:
  config  -- load config.json into a typed Cfg carried through everything
  rules   -- pure decision/math (decay, level, private-target lock, allowlist)
  store   -- the SQLite offender/event store + record/decay operations
  ingest  -- filter-log (v4/v6) and Suricata eve.json parsers
  enforce -- pf table sync + family/blackhole routing
"""
