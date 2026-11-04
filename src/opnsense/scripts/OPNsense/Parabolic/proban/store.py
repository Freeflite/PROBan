# SQLite offender/event store + the record and decay operations.
import os
import sqlite3
from itertools import groupby

from . import rules


def db(cfg):
    try:
        os.makedirs(os.path.dirname(cfg.db), exist_ok=True)   # so a direct `configctl proban run` can't crash
    except Exception:
        pass
    c = sqlite3.connect(cfg.db)
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("CREATE TABLE IF NOT EXISTS offenders(ip TEXT PRIMARY KEY,hits INT,first_seen INT,last_seen INT,ban_secs REAL,last_calc INT,blocked_until INT,level INT,reasons TEXT)")
    try:
        c.execute("ALTER TABLE offenders ADD COLUMN blackhole_until INT DEFAULT 0")   # v3: post-max blackhole state
    except Exception:
        pass
    c.execute("CREATE TABLE IF NOT EXISTS events(ts INT,ip TEXT,source TEXT,reason TEXT,hits INT NOT NULL DEFAULT 1)")
    if "hits" not in {column[1] for column in c.execute("PRAGMA table_info(events)")}:
        c.execute("ALTER TABLE events ADD COLUMN hits INT NOT NULL DEFAULT 1")
    c.execute("CREATE INDEX IF NOT EXISTS events_ts ON events(ts)")
    c.execute("CREATE INDEX IF NOT EXISTS events_ip_ts ON events(ip,ts)")
    c.execute("CREATE TABLE IF NOT EXISTS state(k TEXT PRIMARY KEY,v TEXT)")
    return c


def gs(c, k, d=""):
    r = c.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
    return r[0] if r else d


def ss(c, k, v):
    c.execute("INSERT OR REPLACE INTO state VALUES(?,?)", (k, str(v)))


def record(cfg, c, ip, src, reason, ets):
    record_batch(cfg, c, ip, src, reason, ets, 1)


def record_many(cfg, connection, events, pending=None):
    total = 0
    for event, matching in groupby(events):
        ip, source, reason, timestamp = event
        count = sum(1 for entry in matching)
        newly_active = record_batch(cfg, connection, ip, source, reason, timestamp, count)
        if newly_active and pending is not None:
            pending.add(ip)
        total += count
    return total


def record_batch(cfg, c, ip, src, reason, ets, count):
    if count <= 0 or rules.allowed(cfg, ip):
        return
    c.execute("INSERT INTO events(ts,ip,source,reason,hits) VALUES(?,?,?,?,?)", (ets, ip, src, reason, count))
    r = c.execute("SELECT hits,first_seen,ban_secs,last_calc,reasons,blackhole_until FROM offenders WHERE ip=?", (ip,)).fetchone()
    if r:
        previous_hits = r[0]
        first = r[1]
        bh = r[5] or 0
        ban = rules.decay_ban(cfg, r[2], r[3], ets, bh)
        reasons = r[4] or ""
    else:
        previous_hits = 0
        first = ets
        bh = 0
        ban = 0.0
        reasons = ""
    was_active = ban > 0
    hits = previous_hits + count
    # while serving the blackhole, escalation is frozen -- they're being dropped, we just bleed them down
    frozen = (cfg.blackhole_on and bh > ets)
    if (not frozen) and hits >= cfg.grace and ban < cfg.maxban:
        eligible_hits = hits - max(previous_hits, cfg.grace - 1)
        exponent = max(previous_hits, cfg.grace - 1) - cfg.grace + 1
        try:
            if cfg.mult == 1:
                inc = cfg.step * eligible_hits
            else:
                inc = cfg.step * (cfg.mult ** exponent) * (cfg.mult ** eligible_hits - 1) / (cfg.mult - 1)
        except OverflowError:
            inc = cfg.maxban
        ban = min(cfg.maxban, ban + inc)
    rl = [x for x in reasons.split("\n") if x][-4:] + [f"{src}:{reason}"]
    c.execute("INSERT OR REPLACE INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
              (ip, hits, first, ets, ban, ets, rules.wall_until(cfg, ets, ban), rules.level_of(ban), "\n".join(rl[-5:]), bh))
    return ban > 0 and not was_active


def decay_pass(cfg, c, now):
    for ip, ban, lc, bh in c.execute("SELECT ip,ban_secs,last_calc,blackhole_until FROM offenders WHERE ban_secs>0").fetchall():
        bh = bh or 0
        nb = rules.decay_ban(cfg, ban, lc, now, bh)
        if cfg.blackhole_on and bh == 0 and ban >= cfg.maxban:
            nbh = now + int(cfg.bhhours * 3600)   # just maxed out -> into the hole
        elif cfg.blackhole_on and bh > 0 and now >= bh:
            nbh = 0                                # served the hole -> back to the tarpit
        else:
            nbh = bh
        c.execute("UPDATE offenders SET ban_secs=?,last_calc=?,blocked_until=?,level=?,blackhole_until=? WHERE ip=?",
                  (nb, now, rules.wall_until(cfg, now, nb), rules.level_of(nb), nbh, ip))
