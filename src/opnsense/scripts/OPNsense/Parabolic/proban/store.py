# SQLite offender/event store + the record and decay operations.
import os
import sqlite3

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
    c.execute("CREATE TABLE IF NOT EXISTS events(ts INT,ip TEXT,source TEXT,reason TEXT)")
    c.execute("CREATE TABLE IF NOT EXISTS state(k TEXT PRIMARY KEY,v TEXT)")
    return c


def gs(c, k, d=""):
    r = c.execute("SELECT v FROM state WHERE k=?", (k,)).fetchone()
    return r[0] if r else d


def ss(c, k, v):
    c.execute("INSERT OR REPLACE INTO state VALUES(?,?)", (k, str(v)))


def record(cfg, c, ip, src, reason, ets):
    if rules.allowed(cfg, ip):
        return
    c.execute("INSERT INTO events VALUES(?,?,?,?)", (ets, ip, src, reason))
    r = c.execute("SELECT hits,first_seen,ban_secs,last_calc,reasons,blackhole_until FROM offenders WHERE ip=?", (ip,)).fetchone()
    if r:
        hits = r[0] + 1
        first = r[1]
        bh = r[5] or 0
        ban = rules.decay_ban(cfg, r[2], r[3], ets, bh)
        reasons = r[4] or ""
    else:
        hits = 1
        first = ets
        bh = 0
        ban = 0.0
        reasons = ""
    # while serving the blackhole, escalation is frozen -- they're being dropped, we just bleed them down
    frozen = (cfg.blackhole_on and bh > ets)
    if (not frozen) and hits >= cfg.grace and ban < cfg.maxban:
        en = hits - cfg.grace + 1
        try:
            inc = cfg.step * (cfg.mult ** (en - 1))
        except OverflowError:
            inc = cfg.maxban
        ban = min(cfg.maxban, ban + inc)
    rl = [x for x in reasons.split("\n") if x][-4:] + [f"{src}:{reason}"]
    c.execute("INSERT OR REPLACE INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
              (ip, hits, first, ets, ban, ets, rules.wall_until(cfg, ets, ban), rules.level_of(ban), "\n".join(rl[-5:]), bh))


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
