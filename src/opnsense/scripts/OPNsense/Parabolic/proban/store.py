# SQLite offender/event store + the record and decay operations.
import ipaddress
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
    c.execute("CREATE TABLE IF NOT EXISTS scan_ports(ip TEXT,destination TEXT,protocol TEXT,port INT,last_seen INT,PRIMARY KEY(ip,destination,protocol,port))")
    c.execute("CREATE INDEX IF NOT EXISTS scan_ports_last_seen ON scan_ports(last_seen)")
    c.execute("CREATE TABLE IF NOT EXISTS v6_rotation(prefix TEXT,ip TEXT,ts INT,hits INT,PRIMARY KEY(prefix,ip,ts))")
    c.execute("CREATE INDEX IF NOT EXISTS v6_rotation_prefix_ts ON v6_rotation(prefix,ts)")
    c.execute("CREATE INDEX IF NOT EXISTS v6_rotation_ts ON v6_rotation(ts)")
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
    rotations = {}
    for event, matching in groupby(events):
        ip, source, reason, timestamp = event[:4]
        minimum_ban = event[4] if len(event) > 4 else 0
        scan_target = event[5] if len(event) > 5 else None
        count = sum(1 for entry in matching)
        newly_active = record_batch(cfg, connection, ip, source, reason, timestamp, count,
                        minimum_ban=minimum_ban, scan_target=scan_target)
        if newly_active and pending is not None:
            pending.add(ip)
        prefix = track_rotation(cfg, connection, ip, timestamp, count, scan_target)
        if prefix is not None:
            rotations[prefix] = max(timestamp, rotations.get(prefix, timestamp))
        total += count
    for prefix, timestamp in rotations.items():
        activate_rotation(cfg, connection, prefix, timestamp, pending)
    return total


def track_rotation(cfg, connection, ip, timestamp, count, target):
    if not cfg.detect_v6_rotation or target is None or target[1] != "tcp" or rules.allowed(cfg, ip):
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if address.version != 6 or address.is_multicast or address.is_unspecified:
        return None
    prefix = str(ipaddress.ip_network(f"{address}/64", strict=False))
    connection.execute("INSERT INTO v6_rotation(prefix,ip,ts,hits) VALUES(?,?,?,?) "
                       "ON CONFLICT(prefix,ip,ts) DO UPDATE SET hits=hits+excluded.hits",
                       (prefix, ip, timestamp, count))
    return prefix


def activate_rotation(cfg, connection, prefix, timestamp, pending=None):
    participants = [row for row in connection.execute(
        "SELECT rotation.ip,SUM(rotation.hits),offender.ban_secs,offender.last_calc,"
        "offender.blackhole_until,offender.reasons FROM v6_rotation AS rotation "
        "JOIN offenders AS offender ON offender.ip=rotation.ip "
        "WHERE rotation.prefix=? AND rotation.ts>? AND rotation.ts<=? GROUP BY rotation.ip",
        (prefix, timestamp - cfg.v6_rotation_window, timestamp)) if not rules.allowed(cfg, row[0])]
    hits = sum(row[1] for row in participants)
    if len(participants) < cfg.v6_rotation_sources or hits < cfg.v6_rotation_hits:
        return
    reason = (f"IPv6 source rotation: {len(participants)} sources in {prefix}, {hits} blocked TCP probes "
              f"in {cfg.v6_rotation_window}s (thresholds {cfg.v6_rotation_sources} sources/{cfg.v6_rotation_hits} probes)")
    minimum_ban = min(cfg.maxban, cfg.v6_rotation_secs * cfg.damt / cfg.dint)
    for ip, probes, balance, last_calc, blackhole_until, reasons in participants:
        blackhole_until = blackhole_until or 0
        calculated_at = max(timestamp, last_calc)
        if cfg.blackhole_on and blackhole_until > calculated_at:
            continue
        ban = rules.decay_ban(cfg, balance, last_calc, calculated_at, blackhole_until)
        previous = [entry for entry in (reasons or "").split("\n") if entry]
        if ban <= 0 or not any(entry.startswith("ipv6-rotation:") for entry in previous):
            connection.execute("INSERT INTO events(ts,ip,source,reason,hits) VALUES(?,?,?,?,0)",
                               (timestamp, ip, "ipv6-rotation", reason))
        ban = max(ban, minimum_ban)
        initial = next((entry for entry in previous if not entry.startswith("pf:")), None)
        entries = [entry for entry in previous if not entry.startswith("ipv6-rotation:")]
        entries.append("ipv6-rotation:" + reason)
        if initial and initial not in entries[-5:]:
            entries = [initial] + entries[-4:]
        connection.execute("UPDATE offenders SET ban_secs=?,last_calc=?,blocked_until=?,level=?,reasons=? WHERE ip=?",
                           (ban, calculated_at, rules.wall_until(cfg, calculated_at, ban), rules.level_of(ban),
                            "\n".join(entries[-5:]), ip))
        if pending is not None and ban > 0:
            pending.add(ip)


def record_batch(cfg, c, ip, src, reason, ets, count, minimum_ban=0, scan_target=None):
    if count <= 0 or rules.allowed(cfg, ip):
        return
    qualified = src not in ("portscan", "ipv6-rotation")
    if src in ("udp", "tcp-scan", "tcp-invalid"):
        recent = c.execute("SELECT COALESCE(SUM(hits),0) FROM events WHERE ip=? AND source=? AND ts>? AND ts<=?",
                           (ip, src, ets - cfg.scan_window, ets)).fetchone()[0] + count
        qualified = recent >= cfg.scan_threshold
        reason += f"; {recent} probes in {cfg.scan_window}s (threshold {cfg.scan_threshold})"
    if cfg.detect_portscan and scan_target is not None:
        destination, protocol, port = scan_target
        c.execute("INSERT INTO scan_ports(ip,destination,protocol,port,last_seen) VALUES(?,?,?,?,?) "
                  "ON CONFLICT(ip,destination,protocol,port) DO UPDATE SET last_seen=MAX(last_seen,excluded.last_seen)",
                  (ip, destination, protocol, port, ets))
        distinct = c.execute("SELECT COUNT(*) FROM scan_ports WHERE ip=? AND destination=? AND protocol=? "
                             "AND last_seen>? AND last_seen<=?",
                             (ip, destination, protocol, ets - cfg.portscan_window, ets)).fetchone()[0]
        qualified = qualified or distinct >= cfg.portscan_threshold
        reason += (f"; port scan: {distinct} distinct {protocol.upper()} destination ports on {destination} "
                   f"in {cfg.portscan_window}s (threshold {cfg.portscan_threshold})")
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
    if qualified and (not frozen) and hits >= cfg.grace and ban < cfg.maxban:
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
    if qualified and not frozen and minimum_ban > 0:
        ban = max(ban, min(cfg.maxban, minimum_ban))
    previous = [entry for entry in reasons.split("\n") if entry]
    initial = next((entry for entry in previous if not entry.startswith("pf:")), None)
    current = f"{src}:{reason}"
    rl = [entry for entry in previous if entry != current and not (src == "pf" and entry.startswith("pf:"))]
    rl.append(current)
    if initial and initial not in rl[-5:]:
        rl = [initial] + rl[-4:]
    c.execute("INSERT OR REPLACE INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
              (ip, hits, first, ets, ban, ets, rules.wall_until(cfg, ets, ban), rules.level_of(ban), "\n".join(rl[-5:]), bh))
    return ban > 0 and not was_active


def decay_pass(cfg, c, now):
    c.execute("DELETE FROM scan_ports WHERE last_seen<=?", (now - cfg.portscan_window,))
    c.execute("DELETE FROM v6_rotation WHERE ts<=?", (now - cfg.v6_rotation_window,))
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
