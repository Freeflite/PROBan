# Synthetic offender seeding for demo / dashboard validation.
#
# Shared by the dev CLI (tools/seed_offenders.py) and the gated in-UI "demo
# mode" (demo_seed.py, driven by the DemoController). Every synthetic row lives
# in the RFC 2544 benchmarking block (198.18.0.0/15): reserved, non-routable,
# and trivially identifiable, so seeded data can never reach a real host and
# one purge removes exactly what was added.
#
# The schema comes from store.db(), so it can never drift from the engine's.
import ipaddress
import random
import time

from . import store

DEMO_NET = "198.18.0.0/15"
MAX_COUNT = 50000

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


def _in_net(ip, network):
    try:
        return ipaddress.ip_address(ip) in network
    except ValueError:
        return False


def purge(connection, net=DEMO_NET):
    """Delete every offender (and its events) inside the synthetic block.

    Returns the number of offenders removed.
    """
    network = ipaddress.ip_network(net, strict=False)
    cursor = connection.cursor()
    victims = [row[0] for row in cursor.execute("SELECT ip FROM offenders")
               if _in_net(row[0], network)]
    cursor.executemany("DELETE FROM offenders WHERE ip=?",
                       [(ip,) for ip in victims])
    cursor.executemany("DELETE FROM events WHERE ip=?",
                       [(ip,) for ip in victims])
    connection.commit()
    return len(victims)


def seed(connection, count=5000, net=DEMO_NET, active_frac=0.35,
         with_events=0, seed_value=1337, clear=True):
    """Insert ``count`` synthetic offenders into the store.

    Returns a dict: seeded, events, total (offenders in the DB now), active
    (blocked-until-future now).
    """
    count = max(1, min(int(count), MAX_COUNT))
    network = ipaddress.ip_network(net, strict=False)
    if clear:
        purge(connection, net)

    rng = random.Random(seed_value)
    now = int(time.time())

    ips = []
    for host in network.hosts():
        ips.append(str(host))
        if len(ips) >= count:
            break

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
        if rng.random() < active_frac:
            blocked_until = now + rng.randint(120, 2 * 86400)
        else:
            blocked_until = last_seen + rng.randint(0, 6 * 3600)
        # Target is flavor text only; use RFC 5737 TEST-NET-1 so synthetic rows
        # carry no real/identifiable LAN address.
        reasons = rng.choice(REASON_TEMPLATES).format(
            target="192.0.2.%d" % rng.randint(2, 254),
            port=rng.choice(PORTS),
            n=rng.randint(1, 40),
        )
        # last_calc = now so the decay pass sees dt=0 on its first run (no jump).
        rows.append((ip, hits, first_seen, last_seen, ban_secs, now,
                     blocked_until, level, reasons, 0))

        if index < with_events:
            for _ in range(rng.randint(2, 8)):
                source = rng.choice(["firewall", "suricata"])
                event_rows.append((
                    rng.randint(first_seen, last_seen), ip, source,
                    reasons.split("\n")[0], rng.randint(1, 5)))

    cursor = connection.cursor()
    cursor.executemany(
        "INSERT OR REPLACE INTO offenders"
        "(ip,hits,first_seen,last_seen,ban_secs,last_calc,blocked_until,"
        "level,reasons,blackhole_until) VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
    if event_rows:
        cursor.executemany(
            "INSERT INTO events(ts,ip,source,reason,hits) VALUES(?,?,?,?,?)",
            event_rows)
    connection.commit()

    total = cursor.execute("SELECT count(*) FROM offenders").fetchone()[0]
    active = cursor.execute(
        "SELECT count(*) FROM offenders WHERE blocked_until>?",
        (now,)).fetchone()[0]
    return {"seeded": len(rows), "events": len(event_rows),
            "total": total, "active": active}
