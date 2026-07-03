# pf table synchronization + the address-family / blackhole routing.
import re
import subprocess

from . import aggregate, rules


def synctable(table, ips):
    cur = subprocess.run(["pfctl", "-t", table, "-T", "show"], capture_output=True, text=True).stdout.split()
    for ip in set(ips) - set(cur):
        subprocess.run(["pfctl", "-t", table, "-T", "add", ip])
    for ip in set(cur) - set(ips):
        subprocess.run(["pfctl", "-t", table, "-T", "delete", ip])


def rdr_target(table):
    """The live rdr target for a pf table (from `pfctl -sn`), or None. Handles the
    bracketed [v6] form. The tamper guard uses this to catch an out-of-band edit that
    re-points the redirect at a public IP (which would turn us into a reflector)."""
    try:
        out = subprocess.run(["pfctl", "-sn"], capture_output=True, text=True).stdout
        for line in out.splitlines():
            if table in line and "->" in line:
                m = re.search(r"->\s+\[?([0-9a-fA-F:.]+)\]?\s+port", line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    return None


def enforce(cfg, c, now):
    """Route every active offender to the right pf table by address family and state.

    Returns (active, dropped, v6, mode):
      active  -- every enforced offender (both families)
      dropped -- everything sent to a blackhole (drop) set, v4 + v6
      v6      -- every v6 entry pushed (tarpit + blackhole, after /64 aggregation)
    """
    rows = [(ip, (bh or 0)) for ip, bh in
            c.execute("SELECT ip,blackhole_until FROM offenders WHERE ban_secs>0").fetchall()
            if not rules.allowed(cfg, ip)]
    v4 = [(ip, bh) for ip, bh in rows if ":" not in ip]
    v6 = [(ip, bh) for ip, bh in rows if ":" in ip]

    # IPv4: split the blackholed (dropped) from the rest (tarpit / honeypot).
    if cfg.blackhole_on:
        v4_drop = [ip for ip, bh in v4 if bh > now]
        v4_keep = [ip for ip, bh in v4 if bh <= now]
    else:
        v4_drop = []
        v4_keep = [ip for ip, bh in v4]

    # IPv6: mirror the v4 tarpit/blackhole split when a v6 tarpit target is set;
    # otherwise block-only. Then collapse each set to /64 wherever a subnet has
    # crossed the aggregation threshold (see proban.aggregate).
    v6_tarpit = cfg.action == "tarpit" and bool(cfg.tarpit_ip6)
    if v6_tarpit and cfg.blackhole_on:
        v6_drop_raw = [ip for ip, bh in v6 if bh > now]
        v6_keep_raw = [ip for ip, bh in v6 if bh <= now]
    else:
        v6_drop_raw = []
        v6_keep_raw = [ip for ip, bh in v6]
    v6_keep = aggregate.plan_v6(v6_keep_raw, cfg.v6_aggregate)
    v6_drop = aggregate.plan_v6(v6_drop_raw, cfg.v6_aggregate)

    active = [ip for ip, bh in rows]
    dropped = v4_drop + v6_drop
    v6_all = v6_keep + v6_drop
    if cfg.dry_run:
        return active, dropped, v6_all, "DRY-RUN"
    synctable(cfg.pf_table, v4_keep)
    synctable(cfg.pf_table_drop, v4_drop)
    synctable(cfg.pf_table6, v6_keep)
    synctable(cfg.pf_table_drop6, v6_drop)
    return active, dropped, v6_all, "enforced"
