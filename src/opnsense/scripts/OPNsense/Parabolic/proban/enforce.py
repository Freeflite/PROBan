# pf table synchronization + the address-family / blackhole routing.
import ipaddress
import json
import re
import subprocess

from . import aggregate, rules, store


def parse_counters(output):
    counters = {}
    address = None
    cleared = None
    packets = None
    for line in output.splitlines() + [""]:
        value = line.strip()
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError:
            network = None
        if network is not None or not value:
            if address is not None:
                if cleared is None or packets is None:
                    raise ValueError(f"missing address counters for {address}")
                counters[address] = [cleared, packets]
            address = (str(network.network_address) if network.num_addresses == 1 else str(network)) if network is not None else None
            cleared = None
            packets = None
        elif value.startswith("Cleared:"):
            cleared = value.partition(":")[2].strip()
        elif value.startswith("In/Block:"):
            match = re.search(r"\[\s*Packets:\s*(\d+)\s+Bytes:", value)
            if match is None:
                raise ValueError("invalid incoming block counter")
            packets = int(match.group(1))
    if output.strip() and not counters:
        raise ValueError("no address counters in pfctl output")
    return counters


def poll_counters(cfg, connection, now):
    if not cfg.enabled or cfg.dry_run or not cfg.sources.get("firewall", True):
        connection.execute("DELETE FROM state WHERE k LIKE 'pf_counters:%'")
        store.ss(connection, "counter_error", "")
        return 0
    tables = []
    for table, drop_table, target in (
            (cfg.pf_table, cfg.pf_table_drop, cfg.tarpit_ip),
            (cfg.pf_table6, cfg.pf_table_drop6, cfg.tarpit_ip6)):
        if cfg.action != "tarpit" or not rules.is_private_target(target):
            tables.append(table)
        elif cfg.blackhole_on:
            tables.append(drop_table)
    counts = {}
    errors = []
    for table in tables:
        try:
            result = subprocess.run(["pfctl", "-t", table, "-v", "-T", "show"],
                                    capture_output=True, text=True, check=True, timeout=10)
            current = parse_counters(result.stdout)
        except (OSError, subprocess.SubprocessError, ValueError) as error:
            errors.append(f"{table}: {error}")
            continue
        key = "pf_counters:" + table
        try:
            previous = json.loads(store.gs(connection, key, "null"))
        except ValueError:
            previous = None
        if isinstance(previous, dict):
            for address, (cleared, packets) in current.items():
                old = previous.get(address)
                delta = packets if old is None or old[0] is None or old[0] != cleared or packets < old[1] else packets - old[1]
                if delta > 0 and not rules.allowed(cfg, address):
                    counts[address] = counts.get(address, 0) + delta
        store.ss(connection, key, json.dumps(current))
    for address, count in counts.items():
        reason = f"{count} blocked packets"
        if "/" in address:
            reason += " (subnet total)"
        store.record_batch(cfg, connection, address, "pf", reason, now, count)
    store.ss(connection, "counter_error", "; ".join(errors))
    return sum(counts.values())


def synctable(table, ips, connection=None):
    cur = subprocess.run(["pfctl", "-t", table, "-T", "show"], capture_output=True, text=True).stdout.split()
    key = "pf_counters:" + table
    try:
        snapshot = json.loads(store.gs(connection, key, "{}")) if connection is not None else {}
    except ValueError:
        snapshot = {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    changed = False
    for ip in set(ips) - set(cur):
        result = subprocess.run(["pfctl", "-t", table, "-T", "add", ip])
        if result.returncode == 0:
            snapshot[ip] = [None, 0]
            changed = True
    for ip in set(cur) - set(ips):
        result = subprocess.run(["pfctl", "-t", table, "-T", "delete", ip])
        if result.returncode == 0:
            snapshot.pop(ip, None)
            changed = True
    if connection is not None and changed:
        store.ss(connection, key, json.dumps(snapshot))


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
    snapshots = c if cfg.sources.get("firewall", True) else None
    synctable(cfg.pf_table, v4_keep, snapshots)
    synctable(cfg.pf_table_drop, v4_drop, snapshots)
    synctable(cfg.pf_table6, v6_keep, snapshots)
    synctable(cfg.pf_table_drop6, v6_drop, snapshots)
    return active, dropped, v6_all, "enforced"
