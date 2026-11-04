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
        else:
            if cfg.detect_udp or cfg.detect_portscan:
                tables.append(table)
            if cfg.blackhole_on:
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
        reason = f"{count} additional incoming packets blocked by PF while the ban is active"
        if "/" in address:
            reason += " (subnet total)"
        store.record_batch(cfg, connection, address, "pf", reason, now, count)
    store.ss(connection, "counter_error", "; ".join(errors))
    return sum(counts.values())


def synctable(table, ips, connection=None, additive=False):
    cur = set(subprocess.run(["pfctl", "-t", table, "-T", "show"],
                             capture_output=True, text=True, check=True, timeout=10).stdout.split())
    desired = set(ips)
    additions = desired - cur
    removals = set() if additive else cur - desired
    if not additions and not removals:
        return
    key = "pf_counters:" + table
    try:
        snapshot = json.loads(store.gs(connection, key, "{}")) if connection is not None else {}
    except ValueError:
        snapshot = {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    for operation, addresses in (("add", additions), ("delete", removals)):
        if not addresses:
            continue
        subprocess.run(["pfctl", "-t", table, "-T", operation, "-f", "-"],
                       input="\n".join(sorted(addresses)) + "\n",
                       capture_output=True, text=True, check=True, timeout=10)
        for address in addresses:
            if operation == "add":
                snapshot[address] = [None, 0]
            else:
                snapshot.pop(address, None)
    if connection is not None:
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


def safe_v6_plan(cfg, addresses):
    members = {}
    for address in addresses:
        subnet = aggregate.net64(address)
        if subnet is not None:
            members.setdefault(subnet, []).append(address)
    planned = []
    for address in aggregate.plan_v6(addresses, cfg.v6_aggregate):
        if not rules.allowed(cfg, address):
            planned.append(address)
        else:
            planned.extend(member for member in members.get(address, []) if not rules.allowed(cfg, member))
    return list(dict.fromkeys(planned))


def table_plan(cfg, rows, now):
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
    v6_keep = safe_v6_plan(cfg, v6_keep_raw)
    v6_drop = safe_v6_plan(cfg, v6_drop_raw)

    active = [ip for ip, bh in rows]
    dropped = v4_drop + v6_drop
    v6_all = v6_keep + v6_drop
    tables = ((cfg.pf_table, v4_keep), (cfg.pf_table_drop, v4_drop),
              (cfg.pf_table6, v6_keep), (cfg.pf_table_drop6, v6_drop))
    return active, dropped, v6_all, tables


def enforce_pending(cfg, connection, now, pending):
    if not cfg.enabled or cfg.dry_run or not pending:
        return
    addresses = sorted(pending)
    rows = []
    for start in range(0, len(addresses), 400):
        selected = addresses[start:start + 400]
        placeholders = ",".join("?" for address in selected)
        query = ("SELECT ip,blackhole_until FROM offenders WHERE ban_secs>0 AND blocked_until>? "
                 f"AND ip IN ({placeholders})")
        rows.extend((ip, bh or 0) for ip, bh in connection.execute(query, [now] + selected)
                    if not rules.allowed(cfg, ip))
    active, dropped, v6_all, tables = table_plan(cfg, rows, now)
    snapshots = connection if cfg.sources.get("firewall", True) else None
    for table, addresses in tables:
        if addresses:
            synctable(table, addresses, snapshots, additive=True)


def enforce(cfg, c, now):
    """Return active, dropped, IPv6 entries and mode after a full table reconciliation."""
    rows = [(ip, bh or 0) for ip, bh in
            c.execute("SELECT ip,blackhole_until FROM offenders WHERE ban_secs>0").fetchall()
            if not rules.allowed(cfg, ip)]
    active, dropped, v6_all, tables = table_plan(cfg, rows, now)
    if cfg.dry_run:
        return active, dropped, v6_all, "DRY-RUN"
    snapshots = c if cfg.sources.get("firewall", True) else None
    for table, addresses in tables:
        synctable(table, addresses, snapshots)
    return active, dropped, v6_all, "enforced"
