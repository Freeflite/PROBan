# Firewall filter-log (IPv4 + IPv6) and Suricata eve.json ingestion.
import datetime
import json
import os
import time

from . import rules, store

MAX_LINES = 1000
MAX_BYTES = 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_SECONDS = 0.25


def read_lines(connection, path, key):
    try:
        handle = open(path, "rb")
    except FileNotFoundError:
        for suffix in ("_pending", "_backlog"):
            if store.gs(connection, key + suffix) not in ("", "0"):
                store.ss(connection, key + suffix, 0)
        return
    with handle:
        info = os.fstat(handle.fileno())
        identity = f"{info.st_dev}:{info.st_ino}"
        previous = store.gs(connection, key + "_identity")
        offset = int(store.gs(connection, key, "0") or 0)
        discarding = store.gs(connection, key + "_discarding") == "1"
        if (previous and previous != identity) or offset > info.st_size:
            offset = 0
            discarding = False
        handle.seek(offset)
        consumed = 0
        oversized = 0
        partial = False
        deadline = time.monotonic() + MAX_SECONDS
        for scanned in range(MAX_LINES):
            if consumed >= MAX_BYTES or time.monotonic() >= deadline:
                break
            start = handle.tell()
            line = handle.readline(min(MAX_LINE_BYTES + 1, MAX_BYTES - consumed))
            if not line:
                break
            consumed += len(line)
            if discarding:
                discarding = not line.endswith(b"\n")
                continue
            if len(line) > MAX_LINE_BYTES:
                oversized += 1
                discarding = not line.endswith(b"\n")
                continue
            if not line.endswith(b"\n"):
                handle.seek(start)
                partial = True
                break
            yield line.decode("utf-8", errors="ignore")
        store.ss(connection, key, handle.tell())
        store.ss(connection, key + "_identity", identity)
        store.ss(connection, key + "_discarding", int(discarding))
        backlog = max(0, os.fstat(handle.fileno()).st_size - handle.tell())
        store.ss(connection, key + "_backlog", backlog)
        store.ss(connection, key + "_pending", int(backlog > 0 and not partial))
        if oversized:
            store.ss(connection, key + "_oversized", int(store.gs(connection, key + "_oversized", "0")) + oversized)


def parse_ts(s, default):
    try:
        return int(datetime.datetime.fromisoformat(s.replace("+0000", "+00:00")).timestamp())
    except Exception:
        return default


def ingest_fwlog(cfg, c, now, pending=None):
    events = []
    for line in read_lines(c, cfg.fwlog, "fw_offset"):
        if (",block,in," not in line) and (",pass,in," not in line):
            continue
        sp = line.split(" ", 3)
        ets = parse_ts(sp[1], now) if len(sp) > 1 else now
        i = line.rfind("] ")
        p2 = (line[i + 2:] if i >= 0 else line).split(",")
        if len(p2) < 9 or p2[4] != cfg.wan_if:
            continue
        ver = p2[8]
        dst = ''
        if ver == "4":
            if len(p2) < 24 or p2[16] != "tcp" or p2[23].strip() != "S":
                continue
            src = p2[18]
            dst = p2[19] if len(p2) > 19 else ''
            dport = p2[21]
        elif ver == "6":
            if len(p2) < 21 or p2[12] != "tcp" or p2[20].strip() != "S":
                continue
            src = p2[15]
            dst = p2[16]
            dport = p2[18]
        else:
            continue
        if not src or rules.allowed(cfg, src):
            continue

        dport_int = int(dport) if str(dport).strip().isdigit() else -1
        if dport_int in cfg.protected_port_set:
            continue

        if p2[6] == "pass":
            if cfg.action != 'tarpit':
                continue
            target = cfg.tarpit_ip6 if ver == "6" else cfg.tarpit_ip
            if target and dst != target:
                continue
            if cfg.tarpit_port_set and dport_int not in cfg.tarpit_port_set:
                continue
            events.append((src, "tarpit", f"tarpit knock :{dport}", ets))
        else:
            events.append((src, "firewall", f"SYN probe :{dport}", ets))
    return store.record_many(cfg, c, events, pending)


def ingest_suricata(cfg, c, now, pending=None):
    events = []
    for line in read_lines(c, cfg.eve, "eve_offset"):
        try:
            e = json.loads(line)
        except Exception:
            continue
        if isinstance(e, dict) and e.get("event_type") == "alert":
            ip = e.get("src_ip")
            a = e.get("alert", {})
            if not isinstance(a, dict):
                continue
            ets = parse_ts(e.get("timestamp", ""), now)
            if ip and not rules.allowed(cfg, ip):
                events.append((ip, "suricata", f"[sev{a.get('severity', 3)}] {str(a.get('signature', ''))[:60]}", ets))
    return store.record_many(cfg, c, events, pending)
