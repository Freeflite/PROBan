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
        if (len(p2) < 9 or p2[4] != cfg.wan_if or p2[7] != "in"
                or p2[6] not in ("block", "pass")):
            continue
        ver = p2[8]
        if ver == "4":
            if len(p2) < 23:
                continue
            protocol, src, dst, dport = p2[16], p2[18], p2[19], p2[21]
            flag_index = 23
        elif ver == "6":
            if len(p2) < 20:
                continue
            protocol, src, dst, dport = p2[12], p2[15], p2[16], p2[18]
            flag_index = 20
        else:
            continue
        if not src or rules.allowed(cfg, src):
            continue

        dport_int = int(dport) if str(dport).strip().isdigit() else -1
        if not 1 <= dport_int <= 65535 or dport_int in cfg.protected_port_set:
            continue

        source = "firewall"
        if protocol == "udp":
            if p2[6] != "block":
                continue
            detected = cfg.detect_udp
            probe = "UDP probe"
            source = "udp"
        elif protocol == "tcp" and len(p2) > flag_index:
            flags = p2[flag_index].strip()
            if flags == "S":
                detected = cfg.detect_syn
                probe = "TCP SYN probe"
            elif p2[6] == "block":
                flag_set = frozenset(flags)
                if "S" in flag_set and ("F" in flag_set or "R" in flag_set):
                    scan = "SYN" + ("+FIN" if "F" in flag_set else "") + ("+RST" if "R" in flag_set else "")
                    detected = cfg.detect_tcp_invalid
                    source = "tcp-invalid"
                else:
                    scan = {frozenset(): "NULL", frozenset("F"): "FIN", frozenset("FPU"): "XMAS"}.get(flag_set)
                    if scan is None:
                        continue
                    detected = cfg.detect_tcp_scan
                    source = "tcp-scan"
                probe = f"TCP {scan} scan (flags {flags or 'none'})"
            else:
                continue
        else:
            continue
        if not detected and not (cfg.detect_portscan and p2[6] == "block"):
            continue
        destination = f"[{dst}]:{dport_int}" if ver == "6" else f"{dst}:{dport_int}"
        if p2[6] == "pass":
            if cfg.action != 'tarpit':
                continue
            target = cfg.tarpit_ip6 if ver == "6" else cfg.tarpit_ip
            if not target or dst != target:
                continue
            if cfg.tarpit_port_set and dport_int not in cfg.tarpit_port_set:
                continue
            events.append((src, "tarpit", f"tarpit knock: {probe} to {destination} on {cfg.wan_if}", ets))
        else:
            scan_target = (dst, protocol, dport_int) if cfg.detect_portscan else None
            events.append((src, source if detected else "portscan",
                           f"{probe} to {destination} blocked on {cfg.wan_if}", ets, 0, scan_target))
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
                try:
                    severity = int(a.get("severity", 0))
                except (TypeError, ValueError):
                    severity = 0
                if severity not in (1, 2, 3):
                    severity = 0
                try:
                    signature_id = int(a.get("signature_id", 0))
                except (TypeError, ValueError):
                    signature_id = 0
                signature = str(a.get("signature") or "Unknown signature").replace("\n", " ").replace("\r", " ")[:120]
                reason = f"Suricata alert: {signature} (SID {signature_id or 'unknown'}, severity {severity or 'unknown'})"
                destination = str(e.get("dest_ip") or "unknown")[:64]
                if ":" in destination:
                    destination = f"[{destination}]"
                try:
                    port = int(e.get("dest_port", 0))
                except (TypeError, ValueError):
                    port = 0
                protocol = str(e.get("proto") or "unknown").upper()[:16]
                reason += f"; {protocol} to {destination}:{port or 'unknown'}"
                minimum_ban = 0
                if (cfg.suricata_priority and severity and severity <= cfg.suricata_priority_severity
                        and (not cfg.suricata_priority_sids or signature_id in cfg.suricata_priority_sids)
                        and port not in cfg.protected_port_set):
                    minimum_ban = min(cfg.maxban, cfg.suricata_priority_secs * cfg.damt / cfg.dint)
                    reason += f"; priority minimum {int(minimum_ban * cfg.dint / cfg.damt)}s"
                events.append((ip, "suricata", reason, ets, minimum_ban))
    return store.record_many(cfg, c, events, pending)
