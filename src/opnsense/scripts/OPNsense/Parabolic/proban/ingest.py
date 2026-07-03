# Firewall filter-log (IPv4 + IPv6) and Suricata eve.json ingestion.
import datetime
import json
import os

from . import rules, store


def parse_ts(s, default):
    try:
        return int(datetime.datetime.fromisoformat(s.replace("+0000", "+00:00")).timestamp())
    except Exception:
        return default


def ingest_fwlog(cfg, c, now):
    p = cfg.fwlog
    if not os.path.exists(p):
        return 0
    off = int(store.gs(c, "fw_offset", "0") or 0)
    sz = os.path.getsize(p)
    if off > sz:
        off = 0
    n = 0
    with open(p, errors="ignore") as f:
        f.seek(off)
        for line in f:
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
                # v6 shifts every field after ipversion.
                # Supports both block (probes) and pass,in (tarpit knocks when v6 target set).
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

            # block,in = default-deny / new offender
            # pass,in (v4) = a tarpit-rdr knock -> re-escalate (only if it matches our tarpit config)
            if p2[6] == "pass":
                if cfg.action != 'tarpit':
                    continue
                target = cfg.tarpit_ip6 if ver == "6" else cfg.tarpit_ip
                if target and dst != target:
                    continue  # stricter: must be destined to our tarpit target IP
                # empty set means "honeypot on all ports" -> count any pass,in as knock
                if cfg.tarpit_port_set and dport_int not in cfg.tarpit_port_set:
                    continue
                store.record(cfg, c, src, "tarpit", f"tarpit knock :{dport}", ets)
            else:
                store.record(cfg, c, src, "firewall", f"SYN probe :{dport}", ets)
            n += 1
        store.ss(c, "fw_offset", f.tell())
    return n


def ingest_suricata(cfg, c, now):
    p = cfg.eve
    if not p or not os.path.exists(p):
        return 0
    off = int(store.gs(c, "eve_offset", "0") or 0)
    sz = os.path.getsize(p)
    if off > sz:
        off = 0
    n = 0
    with open(p, errors="ignore") as f:
        f.seek(off)
        for line in f:
            try:
                e = json.loads(line)
            except Exception:
                continue
            if e.get("event_type") == "alert":
                ip = e.get("src_ip")
                a = e.get("alert", {})
                ets = parse_ts(e.get("timestamp", ""), now)
                if ip and not rules.allowed(cfg, ip):
                    store.record(cfg, c, ip, "suricata", f"[sev{a.get('severity', 3)}] {a.get('signature', '')[:60]}", ets)
                    n += 1
        store.ss(c, "eve_offset", f.tell())
    return n
