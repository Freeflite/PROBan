# Config loading + the Cfg object that carries all derived settings through the engine.
import ipaddress
import json
import os

# Private/reserved ranges that are ALWAYS protected, even if removed from the allowlist.
SAFETY = ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
          "::1/128", "fe80::/10", "fc00::/7"]   # v4 RFC1918 + v6 loopback, link-local (RA/ND), ULA


class Cfg:
    """Parsed, typed view over config.json. Passed to every engine function."""

    def __init__(self, d):
        self.raw = d
        g = lambda k, dv: (d[k] if d.get(k) is not None else dv)
        self.enabled = bool(g("enabled", True))
        self.dry_run = bool(g("dry_run", False))
        self.db = g("db", "/var/log/parabolic/offenders.db")
        self.fwlog = g("fwlog", "/var/log/filter/latest.log")
        self.eve = g("eve", "")
        self.wan_if = g("wan_if", "")
        self.tarpit_ip = g("tarpit_ip", "")
        self.tarpit_ports = g("tarpit_ports", "")
        self.tarpit_port_set = Cfg._parse_port_set(self.tarpit_ports)
        self.pf_table = g("pf_table", "parabolic_block")           # tarpit / primary set
        self.pf_table_drop = g("pf_table_drop", "parabolic_drop")   # blackhole (post-max, dropped)
        self.pf_table6 = g("pf_table6", "parabolic_block6")         # IPv6 tarpit / primary set
        self.pf_table_drop6 = g("pf_table_drop6", "parabolic_drop6") # IPv6 blackhole set
        self.tarpit_ip6 = g("tarpit_ip6", "")                       # v6 tarpit target (ULA); when set, v6 gets tarpitted too
        self.v6_aggregate = int(g("v6_aggregate", 4))              # distinct /128 offenders in a /64 before escalating to the /64

        # Ports that ProBAN should completely ignore for probes and knocks.
        # Useful for VPN server ports (OpenVPN/TCP etc.) and other legitimate inbound services
        # so that real users connecting to them are not treated as "knocks" or probes.
        pp = g("protected_ports", "")
        self.protected_port_set = Cfg._parse_port_set(pp)
        self.grace = int(g("grace_hits", 1))
        self.step = float(g("step_secs", 30))
        self.mult = float(g("multiplier", 1.5))
        self.maxban = float(g("max_ban_secs", 2592000))
        self.damt = float(g("decay_amount", 30))
        if self.damt <= 0:
            self.damt = 1.0
        self.dint = float(g("decay_interval", 60))
        if self.dint <= 0:
            self.dint = 1.0
        self.sources = g("sources", {"firewall": True, "suricata": True})
        self.eret = int(g("event_retention_days", 14))
        self.amnesia = int(g("offender_amnesia_days", 30))
        self.action = g("action", "drop")
        self.postmax = g("post_max_action", "hold")
        self.bhhours = float(g("blackhole_hours", 12))
        self.bhdecay = float(g("blackhole_decay", 7200))           # ban-seconds knocked off per hour
        self.bhrate = self.bhdecay / 3600.0                         # ...per real second
        # blackhole only applies in tarpit/honeypot mode
        self.blackhole_on = (self.postmax == "blackhole" and self.action == "tarpit")
        al = g("allowlist", [])
        if isinstance(al, str):
            al = al.split()   # config.json may carry the allowlist as a whitespace/newline string
        self.allow = []
        for c in list(al) + SAFETY:
            try:
                self.allow.append(ipaddress.ip_network(c, strict=False))
            except Exception:
                pass


    @staticmethod
    def _parse_port_set(s):
        port_set = set()
        for token in str(s).replace(",", " ").split():
            token = token.strip()
            if token.isdigit():
                p = int(token)
                if 1 <= p <= 65535:
                    port_set.add(p)
        return port_set


def load(base):
    """Load config.json from the engine's directory. The caller handles a torn read."""
    with open(os.path.join(base, "config.json")) as f:
        return Cfg(json.load(f))
