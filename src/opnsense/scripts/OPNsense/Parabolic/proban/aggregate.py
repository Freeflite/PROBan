# Evidence-based IPv6 offender aggregation.
#
# A v6 attacker usually controls a whole /64 and can rotate source addresses for
# free, so banning individual /128s is whack-a-mole. But a /64 can also be a SHARED
# hosting subnet -- some datacenters hand a single /128 to each customer -- so
# blindly banning the /64 would punish innocent neighbours. So we ban /128s and only
# escalate to the /64 once it holds >= `threshold` DISTINCT offenders: evidence the
# subnet itself is hostile (one attacker cycling addresses), not one bad tenant.
import ipaddress
from collections import defaultdict


def net64(ip):
    """The /64 network (as a string) containing an IPv6 address, or None if `ip`
    is not a valid IPv6 address."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a.version != 6:
        return None
    return str(ipaddress.ip_network((ip, 64), strict=False))


def plan_v6(ips, threshold):
    """Given the offending v6 /128 addresses, return the list to actually push to pf:
    individual /128s, except any /64 that holds >= `threshold` distinct offenders,
    which collapses to a single /64 entry. `threshold` <= 0 disables aggregation
    entirely (always /128 -- the most conservative, zero-collateral setting)."""
    ips = list(dict.fromkeys(ips))                 # de-dup, preserve order
    if not threshold or threshold <= 0:
        return ips
    by64 = defaultdict(list)
    loose = []
    for ip in ips:
        n = net64(ip)
        by64[n].append(ip) if n else loose.append(ip)
    out = list(loose)
    for n, members in by64.items():
        if len(members) >= threshold:
            out.append(n)                          # collapse: ban the whole /64
        else:
            out.extend(members)                    # keep the individual /128s
    return out
