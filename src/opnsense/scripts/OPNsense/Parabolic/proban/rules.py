# Pure decision/math helpers. No I/O; everything comes from cfg or the arguments.
import ipaddress


def allowed(cfg, ip):
    try:
        return any(ipaddress.ip_address(ip) in n for n in cfg.allow)
    except Exception:
        return True


def is_private_target(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 4 and a in ipaddress.ip_network("100.64.0.0/10"):
            return True   # CGNAT (VPN/Tailscale)
        return a.is_private or a.is_loopback or a.is_link_local
    except Exception:
        return False


def decay_ban(cfg, ban, last_calc, t, bh_until):
    # Decay from last_calc to t. Time spent inside the blackhole window bleeds at the
    # accelerated blackhole rate; the rest at the normal silence-decay rate.
    if ban <= 0:
        return 0.0
    dt = t - last_calc
    if dt <= 0:
        return ban
    if cfg.blackhole_on and bh_until > last_calc:
        bh_secs = min(t, bh_until) - last_calc
        if bh_secs < 0:
            bh_secs = 0
        drained = bh_secs * cfg.bhrate + ((dt - bh_secs) / cfg.dint) * cfg.damt
    else:
        drained = (dt / cfg.dint) * cfg.damt
    return max(0.0, ban - drained)


def wall_until(cfg, t, ban):
    return int(t + (ban / cfg.damt) * cfg.dint) if ban > 0 else 0   # wall-clock expiry under silence


def level_of(ban):
    if ban <= 0:
        return 0
    if ban < 300:
        return 1
    if ban < 3600:
        return 2
    if ban < 21600:
        return 3
    if ban < 86400:
        return 4
    return 5
