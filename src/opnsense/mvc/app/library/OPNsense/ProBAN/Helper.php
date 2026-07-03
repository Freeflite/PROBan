<?php

namespace OPNsense\ProBAN;

/**
 * Shared validation / parsing helpers for ProBAN.
 *
 * Single source of truth for the rules that would otherwise drift between the
 * firewall hook (plugins.inc.d/proban.inc) and the API controllers. The
 * private-target check in particular MUST stay equivalent to
 * proban/rules.py:is_private_target() -- the engine's tamper guard uses the Python
 * one, so every layer has to agree (the canonical cases are pinned in
 * tests/test_engine.py:test_is_private_target).
 */
class Helper
{
    /**
     * True when $ip is a private / reserved / CGNAT address usable as a
     * reflection-safe redirect target: RFC1918, loopback, link-local, IPv6 ULA, and
     * CGNAT 100.64/10 (VPN / Tailscale). Public IPs -> false. Empty / invalid -> false.
     */
    public static function isPrivateTarget($ip)
    {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }
        // filter_var does NOT classify CGNAT 100.64/10 as private/reserved, but the
        // engine (and the docs) allow it -- handle it explicitly so all layers agree.
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $l = ip2long($ip);
            if ($l !== false && $l >= ip2long('100.64.0.0') && $l <= ip2long('100.127.255.255')) {
                return true;
            }
        }
        // filter_var returns the IP only when it is PUBLIC -> === false means private/reserved.
        return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    /**
     * Parse a "22,23 443" port string into a de-duplicated, ordered list of valid
     * ints (1-65535). Rejected tokens are appended to &$invalid for error reporting.
     */
    public static function parsePorts($raw, &$invalid = null)
    {
        $invalid = [];
        $seen = [];
        foreach (preg_split('/[,\s]+/', (string)$raw, -1, PREG_SPLIT_NO_EMPTY) as $p) {
            if (ctype_digit($p) && (int)$p >= 1 && (int)$p <= 65535) {
                $seen[(int)$p] = true;
            } else {
                $invalid[] = $p;
            }
        }
        return array_keys($seen);
    }

    /**
     * Parse a duration like "30d", "1y 2d", "2h" (or a bare seconds integer) into
     * seconds. Mirrors the JS parseDur() in the dashboard and rules used by the
     * engine. Unrecognized input -> 0.
     */
    public static function parseDuration($s)
    {
        $s = strtolower(trim((string)$s));
        $mul = ["y" => 31536000, "d" => 86400, "h" => 3600, "m" => 60, "s" => 1];
        $tot = 0;
        $matched = false;
        if (preg_match_all('/(\d+)\s*([ydhms])/', $s, $m, PREG_SET_ORDER)) {
            foreach ($m as $x) {
                $tot += (int)$x[1] * $mul[$x[2]];
                $matched = true;
            }
        }
        if (!$matched && ctype_digit($s)) {
            $tot = (int)$s;
        }
        return $tot;
    }
}
