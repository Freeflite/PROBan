// ProBAN dashboard -- formatters (pure; no DOM, no state, no API).
window.PROBAN = window.PROBAN || {};
PROBAN.fmt = (function () {
    var COLORS = PROBAN.COLORS || ['#8bc34a', '#ffc107', '#ff9800', '#f4511e', '#c62828'];
    // Time rendering mode. 'browser' uses the viewer's local zone (default);
    // 'firewall' pins every timestamp to the firewall's own zone (TZ, an IANA name)
    // so what the dashboard shows matches the firewall's logs/clock regardless of
    // where the browser is. All timestamps are epoch, so only the display zone changes.
    var TMODE = 'browser', TZ = null;
    // merge the firewall timeZone into a toLocale* options object when in firewall mode
    function zopts(base) {
        if (TMODE === 'firewall' && TZ) {
            var o = {}; for (var k in (base || {})) { o[k] = base[k]; } o.timeZone = TZ; return o;
        }
        // Never hand null to toLocale*(): toLocaleString([], null) throws (ToObject(null)),
        // which is how ftime (base=null) blew up the offenders render. undefined == defaults.
        return base == null ? undefined : base;
    }
    return {
        // tier (1..5) -> colour
        tcolor: function (t) { return COLORS[Math.min((t || 1) - 1, 4)] || '#999'; },
        // epoch seconds -> locale date/time
        ftime: function (ts) { return new Date(ts * 1000).toLocaleString([], zopts(null)); },
        // epoch ms -> short "Jul 4, 09:15" label
        fmtLbl: function (ms) { return new Date(ms).toLocaleString([], zopts({month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'})); },
        // epoch ms -> "09:15" axis tick
        fmtTick: function (ms) { return new Date(ms).toLocaleTimeString([], zopts({hour: '2-digit', minute: '2-digit'})); },
        // switch time rendering. tz is an IANA name (e.g. "America/Chicago"); validated
        // once here so a bad/unknown zone silently falls back to browser-local instead of
        // throwing RangeError out of every formatter.
        setTimeMode: function (mode, tz) {
            if (mode === 'firewall' && tz) {
                try { new Date().toLocaleString([], {timeZone: tz}); TMODE = 'firewall'; TZ = tz; return; }
                catch (e) { /* unknown zone -> fall through to browser */ }
            }
            TMODE = 'browser'; TZ = null;
        },
        timeMode: function () { return TMODE; },
        timeZone: function () { return TZ; },
        // seconds -> "1y 2d 6h" (drops trailing units once a coarser one is present)
        fmtDur: function (s) {
            s = Math.round(+s); if (s <= 0) return '-';
            var y = Math.floor(s / 31536000); s %= 31536000;
            var d = Math.floor(s / 86400); s %= 86400;
            var h = Math.floor(s / 3600); s %= 3600;
            var m = Math.floor(s / 60); var sec = s % 60; var o = [];
            if (y) o.push(y + 'y'); if (d) o.push(d + 'd'); if (h) o.push(h + 'h'); if (m) o.push(m + 'm');
            if (sec && !y && !d && !h) o.push(sec + 's');
            return o.join(' ') || '0s';
        },
        // dotted-quad -> sortable integer (0 for non-v4, e.g. IPv6 -- sorts to the top/bottom)
        ipNum: function (ip) { var p = ('' + ip).split('.'); return p.length === 4 ? (((+p[0]) * 256 + (+p[1])) * 256 + (+p[2])) * 256 + (+p[3]) : 0; },
        // "1y 2d", "2h", or a bare seconds int -> seconds (mirrors Helper::parseDuration)
        parseDur: function (t) {
            t = ('' + t).toLowerCase();
            var mul = {y: 31536000, d: 86400, h: 3600, m: 60, s: 1}, tot = 0, mm, re = /(\d+)\s*([ydhms])/g, any = false;
            while ((mm = re.exec(t))) { tot += parseInt(mm[1], 10) * mul[mm[2]]; any = true; }
            if (!any) { var n = parseInt(t, 10); if (!isNaN(n)) tot = n; }
            return tot;
        }
    };
})();
