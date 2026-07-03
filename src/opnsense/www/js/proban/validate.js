// ProBAN dashboard -- client-side validation (progressive enhancement only; the server
// is authoritative -- see OPNsense\ProBAN\Helper::isPrivateTarget and proban/rules.py).
window.PROBAN = window.PROBAN || {};
PROBAN.validate = {
    // Keep equivalent to Helper::isPrivateTarget / rules.is_private_target:
    // RFC1918 + loopback + link-local + IPv6 ULA + CGNAT 100.64/10.
    isPrivateIp: function (ip) {
        return /^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(ip) ||
            /^127\./.test(ip) || /^169\.254\./.test(ip) ||
            /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./.test(ip) ||
            /^(fc|fd)[0-9a-f]*:/i.test(ip) || /^(::1|fe80:)/i.test(ip);
    }
};
