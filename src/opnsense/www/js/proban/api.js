// ProBAN dashboard -- API endpoint wrappers (thin adapters over OPNsense's global
// ajaxGet/ajaxCall). One place to add push-out callers, new views, etc.
window.PROBAN = window.PROBAN || {};
PROBAN.api = {
    stats: function (cb) { ajaxGet('/api/proban/overview/stats', {}, cb); },
    timeline: function (bucket, win, end, cb) { ajaxGet('/api/proban/overview/timeline/' + bucket + '/' + win + '/' + end, {}, cb); },
    health: function (cb) { ajaxGet('/api/proban/overview/health', {}, cb); },
    offenders: function (params, cb) {
        if (typeof params === 'function') { cb = params; params = {}; }
        ajaxGet('/api/proban/overview/offenders', params || {}, cb);
    },
    events: function (ip, params, cb) {
        if (typeof params === 'function') { cb = params; params = {}; }
        ajaxGet('/api/proban/overview/events', Object.assign({}, params || {}, {ip: ip}), cb);
    },
    settingsGet: function (cb) { ajaxGet('/api/proban/settings/get', {}, cb); },
    settingsSet: function (payload, cb) { ajaxCall('/api/proban/settings/set', payload, cb); }
};
