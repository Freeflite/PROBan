// ProBAN dashboard -- live stats, offense timeline chart, offenders table, health badge.
window.PROBAN = window.PROBAN || {};
PROBAN.dashboard = (function () {
    var fmt = PROBAN.fmt, api = PROBAN.api, T = PROBAN.T || {};
    var chTl = null, chTi = null;
    var tlBucket = 300, tlWindow = 10800, tlEnd = 0;   // timeline: resolution / span / right edge (0 = live)
    var pbRows = [], pbSort = {k: 'ban_secs', dir: -1};
    var pbPageSize = 25;
    var PB_MAX_PAGE = 500;   // hard cap: never request or render more than this many offenders at once
    var pbPage = 0;
    var pbFamily = 0; // 0=both, 4=IPv4, 6=IPv6
    var pbTotal = 0;
    var pbSearch = '';
    var pbRetentionDays = 14;   // event-retention window, from stats; used by the empty hits modal
    var pbOffendersRequest = 0;
    var refreshErrors = {stats: false, offenders: false};
    var pbHistoryIP = '', pbHistoryOffset = 0, pbHistoryTotal = 0, pbHistoryThrough = 0;
    var pbHistoryRequest = 0;

    function loadPersisted() {
        try {
            var ps = localStorage.getItem('proban_offenders_pageSize');
            if (ps !== null) {
                // migrates a previously-persisted 'all' (parseInt -> NaN) back to the default page size
                var n = parseInt(ps, 10);
                if (!isNaN(n) && n > 0) pbPageSize = Math.min(n, PB_MAX_PAGE);
            }
            var fam = localStorage.getItem('proban_offenders_family');
            if (fam !== null) {
                var f = parseInt(fam, 10);
                if (!isNaN(f) && (f === 0 || f === 4 || f === 6)) pbFamily = f;
            }
        } catch (e) {}
    }

    function savePersisted() {
        try {
            localStorage.setItem('proban_offenders_pageSize', pbPageSize);
            localStorage.setItem('proban_offenders_family', pbFamily);
        } catch (e) {}
    }

    loadPersisted();

    function debounce(fn, delay) {
        var timer = null;
        return function () {
            var ctx = this, args = arguments;
            clearTimeout(timer);
            timer = setTimeout(function () {
                fn.apply(ctx, args);
            }, delay || 250);
        };
    }

    function setActive(gid, sec) {
        var g = document.getElementById(gid); if (!g) return;
        Array.prototype.forEach.call(g.querySelectorAll('button'), function (b) {
            if (parseInt(b.getAttribute('data-s'), 10) === sec) b.classList.add('active'); else b.classList.remove('active');
        });
    }
    // segmented-button highlight by data-s (numeric) or data-v (string) value
    function setActiveVal(gid, val) {
        var g = document.getElementById(gid); if (!g) return;
        Array.prototype.forEach.call(g.querySelectorAll('button'), function (b) {
            var bv = b.getAttribute('data-s'); if (bv === null) bv = b.getAttribute('data-v');
            b.classList.toggle('active', String(bv) === String(val));
        });
    }
    // which page-size button reflects the current pbPageSize
    function pageSizeKey() {
        if ([25, 50, 100].indexOf(pbPageSize) !== -1) return pbPageSize;
        return 'custom';
    }
    function reflectLive() {
        var n = document.querySelector('#pbNav button[data-d="0"]');
        if (n) { if (tlEnd === 0) n.classList.add('active'); else n.classList.remove('active'); }
    }
    function loadTimeline() {
        reflectLive();
        api.timeline(tlBucket, tlWindow, tlEnd, function (d) {
            if (!d || d.skip || !window.Chart) return;
            var bk = d.buckets || [];
            var labels = bk.map(function (b) { return fmt.fmtTick(b.t); });
            var vals = bk.map(function (b) { return b.c; });
            if (chTl) chTl.destroy();
            chTl = new Chart(document.getElementById('pbTimeline'), {type: 'line', data: {labels: labels, datasets: [{label: 'offenses', data: vals, borderColor: '#f4511e', backgroundColor: 'rgba(244,81,30,.12)', fill: true, tension: .25, pointRadius: vals.length > 48 ? 0 : 2}]}, options: {maintainAspectRatio: false, animation: false, interaction: {mode: 'index', intersect: false}, scales: {y: {beginAtZero: true}, x: {ticks: {maxTicksLimit: 12, maxRotation: 0, autoSkip: true}}}, plugins: {legend: {display: false}, tooltip: {callbacks: {title: function (it) { return fmt.fmtLbl(bk[it[0].dataIndex].t); }}}}}});
            var lbl = document.getElementById('pbTlLabel');
            if (lbl && bk.length) { lbl.textContent = (tlEnd === 0 ? 'live · ' : '') + fmt.fmtLbl(bk[0].t) + '  →  ' + fmt.fmtLbl(d.end * 1000); }
        });
    }
    function tlPan(dir) { var now = Math.floor(Date.now() / 1000); if (dir === 0) { tlEnd = 0; loadTimeline(); return; } var cur = (tlEnd === 0 ? now : tlEnd); var ne = cur + dir * Math.floor(tlWindow / 2); tlEnd = (ne >= now) ? 0 : ne; loadTimeline(); }
    function tlRes(sec) { tlBucket = sec; setActive('pbRes', sec); loadTimeline(); }
    function tlWin(sec) { tlWindow = sec; setActive('pbWin', sec); loadTimeline(); }

    function renderOffenders() {
        var rows = pbRows; // already sorted & paged by server
        var tb = $('#pbTbl tbody').empty();
        $.each(rows, function (i, r) {
            var until = (r.blocked_until * 1000 > Date.now()) ? fmt.ftime(r.blocked_until) : '<span class="text-muted">' + T.expired + '</span>';
            var badge = (r.level > 0) ? '<span class="tierbadge" style="background:' + fmt.tcolor(r.level) + '">L' + r.level + '</span>' : '<span class="text-muted">-</span>';
            var tr = $('<tr></tr>').html('<td>' + $('<div>').text(r.ip).html() + '</td><td>' + r.hits + '</td><td>' + (r.last_seen ? fmt.ftime(r.last_seen) : '-') + '</td><td>' + fmt.fmtDur(r.ban_secs) + '</td><td>' + badge + '</td><td>' + until + '</td><td><small>' + $('<div>').text(r.last_reason || '').html() + '</small></td>');
            tr.on('click', function () { drill(r.ip); });
            tb.append(tr);
        });
        // sort indicators updated after fetch
        updateOffendersInfo();
    }

    function updateOffendersInfo() {
        var info = $('#pbOffendersInfo');
        if (!info.length) return;
        if (pbTotal === 0) {
            info.text('0 total');
            return;
        }
        var start = pbPage * pbPageSize + 1;
        var end = Math.min((pbPage + 1) * pbPageSize, pbTotal);
        info.text(start + '-' + end + ' of ' + pbTotal);
    }
    function refreshStatus(source, failed) {
        refreshErrors[source] = failed;
        $('#pbRefreshError').toggle(refreshErrors.stats || refreshErrors.offenders);
    }
    // reflect which clock the dashboard is showing times in (firewall zone vs this device)
    function updateTzLabel() {
        var el = $('#pbTzLabel'); if (!el.length || !T.tzLabel) return;
        var which = (fmt.timeMode && fmt.timeMode() === 'firewall')
            ? ((T.tzFirewall || 'firewall') + (fmt.timeZone() ? ' · ' + fmt.timeZone() : ''))
            : (T.tzBrowser || 'this device');
        el.text(T.tzLabel.replace('%S%', which));
    }
    function load() {
        api.stats(function (d) {
            refreshStatus('stats', !d || !!d.skip);
            if (!d || d.skip) return;
            // apply display metadata before anything renders timestamps this cycle
            var prevMode = fmt.timeMode ? fmt.timeMode() : 'browser';
            if (fmt.setTimeMode) fmt.setTimeMode(d.time_source, d.tz);
            if (d.retention_days != null) pbRetentionDays = d.retention_days;
            updateTzLabel();
            if (fmt.timeMode && fmt.timeMode() !== prevMode) { if (pbRows.length) renderOffenders(); loadTimeline(); }
            $('#pb-total').text(d.total || 0); $('#pb-active').text(d.active || 0); $('#pb-events').text(d.events24h || 0);
            $('#pb-mode').text(d.mode || '-').css('color', d.mode === 'enforcing' ? '#c62828' : (d.mode === 'disabled' ? '#999' : '#ff9800'));
            if (d.tamper) { $('#pbTamperIp').text(d.tamper); $('#pbTamper').show(); } else { $('#pbTamper').hide(); }
            if (d.counter_error) { $('#pbCounterErrorText').text(d.counter_error); $('#pbCounterError').show(); } else { $('#pbCounterError').hide(); }
            var L = [], V = [], C = []; $.each(d.levels || {}, function (t, c) { if (parseInt(t) > 0) { L.push('L' + t); V.push(c); C.push(fmt.tcolor(parseInt(t))); } });
            if (window.Chart) { if (chTi) chTi.destroy(); chTi = new Chart(document.getElementById('pbTiers'), {type: 'doughnut', data: {labels: L, datasets: [{data: V, backgroundColor: C}]}, options: {maintainAspectRatio: false, plugins: {legend: {position: 'bottom'}}}}); }
        });
        loadTimeline();
        api.health(function (d) {
            var el = $('#pbHealth'); if (!d || d.status === 'n/a') { el.html(''); return; }
            var col = {healthy: '#8bc34a', degraded: '#ff9800', down: '#c62828'}[d.status] || '#999';
            var tip = (d.ports || []).map(function (p) { return p.port + (p.up ? '✓' : '✗'); }).join(' ');
            el.html('<span title="' + (d.ip || '') + '  ' + tip + '">' + T.target + ': <span style="color:' + col + '">&#9679;</span> ' + d.status + (d.total ? (' <small>(' + d.up + '/' + d.total + ')</small>') : '') + '</span>');
        });
        loadOffenders();
    }

    function loadOffenders() {
        var request = ++pbOffendersRequest;
        var limit = pbPageSize;
        var offset = pbPage * pbPageSize;
        var params = {
            limit: limit,
            offset: offset,
            sort: pbSort.k,
            dir: pbSort.dir,
            family: pbFamily,
            search: pbSearch
        };
        api.offenders(params, function (d) {
            if (request !== pbOffendersRequest) return;
            refreshStatus('offenders', !d || !!d.skip);
            if (!d || d.skip) return;
            pbRows = (d && d.rows) || [];
            pbTotal = (d && d.total) || 0;
            if (pbPageSize > 0) {
                var maxPage = Math.max(0, Math.ceil(pbTotal / pbPageSize) - 1);
                if (pbPage > maxPage) {
                    pbPage = maxPage;
                    loadOffenders();
                    return;
                }
            }
            renderOffenders();
            // update sort indicators (server sorted)
            var k = pbSort.k, dir = pbSort.dir;
            $('#pbTbl thead .pbcar').html('');
            $('#pbTbl thead th.pbsort[data-k="' + k + '"] .pbcar').html(dir < 0 ? '▼' : '▲');
        });
    }
    function searchOffenders() {
        var search = $('#pbSearch').val().trim();
        if (search === pbSearch) return;
        pbSearch = search;
        pbPage = 0;
        $('#pbSearchClear').prop('disabled', !search);
        loadOffenders();
    }
    function historyButtons() {
        $('#pbHistoryRefresh').prop('disabled', false);
        $('#pbHistoryPrev').prop('disabled', pbHistoryOffset <= 0);
        $('#pbHistoryNext').prop('disabled', pbHistoryOffset + 100 >= pbHistoryTotal);
    }
    function loadHistory(offset, resetSnapshot) {
        var request = ++pbHistoryRequest;
        $('#pbHistoryError').hide();
        $('#pbHistoryPrev,#pbHistoryNext,#pbHistoryRefresh').prop('disabled', true);
        api.events(pbHistoryIP, {limit: 100, offset: offset, through: resetSnapshot ? 0 : pbHistoryThrough}, function (d) {
            if (request !== pbHistoryRequest) return;
            if (!d || d.skip) {
                $('#pbHistoryError').show();
                historyButtons();
                return;
            }
            pbHistoryTotal = d.total || 0;
            pbHistoryThrough = d.through || 0;
            var maxOffset = Math.max(0, Math.ceil(pbHistoryTotal / 100) - 1) * 100;
            if (offset > maxOffset) { loadHistory(maxOffset); return; }
            pbHistoryOffset = offset;
            var rows = d.rows || [];
            $('#pbModalBody').empty();
            if (!rows.length) {
                // An offender can outlive its event detail: the offender row (hit count + ban)
                // is kept for offender_amnesia_days, but per-hit events prune after
                // event_retention_days. Explain the blank instead of showing an empty table.
                var msg = (T.noHistoryRet || '').replace('%D%', pbRetentionDays);
                $('#pbModalBody').append('<tr><td colspan="4" class="text-muted" style="padding:18px 12px;text-align:center;line-height:1.5;">' + msg + '</td></tr>');
            }
            $.each(rows, function (i, e) { $('#pbModalBody').append('<tr><td>' + fmt.ftime(e.ts) + '</td><td>' + $('<div>').text(e.source).html() + '</td><td>' + (e.hits || 1) + '</td><td>' + $('<div>').text(e.reason).html() + '</td></tr>'); });
            $('#pbHistoryInfo').text(pbHistoryTotal ? (offset + 1) + '-' + Math.min(offset + rows.length, pbHistoryTotal) + ' of ' + pbHistoryTotal : '0 total');
            $('#pbModal .modal-body').scrollTop(0);
            historyButtons();
        });
    }
    function drill(ip) {
        pbHistoryIP = ip; pbHistoryOffset = 0; pbHistoryTotal = 0; pbHistoryThrough = 0;
        $('#pbModalTitle').text(T.offender + ': ' + ip); $('#pbModalBody').empty();
        $('#pbHistoryInfo').text('');
        loadHistory(0);
        $('#pbModal').modal('show');
    }
    function init() {
        $('#pbNav').on('click', 'button', function () { tlPan(parseInt($(this).attr('data-d'), 10)); });
        $('#pbRes').on('click', 'button', function () { tlRes(parseInt($(this).attr('data-s'), 10)); });
        $('#pbWin').on('click', 'button', function () { tlWin(parseInt($(this).attr('data-s'), 10)); });
        $('#pbSearch').on('input search', debounce(searchOffenders, 250));
        $('#pbSearchClear').on('click', function () {
            $('#pbSearch').val('').focus();
            searchOffenders();
        });
        $('#pbHistoryPrev').on('click', function () { loadHistory(Math.max(0, pbHistoryOffset - 100)); });
        $('#pbHistoryNext').on('click', function () { loadHistory(pbHistoryOffset + 100); });
        $('#pbHistoryRefresh').on('click', function () { loadHistory(0, true); });
        $('#pbModal').on('hidden.bs.modal', function () { pbHistoryRequest++; });

        // Re-wire click-to-sort (server-side now)
        $(document).on('click', '#pbTbl thead th.pbsort', function () {
            var k = $(this).data('k');
            if (pbSort.k === k) {
                pbSort.dir *= -1;
            } else {
                pbSort.k = k;
                pbSort.dir = (k === 'ip') ? 1 : -1;
            }
            pbPage = 0;
            loadOffenders();
        });

        // Segmented filter controls (preserve current sort)
        $('#pbFamily').on('click', 'button', function () {
            pbFamily = parseInt($(this).attr('data-s'), 10) || 0;
            setActiveVal('pbFamily', pbFamily);
            pbPage = 0;
            savePersisted();
            loadOffenders();
        });
        $('#pbPageSize').on('click', 'button', function () {
            var dv = $(this).attr('data-v');
            if (dv === 'custom') {
                // force inline-block: jQuery .show() resolves <input> to display:block under
                // OPNsense's form CSS, which drops it onto its own line beside the buttons.
                $('#pbPageSizeCustom').css('display', 'inline-block').focus();
                $('#pbPageSizeMax').css('display', 'inline-block');
                pbPageSize = Math.min(parseInt($('#pbPageSizeCustom').val(), 10) || 25, PB_MAX_PAGE);
                setActiveVal('pbPageSize', 'custom');
            } else {
                $('#pbPageSizeCustom').css('display', 'none');
                $('#pbPageSizeMax').css('display', 'none');
                pbPageSize = parseInt($(this).attr('data-s'), 10) || 25;
                setActiveVal('pbPageSize', pbPageSize);
            }
            pbPage = 0;
            savePersisted();
            loadOffenders();
        });
        var debouncedCustom = debounce(function () {
            var v = parseInt($(this).val(), 10) || 25;
            if (v < 1) v = 1;
            if (v > PB_MAX_PAGE) v = PB_MAX_PAGE;
            pbPageSize = v;
            pbPage = 0;
            savePersisted();
            setActiveVal('pbPageSize', 'custom');
            loadOffenders();
        }, 300);
        $('#pbPageSizeCustom').on('input', debouncedCustom);
        $('#pbPrev').on('click', function () {
            if (pbPage > 0) {
                pbPage--;
                loadOffenders();
            }
        });
        $('#pbNext').on('click', function () {
            var ps = pbPageSize > 0 ? pbPageSize : 25;
            var maxPage = ps > 0 ? Math.ceil(pbTotal / ps) - 1 : 0;
            if (pbPage < maxPage) {
                pbPage++;
                loadOffenders();
            }
        });

        setActive('pbRes', tlBucket); setActive('pbWin', tlWindow);
        setActiveVal('pbFamily', pbFamily);
        setActiveVal('pbPageSize', pageSizeKey());
        if (pageSizeKey() === 'custom') {
            $('#pbPageSizeCustom').val(pbPageSize).css('display', 'inline-block');
            $('#pbPageSizeMax').css('display', 'inline-block');
        } else {
            $('#pbPageSizeCustom').css('display', 'none');
            $('#pbPageSizeMax').css('display', 'none');
        }
        var k = pbSort.k, dir = pbSort.dir;
        $('#pbTbl thead .pbcar').html('');
        $('#pbTbl thead th.pbsort[data-k="' + k + '"] .pbcar').html(dir < 0 ? '▼' : '▲');
        load(); setInterval(load, 30000);
    }
    return {init: init, load: load, drill: drill};
})();
