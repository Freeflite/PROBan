// ProBAN dashboard -- demo mode: gated synthetic-data controls.
//
// The card is rendered hidden and only revealed when the stats feed reports
// demo_mode on (dashboard.load() -> reflect()). Seeding goes through a confirm
// modal so it can't be a single misclick on a production box; purge is one
// click (it only ever removes the synthetic 198.18.0.0/15 rows).
window.PROBAN = window.PROBAN || {};
PROBAN.demo = (function () {
    var api = PROBAN.api, T = PROBAN.T || {};
    var msgTimer = null;

    function reflect(on) {
        $('#pbDemoCard').css('display', on ? 'flex' : 'none');
    }

    function message(text, kind) {
        var el = $('#pbDemoMsg');
        el.text(text || '').css('color', kind === 'error' ? '#c62828'
            : (kind === 'ok' ? '#2e7d32' : '#666'));
        clearTimeout(msgTimer);
        if (text && kind !== 'busy') {
            msgTimer = setTimeout(function () { el.text(''); }, 8000);
        }
    }

    function busy(on) {
        $('#pbDemoSeed, #pbDemoPurge').prop('disabled', on);
    }

    function fail(d) {
        return (T.demoFailed || 'Demo action failed') + ': '
            + ((d && d.msg) || (T.unknown || 'unknown'));
    }

    function clampCount() {
        var n = parseInt($('#pbDemoCount').val(), 10);
        if (isNaN(n) || n < 1) n = 1;
        if (n > 50000) n = 50000;
        return n;
    }

    function doSeed() {
        var count = clampCount();
        $('#pbDemoSeedConfirm').modal('hide');
        busy(true);
        message(T.demoSeeding || 'Seeding…', 'busy');
        api.demoSeed(count, function (d) {
            busy(false);
            if (d && d.status === 'ok') {
                message((T.demoSeeded || 'Seeded %N% (%A% active) — %T% total.')
                    .replace('%N%', d.seeded != null ? d.seeded : count)
                    .replace('%A%', d.active != null ? d.active : '?')
                    .replace('%T%', d.total != null ? d.total : '?'), 'ok');
                PROBAN.dashboard.load();
            } else {
                message(fail(d), 'error');
            }
        });
    }

    function doPurge() {
        busy(true);
        message(T.demoPurging || 'Purging…', 'busy');
        api.demoPurge(function (d) {
            busy(false);
            if (d && d.status === 'ok') {
                message((T.demoPurged || 'Purged %N% synthetic offenders.')
                    .replace('%N%', d.purged != null ? d.purged : 0), 'ok');
                PROBAN.dashboard.load();
            } else {
                message(fail(d), 'error');
            }
        });
    }

    function init() {
        $('#pbDemoSeed').on('click', function () {
            $('#pbDemoConfirmCount').text(clampCount());
            $('#pbDemoSeedConfirm').modal('show');
        });
        $('#pbDemoSeedOk').on('click', doSeed);
        $('#pbDemoPurge').on('click', doPurge);
    }

    return {init: init, reflect: reflect};
})();
