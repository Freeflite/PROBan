// ProBAN dashboard -- settings modal: load current config, live-preview notes, validate, save.
window.PROBAN = window.PROBAN || {};
PROBAN.settings = (function () {
    var fmt = PROBAN.fmt, api = PROBAN.api, validate = PROBAN.validate, T = PROBAN.T || {};
    var pbTip = '', pbTports = '';   // last-loaded tarpit target/ports (fallback when the field is blank)

    function updateActionUI() { $('#pbTarpitCfg').toggle($('input[name=pbAction]:checked').val() === 'tarpit'); }
    function updateEnforceWarn() { $('#pbEnforceWarn').toggle($('#pbEnforce').prop('checked') && $('#pbEnabled').prop('checked')); }
    function updateDecayNote() { var a = parseFloat($('#pbDecayAmt').val()) || 1, i = parseFloat($('#pbDecayInt').val()) || 1; var rate = (a / i); $('#pbDecayNote').text(T.decayNote.replace('%RATE%', rate.toFixed(2)).replace('%DUR%', fmt.fmtDur((fmt.parseDur($('#pbMaxBan').val()) / a) * i))); }
    function updateBhUI() { $('#pbBhCfg').toggle($('input[name=pbPostMax]:checked').val() === 'blackhole'); updateBhNote(); }
    function updateBhNote() { if ($('input[name=pbPostMax]:checked').val() !== 'blackhole') { $('#pbBhNote').text(''); return; } var h = parseInt($('#pbBhHours').val(), 10) || 0, d = fmt.parseDur($('#pbBhDecay').val()) || 0; $('#pbBhNote').text(h && d ? T.bhNote.replace('%H%', h).replace('%AMT%', fmt.fmtDur(d)).replace('%TOTAL%', fmt.fmtDur(h * d)) : ''); }

    function open() {
        $('#pbSaveMsg').text('');
        api.settingsGet(function (d) {
            if (!d) return;
            $('#pbEnabled').prop('checked', d.enabled != 0);
            $('#pbEnforce').prop('checked', d.dry_run == 0);
            $('#pbGrace').val(d.grace_hits || 1);
            $('#pbStep').val(d.step_secs || 30);
            $('#pbMult').val(d.multiplier || 1.5);
            $('#pbMaxBan').val(fmt.fmtDur(d.max_ban_secs || 2592000));
            $('#pbDecayAmt').val(d.decay_amount || 30);
            $('#pbDecayInt').val(d.decay_interval || 60);
            $('#pbEventRet').val(d.event_retention_days != null ? d.event_retention_days : 14);
            $('#pbAmnesia').val(d.offender_amnesia_days != null ? d.offender_amnesia_days : 30);
            $('#pbAllow').val((d.allowlist || []).join('\n'));
            $('#pbSrcFw').prop('checked', !d.sources || d.sources.firewall != 0);
            $('#pbSrcSuri').prop('checked', !d.sources || d.sources.suricata != 0);
            pbTip = d.tarpit_ip || ''; pbTports = (d.tarpit_ports != null ? d.tarpit_ports : '');
            $('#pbWanIf').val(d.wan_if || '');
            $('#pbProtPorts').val(d.protected_ports || '');
            $('input[name=pbAction][value=' + ((d.action === 'tarpit') ? 'tarpit' : 'drop') + ']').prop('checked', true);
            $('#pbTipIn').val(pbTip); $('#pbTportIn').val(pbTports);
            $('#pbTip6In').val(d.tarpit_ip6 || ''); $('#pbV6Agg').val(d.v6_aggregate != null ? d.v6_aggregate : 4);
            $('input[name=pbPostMax][value=' + ((d.post_max_action === 'blackhole') ? 'blackhole' : 'hold') + ']').prop('checked', true);
            $('#pbBhHours').val(d.blackhole_hours || 12);
            $('#pbBhDecay').val(fmt.fmtDur(d.blackhole_decay || 7200));
            updateActionUI(); updateEnforceWarn(); updateDecayNote(); updateBhUI();
            $('#pbSettings').modal('show');
        });
    }
    function save() {
        if (($('input[name=pbAction]:checked').val() === 'tarpit')) {
            var tip = $('#pbTipIn').val().trim();
            if (!tip) { $('#pbSaveMsg').text(T.needIp); return; }
            if (!validate.isPrivateIp(tip)) { $('#pbSaveMsg').text(T.notPrivate); return; }
        }
        var tip6 = $('#pbTip6In').val().trim();
        if (tip6 && !validate.isPrivateIp(tip6)) { $('#pbSaveMsg').text(T.notPrivate); return; }
        var v6agg = parseInt($('#pbV6Agg').val(), 10); if (isNaN(v6agg)) v6agg = 4;
        if (fmt.parseDur($('#pbMaxBan').val()) < 60) { $('#pbSaveMsg').text(T.maxBanMin); return; }
        var allow = $('#pbAllow').val().split('\n').map(function (x) { return x.trim(); }).filter(function (x) { return x; });
        var payload = {
            enabled: $('#pbEnabled').prop('checked') ? 1 : 0,
            dry_run: $('#pbEnforce').prop('checked') ? 0 : 1,
            grace_hits: parseInt($('#pbGrace').val(), 10) || 1,
            step_secs: parseInt($('#pbStep').val(), 10) || 30,
            multiplier: parseFloat($('#pbMult').val()) || 1.5,
            max_ban: $('#pbMaxBan').val(),
            decay_amount: parseInt($('#pbDecayAmt').val(), 10) || 30,
            decay_interval: parseInt($('#pbDecayInt').val(), 10) || 60,
            event_retention_days: parseInt($('#pbEventRet').val(), 10),
            offender_amnesia_days: parseInt($('#pbAmnesia').val(), 10),
            allowlist: allow,
            src_firewall: $('#pbSrcFw').prop('checked') ? 1 : 0,
            src_suricata: $('#pbSrcSuri').prop('checked') ? 1 : 0,
            wan_if: $('#pbWanIf').val().trim(),
            protected_ports: $('#pbProtPorts').val().trim(),
            action: ($('input[name=pbAction]:checked').val() === 'tarpit') ? 'tarpit' : 'drop',
            tarpit_ip: $('#pbTipIn').val().trim() || pbTip,
            tarpit_ports: $('#pbTportIn').val().trim(),
            tarpit_ip6: tip6,
            v6_aggregate: v6agg,
            post_max_action: $('input[name=pbPostMax]:checked').val() || 'hold',
            blackhole_hours: parseInt($('#pbBhHours').val(), 10) || 12,
            blackhole_decay: $('#pbBhDecay').val().trim() || '2h'
        };
        // clear in-flight feedback: spinner + "Saving…", and blur so the button doesn't
        // linger in the pressed/focused look. Always restored on completion (ajaxCall's
        // callback fires on success AND error), so it can't get stuck "down".
        var $btn = $('#pbSaveBtn'), label = $btn.html();
        $('#pbSaveMsg').text('');
        $btn.prop('disabled', true).blur().html('<i class="fa fa-spinner fa-spin"></i> ' + (T.saving || 'Saving…'));
        api.settingsSet(payload, function (d) {
            $btn.prop('disabled', false).html(label);
            if (d && d.status === 'ok') {
                $('#pbSettings').modal('hide'); PROBAN.dashboard.load();
            } else {
                $('#pbSaveMsg').text(T.saveFailed + ': ' + ((d && d.msg) || T.unknown));
            }
        });
    }
    function init() {
        $(document).on('change', 'input[name=pbAction]', updateActionUI);
        $('#pbEnforce,#pbEnabled').on('change', updateEnforceWarn);
        $('#pbDecayAmt,#pbDecayInt,#pbMaxBan').on('input', updateDecayNote);
        $(document).on('change', 'input[name=pbPostMax]', updateBhUI);
        $('#pbBhHours,#pbBhDecay').on('input', updateBhNote);
        $('#pbSettingsBtn').on('click', open);
        $('#pbSaveBtn').on('click', save);
    }
    return {init: init, open: open, save: save};
})();
