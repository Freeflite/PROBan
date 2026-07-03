<script src="{{ cache_safe('/ui/js/chart.umd.min.js') }}"></script>
<link rel="stylesheet" href="{{ cache_safe('/ui/css/proban.css') }}"/>
<div id="pbHdr">
  <span class="t"><i class="fa fa-ban" style="color:#f4511e;"></i> {{ lang._('Progressive Ban') }} <span id="pbHealth" style="font-size:12px;font-weight:400;margin-left:8px;"></span></span>
  <button type="button" class="btn btn-default btn-sm" id="pbSettingsBtn"><i class="fa fa-cog"></i> {{ lang._('Settings') }}</button>
</div>
<div id="pbTamper" class="alert alert-danger" style="display:none;"><i class="fa fa-exclamation-triangle"></i> <b>{{ lang._('TAMPER DETECTED') }}</b> &mdash; {{ lang._('the tarpit redirect was pointed at a public IP') }} (<span id="pbTamperIp"></span>). {{ lang._('The block table has been flushed to prevent outbound reflection. Fix the target to a private/LAN address in Settings.') }}</div>
<div class="row">
  <div class="col-xs-3"><div class="content-box pb-card"><div class="n" id="pb-total">-</div><div class="l">{{ lang._('Offenders') }}</div></div></div>
  <div class="col-xs-3"><div class="content-box pb-card"><div class="n" id="pb-active">-</div><div class="l">{{ lang._('Active Blocks') }}</div></div></div>
  <div class="col-xs-3"><div class="content-box pb-card"><div class="n" id="pb-events">-</div><div class="l">{{ lang._('Events 24h') }}</div></div></div>
  <div class="col-xs-3"><div class="content-box pb-card"><div class="n" id="pb-mode">-</div><div class="l">{{ lang._('Mode') }}</div></div></div>
</div>
<div class="row" style="display:flex;flex-wrap:wrap;">
  <div class="col-md-8"><div class="content-box" style="padding:15px;height:100%;display:flex;flex-direction:column;">
    <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-bottom:10px;">
      <b style="margin-right:4px;">{{ lang._('Offense timeline') }}</b>
      <div class="btn-group btn-group-xs" id="pbNav">
        <button type="button" class="btn btn-default" data-d="-1" title="{{ lang._('back') }}"><i class="fa fa-chevron-left"></i></button>
        <button type="button" class="btn btn-default" data-d="0">{{ lang._('Now') }}</button>
        <button type="button" class="btn btn-default" data-d="1" title="{{ lang._('forward') }}"><i class="fa fa-chevron-right"></i></button>
      </div>
      <span class="text-muted" style="font-size:11px;margin-left:6px;">{{ lang._('res') }}</span>
      <div class="btn-group btn-group-xs" id="pbRes">
        <button type="button" class="btn btn-default" data-s="300">5m</button>
        <button type="button" class="btn btn-default" data-s="900">15m</button>
        <button type="button" class="btn btn-default" data-s="1800">30m</button>
        <button type="button" class="btn btn-default" data-s="3600">1h</button>
      </div>
      <span class="text-muted" style="font-size:11px;margin-left:6px;">{{ lang._('span') }}</span>
      <div class="btn-group btn-group-xs" id="pbWin">
        <button type="button" class="btn btn-default" data-s="10800">3h</button>
        <button type="button" class="btn btn-default" data-s="21600">6h</button>
        <button type="button" class="btn btn-default" data-s="43200">12h</button>
        <button type="button" class="btn btn-default" data-s="86400">24h</button>
      </div>
      <span id="pbTlLabel" class="text-muted" style="font-size:11px;margin-left:auto;"></span>
    </div>
    <div style="flex:1;min-height:0;position:relative;"><canvas id="pbTimeline"></canvas></div>
  </div></div>
  <div class="col-md-4"><div class="content-box" style="padding:15px;height:100%;"><b>{{ lang._('By level') }}</b><div style="height:330px;position:relative;margin-top:6px;"><canvas id="pbTiers"></canvas></div></div></div>
</div>
<div class="content-box" style="padding:15px;">
  <b>{{ lang._('Offenders') }}</b> <small class="text-muted">- {{ lang._('click a row for its full history') }}</small>
  <div style="margin:6px 0; display:flex; gap:14px; align-items:center; flex-wrap:wrap; font-size:11px;">
    <span>
      <small class="text-muted">{{ lang._('IPv') }}</small>
      <div class="btn-group btn-group-xs" id="pbFamily" style="vertical-align:middle;">
        <button type="button" class="btn btn-default" data-s="4">IPv4</button>
        <button type="button" class="btn btn-default" data-s="6">IPv6</button>
        <button type="button" class="btn btn-default" data-s="0">{{ lang._('Both') }}</button>
      </div>
    </span>
    <span>
      <small class="text-muted">{{ lang._('Per page') }}</small>
      <div class="btn-group btn-group-xs" id="pbPageSize" style="vertical-align:middle;">
        <button type="button" class="btn btn-default" data-s="25">25</button>
        <button type="button" class="btn btn-default" data-s="50">50</button>
        <button type="button" class="btn btn-default" data-s="100">100</button>
        <button type="button" class="btn btn-default" data-v="custom">{{ lang._('Custom') }}</button>
        <button type="button" class="btn btn-default" data-v="all">{{ lang._('All') }}</button>
      </div>
      <input type="number" id="pbPageSizeCustom" class="input-sm" style="width:52px; display:none; vertical-align:middle; height:22px; padding:1px 5px;" value="25" min="1" max="10000">
    </span>
    <span id="pbOffendersInfo" style="margin-left:auto; color:#666;"></span>
    <div class="btn-group btn-group-xs" id="pbPager" style="vertical-align:middle;">
      <button type="button" class="btn btn-default" id="pbPrev" title="{{ lang._('previous') }}"><i class="fa fa-chevron-left"></i></button>
      <button type="button" class="btn btn-default" id="pbNext" title="{{ lang._('next') }}"><i class="fa fa-chevron-right"></i></button>
    </div>
  </div>
  <table class="table table-striped table-condensed" id="pbTbl" style="margin-top:8px;">
    <thead><tr><th class="pbsort" data-k="ip">{{ lang._('Source IP') }} <span class="pbcar"></span></th><th class="pbsort" data-k="hits">{{ lang._('Hits') }} <span class="pbcar"></span></th><th class="pbsort" data-k="ban_secs">{{ lang._('Ban') }} <span class="pbcar"></span></th><th class="pbsort" data-k="level">{{ lang._('Level') }} <span class="pbcar"></span></th><th class="pbsort" data-k="blocked_until">{{ lang._('Blocked until') }} <span class="pbcar"></span></th><th>{{ lang._('Latest reason') }}</th></tr></thead>
    <tbody></tbody>
  </table>
</div>
<div class="modal fade" id="pbModal" tabindex="-1"><div class="modal-dialog modal-lg"><div class="modal-content">
  <div class="modal-header"><button type="button" class="close" data-dismiss="modal">&times;</button><h4 class="modal-title" id="pbModalTitle">{{ lang._('Offender') }}</h4></div>
  <div class="modal-body"><table class="table table-condensed"><thead><tr><th style="width:180px">{{ lang._('Time') }}</th><th style="width:90px">{{ lang._('Source') }}</th><th>{{ lang._('Reason') }}</th></tr></thead><tbody id="pbModalBody"></tbody></table></div>
</div></div></div>
<div class="modal fade" id="pbSettings" tabindex="-1"><div class="modal-dialog"><div class="modal-content">
  <div class="modal-header"><button type="button" class="close" data-dismiss="modal">&times;</button><h4 class="modal-title"><i class="fa fa-cog"></i> {{ lang._('ProBAN Settings') }}</h4></div>
  <div class="modal-body">
    <div class="pb-sect">
      <div class="h">{{ lang._('Enforcement') }}</div>
      <div class="checkbox"><label><input type="checkbox" id="pbEnabled"> {{ lang._('Engine enabled') }} <small class="text-muted">{{ lang._('(uncheck to pause & flush all blocks)') }}</small></label></div>
      <div class="checkbox"><label><input type="checkbox" id="pbEnforce"> <b>{{ lang._('Enforce') }}</b> &mdash; {{ lang._('actively drop offenders') }} <small class="text-muted">{{ lang._('(unchecked = dry-run)') }}</small></label></div>
      <div id="pbEnforceWarn" class="alert alert-danger" style="display:none;padding:6px 10px;margin:6px 0 0;font-size:12px;"><i class="fa fa-exclamation-triangle"></i> {{ lang._('This will actively DROP traffic from listed offenders on the WAN.') }}</div>
    </div>
    <div class="pb-sect">
      <div class="h">{{ lang._('Action for blocked IPs') }}</div>
      <label class="radio-inline"><input type="radio" name="pbAction" value="drop"> <b>{{ lang._('Drop') }}</b> <small class="text-muted">{{ lang._('(silent black-hole)') }}</small></label>
      <label class="radio-inline"><input type="radio" name="pbAction" value="tarpit"> <b>{{ lang._('Tarpit') }}</b> <small class="text-muted">{{ lang._('(redirect into the pit)') }}</small></label>
      <div id="pbTarpitCfg" style="margin-top:8px;">
        <div class="row">
          <div class="col-xs-8"><label style="font-size:11px;">{{ lang._('Tarpit target IP') }}</label><input type="text" class="form-control input-sm" id="pbTipIn" placeholder="10.0.0.1"></div>
          <div class="col-xs-4"><label style="font-size:11px;">{{ lang._('Port(s)') }}</label><input type="text" class="form-control input-sm" id="pbTportIn" placeholder="3333 or 22,23,443"></div>
        </div>
        <small class="text-muted">{{ lang._('Private/LAN target only (remote = via VPN).') }} {{ lang._('Empty = honeypot, all ports preserved (health-checks common services); one port = tarpit, collapse onto it; a list like 22,23,443 = honeypot, redirect ONLY these (rest stay closed — looks like a firewalled box with a few services open).') }}</small>
        <div style="margin-top:10px;border-top:1px dashed #ccc;padding-top:8px;">
          <label style="font-size:11px;display:block;margin-bottom:2px;">{{ lang._('IPv6') }} <small class="text-muted">{{ lang._('(optional — blank keeps IPv6 block-only)') }}</small></label>
          <div class="row">
            <div class="col-xs-8"><label style="font-size:11px;">{{ lang._('IPv6 tarpit target (ULA)') }}</label><input type="text" class="form-control input-sm" id="pbTip6In" placeholder="fd00:66::10"></div>
            <div class="col-xs-4"><label style="font-size:11px;">{{ lang._('Collapse /64 at') }}</label><input type="number" min="0" class="form-control input-sm" id="pbV6Agg" placeholder="4"></div>
          </div>
          <small class="text-muted">{{ lang._('Set a ULA target to tarpit/honeypot IPv6 the same as IPv4. Bans individual /128s, escalating to the whole /64 once this many distinct offenders show up in it (0 = never — /128 only, safest for shared-hosting /64s).') }}</small>
        </div>
        <div style="margin-top:10px;border-top:1px dashed #ccc;padding-top:8px;">
          <label style="font-size:11px;display:block;margin-bottom:2px;">{{ lang._('When an offender hits max ban') }}</label>
          <label class="radio-inline"><input type="radio" name="pbPostMax" value="hold"> {{ lang._('Keep tarpitting') }}</label>
          <label class="radio-inline"><input type="radio" name="pbPostMax" value="blackhole"> <b>{{ lang._('Blackhole') }}</b> <small class="text-muted">{{ lang._('(drop a while, then back to the pit)') }}</small></label>
          <div id="pbBhCfg" class="row" style="margin-top:8px;">
            <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Blackhole hours') }}</label><input type="number" min="1" class="form-control input-sm" id="pbBhHours" placeholder="12"></div>
            <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Bleed / hour') }} <small class="text-muted">{{ lang._('(e.g. 2h)') }}</small></label><input type="text" class="form-control input-sm" id="pbBhDecay" placeholder="2h"></div>
          </div>
          <small class="text-muted" id="pbBhNote"></small>
        </div>
      </div>
    </div>
    <div class="pb-sect">
      <div class="h">{{ lang._('Progressive escalation') }}</div>
      <div class="row">
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Grace — ban after N hits') }}</label><input type="number" min="1" class="form-control input-sm" id="pbGrace"></div>
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Step — seconds added per hit') }}</label><input type="number" min="1" class="form-control input-sm" id="pbStep"></div>
      </div>
      <div class="row" style="margin-top:8px;">
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Multiplier') }} <small class="text-muted">{{ lang._('(1.0 = linear)') }}</small></label><input type="number" min="1" max="10" step="0.1" class="form-control input-sm" id="pbMult"></div>
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Max ban') }} <small class="text-muted">{{ lang._('(e.g. 1y 2d 6h)') }}</small></label><input type="text" class="form-control input-sm" id="pbMaxBan"></div>
      </div>
      <small class="text-muted">{{ lang._('Each hit adds step × multiplier^(n-1) to the ban, capped at max.') }}</small>
    </div>
    <div class="pb-sect">
      <div class="h">{{ lang._('Decay on silence') }}</div>
      <div class="row">
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Decay amount (seconds)') }}</label><input type="number" min="1" class="form-control input-sm" id="pbDecayAmt"></div>
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('per silence interval (seconds)') }}</label><input type="number" min="1" class="form-control input-sm" id="pbDecayInt"></div>
      </div>
      <small class="text-muted" id="pbDecayNote"></small>
    </div>
    <div class="pb-sect">
      <div class="h">{{ lang._('Detection sources') }}</div>
      <label class="checkbox-inline"><input type="checkbox" id="pbSrcFw"> {{ lang._('Firewall SYN probes') }}</label>
      <label class="checkbox-inline"><input type="checkbox" id="pbSrcSuri"> {{ lang._('Suricata alerts') }}</label>
      <div class="row" style="margin-top:8px;">
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('WAN interface device') }} <small class="text-muted">{{ lang._('(filter-log parsing)') }}</small></label><input type="text" class="form-control input-sm" id="pbWanIf" placeholder="vtnet1"></div>
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Protected ports') }} <small class="text-muted">{{ lang._('(ignore for probes/knocks, e.g. OpenVPN TCP)') }}</small></label><input type="text" class="form-control input-sm" id="pbProtPorts" placeholder="1194, 443"></div>
      </div>
    </div>
    <div class="pb-sect">
      <div class="h">{{ lang._('Allowlist') }} <small class="text-muted">{{ lang._('(never banned — one CIDR per line)') }}</small></div>
      <textarea class="form-control input-sm" id="pbAllow" rows="4" style="font-family:monospace;font-size:12px;"></textarea>
      <small class="text-muted">{{ lang._('Private ranges & loopback are always protected regardless.') }}</small>
    </div>
    <div class="pb-sect">
      <div class="h">{{ lang._('Housekeeping') }}</div>
      <div class="row">
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Event retention (days)') }}</label><input type="number" min="0" class="form-control input-sm" id="pbEventRet"></div>
        <div class="col-xs-6"><label style="font-size:11px;">{{ lang._('Offender amnesia (days)') }}</label><input type="number" min="0" class="form-control input-sm" id="pbAmnesia"></div>
      </div>
    </div>
  </div>
  <div class="modal-footer">
    <span id="pbSaveMsg" class="text-danger" style="margin-right:10px;"></span>
    <button type="button" class="btn btn-default" data-dismiss="modal">{{ lang._('Cancel') }}</button>
    <button type="button" class="btn btn-primary" id="pbSaveBtn">{{ lang._('Save') }}</button>
  </div>
</div></div></div>
<script>
// Server-translated strings + palette, read by the dashboard modules below. The %..%
// tokens are runtime placeholders so translators can reorder them.
window.PROBAN = window.PROBAN || {};
PROBAN.COLORS = ['#8bc34a', '#ffc107', '#ff9800', '#f4511e', '#c62828'];
PROBAN.T = {
  expired: "{{ lang._('expired') }}",
  offender: "{{ lang._('Offender') }}",
  target: "{{ lang._('target') }}",
  saveFailed: "{{ lang._('Save failed') }}",
  saving: "{{ lang._('Saving…') }}",
  unknown: "{{ lang._('unknown') }}",
  needIp: "{{ lang._('Tarpit needs a target IP.') }}",
  notPrivate: "{{ lang._('Target must be a private/LAN IP — public IPs are blocked (reflection prevention). Remote tarpit = via VPN tunnel.') }}",
  maxBanMin: "{{ lang._('Max ban must be at least 60s (e.g. 30d, 1y 2d).') }}",
  decayNote: "{{ lang._('= bleeds %RATE%x real-time; a max ban clears after %DUR% of silence.') }}",
  bhNote: "{{ lang._('Maxed offenders sit dropped for %H%h, bleeding %AMT% off the ban each hour (%TOTAL% total), then back to the tarpit.') }}"
};
</script>
<script src="{{ cache_safe('/ui/js/proban/format.js') }}"></script>
<script src="{{ cache_safe('/ui/js/proban/validate.js') }}"></script>
<script src="{{ cache_safe('/ui/js/proban/api.js') }}"></script>
<script src="{{ cache_safe('/ui/js/proban/dashboard.js') }}"></script>
<script src="{{ cache_safe('/ui/js/proban/settings.js') }}"></script>
<script src="{{ cache_safe('/ui/js/proban/proban.js') }}"></script>
