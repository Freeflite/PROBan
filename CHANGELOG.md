# Changelog

## 0.1.5 (2026-11-09)

Dashboard UX pass from field reports on large offender tables (#8, #9, #10), plus an
engine-resilience hardening.

### Fixed
- **"View all" / large page sizes could pin the browser and the API** on firewalls
  with tens of thousands of offenders. The offenders list is now hard-capped at 500
  rows per request (the old ceiling was 10,000, and the "All" page-size button has
  been removed); paging through the full table is unaffected. A previously-saved
  "All" preference migrates to the default page size. (#8)
- **The per-offender hits modal showed a silent blank table** for any source whose
  events had aged out. An offender row (hit count + ban) is kept for
  `offender_amnesia_days`, but the per-hit `events` prune after
  `event_retention_days` — so a source last active beyond the retention window keeps
  its lifetime hit count but has no event detail left to show. The modal now explains
  this instead of rendering an empty table. (#10)
- **A single malformed offender row could stall the whole engine.** The decay pass does
  per-row ban math (`now - last_calc`); a row with a NULL `last_calc` (e.g. a manual DB
  edit or a partial import) raised `int - NoneType` and aborted the *entire* cycle on
  every pass — no decay and no enforcement, for any offender, until it was removed. The
  decay math now tolerates a NULL `last_calc`/`blackhole_until` (the row keeps its balance
  for that pass and the next write repopulates `last_calc`), and each row is processed
  independently so one bad row is logged and skipped instead of halting the pass.

### Added
- **Time-source setting (Settings → Housekeeping → "Show times in").** Choose whether
  the dashboard renders every timestamp in **browser time** (the viewer's local zone,
  the default and prior behavior) or **firewall time** (the firewall's own zone, so
  what you see matches the firewall's logs and clock from anywhere). A small indicator
  above the offenders table shows which clock is in effect. All timestamps on the page
  honor the choice consistently. (#9)
- **"Blocked until" column hint** explaining it is the wall-clock expiry *after* ban
  decay — at the default decay rate (half real-time) a block outlasts its current
  "Ban" value by ~2× — and that the decay rate is tunable under Settings. (#10)

## 0.1.4 (2026-11-08)

### Fixed
- **Engine went blind (`ingested fw=0`) after boot and after log rotation.** The
  default firewall-log path, `/var/log/filter/latest.log`, is a symlink OPNsense
  only (re)creates from its hourly `syslog archive` cron job — so for up to an hour
  after a reboot, and briefly after each rotation, it does not exist even though the
  filter log is actively being written. The engine's plain `open()` hit
  `FileNotFoundError` and ingested nothing the whole time: no detections, no bans,
  no escalation. It now falls back to the newest `filter_*.log` in the same
  directory (the exact file `latest.log` would point at, matching OPNsense's own
  `log_archive` and firewall-log viewer). The dated file and the symlink share an
  inode, so offset/rotation tracking stays seamless when the symlink later appears —
  no missed bytes, no double-counting. Reproduced and fixed on a live OPNsense 26.7
  box: a freshly rebooted box with no `latest.log` now detects and escalates attack
  traffic immediately, with no manual intervention. (#7; also the root cause behind
  the "only updates when I change a setting" reports in #4 and #8.)

## 0.1.3 (2026-11-06)

The bulk of this release comes from **[brotaxt](https://github.com/brotaxt)**
(DominicKo), via their fork at <https://github.com/brotaxt/PROBan>. Thank you.
Merged with their authorship intact and validated end-to-end on OPNsense 26.7.

### Fixed
- **Service failed to start on OPNsense 26.7** (`configd` returned exit status
  126). The `rc.d` launcher shipped non-executable once the plugin build stopped
  force-setting script modes; it (and the engine scripts) are now committed
  executable. (#2, #3)
- **Offender log / levels stopped updating in drop (enforcing) mode** once an IP
  was blocked. The engine now polls pf packet counters, so a blocked offender
  keeps escalating from the traffic pf drops for it — no firewall-log spam
  required. (#4)

### Added
- Persistent, kqueue-driven engine daemon (replaces the run-once engine + sleep
  supervisor), with bounded, log-rotation-aware ingestion (per-cycle line/byte/
  time caps).
- Additional detections, each independently toggleable: UDP probes, TCP scans
  (NULL/FIN/XMAS), TCP-invalid flag combos, port scans, and IPv6 source-rotation
  (ban a /64 when enough rotating sources hammer it).
- pf packet-counter polling and batched `pfctl` table syncs with timeouts.
- Suricata alert prioritisation (severity / SID) and a much larger engine test
  suite.

### Credits
- Exit-126 executable-bit fix independently identified by Freeflite (2026-11-02)
  and brotaxt (2026-11-04); both are reflected in this release.

## 0.1.0

Initial ProBAN release — progressive/parabolic banning with tarpit & honeypot,
IPv4 + IPv6, SQLite-backed offender store, and the OPNsense dashboard.
