# Changelog

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
