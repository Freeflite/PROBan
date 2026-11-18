# Changelog

## 0.1.6

Updates through OPNsense's own firmware page: ProBAN now has a signed package repository,
so after a one-time setup it is installed and updated like any other plugin.

### Added
- **ProBAN package repository** at `https://freeflite.github.io/PROBan/`. After adding it
  once (two `fetch` commands, see the README), `os-proban` appears under
  **System → Firmware → Plugins**, and new versions show up in OPNsense's normal update
  check. The repository is signed; `pkg` refuses anything that doesn't verify against
  `proban.pub`. (#12)
- **CI.** Every push runs the engine and API tests and builds the package in a FreeBSD VM.
  Each release tag publishes the package with a build-provenance attestation, updates the
  repository, and attaches the `.pkg` to the GitHub release.

### Changed
- **Release builds are named `os-proban`** (previously `os-proban-devel`). OPNsense hides
  `-devel` plugins on a normal install. Existing installs switch over once; see the
  README's "Switching from os-proban-devel".
- **One package for every OPNsense release.** ProBAN contains no compiled code, so the
  package is built architecture-independent (`FreeBSD:*:*`) and installs on both
  FreeBSD 14 (OPNsense 26.1) and FreeBSD 15 (OPNsense 26.7).
- **Dashboard times default to firewall time**, so they match the rest of OPNsense out of
  the box. Browser time is still available under Settings → Housekeeping → "Show times
  in"; a saved choice is kept. In browsers that report UTC for privacy (LibreWolf, Firefox
  with fingerprinting resistance), browser time shows UTC. (#9)

### Fixed
- **Upgrades kept running the old engine until the next reboot.** Installing or upgrading
  the package now restarts the ProBAN service (when enabled), so the new version runs
  immediately.

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

- **A slow or failing `pfctl` could silently freeze detection.** Each maintenance cycle
  ran inside a single transaction that only committed *after* the pf-table enforcement
  step, so if a `pfctl` call stalled or errored (e.g. the firewall contending under heavy
  load, or another product holding the pf tables), the whole cycle rolled back — including
  the firewall-log read offset and any newly recorded offenders. The engine then re-read
  the same log lines every cycle and the offender count never climbed, with no error
  surfaced. Detection + decay are now committed **before** enforcement, and enforcement is
  best-effort per table: a failed `pfctl` is caught, the cycle is marked **DEGRADED** with
  the reason recorded, and the next cycle re-reconciles the tables (the reconciliation is
  declarative/idempotent, so nothing is lost). A new **"Firewall enforcement degraded"**
  dashboard banner shows when pf updates are failing, making the condition visible instead
  of a silent stall. The same decoupling is applied to the fast (sub-cycle) ingest path.

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
- **Demo mode (Settings → Housekeeping → "Demo mode").** An off-by-default switch that,
  once enabled, exposes a card above the offenders table to populate the dashboard with
  **synthetic** offenders and to purge them again — so the paging, the 500-row page-size
  cap, the hits modal, and the stats tiles can be exercised against a realistic data set
  without waiting for real traffic. Guard rails: every synthetic row is confined to the
  non-routable RFC 2544 benchmarking block (`198.18.0.0/15`), so seeded data can never
  reach a real host and one purge removes exactly what was added; enabling the mode first
  requires acknowledging a modal, and each seed requires a second confirmation (for
  production boxes); seeding is refused server-side unless demo mode is on (not merely
  hidden in the UI), while purge is always allowed so synthetic data can be cleaned up
  even after the mode is switched back off. The same seeding core backs the dev CLI
  (`tools/seed_offenders.py`) and the in-UI control, sharing the engine's own schema so
  the two can never drift.

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
