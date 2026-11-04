#!/usr/local/bin/python3
# ProBAN v2 progressive-ban engine -- orchestration only.
#
# Per-IP ban BALANCE that grows on every hit (incl. post-block knocks) and decays
# during silence; optional post-max "blackhole" (drop a while, then back to the
# tarpit); IPv4 + IPv6 tarpit/honeypot/blackhole, with v6 collapsing to /64 once a
# subnet shows enough distinct offenders. The actual work lives in the proban/
# package (config, rules, store, ingest, aggregate, enforce) so this stays a
# readable pipeline.
import os
import time

from proban import config, enforce, ingest, rules, store

BASE = os.path.dirname(os.path.abspath(__file__))


def main():
    try:
        cfg = config.load(BASE)
    except Exception:
        raise SystemExit(0)   # torn config read (settings save race) -- retry next cycle

    c = store.db(cfg)
    c.execute("BEGIN IMMEDIATE")
    now = int(time.time())

    if not cfg.enabled:
        if not cfg.dry_run:
            for t in (cfg.pf_table, cfg.pf_table_drop, cfg.pf_table6, cfg.pf_table_drop6):
                enforce.synctable(t, [], c)
        enforce.poll_counters(cfg, c, now)
        c.commit()
        print("engine DISABLED (blocks flushed)")
        c.close()
        return

    # tamper guard: in tarpit mode, if the live rdr points at a PUBLIC IP (edited outside
    # ProBAN), flush the tables so nothing is redirected -> outbound reflection neutralized.
    if cfg.action == "tarpit" and not cfg.dry_run:
        # check the live rdr target for BOTH families (v6 only if a v6 tarpit is set)
        bad = None
        for tbl in [cfg.pf_table] + ([cfg.pf_table6] if cfg.tarpit_ip6 else []):
            tgt = enforce.rdr_target(tbl)
            if tgt and not rules.is_private_target(tgt):
                bad = (tbl, tgt)
                break
        if bad:
            for t in (cfg.pf_table, cfg.pf_table_drop, cfg.pf_table6, cfg.pf_table_drop6):
                enforce.synctable(t, [], c)
            store.ss(c, "tamper", bad[1])
            c.commit()
            print(f"!!! TAMPER: rdr target {bad[1]} on {bad[0]} is PUBLIC - flushed tables to block reflection. Fix the target.")
            c.close()
            return
        store.ss(c, "tamper", "")

    nf = ingest.ingest_fwlog(cfg, c, now) if cfg.sources.get("firewall", True) else 0
    ns = ingest.ingest_suricata(cfg, c, now) if cfg.sources.get("suricata", True) else 0
    npf = enforce.poll_counters(cfg, c, now)
    counter_error = store.gs(c, "counter_error")
    if counter_error:
        c.commit()
        print(f"PF counters unavailable; retaining existing bans and tables: {counter_error}")
        c.close()
        return
    store.decay_pass(cfg, c, now)
    if cfg.eret > 0:
        c.execute("DELETE FROM events WHERE ts < ?", (now - cfg.eret * 86400,))
    if cfg.amnesia > 0:
        c.execute("DELETE FROM offenders WHERE last_seen < ? AND ban_secs<=0", (now - cfg.amnesia * 86400,))

    active, dropped, v6set, em = enforce.enforce(cfg, c, now)
    c.commit()

    tot = c.execute("SELECT COUNT(*) FROM offenders").fetchone()[0]
    bh = f" blackhole={len(dropped)}" if cfg.blackhole_on else ""
    v6n = f" v6={len(v6set)}" if v6set else ""
    print(f"ingested fw={nf} suri={ns} pf={npf} | offenders={tot} active={len(active)}{bh}{v6n} "
          f"step={cfg.step} mult={cfg.mult} maxban={int(cfg.maxban)}s decay={int(cfg.damt)}/{int(cfg.dint)}s | {em}")
    c.close()


if __name__ == "__main__":
    main()
