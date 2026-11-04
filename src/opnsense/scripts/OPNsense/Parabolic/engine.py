#!/usr/local/bin/python3
# ProBAN v2 progressive-ban engine -- orchestration only.
#
# Per-IP ban BALANCE that grows on every hit (incl. post-block knocks) and decays
# during silence; optional post-max "blackhole" (drop a while, then back to the
# tarpit); IPv4 + IPv6 tarpit/honeypot/blackhole, with v6 collapsing to /64 once a
# subnet shows enough distinct offenders. The actual work lives in the proban/
# package (config, rules, store, ingest, aggregate, enforce) so this stays a
# readable pipeline.
import argparse
import os
import select
import signal
import threading
import time

from proban import config, enforce, ingest, rules, store

BASE = os.path.dirname(os.path.abspath(__file__))


def run_cycle(cfg, c, maintenance=True):
    c.execute("BEGIN IMMEDIATE")
    now = int(time.time())

    if not cfg.enabled:
        if not cfg.dry_run:
            for t in (cfg.pf_table, cfg.pf_table_drop, cfg.pf_table6, cfg.pf_table_drop6):
                enforce.synctable(t, [], c)
        enforce.poll_counters(cfg, c, now)
        c.commit()
        print("engine DISABLED (blocks flushed)")
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
            return
        store.ss(c, "tamper", "")

    pending = set()
    nf = ingest.ingest_fwlog(cfg, c, now, pending) if cfg.sources.get("firewall", True) else 0
    ns = ingest.ingest_suricata(cfg, c, now, pending) if cfg.sources.get("suricata", True) else 0
    backlog = sum(int(store.gs(c, key + "_backlog", "0")) for source, key in
                  (("firewall", "fw_offset"), ("suricata", "eve_offset")) if cfg.sources.get(source, True))
    if not maintenance:
        enforce.enforce_pending(cfg, c, now, pending)
        c.commit()
        if nf or ns or backlog:
            print(f"ingested fw={nf} suri={ns} | fast bans={len(pending)} backlog={backlog}B", flush=True)
        return
    npf = enforce.poll_counters(cfg, c, now)
    counter_error = store.gs(c, "counter_error")
    if counter_error:
        c.commit()
        print(f"PF counters unavailable; retaining existing bans and tables: {counter_error}")
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
            f"step={cfg.step} mult={cfg.mult} maxban={int(cfg.maxban)}s decay={int(cfg.damt)}/{int(cfg.dint)}s "
            f"backlog={backlog}B | {em}")


def file_signature(path):
    try:
        info = os.stat(path)
        return path, info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns
    except OSError:
        return path, None


class Runtime:
    def __init__(self, interval=60):
        self.interval = max(1, interval)
        self.connection = None
        self.database = None
        self.settings = None
        self.signature = None
        self.backlog = False
        self.next_batch = 0
        self.next_maintenance = 0
        self.paths = [os.path.join(BASE, "config.json")]

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        self.database = None

    def step(self):
        clock = time.monotonic()
        if clock < self.next_batch:
            return False
        cfg = config.load(BASE)
        sources = []
        if cfg.enabled:
            if cfg.sources.get("firewall", True):
                sources.append((cfg.fwlog, "fw_offset"))
            if cfg.sources.get("suricata", True) and cfg.eve:
                sources.append((cfg.eve, "eve_offset"))
        self.paths = [os.path.join(BASE, "config.json")] + [path for path, key in sources if path]
        signature = tuple(file_signature(path) for path, key in sources)
        maintenance = self.settings != cfg.raw or clock >= self.next_maintenance
        if not maintenance and not self.backlog and signature == self.signature:
            return False
        if self.connection is None or self.database != cfg.db:
            self.close()
            self.connection = store.db(cfg)
            self.database = cfg.db
        try:
            with self.connection:
                run_cycle(cfg, self.connection, maintenance=maintenance)
        finally:
            self.next_batch = time.monotonic() + 1
        self.backlog = any(store.gs(self.connection, key + "_pending") == "1" for path, key in sources)
        self.signature = signature
        self.settings = dict(cfg.raw)
        if maintenance:
            self.next_maintenance = clock + self.interval
        return True


class FileWatcher:
    def __init__(self):
        self.queue = None
        self.handles = {}
        factory = getattr(select, "kqueue", None)
        if callable(factory):
            try:
                self.queue = factory()
            except OSError:
                pass

    def close(self):
        for descriptor, device, inode in self.handles.values():
            os.close(descriptor)
        self.handles.clear()
        if self.queue is not None:
            self.queue.close()
            self.queue = None

    def watch(self, paths):
        if self.queue is None:
            return
        candidates = set(paths) | {os.path.dirname(path) or "." for path in paths}
        for path in set(self.handles) - candidates:
            os.close(self.handles.pop(path)[0])
        for path in sorted(candidates):
            try:
                info = os.stat(path)
            except OSError:
                if path in self.handles:
                    os.close(self.handles.pop(path)[0])
                continue
            previous = self.handles.get(path)
            if previous is not None and previous[1:] == (info.st_dev, info.st_ino):
                continue
            if previous is not None:
                os.close(self.handles.pop(path)[0])
            descriptor = None
            try:
                descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
                change = select.kevent(descriptor, filter=select.KQ_FILTER_VNODE,
                                       flags=select.KQ_EV_ADD | select.KQ_EV_CLEAR,
                                       fflags=select.KQ_NOTE_WRITE | select.KQ_NOTE_EXTEND |
                                       select.KQ_NOTE_DELETE | select.KQ_NOTE_RENAME | select.KQ_NOTE_ATTRIB)
                self.queue.control([change], 0, 0)
                self.handles[path] = (descriptor, info.st_dev, info.st_ino)
            except OSError:
                if descriptor is not None:
                    os.close(descriptor)

    def wait(self, timeout, stop):
        if stop.is_set():
            return False
        if self.queue is None:
            stop.wait(timeout)
            return False
        try:
            return bool(self.queue.control(None, 64, timeout))
        except OSError:
            stop.wait(timeout)
            return False


def serve(interval=60, stop=None):
    stop = stop if stop is not None else threading.Event()
    runtime = Runtime(interval)
    watcher = FileWatcher()
    print(f"service started: watcher={'kqueue' if watcher.queue is not None else 'poll'} maintenance={runtime.interval}s", flush=True)
    try:
        while not stop.is_set():
            try:
                runtime.step()
            except Exception as error:
                runtime.next_batch = time.monotonic() + 1
                print(f"engine cycle failed; retrying: {error}", flush=True)
            if stop.is_set():
                break
            watcher.watch(runtime.paths)
            cooldown = runtime.next_batch - time.monotonic()
            if cooldown > 0:
                stop.wait(min(cooldown, 1))
            else:
                watcher.wait(1, stop)
    finally:
        watcher.close()
        runtime.close()


def main():
    try:
        cfg = config.load(BASE)
    except Exception:
        raise SystemExit(0)
    connection = store.db(cfg)
    try:
        with connection:
            run_cycle(cfg, connection)
    finally:
        connection.close()


def cli():
    parser = argparse.ArgumentParser(description="ProBAN engine")
    parser.add_argument("--daemon", action="store_true")
    parser.add_argument("--interval", type=float, default=60)
    options = parser.parse_args()
    if options.daemon:
        stop = threading.Event()
        for signum in (signal.SIGTERM, signal.SIGINT):
            signal.signal(signum, lambda received, frame: stop.set())
        serve(options.interval, stop)
    else:
        main()


if __name__ == "__main__":
    cli()
