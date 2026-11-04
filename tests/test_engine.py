#!/usr/bin/env python3
"""Unit tests for the ProBAN engine package (proban.*).

Imports the package directly and drives the functions with a Cfg object and
controlled timestamps -- deterministic, no pf, no wall clock (enforce() runs in
dry_run, which skips pfctl).

Run:  python -m unittest discover -s tests      (or: python tests/test_engine.py)
"""
import os
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "src", "opnsense", "scripts", "OPNsense", "Parabolic")))

from proban import aggregate, config, enforce, ingest, rules, store   # noqa: E402
import engine   # noqa: E402


def make_cfg(**overrides):
    d = {
        "enabled": True, "dry_run": True,
        "db": ":memory:", "fwlog": "", "eve": "", "wan_if": "vtnet1",
        "pf_table": "parabolic_block", "pf_table_drop": "parabolic_drop", "pf_table6": "parabolic_block6",
        "allowlist": "", "grace_hits": 1, "step_secs": 30, "multiplier": 1.5,
        "max_ban_secs": 2592000, "decay_amount": 30, "decay_interval": 60,
        "event_retention_days": 14, "offender_amnesia_days": 30,
        "sources": {"firewall": True, "suricata": True},
        "action": "drop", "tarpit_ip": "", "tarpit_ports": "", "protected_ports": "",
        "tarpit_ip6": "", "v6_aggregate": 4,
        "post_max_action": "hold", "blackhole_hours": 12, "blackhole_decay": 7200,
    }
    d.update(overrides)
    return config.Cfg(d)


class PureMath(unittest.TestCase):
    def test_level_of(self):
        self.assertEqual(rules.level_of(0), 0)
        self.assertEqual(rules.level_of(299), 1)
        self.assertEqual(rules.level_of(300), 2)
        self.assertEqual(rules.level_of(3599), 2)
        self.assertEqual(rules.level_of(3600), 3)
        self.assertEqual(rules.level_of(86400), 5)

    def test_decay_linear(self):
        cfg = make_cfg(decay_amount=30, decay_interval=60)
        self.assertEqual(rules.decay_ban(cfg, 1000, 0, 60, 0), 970)      # 60s @ 30/60 -> -30
        self.assertEqual(rules.decay_ban(cfg, 10, 0, 3600, 0), 0.0)      # never below zero
        self.assertEqual(rules.decay_ban(cfg, 500, 100, 100, 0), 500)    # no elapsed time

    def test_decay_blackhole_is_accelerated(self):
        cfg = make_cfg(action="tarpit", tarpit_ip="10.66.66.10",
                       post_max_action="blackhole", blackhole_decay=3600,
                       decay_amount=30, decay_interval=60)
        self.assertTrue(cfg.blackhole_on)
        self.assertEqual(rules.decay_ban(cfg, 10000, 0, 3600, 7200), 10000 - 3600)

    def test_blackhole_off_when_not_tarpit(self):
        self.assertFalse(make_cfg(action="drop", post_max_action="blackhole").blackhole_on)

    def test_wall_until(self):
        cfg = make_cfg(decay_amount=30, decay_interval=60)
        self.assertEqual(rules.wall_until(cfg, 0, 300), 600)
        self.assertEqual(rules.wall_until(cfg, 0, 0), 0)

    def test_is_private_target(self):
        # Canonical reflection-lock contract. The PHP Helper::isPrivateTarget()
        # (library/OPNsense/ProBAN/Helper.php, used by the hook + settings API) and the
        # dashboard's JS isPrivateIp() MUST agree with these -- in particular CGNAT
        # 100.64/10, which PHP filter_var does NOT treat as private, so it needs an
        # explicit range check to match this engine-side rule.
        allow = ["10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1",
                 "100.64.0.1", "100.127.255.255",     # CGNAT 100.64/10 (VPN / Tailscale)
                 "fd00:66::10", "fc00::1",             # IPv6 ULA
                 "fe80::1", "::1"]                     # link-local, loopback
        for ip in allow:
            self.assertTrue(rules.is_private_target(ip), ip)
        deny = ["8.8.8.8", "1.1.1.1", "93.184.216.34",
                "100.63.255.255", "100.128.0.0",      # just outside CGNAT -> public
                "2606:4700:4700::1111"]               # public IPv6
        for ip in deny:
            self.assertFalse(rules.is_private_target(ip), ip)

    def test_allowlist(self):
        cfg = make_cfg(allowlist="203.0.113.0/24")
        self.assertTrue(rules.allowed(cfg, "203.0.113.50"))   # custom allowlist entry
        self.assertTrue(rules.allowed(cfg, "10.0.0.1"))        # RFC1918 always protected
        self.assertFalse(rules.allowed(cfg, "8.8.8.8"))        # public, not allowlisted


class Aggregation(unittest.TestCase):
    """Evidence-based v6 /128 -> /64 escalation (proban.aggregate)."""

    def test_net64(self):
        self.assertEqual(aggregate.net64("2001:db8:abcd:1234::5"), "2001:db8:abcd:1234::/64")
        self.assertIsNone(aggregate.net64("203.0.113.1"))         # v4 -> None
        self.assertIsNone(aggregate.net64("not-an-ip"))

    def test_shared_64_below_threshold_stays_128(self):
        ips = ["2001:db8:a::1", "2001:db8:a::2"]                   # a couple bad tenants
        out = aggregate.plan_v6(ips, 4)
        self.assertEqual(set(out), set(ips))                       # innocent neighbours spared
        self.assertNotIn("2001:db8:a::/64", out)

    def test_rotation_at_threshold_collapses_to_64(self):
        ips = ["2001:db8:a::1", "2001:db8:a::2", "2001:db8:a::3", "2001:db8:a::4"]
        self.assertEqual(aggregate.plan_v6(ips, 4), ["2001:db8:a::/64"])

    def test_repeats_are_one_distinct_offender(self):
        self.assertEqual(aggregate.plan_v6(["2001:db8:a::1"] * 5, 4), ["2001:db8:a::1"])

    def test_mixed_subnets(self):
        ips = ["2001:db8:a::%d" % i for i in range(4)] + ["2001:db8:b::1", "2001:db8:b::2"]
        out = set(aggregate.plan_v6(ips, 4))
        self.assertIn("2001:db8:a::/64", out)                      # A: 4 distinct -> collapsed
        self.assertIn("2001:db8:b::1", out)                        # B: 2 distinct -> kept
        self.assertIn("2001:db8:b::2", out)
        self.assertNotIn("2001:db8:b::/64", out)

    def test_threshold_zero_disables_aggregation(self):
        ips = ["2001:db8:a::%d" % i for i in range(10)]
        out = aggregate.plan_v6(ips, 0)
        self.assertEqual(len(out), 10)                             # all /128s, nothing collapsed
        self.assertNotIn("2001:db8:a::/64", out)


class BanGrowth(unittest.TestCase):
    def _ban(self, c, ip):
        return c.execute("SELECT ban_secs FROM offenders WHERE ip=?", (ip,)).fetchone()[0]

    def test_grace_and_progressive_growth(self):
        cfg = make_cfg(grace_hits=3, step_secs=30, multiplier=2.0)
        c = store.db(cfg)
        ip = "203.0.113.7"
        store.record(cfg, c, ip, "t", "probe", 1000)              # hit 1 (< grace)
        store.record(cfg, c, ip, "t", "probe", 1001)              # hit 2 (< grace)
        self.assertEqual(self._ban(c, ip), 0.0)
        store.record(cfg, c, ip, "t", "probe", 1002)              # hit 3 -> +30
        self.assertAlmostEqual(self._ban(c, ip), 30.0, places=3)
        store.record(cfg, c, ip, "t", "probe", 1003)              # hit 4 -> +60, minus 1s decay
        self.assertAlmostEqual(self._ban(c, ip), 30 + 60 - (1 / 60) * 30, places=1)

    def test_max_ban_cap(self):
        cfg = make_cfg(grace_hits=1, step_secs=1000000, multiplier=2.0, max_ban_secs=5000)
        c = store.db(cfg)
        store.record(cfg, c, "203.0.113.8", "t", "probe", 2000)
        self.assertLessEqual(self._ban(c, "203.0.113.8"), 5000)

    def test_allowlisted_ip_not_recorded(self):
        cfg = make_cfg(allowlist="203.0.113.0/24")
        c = store.db(cfg)
        store.record(cfg, c, "203.0.113.9", "t", "probe", 1000)
        self.assertIsNone(c.execute("SELECT 1 FROM offenders WHERE ip=?", ("203.0.113.9",)).fetchone())


class StoreIndexes(unittest.TestCase):
    def test_event_queries_use_indexes(self):
        connection = store.db(make_cfg())
        self.addCleanup(connection.close)
        queries = (
            ("SELECT SUM(hits) FROM events WHERE ts >= ? AND ts < ?", (1000, 2000), "events_ts"),
            ("SELECT ts,source,reason,hits FROM events WHERE ip=? ORDER BY ts DESC,rowid DESC LIMIT 100",
             ("203.0.113.7",), "events_ip_ts"),
            ("DELETE FROM events WHERE ts < ?", (1000,), "events_ts"),
        )
        for query, parameters, index in queries:
            with self.subTest(query=query):
                plan = " ".join(row[3] for row in connection.execute("EXPLAIN QUERY PLAN " + query, parameters))
                self.assertIn(index, plan)
                self.assertNotIn("SCAN events", plan)
                self.assertNotIn("TEMP B-TREE", plan)

    def test_existing_database_is_indexed_without_changing_records(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "offenders.db")
            with sqlite3.connect(path) as old:
                old.execute("CREATE TABLE events(ts INT,ip TEXT,source TEXT,reason TEXT)")
                old.execute("INSERT INTO events VALUES(1000,'203.0.113.7','firewall','original')")
                plan = " ".join(row[3] for row in old.execute("EXPLAIN QUERY PLAN SELECT * FROM events WHERE ts > 0"))
                self.assertIn("SCAN events", plan)
            for attempt in range(2):
                connection = store.db(make_cfg(db=path))
                self.assertEqual(connection.execute("SELECT ts,ip,source,reason,hits FROM events").fetchall(),
                                 [(1000, "203.0.113.7", "firewall", "original", 1)])
                indexes = {row[1] for row in connection.execute("PRAGMA index_list(events)")}
                self.assertEqual(indexes, {"events_ts", "events_ip_ts"})
                connection.commit()
                connection.close()


class BatchedHits(unittest.TestCase):
    def test_batch_matches_repeated_hits_and_writes_one_event(self):
        for multiplier in (1.0, 1.5, 2.0):
            with self.subTest(multiplier=multiplier):
                cfg = make_cfg(grace_hits=3, multiplier=multiplier)
                repeated = store.db(cfg)
                batched = store.db(cfg)
                self.addCleanup(repeated.close)
                self.addCleanup(batched.close)
                for connection in (repeated, batched):
                    store.record(cfg, connection, "203.0.113.7", "firewall", "probe", 1000)
                for hit in range(8):
                    store.record(cfg, repeated, "203.0.113.7", "pf", "blocked", 1060)
                store.record_batch(cfg, batched, "203.0.113.7", "pf", "blocked", 1060, 8)
                query = "SELECT hits,ban_secs,last_seen,blocked_until FROM offenders"
                self.assertEqual(repeated.execute(query).fetchone(), batched.execute(query).fetchone())
                self.assertEqual(batched.execute("SELECT COUNT(*) FROM events").fetchone()[0], 2)

    def test_large_batch_is_capped_and_stored_once(self):
        cfg = make_cfg(max_ban_secs=5000)
        connection = store.db(cfg)
        self.addCleanup(connection.close)
        store.record_batch(cfg, connection, "203.0.113.8", "pf", "blocked", 1000, 1000000)
        self.assertEqual(connection.execute("SELECT hits,ban_secs FROM offenders").fetchone(), (1000000, 5000))
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
        self.assertEqual(connection.execute("SELECT SUM(hits) FROM events").fetchone()[0], 1000000)

    def test_existing_events_are_migrated_without_losing_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "offenders.db")
            with sqlite3.connect(path) as old:
                old.execute("CREATE TABLE events(ts INT,ip TEXT,source TEXT,reason TEXT)")
                old.execute("INSERT INTO events VALUES(1000,'203.0.113.7','firewall','original')")
            cfg = make_cfg(db=path)
            connection = store.db(cfg)
            store.record_batch(cfg, connection, "203.0.113.7", "pf", "blocked", 1060, 250)
            self.assertEqual(connection.execute("SELECT COUNT(*),SUM(hits) FROM events").fetchone(), (2, 251))
            connection.commit()
            connection.close()
            connection = store.db(cfg)
            self.assertEqual(connection.execute("SELECT reason,hits FROM events ORDER BY ts").fetchall(),
                             [("original", 1), ("blocked", 250)])
            connection.close()

    def test_batch_respects_blackhole_freeze(self):
        cfg = make_cfg(action="tarpit", post_max_action="blackhole", blackhole_decay=3600)
        connection = store.db(cfg)
        self.addCleanup(connection.close)
        connection.execute("INSERT INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
                           ("203.0.113.9", 10, 1000, 1000, 5000, 1000, 0, 3, "", 2000))
        store.record_batch(cfg, connection, "203.0.113.9", "pf", "blocked", 1060, 100)
        self.assertEqual(connection.execute("SELECT hits,ban_secs FROM offenders").fetchone(), (110, 4940))

    def test_empty_batches_and_allowlisted_addresses_are_ignored(self):
        cfg = make_cfg(allowlist="203.0.113.0/24")
        connection = store.db(cfg)
        self.addCleanup(connection.close)
        store.record_batch(cfg, connection, "203.0.113.10", "pf", "blocked", 1000, 100)
        for count in (0, -1):
            store.record_batch(cfg, connection, "198.51.100.10", "pf", "blocked", 1000, count)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM offenders").fetchone()[0], 0)
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM events").fetchone()[0], 0)


class PfCounters(unittest.TestCase):
    @staticmethod
    def output(address, count, cleared="Wed Nov 4 11:00:00 2026"):
        return (f"   {address}\n\tCleared: {cleared}\n"
                f"\tIn/Block: [ Packets: {count} Bytes: 1000 ]\n"
                "\tIn/Pass: [ Packets: 9999 Bytes: 1000 ]\n"
                "\tOut/Block: [ Packets: 8888 Bytes: 1000 ]\n")

    def setUp(self):
        self.cfg = make_cfg(dry_run=False)
        self.connection = store.db(self.cfg)
        self.addCleanup(self.connection.close)
        self.outputs = {self.cfg.pf_table: "", self.cfg.pf_table6: ""}
        self.runner = patch("proban.enforce.subprocess.run", side_effect=self.run_pfctl).start()
        self.addCleanup(patch.stopall)

    def run_pfctl(self, command, **kwargs):
        output = self.outputs[command[2]]
        if isinstance(output, Exception):
            raise output
        return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")

    def test_parser_reads_only_incoming_block_packets(self):
        output = self.output("203.0.113.7/32", 12) + self.output("2001:db8::1/128", 34)
        counters = enforce.parse_counters(output)
        self.assertEqual(counters["203.0.113.7"][1], 12)
        self.assertEqual(counters["2001:db8::1"][1], 34)
        self.assertEqual(enforce.parse_counters(""), {})
        with self.assertRaises(ValueError):
            enforce.parse_counters("203.0.113.7\nCleared: now\n")
        with self.assertRaises(ValueError):
            enforce.parse_counters("X 203.0.113.7\nCleared: now\n")

    def test_initial_snapshot_then_delta_are_persisted_once(self):
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 100)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1000), 0)
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 350)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1060), 250)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1120), 0)
        self.assertEqual(self.connection.execute("SELECT hits,last_seen FROM offenders").fetchone(), (250, 1060))
        self.assertEqual(self.connection.execute("SELECT COUNT(*),SUM(hits) FROM events").fetchone(), (1, 250))
        self.assertIn("250 blocked packets", self.connection.execute("SELECT reason FROM events").fetchone()[0])

    def test_new_entry_and_counter_resets_are_counted(self):
        enforce.poll_counters(self.cfg, self.connection, 1000)
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 50)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1060), 50)
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 7)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1120), 7)
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 20, "Wed Nov 4 11:05:00 2026")
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1180), 20)
        self.assertEqual(self.connection.execute("SELECT hits FROM offenders").fetchone(), (77,))

    def test_disappearing_entry_does_not_reuse_old_counter(self):
        enforce.poll_counters(self.cfg, self.connection, 1000)
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 100)
        enforce.poll_counters(self.cfg, self.connection, 1060)
        self.outputs[self.cfg.pf_table] = ""
        enforce.poll_counters(self.cfg, self.connection, 1120)
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 150)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1180), 150)

    def test_read_failure_retains_snapshot_and_recovers(self):
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 100)
        enforce.poll_counters(self.cfg, self.connection, 1000)
        self.outputs[self.cfg.pf_table] = subprocess.CalledProcessError(1, "pfctl")
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1060), 0)
        self.assertIn(self.cfg.pf_table, store.gs(self.connection, "counter_error"))
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 200)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1120), 100)
        self.assertEqual(store.gs(self.connection, "counter_error"), "")

    def test_allowlisted_addresses_do_not_gain_hits(self):
        enforce.poll_counters(self.cfg, self.connection, 1000)
        self.outputs[self.cfg.pf_table] = self.output("10.0.0.1", 100)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1060), 0)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM offenders").fetchone()[0], 0)

    def test_dry_run_disabled_and_firewall_source_off_do_not_read_pf(self):
        for overrides in ({"dry_run": True}, {"enabled": False}, {"sources": {"firewall": False}}):
            with self.subTest(overrides=overrides):
                cfg = make_cfg(dry_run=False, **overrides) if "dry_run" not in overrides else make_cfg(**overrides)
                self.assertEqual(enforce.poll_counters(cfg, self.connection, 1000), 0)
        self.runner.assert_not_called()

    def test_tarpit_pass_tables_are_not_counted(self):
        cfg = make_cfg(dry_run=False, action="tarpit", tarpit_ip="10.66.66.10", tarpit_ip6="fd00:66::10",
                       post_max_action="blackhole")
        self.outputs = {cfg.pf_table_drop: "", cfg.pf_table_drop6: ""}
        enforce.poll_counters(cfg, self.connection, 1000)
        self.outputs[cfg.pf_table_drop] = self.output("203.0.113.7", 100)
        self.assertEqual(enforce.poll_counters(cfg, self.connection, 1060), 100)
        self.assertEqual({call.args[0][2] for call in self.runner.call_args_list}, set(self.outputs))

    def test_reenabling_collection_starts_with_a_fresh_baseline(self):
        packet_count = 100
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", packet_count)
        enforce.poll_counters(self.cfg, self.connection, 1000)
        for overrides in ({"dry_run": True}, {"enabled": False}, {"sources": {"firewall": False}}):
            with self.subTest(overrides=overrides):
                enforce.poll_counters(make_cfg(**overrides), self.connection, 1060)
                packet_count += 900
                self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", packet_count)
                self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1120), 0)
        self.assertEqual(self.connection.execute("SELECT COUNT(*) FROM offenders").fetchone()[0], 0)

    def test_ipv6_subnet_hits_are_not_invented_for_individual_hosts(self):
        enforce.poll_counters(self.cfg, self.connection, 1000)
        self.outputs[self.cfg.pf_table6] = self.output("2001:db8:bad::/64", 250)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1060), 250)
        self.assertEqual(self.connection.execute("SELECT ip,hits FROM offenders").fetchall(),
                         [("2001:db8:bad::/64", 250)])
        self.assertIn("subnet total", self.connection.execute("SELECT reason FROM events").fetchone()[0])
        with patch("proban.enforce.synctable") as sync:
            enforce.enforce(self.cfg, self.connection, 1060)
        self.assertIn("2001:db8:bad::/64", sync.call_args_list[2].args[1])

    def test_subnet_overlapping_allowlist_is_protected(self):
        cfg = make_cfg(dry_run=False, allowlist="2001:db8:bad::1/128")
        enforce.poll_counters(cfg, self.connection, 1000)
        self.outputs[cfg.pf_table6] = self.output("2001:db8:bad::/64", 250)
        self.assertEqual(enforce.poll_counters(cfg, self.connection, 1060), 0)

    def test_sync_initializes_new_entry_and_discards_removed_snapshot(self):
        store.ss(self.connection, "pf_counters:" + self.cfg.pf_table,
                 json.dumps({"203.0.113.8": ["old", 500]}))
        with patch("proban.enforce.subprocess.run") as runner:
            runner.side_effect = [subprocess.CompletedProcess([], 0, stdout="203.0.113.8\n"),
                                  subprocess.CompletedProcess([], 0), subprocess.CompletedProcess([], 0)]
            enforce.synctable(self.cfg.pf_table, ["203.0.113.7"], self.connection)
        self.assertEqual(json.loads(store.gs(self.connection, "pf_counters:" + self.cfg.pf_table)),
                         {"203.0.113.7": [None, 0]})
        self.outputs[self.cfg.pf_table] = self.output("203.0.113.7", 30)
        self.assertEqual(enforce.poll_counters(self.cfg, self.connection, 1060), 30)


class CounterIntegration(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.cfg = make_cfg(db=os.path.join(self.directory.name, "offenders.db"), dry_run=False,
                            sources={"firewall": True, "suricata": False})
        connection = store.db(self.cfg)
        store.record(self.cfg, connection, "203.0.113.7", "firewall", "probe", 1000)
        store.ss(connection, "pf_counters:" + self.cfg.pf_table,
                 json.dumps({"203.0.113.7": ["Wed Nov 4 11:00:00 2026", 0]}))
        connection.commit()
        connection.close()

    def test_engine_renews_ban_before_decay_and_restart_does_not_recount(self):
        def run_pfctl(command, **kwargs):
            output = PfCounters.output("203.0.113.7", 250) if command[2] == self.cfg.pf_table else ""
            return subprocess.CompletedProcess(command, 0, stdout=output, stderr="")
        with patch("engine.config.load", return_value=self.cfg), patch("engine.time.time", return_value=1120), \
                patch("engine.ingest.ingest_fwlog", return_value=0), patch("engine.enforce.synctable"), \
                patch("proban.enforce.subprocess.run", side_effect=run_pfctl), patch("builtins.print"):
            engine.main()
            engine.main()
        connection = store.db(self.cfg)
        self.addCleanup(connection.close)
        hits, ban = connection.execute("SELECT hits,ban_secs FROM offenders").fetchone()
        self.assertEqual(hits, 251)
        self.assertGreater(ban, 0)
        self.assertEqual(connection.execute("SELECT COUNT(*),SUM(hits) FROM events").fetchone(), (2, 251))

    def test_counter_failure_keeps_existing_ban_and_pf_tables(self):
        with patch("engine.config.load", return_value=self.cfg), patch("engine.time.time", return_value=1120), \
                patch("engine.ingest.ingest_fwlog", return_value=0), patch("engine.enforce.synctable") as sync, \
                patch("proban.enforce.subprocess.run", side_effect=OSError("pf unavailable")), patch("builtins.print"):
            engine.main()
        connection = store.db(self.cfg)
        self.addCleanup(connection.close)
        self.assertEqual(connection.execute("SELECT hits,ban_secs FROM offenders").fetchone(), (1, 30))
        self.assertIn("pf unavailable", store.gs(connection, "counter_error"))
        sync.assert_not_called()

    def test_disabled_engine_discards_counter_baselines(self):
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run):
                connection = store.db(self.cfg)
                store.ss(connection, "pf_counters:" + self.cfg.pf_table, '{"203.0.113.7":[null,100]}')
                connection.commit()
                connection.close()
                cfg = make_cfg(db=self.cfg.db, enabled=False, dry_run=dry_run)
                with patch("engine.config.load", return_value=cfg), patch("engine.enforce.synctable"), \
                        patch("proban.enforce.subprocess.run") as runner, patch("builtins.print"):
                    engine.main()
                connection = store.db(self.cfg)
                self.addCleanup(connection.close)
                self.assertEqual(store.gs(connection, "pf_counters:" + cfg.pf_table, "missing"), "missing")
                runner.assert_not_called()


class Blackhole(unittest.TestCase):
    def _insert(self, c, ip, ban, now, bh_until):
        c.execute("INSERT INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (ip, 100, now - 10, now, ban, now, 0, 0, "", bh_until))

    def test_entry_then_release(self):
        cfg = make_cfg(action="tarpit", tarpit_ip="10.66.66.10",
                       post_max_action="blackhole", blackhole_hours=12,
                       blackhole_decay=7200, max_ban_secs=100000)
        self.assertTrue(cfg.blackhole_on)
        c = store.db(cfg)
        now = 1_000_000
        self._insert(c, "203.0.113.10", cfg.maxban, now, 0)       # maxed, not yet blackholed
        store.decay_pass(cfg, c, now)
        bh = c.execute("SELECT blackhole_until FROM offenders WHERE ip=?", ("203.0.113.10",)).fetchone()[0]
        self.assertEqual(bh, now + 12 * 3600)                     # parked in the hole for 12h
        store.decay_pass(cfg, c, now + 12 * 3600 + 1)             # window elapsed
        bh2 = c.execute("SELECT blackhole_until FROM offenders WHERE ip=?", ("203.0.113.10",)).fetchone()[0]
        self.assertEqual(bh2, 0)                                  # released back to the tarpit

    def test_enforce_routes_across_two_tables(self):
        cfg = make_cfg(action="tarpit", tarpit_ip="10.66.66.10", post_max_action="blackhole", dry_run=True)
        c = store.db(cfg)
        now = 2_000_000
        self._insert(c, "203.0.113.20", 500.0, now, now + 3600)   # blackholed -> drop set
        self._insert(c, "203.0.113.21", 500.0, now, 0)            # normal -> tarpit set
        active, drop_set, v6, mode = enforce.enforce(cfg, c, now)
        self.assertEqual(mode, "DRY-RUN")
        self.assertIn("203.0.113.20", drop_set)
        self.assertNotIn("203.0.113.21", drop_set)
        self.assertEqual(set(active), {"203.0.113.20", "203.0.113.21"})


class IngestV6(unittest.TestCase):
    """IPv6 filter-log parsing: v6 shifts every field after ipversion.
    Supports block (probes) and pass,in (tarpit knocks) when v6 tarpit target is configured.
    Also tests protected_ports and stricter target/port knock matching for both v4/v6.
    """

    def _cfg_with_log(self, csv_lines, **overrides):
        tmp = tempfile.mkdtemp(prefix="proban_test_")
        path = os.path.join(tmp, "filter.log")
        with open(path, "w") as f:
            for csv in csv_lines:
                f.write("x TS h [x] " + csv + "\n")   # "] " + CSV is what the engine parses
        return make_cfg(fwlog=path, wan_if="vtnet1", **overrides)

    def test_v6_syn_is_recorded(self):
        v6syn = "21,,,trk,vtnet1,match,block,in,6,0x00,0x00000,64,tcp,6,60,2001:db8:bad::1,2601:0:0::1,44321,23,40,S,,"
        cfg = self._cfg_with_log([v6syn])
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 1)
        row = c.execute("SELECT ban_secs FROM offenders WHERE ip=?", ("2001:db8:bad::1",)).fetchone()
        self.assertIsNotNone(row)
        self.assertGreater(row[0], 0)

    def test_icmpv6_is_ignored(self):
        ra = "21,,,trk,vtnet1,match,pass,in,6,0x00,0x00000,255,ipv6-icmp,58,32,fe80::21c:73ff:fe00:99,fe80::be24:11ff:fe70:269a,datalength=32"
        cfg = self._cfg_with_log([ra])
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)
        self.assertIsNone(c.execute("SELECT 1 FROM offenders").fetchone())

    def test_v6_linklocal_is_safe(self):
        ll = "21,,,trk,vtnet1,match,block,in,6,0x00,0x00000,64,tcp,6,60,fe80::dead,2601:0:0::1,44321,23,40,S,,"
        cfg = self._cfg_with_log([ll])
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)

    def test_protected_ports_skipped(self):
        # pass,in that would normally be a tarpit knock, but port is protected
        knock_line = "21,,,trk,vtnet1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.99,10.66.66.10,54321,443,0,S,,"
        cfg = self._cfg_with_log([knock_line], action="tarpit", tarpit_ip="10.66.66.10", tarpit_ports="443", protected_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)
        self.assertIsNone(c.execute("SELECT 1 FROM offenders").fetchone())

    def test_knock_only_on_matching_tarpit_port_and_target(self):
        # pass,in on tarpit port + target -> knock
        good_knock = "21,,,trk,vtnet1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.77,10.66.66.10,12345,443,0,S,,"
        cfg = self._cfg_with_log([good_knock], action="tarpit", tarpit_ip="10.66.66.10", tarpit_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 1)
        row = c.execute("SELECT reasons FROM offenders").fetchone()
        self.assertIn("tarpit knock", row[0])

        # different target -> not knock
        bad_target = "21,,,trk,vtnet1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.77,10.0.0.1,12345,443,0,S,,"
        cfg = self._cfg_with_log([bad_target], action="tarpit", tarpit_ip="10.66.66.10", tarpit_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)

        # different port -> not knock (when ports specified)
        bad_port = "21,,,trk,vtnet1,match,pass,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.77,10.66.66.10,12345,80,0,S,,"
        cfg = self._cfg_with_log([bad_port], action="tarpit", tarpit_ip="10.66.66.10", tarpit_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)

    def test_protected_port_skips_probe(self):
        probe_line = "21,,,trk,vtnet1,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.88,1.2.3.4,54321,443,0,S,,"
        cfg = self._cfg_with_log([probe_line], protected_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)

    def test_v6_knock_with_protected_and_target(self):
        # v6 pass,in to tarpit target on protected port -> skipped
        v6_knock = "21,,,trk,vtnet1,match,pass,in,6,0x00,0x00000,64,tcp,6,60,2001:db8:bad::99,fd00:66::10,54321,443,40,S,,"
        cfg = self._cfg_with_log([v6_knock], action="tarpit", tarpit_ip="10.66.66.10", tarpit_ip6="fd00:66::10", tarpit_ports="443", protected_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 0)

        # v6 knock on matching target and port (not protected)
        good_v6 = "21,,,trk,vtnet1,match,pass,in,6,0x00,0x00000,64,tcp,6,60,2001:db8:bad::77,fd00:66::10,12345,443,40,S,,"
        cfg = self._cfg_with_log([good_v6], action="tarpit", tarpit_ip="10.66.66.10", tarpit_ip6="fd00:66::10", tarpit_ports="443")
        c = store.db(cfg)
        self.assertEqual(ingest.ingest_fwlog(cfg, c, 1000), 1)
        row = c.execute("SELECT reasons FROM offenders").fetchone()
        self.assertIn("tarpit knock", row[0])

    def test_enforce_routes_v6_to_block6_set(self):
        cfg = make_cfg()
        c = store.db(cfg)
        now = 3_000_000
        c.execute("INSERT INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
                  ("2001:db8:bad::9", 5, now, now, 500.0, now, 0, 2, "", 0))   # IPv6
        c.execute("INSERT INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
                  ("203.0.113.30", 5, now, now, 500.0, now, 0, 2, "", 0))       # IPv4
        active, drop_set, v6, mode = enforce.enforce(cfg, c, now)
        self.assertIn("2001:db8:bad::9", v6)
        self.assertNotIn("203.0.113.30", v6)
        self.assertEqual(set(active), {"2001:db8:bad::9", "203.0.113.30"})


class V6Routing(unittest.TestCase):
    """enforce() gives IPv6 the same tarpit/blackhole treatment as v4 once a v6
    tarpit target is set, and applies /64 aggregation to the pushed sets."""

    def _ins(self, c, ip, now, bh_until):
        c.execute("INSERT INTO offenders VALUES(?,?,?,?,?,?,?,?,?,?)",
                  (ip, 5, now, now, 500.0, now, 0, 5, "", bh_until))

    def test_v6_tarpit_and_blackhole_split(self):
        cfg = make_cfg(action="tarpit", tarpit_ip="10.66.66.10", tarpit_ip6="fd00:66::10",
                       post_max_action="blackhole", v6_aggregate=4, dry_run=True)
        self.assertTrue(cfg.blackhole_on)
        c = store.db(cfg)
        now = 4_000_000
        self._ins(c, "2001:db8:c::1", now, now + 3600)             # blackholed -> drop set
        self._ins(c, "2001:db8:c::2", now, 0)                      # normal -> tarpit set
        active, dropped, v6, mode = enforce.enforce(cfg, c, now)
        self.assertIn("2001:db8:c::1", dropped)                    # v6 blackhole now works (parity)
        self.assertNotIn("2001:db8:c::2", dropped)
        self.assertIn("2001:db8:c::2", v6)

    def test_v6_enforce_aggregates_to_64(self):
        cfg = make_cfg(action="tarpit", tarpit_ip="10.66.66.10", tarpit_ip6="fd00:66::10",
                       v6_aggregate=3, dry_run=True)
        c = store.db(cfg)
        now = 5_000_000
        for i in range(1, 4):
            self._ins(c, "2001:db8:d::%d" % i, now, 0)             # 3 distinct in one /64
        active, dropped, v6, mode = enforce.enforce(cfg, c, now)
        self.assertIn("2001:db8:d::/64", v6)                       # collapsed to the /64
        self.assertNotIn("2001:db8:d::1", v6)

    def test_block_only_when_no_v6_target(self):
        cfg = make_cfg(action="tarpit", tarpit_ip="10.66.66.10", v6_aggregate=4, dry_run=True)  # no tarpit_ip6
        c = store.db(cfg)
        now = 6_000_000
        self._ins(c, "2001:db8:e::1", now, now + 3600)             # bh set, but v6 tarpit is off
        active, dropped, v6, mode = enforce.enforce(cfg, c, now)
        self.assertIn("2001:db8:e::1", v6)                         # falls back to the block set
        self.assertNotIn("2001:db8:e::1", dropped)                 # not split into a drop set


if __name__ == "__main__":
    unittest.main(verbosity=2)
