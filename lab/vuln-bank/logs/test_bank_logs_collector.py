import base64
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from purple.collector import collector as waf_collector
from purple.collector.collector import EvidenceError

collector_path = Path(__file__).with_name("collector.py")
spec = importlib.util.spec_from_file_location("bank_logs_collector", collector_path)
bank_logs = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bank_logs)
Collector = bank_logs.Collector


class BankLogCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.app = root / "app.log"
        self.postgres = root / "postgresql.log"
        self.state = root / "state"
        self.sources = {"app": self.app, "postgres": self.postgres}

    def test_complete_lines_are_preserved_and_partial_lines_wait(self):
        raw = b"invalid utf-8: \xff\n"
        self.app.write_bytes(raw + b"unfinished")
        self.postgres.write_bytes(b"statement: SELECT 1\n")
        collector = Collector(self.state, self.sources)
        self.addCleanup(collector.close)

        collector.ingest()
        rows = collector.db.execute("SELECT payload FROM events ORDER BY rowid").fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(base64.b64decode(json.loads(rows[0][0])["raw_base64"]), raw)

        with self.app.open("ab") as stream:
            stream.write(b" complete\n")
        collector.ingest()
        rows = collector.db.execute("SELECT payload FROM events ORDER BY rowid").fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual(json.loads(rows[2][0])["message"], "unfinished complete")

    def test_shortened_source_is_reported_as_coverage_gap(self):
        self.app.write_bytes(b"original complete line\n")
        self.postgres.write_bytes(b"")
        collector = Collector(self.state, self.sources)
        self.addCleanup(collector.close)
        collector.ingest()
        self.app.write_bytes(b"short\n")

        with self.assertRaisesRegex(EvidenceError, "shrank"):
            collector.ingest()
        self.assertEqual(collector.pending(), 1)

    def test_legacy_mount_device_change_keeps_log_cursor(self):
        self.app.write_bytes(b"first line\n")
        self.postgres.write_bytes(b"")
        collector = Collector(self.state, self.sources)
        self.addCleanup(collector.close)
        collector.ingest()
        with collector.db:
            collector._save_state("app:identity", f"999:{os.stat(self.app).st_ino}")
        with self.app.open("ab") as stream:
            stream.write(b"second line\n")

        collector.ingest()

        self.assertEqual(collector.db.execute("SELECT count(*) FROM events").fetchone()[0], 2)
        self.assertEqual(int(collector._state("app:offset")), self.app.stat().st_size)
        self.assertTrue(collector._state("app:identity").startswith("v2:"))

    def test_checkpoint_detects_in_place_log_rewrite(self):
        self.app.write_bytes(b"first line\n")
        self.postgres.write_bytes(b"")
        collector = Collector(self.state, self.sources)
        self.addCleanup(collector.close)
        collector.ingest()
        self.app.write_bytes(b"other line\n")

        with self.assertRaisesRegex(EvidenceError, "replaced"):
            collector.ingest()
        self.assertEqual(collector.pending(), 1)

    def test_unacknowledged_batch_remains_queued_for_retry(self):
        class FakeHEC:
            attempts = 0

            def send(self, events):
                self.attempts += 1
                if self.attempts == 1:
                    raise EvidenceError("simulated HEC failure")
                self.events = events

        self.app.write_bytes(b"app observation\n")
        self.postgres.write_bytes(b"")
        fake = FakeHEC()
        collector = Collector(self.state, self.sources, fake)
        self.addCleanup(collector.close)
        collector.ingest()

        with self.assertRaises(EvidenceError):
            collector.upload()
        self.assertEqual(collector.pending(), 1)
        collector.upload()
        self.assertEqual(collector.pending(), 0)
        self.assertEqual(fake.events[0]["sourcetype"], "artex:vuln-bank:app")

    def test_bank_waf_scope_keeps_evidence_ids_separate(self):
        fixture = (Path(__file__).parents[2] / "purple" / "collector" / "fixtures"
                   / "apache-sqli-blocked.log").read_bytes()
        purple = waf_collector.normalize_native(fixture)
        with patch.object(waf_collector, "SCOPE", "artex-vuln-bank-modsecurity"):
            bank = waf_collector.normalize_native(fixture)
        self.assertEqual(bank["control_scope"], "artex-vuln-bank-modsecurity")
        self.assertNotEqual(bank["id"], purple["id"])


if __name__ == "__main__":
    unittest.main()
