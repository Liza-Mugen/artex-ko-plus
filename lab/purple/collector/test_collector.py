import hashlib
import http.server
import json
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from collector import Collector, EvidenceError, PinnedHEC, native_frames, normalize_native


VERIFICATION = "36e1c3df-0f65-47cd-a8dc-966b66a05b67"


def audit(mode="ENABLED", status=403, intercepted=True, rule="1001001", headers=None):
    headers = headers or f"X-ARTEX-Verification-ID: {VERIFICATION}"
    message = (f'Message: Warning. Pattern match [file "/etc/modsecurity.d/lab.conf"] '
               f'[line "8"] [id "{rule}"] [msg "ARTEX lab FTP disclosure policy"]\n') if rule else ""
    return ("--abc123-A--\n"
            "[10/Oct/2026:01:02:03 +0000] request-unique-id 172.18.0.1 50000 172.18.0.2 8080\n"
            "--abc123-B--\nGET /ftp/acquisitions.md?unused=1 HTTP/1.1\n"
            f"Host: purple-lab-target:8080\n{headers}\n"
            f"--abc123-F--\nHTTP/1.1 {status} Response\nContent-Type: text/plain\n"
            "--abc123-H--\n" + message +
            ("Action: Intercepted (phase 1)\n" if intercepted else "") +
            (f'Engine-Mode: "{mode}"\n' if mode else "") +
            "--abc123-Z--\n").encode()


class NativeTests(unittest.TestCase):
    def test_current_official_apache_native_sample(self):
        # Captured from the separate local lab, with synthetic correlation/UID.
        raw = (Path(__file__).parent / "fixtures/apache-detection-only.log").read_bytes()
        event = normalize_native(raw)
        self.assertEqual(event["timestamp"], "2026-10-10T04:46:52.987228Z")
        self.assertEqual(event["audit_header_timestamp"], "2026-10-10T04:46:52.992194Z")
        self.assertEqual(event["timestamp_basis"], "modsecurity_stopwatch_transaction_start")
        self.assertEqual(event["action"], "allowed")
        self.assertIn("1001001", event["rule_ids"])
        self.assertEqual(event["request_host"], "127.0.0.1:18790")
        self.assertEqual(event["target"], "purple-lab-target:8080")

    def test_inconsistent_stopwatch_is_not_silently_trusted(self):
        raw = audit().replace(b'--abc123-H--\n', b'--abc123-H--\nStopwatch: 1 2000 (- - -)\n')
        with self.assertRaises(EvidenceError):
            normalize_native(raw)

    def test_current_apache_ftp_phase1_interception_sample(self):
        event = normalize_native((Path(__file__).parent / "fixtures/apache-ftp-blocked.log").read_bytes())
        self.assertEqual(event["action"], "blocked")
        self.assertEqual(event["action_basis"], "Action: Intercepted (phase 1)")
        self.assertEqual(event["rule_ids"], ["1001001"])
        self.assertEqual(event["engine_mode"], "ENABLED")

    def test_current_apache_sqli_phase2_interception_sample(self):
        event = normalize_native((Path(__file__).parent / "fixtures/apache-sqli-blocked.log").read_bytes())
        self.assertEqual(event["action"], "blocked")
        self.assertEqual(event["action_basis"], "Action: Intercepted (phase 2)")
        self.assertIn("942100", event["rule_ids"])
        self.assertIn("949110", event["rule_ids"])

    def test_conflicting_stopwatch_values_are_rejected(self):
        raw = audit().replace(b'--abc123-H--\n', b'--abc123-H--\nStopwatch: 1 2000 (- - -)\nStopwatch2: 2 2000; p1=100\n')
        with self.assertRaises(EvidenceError):
            normalize_native(raw)

    def test_real_interception_is_blocked(self):
        event = normalize_native(audit())
        self.assertEqual(event["action"], "blocked")
        self.assertEqual(event["action_reason"], "modsecurity_intercepted_transaction")
        self.assertEqual(event["rule_ids"], ["1001001"])
        self.assertEqual(event["artex_verification_id"], VERIFICATION)
        self.assertEqual(event["timestamp"], "2026-10-10T01:02:03Z")
        self.assertEqual(event["path"], "/ftp/acquisitions.md")
        self.assertNotIn("response_complete", event)

    def test_detection_only_match_is_allowed_policy(self):
        event = normalize_native(audit(mode="DETECTION_ONLY", status=200, intercepted=False))
        self.assertEqual(event["action"], "allowed")
        self.assertTrue(event["matched_rules"])

    def test_preserves_native_query_without_inventing_rule_match(self):
        raw = audit(rule=None).replace(b'/ftp/acquisitions.md?unused=1', b'/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
        event = normalize_native(raw)
        self.assertEqual(event['path'], '/rest/products/search')
        self.assertEqual(event['query_string'], 'q=%3Cscript%3Ealert(1)%3C%2Fscript%3E')
        self.assertEqual(event['request_target'], '/rest/products/search?' + event['query_string'])
        self.assertFalse(event['matched_rules'])

    def test_native_uri_limits_are_explicit(self):
        raw = audit(rule=None).replace(b'/ftp/acquisitions.md?unused=1', b'/search?q=' + b'a' * 4200)
        event = normalize_native(raw)
        self.assertEqual(len(event['request_target']), 4096)
        self.assertEqual(len(event['query_string']), 4096)
        self.assertTrue(event['request_target_truncated'])
        self.assertTrue(event['query_string_truncated'])

    def test_backend_403_is_not_waf_block(self):
        event = normalize_native(audit(status=403, intercepted=False, rule=None))
        self.assertEqual(event["action"], "allowed")
        self.assertFalse(event["matched_rules"])

    def test_mode_missing_and_disabled_are_unknown(self):
        for mode in (None, "DISABLED"):
            with self.subTest(mode=mode):
                self.assertEqual(normalize_native(audit(mode=mode))["action"], "unknown")

    def test_detection_only_interception_is_inconsistent(self):
        self.assertEqual(normalize_native(audit(mode="DETECTION_ONLY"))["action"], "unknown")

    def test_uuid_duplicate_or_invalid_is_not_correlated(self):
        for headers in ("X-ARTEX-Verification-ID: invalid",
                        f"X-ARTEX-Verification-ID: {VERIFICATION}\nX-ARTEX-Verification-ID: {VERIFICATION}"):
            with self.subTest(headers=headers):
                event = normalize_native(audit(headers=headers))
                self.assertEqual(event["correlation_status"], "invalid")
                self.assertNotIn("artex_verification_id", event)

    def test_rule_meta_is_not_taken_from_escaped_user_text(self):
        value = audit(rule=None).replace(b'--abc123-H--\n', b'--abc123-H--\nMessage: matched value "[file \\"fake\\"] [line \\"8\\"] [id \\"1001001\\"]"\n')
        self.assertEqual(normalize_native(value)["rule_ids"], [])

    def test_id_is_stable_from_raw_digest(self):
        self.assertEqual(normalize_native(audit())["id"], normalize_native(audit())["id"])
        self.assertNotEqual(normalize_native(audit())["id"], normalize_native(audit(status=200))["id"])
        digest = hashlib.sha256(audit()).hexdigest()
        self.assertEqual(normalize_native(audit())["id"],
                         str(uuid5(NAMESPACE_URL, "artex-purple-lab-native:" + digest)))

    def test_frames_wait_for_complete_final_line(self):
        raw = audit()
        self.assertEqual(list(native_frames(raw[:-1])), [])
        self.assertEqual(list(native_frames(raw + b"\n")), [(raw, len(raw))])

    def test_frames_handle_multiple_transactions(self):
        first, second = audit(), audit(status=200, intercepted=False)
        self.assertEqual([end for _raw, end in native_frames(first + b"\n" + second)], [len(first), len(first) + 1 + len(second)])

    def test_frames_reject_skipped_incomplete_record(self):
        with self.assertRaises(EvidenceError):
            list(native_frames(audit().split(b"--abc123-Z--")[0] + audit()))

    def test_header_and_raw_credentials_are_not_exported(self):
        event = normalize_native(audit(headers=f"X-ARTEX-Verification-ID: {VERIFICATION}\nAuthorization: test-synthetic-secret\nCookie: synthetic-cookie"))
        encoded = json.dumps(event)
        self.assertNotIn("test-synthetic-secret", encoded)
        self.assertNotIn("synthetic-cookie", encoded)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.source = self.directory / "modsec_audit.log"
        self.source.write_bytes(audit())
        self.collector = Collector(self.directory, self.source, "purple-lab-target:8080")

    def tearDown(self):
        self.collector.db.close()
        self.temporary.cleanup()

    def test_tail_and_restart_do_not_duplicate_local_audit(self):
        self.collector.ingest()
        self.collector.export()
        self.collector.ingest()
        self.collector.export()
        self.collector.db.close()
        self.collector = Collector(self.directory, self.source, "purple-lab-target:8080")
        self.collector.ingest()
        self.collector.export()
        self.assertEqual(len((self.directory / "audit.jsonl").read_text().splitlines()), 1)

    def test_legacy_mount_device_change_keeps_the_same_source_cursor(self):
        self.collector.ingest()
        with self.collector.db:
            self.collector._save_state("source_identity", f"999:{os.stat(self.source).st_ino}")
        with self.source.open("ab") as stream:
            stream.write(b"\n" + audit(status=200))

        self.collector.ingest()

        self.assertEqual(self.collector.db.execute("SELECT count(*) FROM events").fetchone()[0], 2)
        self.assertEqual(int(self.collector._state("offset")), self.source.stat().st_size)
        self.assertTrue(self.collector._state("source_identity").startswith("v2:"))

    def test_checkpoint_detects_in_place_source_rewrite(self):
        self.collector.ingest()
        self.source.write_bytes(audit(status=200))

        with self.assertRaisesRegex(EvidenceError, "rotated"):
            self.collector.ingest()
        self.assertEqual(self.collector.db.execute("SELECT count(*) FROM events").fetchone()[0], 1)

    def test_outbox_retries_while_preserving_local_record(self):
        class FakeHEC:
            def send(self, events):
                raise OSError("synthetic outage")
        self.collector.hec = FakeHEC()
        self.collector.ingest()
        self.collector.export()
        with self.assertRaises(OSError):
            self.collector.upload()
        self.assertEqual(self.collector.status()["pending_count"], 1)
        self.assertEqual(len((self.directory / "audit.jsonl").read_text().splitlines()), 1)
        self.collector.hec.send = lambda events: None
        self.collector.upload()
        self.assertEqual(self.collector.status()["pending_count"], 0)

    def test_partial_record_does_not_advance_cursor(self):
        self.source.write_bytes(audit()[:-1])
        self.collector.ingest()
        self.assertEqual(self.collector._state("offset", "0"), "0")
        self.source.write_bytes(audit())
        self.collector.ingest()
        self.assertEqual(self.collector._state("offset"), str(len(audit())))

    def test_truncation_is_not_silently_skipped(self):
        self.collector.ingest()
        self.source.write_bytes(b"")
        with self.assertRaises(EvidenceError):
            self.collector.ingest()

    def test_export_crash_after_append_does_not_duplicate_after_restart(self):
        self.collector.ingest()
        self.collector.export()
        self.collector.db.execute("UPDATE events SET exported=0")
        self.collector.db.commit()
        self.collector.db.close()
        self.collector = Collector(self.directory, self.source, "purple-lab-target:8080")
        self.collector.export()
        self.assertEqual(len((self.directory / "audit.jsonl").read_text().splitlines()), 1)


@unittest.skipUnless(shutil.which("openssl"), "TLS integration needs openssl")
class PinTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        cert, key = self.directory / "server.pem", self.directory / "server.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=synthetic-lab"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = ssl.PEM_cert_to_DER_cert(cert.read_text())
        self.pin = self.directory / "pin"
        self.pin.write_text(hashlib.sha256(der).hexdigest())
        self.token = self.directory / "token"
        self.token.write_text("synthetic-hec-unit-test-token")
        received = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.headers.get("Authorization"), self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()
                self.wfile.write(getattr(self.server, "response_body", b'{"code":0}'))

            def log_message(self, _format, *_args):
                pass
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        self.context = context
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.received = received
        self.sender = PinnedHEC(f"https://127.0.0.1:{self.server.server_port}/services/collector/event", self.token, self.pin)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temporary.cleanup()

    def test_valid_pin_sends_audit_sourcetype_only(self):
        self.sender.send([normalize_native(audit())])
        self.assertEqual(len(self.received), 1)
        self.assertEqual(self.received[0][0], "Splunk synthetic-hec-unit-test-token")
        payload = json.loads(self.received[0][1])
        self.assertEqual(payload["sourcetype"], "artex:lab:audit")
        self.assertEqual(payload["event"]["event_kind"], "audit")
        self.assertEqual(payload["source"], "modsecurity-native-audit")
        self.assertEqual(payload["source"], payload["event"]["source"])

    def test_wrong_pin_sends_no_token_and_no_http_request(self):
        self.pin.write_text("0" * 64)
        with self.assertRaises(EvidenceError):
            self.sender.send([normalize_native(audit())])
        self.assertEqual(self.received, [])

    def test_malformed_hec_success_is_not_acknowledged(self):
        for body in (b'[]', b'{"code":false}', b'{"code":6}'):
            with self.subTest(body=body):
                self.server.response_body = body
                with self.assertRaises(EvidenceError):
                    self.sender.send([normalize_native(audit())])

    def test_plain_http_is_rejected(self):
        with self.assertRaises(ValueError):
            PinnedHEC("http://127.0.0.1:8088/services/collector/event", self.token, self.pin)

    def test_matching_but_expired_pin_sends_no_token(self):
        request, expired = self.directory / "request.csr", self.directory / "expired.pem"
        (self.directory / "index").write_text("")
        (self.directory / "serial").write_text("1000\n")
        config = self.directory / "ca.cnf"
        config.write_text(
            "[ca]\ndefault_ca=test_ca\n[test_ca]\n" +
            f"database={self.directory}/index\nserial={self.directory}/serial\n" +
            f"new_certs_dir={self.directory}\nprivate_key={self.directory}/server.key\n" +
            f"certificate={self.directory}/server.pem\ndefault_md=sha256\n" +
            "policy=policy\n[policy]\ncommonName=supplied\n")
        subprocess.run(["openssl", "req", "-new", "-key", str(self.directory / "server.key"),
                        "-out", str(request), "-subj", "/CN=synthetic-expired-lab"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["openssl", "ca", "-selfsign", "-batch", "-config", str(config),
                        "-in", str(request), "-out", str(expired), "-startdate", "20200101000000Z",
                        "-enddate", "20210101000000Z"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # openssl ca includes a human-readable prefix; canonicalize the PEM.
        subprocess.run(["openssl", "x509", "-in", str(expired), "-out", str(expired)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.context.load_cert_chain(expired, self.directory / "server.key")
        self.pin.write_text(hashlib.sha256(ssl.PEM_cert_to_DER_cert(expired.read_text())).hexdigest())
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.sender.send([normalize_native(audit())])
        self.assertEqual(self.received, [])


if __name__ == "__main__":
    unittest.main()
