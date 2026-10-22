import configparser
import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch


SOURCE = Path(__file__).resolve().parents[1] / "bootstrap_splunk.py"
SPEC = importlib.util.spec_from_file_location("bootstrap_splunk", SOURCE)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class FakeSplunk:
    def __init__(self):
        self.calls = []
        self.resources = {}

    def request(self, method, path, form=None, limit=None):
        self.calls.append((method, path, form))
        if method == "GET":
            if path not in self.resources:
                raise lab.HTTPError(404)
            return self.resources[path]
        if method == "POST" and path.endswith("/acl"):
            self.resources[path[:-4]]["entry"][0]["acl"] = {
                "app": lab.APP, "owner": "admin", "sharing": "app",
                "perms": {"read": ["admin"], "write": ["admin"]},
            }
        elif method == "POST":
            values = json.loads(json.dumps(form or {}))
            resource = path + "/" + values.pop("name") if "name" in values else path
            if "/authorization/roles" in path:
                for key in ("srchIndexesAllowed", "srchIndexesDefault"):
                    values[key] = [values[key]]
                values["imported_roles"] = []
            self.resources[resource] = {"entry": [{"content": values}]}
        return {"entry": [{"content": {}}]}


class BootstrapTests(unittest.TestCase):
    def test_ag_collector_index_has_searchable_storage_paths(self):
        root = Path(__file__).resolve().parents[3]
        override = (root / "docker-compose.purple-lab-ag.yml").read_text()
        match = re.search(r"^\s*SPLUNK_INDEX:\s*([A-Za-z0-9_]+)\s*$", override, re.MULTILINE)
        self.assertIsNotNone(match)
        index = match.group(1)
        config = configparser.ConfigParser(interpolation=None)
        config.optionxform = str
        config.read(root / "lab/purple/splunk/default/indexes.conf")
        self.assertIn(index, config)
        for key, directory in (("homePath", "db"), ("coldPath", "colddb"), ("thawedPath", "thaweddb")):
            self.assertEqual(config[index][key], f"$SPLUNK_DB/{index}/{directory}")

    def test_private_files_are_restricted_and_symlinks_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            secret = Path(folder) / "secret"
            lab.private_write(secret, "opaque-demo-placeholder\n")
            self.assertEqual(secret.stat().st_mode & 0o777, 0o600)
            self.assertEqual(lab.private_read(secret), "opaque-demo-placeholder")
            secret.chmod(0o644)
            with self.assertRaises(lab.LabError):
                lab.private_read(secret)
            link = Path(folder) / "link"
            link.symlink_to(secret)
            with self.assertRaises(lab.LabError):
                lab.private_write(link, "replacement")

    def test_new_trust_requires_loopback_and_explicit_flag(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pin"
            with patch.object(lab, "peer_pin") as network:
                with self.assertRaises(lab.LabError):
                    lab.ensure_pin("https://127.0.0.1:8089", path)
                with self.assertRaises(lab.LabError):
                    lab.ensure_pin("https://example.com:8089", path, trust_new=True)
                network.assert_not_called()

    def test_existing_pin_never_rotates(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "pin"
            lab.private_write(path, "a" * 64 + "\n")
            with patch.object(lab, "peer_pin", return_value="b" * 64):
                with self.assertRaises(lab.LabError):
                    lab.ensure_pin("https://127.0.0.1:8089", path, trust_new=True)
            self.assertEqual(lab.private_read(path), "a" * 64)

    def test_restart_wait_retries_transport_only(self):
        with patch.object(lab, "ensure_pin", side_effect=[lab.LabConnectionError("pending"), "a" * 64]), patch.object(lab.time, "sleep"):
            self.assertEqual(lab.readiness("https://127.0.0.1:8089", Path("unused"), False, lab.time.monotonic() + 10), "a" * 64)
        with patch.object(lab, "ensure_pin", side_effect=lab.LabError("changed pin")), patch.object(lab.time, "sleep") as waiting:
            with self.assertRaises(lab.LabError):
                lab.readiness("https://127.0.0.1:8089", Path("unused"), True, lab.time.monotonic() + 10)
            waiting.assert_not_called()

    def test_auth_is_never_sent_before_pin_validation(self):
        class FakeSocket:
            def getpeercert(self, binary_form):
                return b"server certificate"

        class FakeConnection:
            sock = FakeSocket()
            sent = False

            def connect(self):
                pass

            def request(self, *args, **kwargs):
                self.sent = True

            def close(self):
                pass

        connection = FakeConnection()
        with patch.object(lab.http.client, "HTTPSConnection", return_value=connection), patch.object(lab, "valid_certificate"):
            client = lab.Client("https://127.0.0.1:8089", "0" * 64, "admin", "private-placeholder")
            with self.assertRaises(lab.LabError):
                client.request("GET", "/services/server/info")
        self.assertFalse(connection.sent)

    def test_setup_only_creates_scoped_reader_and_audit_ingestion(self):
        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            lab.private_write(state / "splunk-search-password", "local-search-placeholder-0000")
            lab.private_write(state / "hec-token", "12345678-1234-4234-8234-123456789abc")
            lab.private_write(state / "splunk-management.sha256", "a" * 64)
            client = FakeSplunk()
            lab.configure(client, state, connector_url="https://purple-lab-splunk:8089")
            role = next(form for method, path, form in client.calls if method == "POST" and path == "/services/authorization/roles")
            self.assertEqual(role["srchIndexesAllowed"], "artex_lab")
            self.assertEqual(role["imported_roles"], "")
            self.assertEqual(set(role["capabilities"]), {"search", "rest_access_server_endpoints"})
            self.assertNotIn("schedule_search", role["capabilities"])
            hec = next(form for method, path, form in client.calls if method == "POST" and path == "/services/data/inputs/http")
            self.assertEqual(hec["indexes"], "artex_lab")
            self.assertEqual(hec["sourcetype"], "artex:lab:audit")
            template = json.loads((state / "connector-template.json").read_text())
            self.assertNotIn("password", template)
            self.assertNotIn("token", template)

    def test_real_scheduled_alert_preserves_audit_time_and_correlation(self):
        values = lab.saved_search_values()
        self.assertEqual(values["actions"], "logevent")
        self.assertEqual(values["alert.digest_mode"], "0")
        self.assertEqual(values["action.logevent.param.sourcetype"], "artex:lab:alert")
        self.assertEqual(values["action.logevent.param.event"], "$result.alert_payload$")
        self.assertIn('"event_epoch",tonumber(_time)', values["search"])
        self.assertIn('"alert_created_at",strftime(now()', values["search"])
        self.assertIn('"artex_verification_id",artex_verification_id', values["search"])
        self.assertNotIn("isnotnull(artex_verification_id)", values["search"])
        self.assertIn('artex_verification_id=coalesce(artex_verification_id,"")', values["search"])
        self.assertNotIn("| collect", values["search"])
        self.assertIn("| fields _raw _time | spath |", values["search"])
        self.assertIn('"rule_id",tostring(rule_id)', values["search"])
        self.assertIn('"rule_ids",mv_to_json_array(\'rule_ids{}\',false())', values["search"])

    def test_existing_hec_is_not_rotated_and_disabled_cutoff_is_preserved(self):
        token = "12345678-1234-4234-8234-123456789abc"

        class ExistingSplunk(FakeSplunk):
            def request(self, method, path, form=None, limit=None):
                if method == "GET" and path.endswith("/http/artex_lab_audit"):
                    self.calls.append((method, path, form))
                    return {"entry": [{"content": {"token": token.upper()}}]}
                if method == "GET" and path.endswith("/saved/searches/" + lab.SAVED_SEARCH):
                    self.calls.append((method, path, form))
                    return {"entry": [{"content": {"disabled": True, "search": lab.saved_search_values(1800000000)["search"]},
                        "acl": {"app": lab.APP, "owner": "admin", "sharing": "app",
                                "perms": {"read": ["admin"], "write": ["admin"]}}}]}
                return super().request(method, path, form, limit)

        with tempfile.TemporaryDirectory() as folder:
            state = Path(folder)
            lab.private_write(state / "splunk-search-password", "local-search-placeholder-0000")
            lab.private_write(state / "hec-token", token)
            lab.private_write(state / "splunk-management.sha256", "a" * 64)
            client = ExistingSplunk()
            lab.configure(client, state, connector_url="https://purple-lab-splunk:8089")
            update = next(form for method, path, form in client.calls if method == "POST" and path.endswith("/http/artex_lab_audit"))
            self.assertNotIn("token", update)
            self.assertEqual(lab.private_read(state / "hec-token"), token)
            saved = next(form for method, path, form in client.calls if method == "POST" and path.endswith("/saved/searches/" + lab.SAVED_SEARCH))
            self.assertEqual(saved["disabled"], "true")
            self.assertIn("| where _time >= 1800000000.000000 |", saved["search"])

    def test_reader_role_creation_defaults_are_removed_and_verified(self):
        class DefaultsSplunk(FakeSplunk):
            def request(self, method, path, form=None, limit=None):
                result = super().request(method, path, form, limit)
                if method == "POST" and path == "/services/authorization/roles":
                    self.resources[path + "/" + lab.SEARCH_ROLE]["entry"][0]["content"]["capabilities"] += ["run_collect"]
                return result

        client = DefaultsSplunk()
        lab.configure_reader_role(client)
        role = lab.content(client.request("GET", "/services/authorization/roles/" + lab.SEARCH_ROLE))
        self.assertEqual(set(role["capabilities"]), {"search", "rest_access_server_endpoints"})
        self.assertTrue(any(method == "POST" and path.endswith("/roles/" + lab.SEARCH_ROLE) for method, path, _ in client.calls))
        class UnrestrictedSplunk(DefaultsSplunk):
            def request(self, method, path, form=None, limit=None):
                result = super().request(method, path, form, limit)
                if method == "GET" and path.endswith("/roles/" + lab.SEARCH_ROLE):
                    result["entry"][0]["content"]["srchIndexesAllowed"] = ["*"]
                return result
        with self.assertRaises(lab.LabError):
            lab.configure_reader_role(UnrestrictedSplunk())

    def test_saved_search_matching_acl_skips_post_and_conflict_requires_verification(self):
        resource = "/servicesNS/nobody/artex_lab/saved/searches/" + lab.SAVED_SEARCH
        valid = {"entry": [{"acl": {"app": lab.APP, "owner": "admin", "sharing": "app",
            "perms": {"read": ["admin"], "write": ["admin"]}}}]}
        client = FakeSplunk()
        client.resources[resource] = valid
        lab.ensure_saved_search_acl(client, resource)
        self.assertFalse(any(method == "POST" for method, _, _ in client.calls))
        class ConflictSplunk(FakeSplunk):
            def __init__(self, resolves):
                super().__init__(); self.resolves = resolves
                self.resources[resource] = {"entry": [{"acl": {"sharing": "user"}}]}
            def request(self, method, path, form=None, limit=None):
                if method == "POST":
                    if self.resolves:
                        self.resources[resource] = valid
                    raise lab.HTTPError(409)
                return super().request(method, path, form, limit)
        lab.ensure_saved_search_acl(ConflictSplunk(True), resource)
        with self.assertRaises(lab.HTTPError):
            lab.ensure_saved_search_acl(ConflictSplunk(False), resource)

    def test_only_legacy_private_copy_of_correct_app_rule_is_removed(self):
        resource = "/servicesNS/nobody/artex_lab/saved/searches/" + lab.SAVED_SEARCH
        personal = resource.replace("/nobody/", "/admin/")
        client = FakeSplunk()
        client.resources[resource] = {"entry": [{"acl": {"app": lab.APP, "owner": "admin", "sharing": "app",
            "perms": {"read": ["admin"], "write": ["admin"]}}}]}
        client.resources[personal] = {"entry": [{"acl": {"app": lab.APP, "owner": "admin", "sharing": "user"}}]}
        lab.remove_legacy_personal_copy(client, resource)
        self.assertIn(("DELETE", personal, None), client.calls)
        client.calls.clear()
        client.resources[personal] = client.resources[resource]
        lab.remove_legacy_personal_copy(client, resource)
        self.assertFalse(any(method == "DELETE" for method, _, _ in client.calls))

    def test_reenable_cutoff_excludes_the_off_period(self):
        values = lab.saved_search_values(1900000000.123456)
        self.assertIn("| where _time >= 1900000000.123456 |", values["search"])
        self.assertNotIn("ARTEX_ENABLED_SINCE", values["search"])

    def test_repeated_on_preserves_pending_events_and_reenable_excludes_off_events(self):
        resource = "/servicesNS/nobody/artex_lab/saved/searches/" + lab.SAVED_SEARCH
        for disabled, expected_cutoff in ((False, 100.25), (True, 200.5)):
            with self.subTest(disabled=disabled), tempfile.TemporaryDirectory() as folder:
                client = FakeSplunk()
                client.resources[resource] = {"entry": [{"content": {
                    "disabled": disabled, "search": lab.saved_search_values(100.25)["search"],
                }}]}
                with patch.object(lab.time, "time", return_value=200.5):
                    lab.set_detection(client, Path(folder), "on")
                update = next(form for method, path, form in client.calls if method == "POST" and path == resource)
                self.assertIn(f"| where _time >= {expected_cutoff:.6f} |", update["search"])
                # An event awaiting the next cron must survive repeated on;
                # the same timestamp from a disabled interval must stay excluded.
                self.assertEqual(150.0 >= expected_cutoff, not disabled)
                self.assertTrue(201.0 >= expected_cutoff)
                state = json.loads((Path(folder) / "detection-state.json").read_text())
                self.assertEqual(state["enabled_since"], expected_cutoff)
                self.assertTrue(state["enabled"])

    def test_on_never_shrinks_unknown_active_window_and_off_retains_search(self):
        resource = "/servicesNS/nobody/artex_lab/saved/searches/" + lab.SAVED_SEARCH
        client = FakeSplunk()
        client.resources[resource] = {"entry": [{"content": {"disabled": False, "search": "unexpected query"}}]}
        with tempfile.TemporaryDirectory() as folder:
            with self.assertRaises(lab.LabError):
                lab.set_detection(client, Path(folder), "on")
            self.assertFalse(any(method == "POST" for method, _, _ in client.calls))
            lab.set_detection(client, Path(folder), "off")
            update = next(form for method, path, form in client.calls if method == "POST" and path == resource)
            self.assertEqual(update, {"disabled": "1"})

    def test_incomplete_export_warns_and_never_accepts_error_or_preview(self):
        client = lab.Client("https://127.0.0.1:8089", "0" * 64, "reader", "placeholder")
        with patch.object(client, "raw", return_value=b'{"messages":[{"type":"WARN","text":"untrusted"}]}\n{"result":{"id":"one"}}\n'):
            results, warnings = client.export("search index=artex_lab", "-5m", "now")
            self.assertEqual(len(results), 1)
            self.assertEqual(len(warnings), 1)
            self.assertNotIn("untrusted", warnings[0])
        for row in (b'{"preview":true,"result":{"id":"one"}}', b'{"messages":[{"type":"ERROR"}]}'):
            with patch.object(client, "raw", return_value=row):
                with self.assertRaises(lab.LabError):
                    client.export("search index=artex_lab", "-5m", "now")


if __name__ == "__main__":
    unittest.main()
