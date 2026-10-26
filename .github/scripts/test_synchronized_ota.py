import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import yaml

HERE = Path(__file__).resolve().parent
os.environ.setdefault("GITHUB_WORKSPACE", str(HERE.parents[2]))
os.environ.setdefault("GITHUB_REPOSITORY", "Artemis311/ota")
import apatch_sync as ap
import prepare_stock_bbr as bbr

def coordinator():
    document = yaml.safe_load((HERE.parent / "workflows/blazer-v31.yaml").read_text())
    step = next(x for x in document["jobs"]["build"]["steps"] if x.get("id") == "build")
    text = step["run"].split("python3 - <<'PYTHON'\n", 1)[1].rsplit("\nPYTHON", 1)[0]
    scope = {"__name__": "coordinator_under_test"}
    exec(compile(text, "blazer-v31-inline.py", "exec"), scope)
    return scope

class PublicationTests(unittest.TestCase):
    def run_case(self, *, stage_error=False, publish_error=False, public_magisk=False, mismatch=False, test_only=False):
        scope = coordinator()
        events = []
        version = "2026102101"
        magisk = {"kind": "release", "tag": "test", "apk_sha256": "a" * 64, "url": "https://github.com/pixincreate/Magisk"}
        manifest = {"grapheneos": version, "magisk": magisk}
        release = {"id": 1, "draft": not public_magisk}
        partner = {"manifest": {"grapheneos": "2026102201" if mismatch else version},
                   "release": {"id": 2, "draft": True}}
        def stage(v, publish):
            self.assertEqual(v, version)
            events.append("stage-apatch")
            if stage_error:
                raise RuntimeError("APatch build failed")
            return partner
        def publish(part):
            events.append("publish-apatch")
            if publish_error:
                raise RuntimeError("APatch publication failed")
        def gh(*args, **kwargs):
            if args[:2] == ("release", "edit"):
                events.append("publish-magisk" if "--draft=false" in args else "rollback-magisk")
            elif args[:2] == ("release", "create"):
                events.append("draft-magisk")
            elif args[:2] == ("release", "upload"):
                events.append("upload-magisk")
            return b""
        releases = (lambda tag: release) if public_magisk else (lambda tag: release if "upload-magisk" in events else None)
        manifests = (lambda r, v: manifest) if public_magisk else (lambda r, v: manifest if "upload-magisk" in events else None)
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, {
                "OTA_VERSION": version, "PUBLISH": "false" if test_only else "true"}):
            overrides = {"resolve_magisk": lambda: ("test", magisk), "output": lambda *a: None,
                         "pages": lambda *a: [], "release_by_tag": releases,
                         "existing_manifest": manifests, "DIST": Path(folder),
                         "build": lambda *a: events.append("build-magisk") or manifest,
                         "gh": gh, "stage_apatch": stage, "publish_apatch": publish,
                         "rollback_apatch": lambda p: events.append("rollback-apatch"),
                         "prepare_feed": lambda p: events.append("sign-apatch") or Path(folder),
                         "sync_feed": lambda *a: events.append("feed")}
            with patch.dict(scope, overrides):
                try:
                    scope["main"]()
                except RuntimeError:
                    events.append("error")
        return events

    def test_partner_failure_keeps_both_private(self):
        events = self.run_case(stage_error=True)
        self.assertIn("upload-magisk", events)
        self.assertNotIn("publish-magisk", events)
        self.assertNotIn("publish-apatch", events)
        self.assertNotIn("feed", events)

    def test_both_ready_before_publication_and_feed(self):
        events = self.run_case()
        self.assertLess(events.index("stage-apatch"), events.index("sign-apatch"))
        self.assertLess(events.index("sign-apatch"), events.index("publish-magisk"))
        self.assertLess(events.index("publish-magisk"), events.index("publish-apatch"))
        self.assertLess(events.index("publish-apatch"), events.index("feed"))

    def test_failed_second_publication_rolls_back_only_new_releases(self):
        events = self.run_case(publish_error=True)
        self.assertIn("rollback-magisk", events)
        self.assertIn("rollback-apatch", events)
        self.assertNotIn("feed", events)
        events = self.run_case(publish_error=True, public_magisk=True)
        self.assertNotIn("rollback-magisk", events)

    def test_mismatched_os_never_publishes(self):
        events = self.run_case(mismatch=True)
        self.assertNotIn("publish-magisk", events)
        self.assertNotIn("publish-apatch", events)

    def test_existing_magisk_is_reused_but_partner_is_still_checked(self):
        events = self.run_case(public_magisk=True)
        self.assertNotIn("build-magisk", events)
        self.assertNotIn("publish-magisk", events)
        self.assertIn("stage-apatch", events)
        self.assertIn("publish-apatch", events)

    def test_manual_test_build_never_publishes(self):
        events = self.run_case(test_only=True)
        self.assertIn("stage-apatch", events)
        self.assertNotIn("publish-magisk", events)
        self.assertNotIn("publish-apatch", events)
        self.assertNotIn("feed", events)

class CompanionChecks(unittest.TestCase):
    def setUp(self):
        self.expected = {"schema": 1, "device": "blazer", "grapheneos": "2026102101", "fingerprint": "f"}
        self.name = "blazer-2026102101-apatch.zip"
        self.manifest = {**self.expected, "files": {self.name: {"sha256": "a" * 64, "size": 20}}}
        self.release = {"draft": True, "assets": [{"name": self.name, "state": "uploaded",
                         "digest": "sha256:" + "a" * 64, "size": 20}]}

    def test_no_extra_attachments(self):
        ap.validate_release(self.release, self.expected, self.manifest)
        self.release["assets"].append({"name": "manager.apk"})
        with self.assertRaises(RuntimeError):
            ap.validate_release(self.release, self.expected, self.manifest)

    def test_os_and_digest_are_bound(self):
        bad = copy.deepcopy(self.manifest)
        bad["grapheneos"] = "2026102201"
        with self.assertRaises(RuntimeError):
            ap.validate_release(self.release, self.expected, bad)
        self.release["assets"][0]["digest"] = "sha256:" + "b" * 64
        with self.assertRaises(RuntimeError):
            ap.validate_release(self.release, self.expected, self.manifest)

    def test_manifest_roundtrip_and_reject_malformed(self):
        body = ap.MARKER + json.dumps(self.manifest) + "\n-->"
        self.assertEqual(ap.manifest_from_body(body), self.manifest)
        self.assertIsNone(ap.manifest_from_body(ap.MARKER + "{bad}\n-->"))

    def test_fingerprint_changes_when_payload_inputs_change(self):
        resolved = {"version": "11282", "manager_sha256": "a" * 64}
        with patch.object(ap, "source_ids", return_value={"script": "a"}):
            first = ap.expectation("2026102101", resolved)
        with patch.object(ap, "source_ids", return_value={"script": "b"}):
            second = ap.expectation("2026102101", resolved)
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])

class WorkflowChecks(unittest.TestCase):
    def test_failed_pair_cannot_publish_actions_artifacts(self):
        document = yaml.safe_load((HERE.parent / "workflows/blazer-v31.yaml").read_text())
        artifact = next(step for step in document["jobs"]["build"]["steps"]
                        if step.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertIn("success()", artifact["if"])
        self.assertNotIn("always()", artifact["if"])

class DraftRecoveryChecks(unittest.TestCase):
    def test_matching_incomplete_draft_is_rebuilt_without_duplicate_release(self):
        expected = {"schema": 1, "device": "blazer", "grapheneos": "2026102201",
                    "apatch": "11282", "fingerprint": "f" * 64}
        manifest = {**expected, "files": {"blazer-2026102201-apatch.zip": {"sha256": "a" * 64, "size": 20}}}
        draft = {"id": 5, "draft": True, "assets": [], "body": ap.MARKER + json.dumps(manifest) + "\n-->",
                 "upload_url": "https://uploads.github.com/repos/Artemis311/ota/releases/5/assets{?name}"}
        complete = {**draft, "assets": [{"name": "blazer-2026102201-apatch.zip", "size": 20,
                    "state": "uploaded", "digest": "sha256:" + "a" * 64}]}
        calls = []
        def fake_api(method, endpoint, data=None):
            calls.append(method)
            return complete if method == "GET" else draft
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": ap.REPO, "GITHUB_TOKEN": "test", "GITHUB_SHA": "c" * 40}), \
             patch.object(ap, "resolve_apatch", return_value={"version": "11282"}), \
             patch.object(ap, "expectation", return_value=expected), \
             patch.object(ap, "legacy_partner", return_value=None), \
             patch.object(ap, "get_release", return_value=draft), \
             patch.object(ap, "build_apatch", return_value=(Path("/tmp/blazer-2026102201-apatch.zip"), manifest)), \
             patch.object(ap, "notes", return_value="updated"), \
             patch.object(ap, "api", side_effect=fake_api), \
             patch.object(ap.subprocess, "run"):
            result = ap.stage_apatch("2026102201", True)
        self.assertEqual(result["release"]["id"], 5)
        self.assertIn("PATCH", calls)
        self.assertNotIn("POST", calls)

    def test_incomplete_public_release_is_never_rebuilt(self):
        expected = {"grapheneos": "2026102201", "apatch": "11282", "fingerprint": "f"}
        bad = {"id": 5, "draft": False, "assets": [], "body": ap.MARKER + json.dumps(expected) + "\n-->"}
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": ap.REPO}), \
             patch.object(ap, "resolve_apatch", return_value={"version": "11282"}), \
             patch.object(ap, "expectation", return_value=expected), \
             patch.object(ap, "legacy_partner", return_value=None), \
             patch.object(ap, "get_release", return_value=bad), \
             patch.object(ap, "build_apatch") as build:
            with self.assertRaises(RuntimeError):
                ap.stage_apatch("2026102201", True)
            build.assert_not_called()

class KernelChecks(unittest.TestCase):
    def test_new_patchlevel_is_identified_from_real_banner(self):
        k, prefix = bbr.identify_kernel(b"\0Linux version 6.6.150-android15-8-gabcdef123456-4k (builder)\0")
        self.assertEqual(prefix, "abcdef123456")
        self.assertIn("150", k)

    def test_unreviewed_family_and_dirty_kernel_stop(self):
        for text in (b"Linux version 6.12.1-android16-1-gabcdef123456-4k ",
                     b"Linux version 6.6.150-android15-8-gabcdef123456-dirty ",
                     b"no version"):
            with self.assertRaises(RuntimeError):
                bbr.identify_kernel(text)

    def test_bbr1_and_fq_required_and_no_other_bbr_generation(self):
        settings = {"CONFIG_TCP_CONG_BBR": "y", "CONFIG_NET_SCH_FQ": "y"}
        bbr.validate_config(settings)
        for bad in ({}, {**settings, "CONFIG_TCP_CONG_BBR3": "y"}, {**settings, "CONFIG_NET_SCH_FQ": "m"}):
            with self.assertRaises(RuntimeError):
                bbr.validate_config(bad)

class FeedChecks(unittest.TestCase):
    def test_apatch_feed_preserves_other_channels_and_refuses_downgrade(self):
        from apatch_feed import write_feed
        with tempfile.TemporaryDirectory() as folder:
            repo = Path(folder) / "site"
            prepared = Path(folder) / "prepared"
            (repo / "pixincreate").mkdir(parents=True)
            prepared.mkdir()
            other = repo / "pixincreate/blazer.json"
            other.write_text("unchanged")
            record = {"grapheneos": "2026102101", "signature": "test.zip.csig"}
            (prepared / "manifest.json").write_text(json.dumps(record))
            (prepared / "blazer.json").write_text('{"version":2}')
            (prepared / "test.zip.csig").write_bytes(b"signed metadata")
            paths = write_feed(repo, prepared)
            self.assertEqual(other.read_text(), "unchanged")
            self.assertEqual(len(paths), 3)
            self.assertEqual((repo / "apatch/test.zip.csig").read_bytes(), b"signed metadata")
            record["grapheneos"] = "2026102001"
            (prepared / "manifest.json").write_text(json.dumps(record))
            with self.assertRaises(RuntimeError):
                write_feed(repo, prepared)

if __name__ == "__main__":
    unittest.main(verbosity=2)
