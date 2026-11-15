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
                         "release_tag": lambda *a: "blazer-test",
                         "attach_sidecars": lambda manifest, *a: manifest,
                         "store_manifest": lambda *a: None,
                         "unify": lambda release, manifest, partner: {**partner, "release": release},
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

    def test_release_editor_line_endings_preserve_manifest(self):
        body = ap.MARKER + json.dumps(self.manifest) + "\n-->"
        for ending in ("\n", "\r\n", "\r"):
            self.assertEqual(ap.manifest_from_body(body.replace("\n", ending)), self.manifest)

    def test_unterminated_manifest_is_rejected(self):
        self.assertIsNone(ap.manifest_from_body(ap.MARKER + json.dumps(self.manifest)))

    def test_fingerprint_changes_when_payload_inputs_change(self):
        resolved = {"version": "11282", "manager_sha256": "a" * 64}
        with patch.object(ap, "source_ids", return_value={"script": "a"}):
            first = ap.expectation("2026102101", resolved)
        with patch.object(ap, "source_ids", return_value={"script": "b"}):
            second = ap.expectation("2026102101", resolved)
        self.assertNotEqual(first["fingerprint"], second["fingerprint"])

class UnifiedReleaseChecks(unittest.TestCase):
    def setUp(self):
        import unified_release as unified
        self.unified = unified
        self.version = "2026111301"
        self.tag = "blazer-test"
        self.apatch = {"schema": 1, "device": "blazer", "grapheneos": self.version,
                       "apatch": "11282", "fingerprint": "f" * 64}
        self.ap_name = f"blazer-{self.version}-apatch.zip"
        self.apatch["files"] = {self.ap_name: {"size": 20, "sha256": "a" * 64}}
        self.manifest = {"grapheneos": self.version,
            "flavors": {"pixincreate": f"blazer-{self.version}-pixincreate-v31.1.zip",
                        "rootless": f"blazer-{self.version}-rootless.zip"}}
        self.manifest["files"] = {n: {"size": 30, "sha256": "b" * 64}
                                  for n in self.manifest["flavors"].values()}
        self.assets = [{"name": n, "state": "uploaded", "size": m["size"],
                        "digest": "sha256:" + m["sha256"], "id": i}
                       for i, (n, m) in enumerate({**self.manifest["files"], **self.apatch["files"]}.items())]
        self.release = {"id": 123, "tag_name": self.tag, "draft": False,
                        "html_url": "https://github.com/Artemis311/ota/releases/tag/" + self.tag,
                        "assets": self.assets,
                        "body": unified.MARKER + json.dumps(self.manifest) + "\n-->\n"
                                + ap.MARKER + json.dumps(self.apatch) + "\n-->"}
        self.expected = {k: v for k, v in self.apatch.items() if k != "files"}

    def test_combined_release_checks_all_three_zip_digests(self):
        ap.validate_release(self.release, self.expected, self.apatch)
        for mutate in ("extra", "missing", "digest"):
            bad = copy.deepcopy(self.release)
            if mutate == "extra":
                bad["assets"].append({"name": "unrelated.apk"})
            elif mutate == "missing":
                bad["assets"].pop(0)
            else:
                bad["assets"][0]["digest"] = "sha256:" + "c" * 64
            with self.assertRaises(RuntimeError):
                ap.validate_release(bad, self.expected, self.apatch)

    def test_sidecar_data_is_bound_to_original_size_and_hash(self):
        import base64, hashlib
        data = b"signed Custota metadata"
        manifest = {"files": {"test.csig": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}},
                    "sidecars": {"test.csig": base64.b64encode(data).decode()}}
        self.assertEqual(self.unified.checked_sidecar(manifest, "test.csig"), data)
        manifest["sidecars"]["test.csig"] = base64.b64encode(b"changed").decode()
        with self.assertRaises(RuntimeError):
            self.unified.checked_sidecar(manifest, "test.csig")

    def test_combined_manifest_accepts_github_editor_line_endings(self):
        body = self.unified.MARKER + json.dumps(self.manifest) + "\n-->"
        self.assertEqual(self.unified.manifest_body(body.replace("\n", "\r\n")), self.manifest)

    def test_apatch_update_on_same_os_gets_a_new_release_tag(self):
        with patch.object(self.unified, "get_release", return_value=self.release), \
             patch.object(ap, "resolve_apatch", return_value={}), \
             patch.object(ap, "expectation", return_value=self.expected):
            original = self.unified.release_tag(self.version, "a" * 64)
        with patch.object(self.unified, "get_release", return_value=self.release), \
             patch.object(ap, "resolve_apatch", return_value={}), \
             patch.object(ap, "expectation", return_value={**self.expected, "fingerprint": "e" * 64}):
            updated = self.unified.release_tag(self.version, "a" * 64)
        self.assertNotEqual(original, updated)
        self.assertTrue(updated.endswith("-apatch-" + "e" * 12))

    def test_cleanup_waits_for_all_feeds_and_preserves_zip_assets(self):
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder)
            for flavor in ("apatch", "pixincreate", "rootless"):
                (site / flavor).mkdir()
                (site / flavor / "blazer.json").write_text(json.dumps({"full": {
                    "location_ota": f"https://github.com/{ap.REPO}/releases/download/{self.tag}/test.zip"}}))
            (site / "apatch/manifest.json").write_text(json.dumps({"release_id": 123}))
            initial = copy.deepcopy(self.release)
            initial["assets"].append({"name": "ota.crt", "id": 999})
            with patch.object(self.unified, "api", side_effect=[initial, None, self.release]) as api, \
                 patch.object(self.unified, "verify_live_sidecars"):
                self.unified.cleanup(site)
            self.assertEqual(api.call_args_list[1].args, ("DELETE", f"repos/{ap.REPO}/releases/assets/999"))
            (site / "rootless/blazer.json").write_text(json.dumps({"full": {"location_ota": "old-release"}}))
            with patch.object(self.unified, "api", return_value=initial) as api:
                with self.assertRaisesRegex(RuntimeError, "Feed still points"):
                    self.unified.cleanup(site)
                self.assertEqual(api.call_count, 1)

    def test_live_signature_mismatch_is_rejected(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as folder:
            site = Path(folder)
            for flavor in ("apatch", "pixincreate", "rootless"):
                (site / flavor).mkdir()
                (site / flavor / "signature.csig").write_bytes(b"verified")
                (site / flavor / "blazer.json").write_text(json.dumps({"full": {
                    "location_csig": f"https://artemis311.github.io/ota/{flavor}/signature.csig"}}))
            with patch.object(self.unified.subprocess, "run", return_value=SimpleNamespace(stdout=b"verified")):
                self.unified.verify_live_sidecars(site)
            with patch.object(self.unified.subprocess, "run", return_value=SimpleNamespace(stdout=b"wrong")):
                with self.assertRaisesRegex(RuntimeError, "Live Custota signature differs"):
                    self.unified.verify_live_sidecars(site)


class WorkflowChecks(unittest.TestCase):
    def test_pages_artifact_is_unique_for_each_retry(self):
        document = yaml.safe_load((HERE.parent / "workflows/blazer-v31.yaml").read_text())
        steps = document["jobs"]["deploy-pages"]["steps"]
        upload = next(x for x in steps if x.get("uses", "").startswith("actions/upload-pages-artifact@"))
        deploy = next(x for x in steps if x.get("uses", "").startswith("actions/deploy-pages@"))
        self.assertEqual(upload["with"]["name"], deploy["with"]["artifact_name"])
        self.assertIn("github.run_attempt", upload["with"]["name"])

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
    def test_pinned_kernelpatch_fallback_preserves_failure_and_rejects_drift(self):
        import hashlib
        import patch_kernelpatch_tools as kp
        fixture = (kp.OLD + '\n    tools_logw("pid_vnr verification failed\\n");\n}' +
                   '\n            if (aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0) {').encode()
        blob = hashlib.sha1(b"blob " + str(len(fixture)).encode() + b"\0" + fixture).hexdigest()
        with patch.object(kp, "SOURCE_BLOB", blob):
            changed = kp.patched_source(fixture)
            self.assertIn(kp.NEW.encode(), changed)
            self.assertIn(b"pid_vnr verfied tpidrro_el0", changed)
            self.assertIn(b"0xd5300000", changed)  # Require MRS, not an MSR write.
            self.assertIn(b"pid_vnr verification failed", changed)
            with self.assertRaises(RuntimeError):
                kp.patched_source(changed)
        with self.assertRaises(RuntimeError):
            kp.patched_source(fixture)

    def test_bbr_download_retries_429_and_honors_bounded_retry_after(self):
        import io
        import urllib.error
        from email.message import Message
        headers = Message()
        headers["Retry-After"] = "120"
        failure = urllib.error.HTTPError("https://raw.githubusercontent.com/test", 429, "throttled", headers, None)
        with patch.object(bbr.urllib.request, "urlopen", side_effect=[failure, io.BytesIO(b"source")]) as request, \
             patch.object(bbr.time, "sleep") as sleep:
            self.assertEqual(bbr.read_url("https://raw.githubusercontent.com/test"), b"source")
        self.assertEqual(request.call_count, 2)
        sleep.assert_called_once_with(60)

    def test_bbr_raw_throttle_uses_api_and_checksum_still_rejects_changed_source(self):
        import base64
        import io
        import urllib.error
        url = "https://raw.githubusercontent.com/GrapheneOS/kernel_common-6.18/" + "a" * 40 + "/net/ipv4/tcp_bbr.c"
        failure = urllib.error.HTTPError(url, 429, "throttled", {}, None)
        record = {"encoding": "base64", "type": "file", "content": base64.b64encode(b"source").decode()}
        with patch.object(bbr.urllib.request, "urlopen", side_effect=[failure] * 5 + [io.BytesIO(json.dumps(record).encode())]) as request, \
             patch.object(bbr.time, "sleep"):
            self.assertEqual(bbr.read_url(url), b"source")
        self.assertIn("api.github.com/repos/GrapheneOS/kernel_common-6.18/contents/net/ipv4/tcp_bbr.c?ref=", request.call_args.args[0].full_url)

    def test_bbr_permanent_http_error_is_not_retried(self):
        import urllib.error
        failure = urllib.error.HTTPError("https://example.com", 404, "missing", {}, None)
        with patch.object(bbr.urllib.request, "urlopen", side_effect=failure), patch.object(bbr.time, "sleep") as sleep:
            with self.assertRaises(urllib.error.HTTPError):
                bbr.read_url("https://example.com")
        sleep.assert_not_called()

    def test_memblock_validation_accepts_local_and_global_text_only(self):
        import inspect
        import re
        import apatch_pipeline
        source = inspect.getsource(apatch_pipeline.prepare)
        pattern = re.search(r"'(memblock_phys_alloc_try_nid[^']+)'", source).group(1)
        self.assertIn("grep -Eq", source)
        for kind in ("t", "T"):
            self.assertRegex(f"[+] memblock_phys_alloc_try_nid: type: {kind}, offset: 0x0230c7c8", pattern)
        for line in ("memblock_phys_alloc_try_nid: type: D, offset: 0x1234",
                     "memblock_phys_alloc_try_nid: type: T, offset: 0x",
                     "no symbol: memblock_phys_alloc_try_nid"):
            self.assertNotRegex(line, pattern)

    def test_android17_kernel_uses_its_own_reviewed_source(self):
        import hashlib
        banner = b"Linux version 6.18.38-android17-5-g8299417b96c4-4k (builder)\0"
        kernel, prefix = bbr.identify_kernel(banner)
        commit = prefix + "f" * (40 - len(prefix))
        source = b"reviewed BBR fixture"
        with patch.dict(bbr.REVIEWED_BBR_SOURCES, {"6.18": hashlib.sha256(source).hexdigest()}), \
             patch.object(bbr, "read_url", side_effect=[json.dumps({"sha": commit}).encode(), source]) as read:
            result = bbr.verified_source(kernel, prefix)
        self.assertEqual(result[0], commit)
        self.assertEqual(result[2], source)
        self.assertIn("kernel_common-6.18/commits/" + prefix, read.call_args_list[0].args[0])
        self.assertIn("kernel_common-6.18/" + commit, result[1])

    def test_new_family_still_rejects_changed_bbr_and_wrong_commit(self):
        kernel, prefix = bbr.identify_kernel(b"Linux version 6.18.38-android17-5-g8299417b96c4-4k ")
        commit = prefix + "f" * (40 - len(prefix))
        with patch.object(bbr, "read_url", side_effect=[json.dumps({"sha": commit}).encode(), b"changed TCP code"]):
            with self.assertRaisesRegex(RuntimeError, "Stock BBR code changed"):
                bbr.verified_source(kernel, prefix)
        with patch.object(bbr, "read_url", return_value=json.dumps({"sha": "f" * 40}).encode()):
            with self.assertRaisesRegex(RuntimeError, "source commit does not match"):
                bbr.verified_source(kernel, prefix)

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
    def test_unchanged_feed_with_untracked_cache_does_not_attempt_empty_commit(self):
        import base64, hashlib, subprocess
        def git(*args):
            return subprocess.run(["git", *map(str, args)], check=True, capture_output=True, text=True).stdout.strip()
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            remote, seed, prepared = root / "remote.git", root / "seed", root / "prepared"
            git("init", "--bare", "--initial-branch=main", remote)
            git("clone", remote, seed)
            git("-C", seed, "checkout", "-b", "gh-pages")
            git("-C", seed, "config", "user.name", "test")
            git("-C", seed, "config", "user.email", "test@example.invalid")
            (seed / ".nojekyll").touch()
            (seed / "index.html").write_text("feed")
            (seed / "server-owner.txt").write_text(ap.REPO)
            git("-C", seed, "add", ".")
            git("-C", seed, "commit", "-m", "seed")
            git("-C", seed, "push", "origin", "gh-pages")
            prepared.mkdir()
            (prepared / "manifest.json").write_text(json.dumps({"grapheneos": "2026111301", "signature": "test.csig"}))
            (prepared / "blazer.json").write_text('{"version":2}')
            (prepared / "test.csig").write_bytes(b"signed")
            data = b"signature"
            names = {"pixincreate": "blazer-2026111301-pixin.zip", "rootless": "blazer-2026111301-rootless.zip"}
            manifest = {"grapheneos": "2026111301", "flavors": names,
                "files": {n + ".csig": {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for n in names.values()},
                "sidecars": {n + ".csig": base64.b64encode(data).decode() for n in names.values()}}
            scope = coordinator()
            heads = []
            for attempt in (1, 2):
                workspace = root / str(attempt)
                workspace.mkdir()
                git("clone", remote, workspace / "ota")
                (workspace / "ota/untracked-cache.pyc").write_bytes(b"cache")
                with patch.dict(os.environ, {"GITHUB_WORKSPACE": str(workspace)}), \
                     patch.dict(scope, {"output": lambda *a: None}):
                    scope["sync_feed"](manifest, "blazer-test", prepared)
                heads.append(git("--git-dir", remote, "rev-parse", "refs/heads/gh-pages"))
            self.assertEqual(heads[0], heads[1])

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

class CustotaIntegrationChecks(unittest.TestCase):
    def test_unexpected_system_changes_are_rejected(self):
        from verify_apatch_custota import compare
        with tempfile.TemporaryDirectory() as folder:
            left, right = Path(folder) / "expected", Path(folder) / "actual"
            left.mkdir()
            right.mkdir()
            (left / "policy").write_bytes(b"reviewed rules")
            (right / "policy").write_bytes(b"reviewed rules")
            compare(left, right, "policy")
            (right / "unexpected.apk").write_bytes(b"unreviewed")
            with self.assertRaises(RuntimeError):
                compare(left, right, "system")
            (right / "unexpected.apk").unlink()
            (right / "policy").write_bytes(b"different rules")
            with self.assertRaises(RuntimeError):
                compare(left, right, "policy")

    def test_custota_is_part_of_release_identity(self):
        with patch.object(ap, "source_ids", return_value={}):
            manifest = ap.expectation("2026102101", {"version": "11282", "manager_sha256": "a" * 64})
        self.assertEqual(manifest["profile"]["custota"]["version"], "6.7")
        from verify_apatch_custota import CUSTOTA_SHA
        self.assertEqual(manifest["profile"]["custota"]["module_sha256"], CUSTOTA_SHA)

class UntaggedDraftChecks(unittest.TestCase):
    def test_untagged_draft_is_found_after_tag_endpoint_404(self):
        from types import SimpleNamespace
        draft = {"id": 17, "draft": True, "tag_name": "wanted"}
        missing = SimpleNamespace(returncode=1, stderr="HTTP 404", stdout="")
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test"}), \
             patch.object(ap.subprocess, "run", return_value=missing), \
             patch.object(ap, "api", return_value=[draft]):
            self.assertEqual(ap.get_release("wanted"), draft)

    def test_duplicate_drafts_are_not_silently_selected(self):
        from types import SimpleNamespace
        drafts = [{"id": i, "draft": True, "tag_name": "wanted"} for i in (17, 18)]
        missing = SimpleNamespace(returncode=1, stderr="HTTP 404", stdout="")
        with patch.dict(os.environ, {"GITHUB_TOKEN": "test"}), \
             patch.object(ap.subprocess, "run", return_value=missing), \
             patch.object(ap, "api", return_value=drafts):
            with self.assertRaises(RuntimeError):
                ap.get_release("wanted")

if __name__ == "__main__":
    unittest.main(verbosity=2)
