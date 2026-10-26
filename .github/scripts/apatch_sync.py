#!/usr/bin/env python3
"""Stage and verify APatch before either synchronized release becomes public."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import urllib.parse
import zipfile
REPO = "Artemis311/ota"
BUILDER = "c1d7484af159e573afddaf351b485f2e0995e530"
KP = "280d32d967feb7ddc0fd1848aa1d1388807945d5"
SELINUX = "8ad91d00b9abd0fb3191d968b74fdc502126f8ca"
LEGACY_IDS = {".github/scripts/apatch_pipeline.py":"f6b16017f72fdefa5c3351f1b675c30842181eb1",".github/scripts/prepare_stock_bbr.py":"a9d9426fa4ade146773603a206e1f928265505a4",".github/scripts/prepare_private_bbr.py":"d6a08b2f843b9642d962eaa6be76f1afa7d7faad",".github/scripts/private_bbr_module.py":"d79f89c1b12f42266c30a1d791fda06150e8c028"}
MARKER = "<!-- synchronized-apatch-manifest\n"
LEGACY_SHA = "faad5d515d29f38c880d584a1a89072831226cd00f406c101dcdbfc5dc3f735e"

def api(method, endpoint, data=None):
    env = os.environ.copy()
    env["GH_TOKEN"] = env.get("GITHUB_TOKEN") or env["GH_TOKEN"]
    args = ["gh", "api", "--method", method, endpoint]
    if data is not None:
        args += ["--input", "-"]
    out = subprocess.run(args, input=json.dumps(data) if data is not None else None,
                         env=env, check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else None

def get_release(tag):
    env = os.environ.copy()
    env["GH_TOKEN"] = env.get("GITHUB_TOKEN") or env["GH_TOKEN"]
    result = subprocess.run(["gh", "api", f"repos/{REPO}/releases/tags/{tag}"],
                            env=env, capture_output=True, text=True)
    if result.returncode == 0:
        return json.loads(result.stdout)
    if "HTTP 404" in result.stderr:
        return None
    raise RuntimeError("Cannot read APatch release: " + result.stderr)

def source_ids():
    root = Path(os.environ["GITHUB_WORKSPACE"]) / "ota"
    result = {}
    for name in (*LEGACY_IDS, ".github/scripts/verify_apatch_custota.py"):
        data = (root / name).read_bytes()
        result[name] = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    return result

def resolve_apatch():
    release = api("GET", "repos/bmax121/APatch/releases/latest")
    version = release["tag_name"]
    if release["draft"] or release["prerelease"] or not re.fullmatch(r"\d{4,}", version):
        raise RuntimeError("Unexpected official stable APatch release")
    matches = [a for a in release["assets"] if a["name"].startswith(f"APatch_{version}_")
               and a["name"].endswith("-release-signed.apk") and a["state"] == "uploaded"]
    if len(matches) != 1 or not re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0].get("digest", "")):
        raise RuntimeError("Official manager APK has no unique verified digest")
    url = matches[0]["browser_download_url"]
    if not url.startswith(f"https://github.com/bmax121/APatch/releases/download/{version}/"):
        raise RuntimeError("Unexpected official manager origin")
    return {"version": version, "manager_url": url,
            "manager_sha256": matches[0]["digest"].split(":")[1], "release": release}

def expectation(version, resolved):
    if not re.fullmatch(r"\d{10}", version):
        raise RuntimeError("Invalid shared GrapheneOS version")
    profile = {"builder": BUILDER, "kernelpatch": KP, "selinux": SELINUX,
               "source_ids": source_ids(), "tcp": "stock-bbrv1-fq", "schema": 1,
               "custota": {"version": "6.7", "module_sha256": "e5a1480b53bfedc20e702541573683d6a68dacb7804792621dd7248c37ad97b6"}}}
    inputs = {"grapheneos": version, "apatch": resolved["version"],
              "manager_sha256": resolved["manager_sha256"], "profile": profile}
    fingerprint = hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()
    return {"schema": 1, "device": "blazer", **inputs, "fingerprint": fingerprint}

def manifest_from_body(body):
    if MARKER not in body:
        return None
    try:
        return json.loads(body.split(MARKER, 1)[1].split("\n-->", 1)[0])
    except (ValueError, IndexError):
        return None

def validate_release(release, expected, manifest, require_public=False):
    if not manifest or any(manifest.get(k) != v for k, v in expected.items()):
        raise RuntimeError("APatch release does not match the shared OS and exact profile")
    files = manifest.get("files", {})
    name = f"blazer-{expected['grapheneos']}-apatch.zip"
    if set(files) != {name} or len(release["assets"]) != 1:
        raise RuntimeError("APatch must expose exactly one OTA ZIP")
    if require_public and release["draft"]:
        raise RuntimeError("APatch release is still a draft")
    asset, recorded = release["assets"][0], files[name]
    if (asset["name"] != name or asset["state"] != "uploaded" or asset["size"] <= 0 or
        asset["size"] != recorded["size"] or
        not re.fullmatch(r"[0-9a-f]{64}", recorded.get("sha256", "")) or
        asset.get("digest") != "sha256:" + recorded["sha256"]):
        raise RuntimeError("APatch uploaded OTA digest/size mismatch")

def legacy_partner(expected):
    if (expected["grapheneos"] != "2026102101" or expected["apatch"] != "11282" or
        expected["manager_sha256"] != "d6bf0dbcab95fb9a3aa111c35efd945267bcce3a41377c3297c3c1a9eab421a5" or
        expected["profile"]["source_ids"] != LEGACY_IDS):
        return None
    release = get_release("blazer-2026102101-apatch-11282-bbrv1")
    if not release:
        return None
    if release["id"] != 424714647 or release["target_commitish"] != "c9f49ec0be47ed00b249de42eaae507af811f530":
        raise RuntimeError("Previously verified APatch release identity changed")
    manifest = {**expected, "files": {"blazer-2026102101-apatch.zip":
                {"sha256": LEGACY_SHA, "size": 1787655639}}}
    validate_release(release, expected, manifest, require_public=True)
    return {"release": release, "expected": expected, "manifest": manifest, "legacy": True}

def verify_zip(path, version):
    with zipfile.ZipFile(path) as archive:
        text = archive.read("META-INF/com/android/metadata").decode()
    metadata = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
    if metadata.get("post-build-incremental") != version or metadata.get("pre-device") != "blazer":
        raise RuntimeError("APatch ZIP is not for the shared GrapheneOS version/device")

def build_apatch(version, resolved, expected):
    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    builder = workspace / "apatch-builder"
    cache = builder / "release-metadata"
    cache.mkdir(parents=True, exist_ok=True)
    (cache / "apatch.json").write_text(json.dumps(resolved["release"]))
    kp_release = api("GET", "repos/bmax121/KernelPatch/releases/tags/0.13.9")
    if kp_release["tag_name"] != "0.13.9" or kp_release["draft"]:
        raise RuntimeError("Pinned KernelPatch metadata changed")
    (cache / "kernelpatch.json").write_text(json.dumps(kp_release))
    helper = workspace / "ota/.github/scripts/apatch_pipeline.py"
    env = os.environ.copy()
    env.update(OTA_VERSION=version, APATCH_VERSION=resolved["version"])
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "MAGISK_DOWNLOAD_TOKEN"):
        env.pop(key, None)
    subprocess.run([sys.executable, str(helper), "prepare"], env=env, cwd=builder, check=True)
    subprocess.run(["bash", "run-private.sh"], env=env, cwd=builder, check=True)
    private = json.loads((builder / "dist/BUILD_MANIFEST.json").read_text())
    if (private["grapheneos"] != version or private["apatch"] != resolved["version"] or
        private["manager_sha256"] != resolved["manager_sha256"]):
        raise RuntimeError("APatch build did not use the resolved inputs")
    if private.get("custota", {}).get("verified") is not True:
        raise RuntimeError("Custota system integration was not verified")
    path = builder / "dist" / f"blazer-{version}-apatch-private-test.zip"
    verify_zip(path, version)
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    name = f"blazer-{version}-apatch.zip"
    manifest = {**expected, "files": {name: {"sha256": digest, "size": path.stat().st_size}}}
    destination = path.with_name(name)
    path.rename(destination)
    return destination, manifest

def notes(manifest, resolved):
    version = manifest["grapheneos"]
    name, data = next(iter(manifest["files"].items()))
    commit = os.environ["GITHUB_SHA"]
    return (
        f"Experimental APatch OTA for **Pixel 10 Pro (blazer)**, GrapheneOS **{version}**.\n\n"
        f"- APatch manager **{manifest['apatch']}**; KernelPatch **0.13.9**, pinned source {KP}.\n"
        "- Embedded **SELinux Magisk Access Filter 1.1.7**.\n"
        "- Includes **Custota 6.7** as a privileged system app with both SELinux policy copies patched.\n"
        "- Custota OTA server: **https://artemis311.github.io/ota/apatch/**.\n"
        "- Automatically selects the existing **BBRv1 + fq** at each boot; stock TCP code and drivers retained.\n\n"
        "Requires this repository's matching AVB/OTA signing keys. Do not downgrade a newer OS. "
        "CI verifies OTA/AVB signatures and the exact KPM set; hardware validation is not claimed.\n\n"
        f"[Official APatch manager]({resolved['release']['html_url']}) · "
        f"[Exact build sources](https://github.com/{REPO}/tree/{commit}) · "
        f"[OTA builder](https://github.com/david568303/apatch-graphene/tree/{BUILDER}) · "
        f"[KernelPatch](https://github.com/david568303/KernelPatch/tree/{KP}) · "
        f"[SELinux filter](https://github.com/Admirepowered/selinux_hook/tree/{SELINUX}) · "
        "[GrapheneOS sources](https://grapheneos.org/source)\n\n"
        f"**Download:** {name}\n\n**SHA-256:**\n~~~text\n{data['sha256']}\n~~~\n\n"
        "Built for the same GrapheneOS version as the synchronized pixincreate/Magisk release.\n\n"
        + MARKER + json.dumps(manifest, sort_keys=True) + "\n-->\n")

def stage_apatch(version, publish):
    if os.environ.get("GITHUB_REPOSITORY") != REPO:
        raise RuntimeError("Unexpected repository")
    resolved = resolve_apatch()
    expected = expectation(version, resolved)
    if publish:
        legacy = legacy_partner(expected)
        if legacy:
            print("Reusing verified APatch companion:", legacy["release"]["html_url"], flush=True)
            return legacy
    tag = f"blazer-{version}-apatch-{resolved['version']}-{expected['fingerprint'][:12]}"
    release = get_release(tag) if publish else None
    if release:
        manifest = manifest_from_body(release.get("body", ""))
        if not manifest or any(manifest.get(k) != v for k, v in expected.items()):
            raise RuntimeError("Existing APatch release has different build inputs")
        try:
            validate_release(release, expected, manifest)
        except RuntimeError:
            if not release["draft"]:
                raise
            expected_name = f"blazer-{version}-apatch.zip"
            if any(a["name"] != expected_name for a in release["assets"]):
                raise RuntimeError("Draft contains unexpected attachments; refusing to remove them")
            # Only an incomplete matching draft can be repaired; published firmware is immutable.
        else:
            return {"release": release, "expected": expected, "manifest": manifest}
    path, manifest = build_apatch(version, resolved, expected)
    if not publish:
        return {"release": None, "expected": expected, "manifest": manifest}
    if release is None:
        release = api("POST", f"repos/{REPO}/releases", {
            "tag_name": tag, "target_commitish": os.environ["GITHUB_SHA"],
            "draft": True, "prerelease": True, "make_latest": "false",
            "name": f"Blazer | GrapheneOS {version} | APatch {resolved['version']} + BBRv1 + Custota",
            "body": notes(manifest, resolved),
        })
    else:
        for asset in release["assets"]:
            api("DELETE", f"repos/{REPO}/releases/assets/{asset['id']}")
        release = api("PATCH", f"repos/{REPO}/releases/{release['id']}",
                      {"body": notes(manifest, resolved)})
    url = release["upload_url"].split("{", 1)[0]
    if not url.startswith(f"https://uploads.github.com/repos/{REPO}/releases/"):
        raise RuntimeError("Unexpected APatch upload destination")
    env = os.environ.copy()
    env["GH_TOKEN"] = env.get("GITHUB_TOKEN") or env["GH_TOKEN"]
    subprocess.run(["gh", "api", "--method", "POST", url + "?name=" + urllib.parse.quote(path.name, safe=""),
                    "-H", "Content-Type: application/octet-stream", "--input", str(path), "--silent"],
                   env=env, check=True)
    release = api("GET", f"repos/{REPO}/releases/{release['id']}")
    validate_release(release, expected, manifest)
    return {"release": release, "expected": expected, "manifest": manifest}

def publish_apatch(partner):
    release = partner["release"]
    current = api("GET", f"repos/{REPO}/releases/{release['id']}")
    validate_release(current, partner["expected"], partner["manifest"])
    if current["draft"]:
        current = api("PATCH", f"repos/{REPO}/releases/{release['id']}",
                      {"draft": False, "prerelease": True, "make_latest": "false"})
    validate_release(current, partner["expected"], partner["manifest"], require_public=True)
    print("Verified public APatch companion:", current["html_url"], flush=True)

def rollback_apatch(partner):
    if partner["release"]["draft"]:
        api("PATCH", f"repos/{REPO}/releases/{partner['release']['id']}", {"draft": True})
