"""One public release with three OTA ZIPs; sidecars live on the OTA site."""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.parse
from apatch_sync import REPO, api, get_release, manifest_from_body, validate_release

MARKER = "<!-- synchronized-ota-manifest\n"


def manifest_body(body):
    body = body.replace("\r\n", "\n").replace("\r", "\n")
    try:
        payload, _ = body.split(MARKER, 1)[1].split("\n-->", 1)
        value = json.loads(payload)
        return value if isinstance(value, dict) else None
    except (ValueError, IndexError):
        return None


def checked_sidecar(manifest, name):
    data = base64.b64decode(manifest.get("sidecars", {}).get(name, ""), validate=True)
    meta = manifest["files"][name]
    if len(data) != meta["size"] or hashlib.sha256(data).hexdigest() != meta["sha256"]:
        raise RuntimeError("Custota signature does not match the build manifest")
    return data


def create_draft(tag, title, notes):
    return api("POST", f"repos/{REPO}/releases", {
        "tag_name": tag, "target_commitish": os.environ["GITHUB_SHA"],
        "draft": True, "name": title, "body": notes})


def upload_asset(release, path, meta):
    path = Path(path)
    if not path.name.endswith(".zip"):
        raise RuntimeError("Only OTA ZIP attachments may be uploaded")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    if path.stat().st_size != meta["size"] or digest != meta["sha256"]:
        raise RuntimeError("OTA upload input checksum mismatch")
    existing = next((a for a in release["assets"] if a["name"] == path.name), None)
    if existing:
        if (existing.get("state") == "uploaded" and existing.get("digest") == "sha256:" + digest
                and existing["size"] == meta["size"]):
            return
        if not release["draft"]:
            raise RuntimeError("Refusing to replace published firmware")
        api("DELETE", f"repos/{REPO}/releases/assets/{existing['id']}")
    url = release["upload_url"].split("{", 1)[0]
    if url != f"https://uploads.github.com/repos/{REPO}/releases/{release['id']}/assets":
        raise RuntimeError("Unexpected ZIP upload destination")
    env = os.environ.copy()
    env["GH_TOKEN"] = env.get("GITHUB_TOKEN") or env["GH_TOKEN"]
    result = subprocess.run(["gh", "api", "--method", "POST",
        url + "?name=" + urllib.parse.quote(path.name, safe=""),
        "--header", "Content-Type: application/octet-stream", "--input", str(path), "--silent"],
        env=env, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("ZIP upload failed: " + result.stderr.strip())


def upload_zip_assets(release, manifest, dist):
    if not release["draft"]:
        raise RuntimeError("Initial ZIP upload requires a draft")
    for name in manifest["flavors"].values():
        if Path(name).name != name:
            raise RuntimeError("Invalid OTA filename")
        upload_asset(release, Path(dist) / name, manifest["files"][name])
    return api("GET", f"repos/{REPO}/releases/{release['id']}")


def set_public(release, public):
    return api("PATCH", f"repos/{REPO}/releases/{release['id']}", {
        "draft": not public, "prerelease": False,
        "make_latest": "true" if public else "false"})


def reuse_magisk(version, magisk, dist, read_manifest, builder_commit):
    # APatch-only updates retain the exact previously verified Magisk/rootless bytes.
    source = get_release(f"blazer-{version}-pixin-{magisk['apk_sha256'][:12]}")
    if not source or source["draft"]:
        return None
    manifest = read_manifest(source, version)
    if (not manifest or manifest.get("builder_commit") != builder_commit or
            manifest.get("magisk", {}).get("apk_sha256") != magisk["apk_sha256"]):
        return None
    manifest = copy.deepcopy(manifest)
    manifest.pop("replaced_releases", None)
    env = os.environ.copy()
    env["GH_TOKEN"] = env.get("GITHUB_TOKEN") or env["GH_TOKEN"]
    def small_download(*args):
        return subprocess.run(["gh", *args], env=env, check=True, capture_output=True).stdout
    manifest = attach_sidecars(manifest, source, dist, small_download)
    destination = Path(dist)
    destination.mkdir(exist_ok=True)
    for name in manifest["flavors"].values():
        if Path(name).name != name:
            raise RuntimeError("Unsafe reusable OTA filename")
        asset = next(a for a in source["assets"] if a["name"] == name)
        path = destination / name
        with path.open("wb") as stream:
            subprocess.run(["gh", "api", f"repos/{REPO}/releases/assets/{asset['id']}",
                "-H", "Accept: application/octet-stream"], env=env, stdout=stream, check=True)
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        meta = manifest["files"][name]
        if path.stat().st_size != meta["size"] or digest != meta["sha256"]:
            raise RuntimeError("Reusable OTA ZIP checksum mismatch")
    print("Reused exact verified Magisk and rootless OTA ZIPs for APatch-only update", flush=True)
    return manifest


def store_manifest(tag, manifest, release=None):
    release = release or get_release(tag)
    if not release or not release["draft"] or release.get("tag_name") != tag:
        raise RuntimeError("Only a draft's initial build manifest can be stored")
    api("PATCH", f"repos/{REPO}/releases/{release['id']}", {
        "body": release.get("body", "").split(MARKER, 1)[0] + "\n" + MARKER
                + json.dumps(manifest, sort_keys=True) + "\n-->\n"})


def attach_sidecars(manifest, release, dist, gh):
    manifest = copy.deepcopy(manifest)
    manifest.setdefault("sidecars", {})
    assets = {a["name"]: a for a in (release or {}).get("assets", [])}
    for name in manifest["flavors"].values():
        name += ".csig"
        if name not in manifest["sidecars"]:
            local = Path(dist) / name
            if local.exists():
                data = local.read_bytes()
            elif name in assets:
                data = gh("api", f"repos/{REPO}/releases/assets/{assets[name]['id']}",
                          "-H", "Accept: application/octet-stream")
            else:
                raise RuntimeError("Missing verified Custota signature")
            manifest["sidecars"][name] = base64.b64encode(data).decode("ascii")
        checked_sidecar(manifest, name)
    return manifest


def release_tag(version, apk_hash):
    # An APatch update on the same OS must get a new release, never overwrite ZIPs.
    from apatch_sync import expectation, resolve_apatch
    tag = f"blazer-{version}-pixin-{apk_hash[:12]}"
    old = get_release(tag)
    previous = manifest_from_body(old.get("body", "")) if old else None
    if previous:
        expected = expectation(version, resolve_apatch())
        if any(previous.get(k) != v for k, v in expected.items()):
            return tag + "-apatch-" + expected["fingerprint"][:12]
    return tag


def body(manifest, partner, replaced):
    apatch = partner["manifest"]
    rows = [
        f"# Pixel 10 Pro (blazer) | GrapheneOS {manifest['grapheneos']}",
        "",
        "Choose one OTA ZIP for the variant you use:",
        f"- **APatch {apatch['apatch']} + BBRv1 + Custota:** blazer-{manifest['grapheneos']}-apatch.zip",
        f"- **pixincreate/Magisk:** {manifest['flavors']['pixincreate']}",
        f"- **Rootless:** {manifest['flavors']['rootless']}",
        "",
        "Requires this repository's matching AVB/OTA signing keys. Do not downgrade.",
        "APatch includes the SELinux filter and Custota; firmware signatures are verified in CI.",
        "Installation and boot on hardware have not been verified by this workflow.",
        "",
        "Custota servers: [APatch](https://artemis311.github.io/ota/apatch/) · "
        "[pixincreate](https://artemis311.github.io/ota/pixincreate/) · "
        "[Rootless](https://artemis311.github.io/ota/rootless/)",
        "",
        "### SHA-256",
        "",
        "```text",
    ]
    for name, meta in {**manifest["files"], **apatch["files"]}.items():
        if name.endswith(".zip"):
            rows.append(f"{meta['sha256']}  {name}")
    rows += ["```", "",
             f"pixincreate source: {manifest['magisk']['url']}", "",
             "KernelPatch upstream fixes: " + ", ".join(
                 f"[{commit[:12]}](https://github.com/bmax121/KernelPatch/commit/{commit})"
                 for commit in apatch.get("profile", {}).get("upstream_fixes", [])), "",
             MARKER + json.dumps({**manifest, "replaced_releases": replaced}, sort_keys=True) + "\n-->",
             "<!-- synchronized-apatch-manifest\n" + json.dumps(apatch, sort_keys=True) + "\n-->\n"]
    return "\n".join(rows)


def unify(release, manifest, partner):
    source = partner["release"]
    validate_release(source, partner["expected"], partner["manifest"])
    name, meta = next(iter(partner["manifest"]["files"].items()))
    existing = next((a for a in release["assets"] if a["name"] == name), None)
    if existing:
        if existing.get("digest") != "sha256:" + meta["sha256"] or existing["size"] != meta["size"]:
            raise RuntimeError("Published APatch ZIP differs; refusing replacement")
    else:
        source_asset = next(a for a in source["assets"] if a["name"] == name)
        workspace = Path(os.environ["GITHUB_WORKSPACE"])
        output = workspace / "unified-release"
        output.mkdir(exist_ok=True)
        destination = output / name
        env = os.environ.copy()
        env["GH_TOKEN"] = env.get("GITHUB_TOKEN") or env["GH_TOKEN"]
        with destination.open("wb") as stream:
            subprocess.run(["gh", "api", f"repos/{REPO}/releases/assets/{source_asset['id']}",
                            "-H", "Accept: application/octet-stream"], env=env, stdout=stream, check=True)
        with destination.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if destination.stat().st_size != meta["size"] or digest != meta["sha256"]:
            raise RuntimeError("APatch transfer checksum mismatch")
        upload_asset(release, destination, meta)
    previous = manifest_body(release.get("body", "")) or {}
    replaced = previous.get("replaced_releases", [])
    if (source["id"] != release["id"] and source["id"] not in replaced
            and manifest_body(source.get("body", "")) is None):
        replaced.append(source["id"])
    updated = api("PATCH", f"repos/{REPO}/releases/{release['id']}", {
        "name": f"Blazer | GrapheneOS {manifest['grapheneos']} | APatch + pixincreate + Rootless",
        "body": body(manifest, partner, replaced),
        "prerelease": False, "make_latest": "false" if release["draft"] else "true",
    })
    result = {**partner, "release": updated}
    validate_release(updated, partner["expected"], partner["manifest"])
    return result


def verify_live_sidecars(site):
    site = Path(site)
    for flavor in ("apatch", "pixincreate", "rootless"):
        feed = json.loads((site / flavor / "blazer.json").read_text())
        url = feed["full"]["location_csig"]
        if not url.startswith(f"https://artemis311.github.io/ota/{flavor}/"):
            raise RuntimeError("Custota signature must be served by the OTA site")
        name = Path(urllib.parse.urlparse(url).path).name
        expected = (site / flavor / name).read_bytes()
        data = subprocess.run(["curl", "--fail", "--silent", "--show-error", "--location",
            "--retry", "8", "--retry-all-errors", "--retry-delay", "5", url],
            check=True, capture_output=True).stdout
        if not expected or data != expected:
            raise RuntimeError("Live Custota signature differs: " + flavor)
    print("Verified all three live Custota signature files")


def cleanup(site):
    # Called only after Pages deployment and live-feed verification succeed.
    site = Path(site)
    record = json.loads((site / "apatch/manifest.json").read_text())
    release = api("GET", f"repos/{REPO}/releases/{record['release_id']}")
    manifest = manifest_body(release.get("body", ""))
    apatch = manifest_from_body(release.get("body", ""))
    if release["draft"] or not manifest or not apatch:
        raise RuntimeError("Combined release is not public and complete")
    expected = {k: v for k, v in apatch.items() if k != "files"}
    validate_release(release, expected, apatch, require_public=True)
    expected_zips = {**{n: manifest["files"][n] for n in manifest["flavors"].values()}, **apatch["files"]}
    assets = {a["name"]: a for a in release["assets"]}
    for name, meta in expected_zips.items():
        asset = assets.get(name, {})
        if asset.get("digest") != "sha256:" + meta["sha256"] or asset.get("size") != meta["size"]:
            raise RuntimeError("Combined ZIP verification failed before cleanup")
    for flavor in ("apatch", "pixincreate", "rootless"):
        feed = json.loads((site / flavor / "blazer.json").read_text())
        if "/releases/download/" + release["tag_name"] + "/" not in feed["full"]["location_ota"]:
            raise RuntimeError("Feed still points to a separate release")
    verify_live_sidecars(site)
    allowed = {"BUILD_MANIFEST.json", "SHA256SUMS", "ota.crt"} | {n + ".csig" for n in manifest["flavors"].values()}
    extras = set(assets) - set(expected_zips)
    if not extras <= allowed:
        raise RuntimeError("Unexpected release attachment; refusing deletion")
    for name in extras:
        api("DELETE", f"repos/{REPO}/releases/assets/{assets[name]['id']}")
    for release_id in manifest.get("replaced_releases", []):
        if release_id == release["id"]:
            raise RuntimeError("Refusing to delete the combined release")
        try:
            old = api("GET", f"repos/{REPO}/releases/{release_id}")
        except RuntimeError as exc:
            if "HTTP 404" in str(exc):
                continue
            raise
        # Only the exact migrated APatch companion may be removed.
        if old["tag_name"] != (f"blazer-{apatch['grapheneos']}-apatch-{apatch['apatch']}-"
                               + apatch["fingerprint"][:12]):
            raise RuntimeError("Unexpected obsolete release identity")
        validate_release(old, expected, apatch)
        api("DELETE", f"repos/{REPO}/releases/{release_id}")
    final = api("GET", f"repos/{REPO}/releases/{release['id']}")
    if {a["name"] for a in final["assets"]} != set(expected_zips):
        raise RuntimeError("ZIP-only cleanup verification failed")
    print("Verified one public release with exactly three OTA ZIP attachments:", final["html_url"])


if __name__ == "__main__":
    cleanup(sys.argv[1])

