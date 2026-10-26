"""Custota metadata for verified APatch OTAs; firmware attachments stay unchanged."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from apatch_sync import REPO, api, validate_release, verify_zip

SITE = "https://artemis311.github.io/ota"
BUILDER = "80ff7950d1eb397c3c44c462a19570c1b7aaa8df"
BLOB = "54bde95262d1f927f93851db70cbcd35ce6311f3"

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def prepare_feed(partner):
    release = api("GET", f"repos/{REPO}/releases/{partner['release']['id']}")
    validate_release(release, partner["expected"], partner["manifest"])
    version = partner["manifest"]["grapheneos"]
    name, meta = next(iter(partner["manifest"]["files"].items()))
    tag = release["tag_name"]
    if not re.fullmatch(r"blazer-[A-Za-z0-9._-]+", tag):
        raise RuntimeError("Unsafe APatch tag")
    workspace = Path(os.environ["GITHUB_WORKSPACE"])
    output = workspace / "apatch-feed"
    output.mkdir(exist_ok=True)
    signature_name = f"{tag}.zip.csig"
    signature = output / signature_name
    record = {"grapheneos": version, "release_id": release["id"], "tag": tag,
              "ota": meta, "signature": signature_name}
    # Fetch an existing sidecar from our authenticated feed branch. No firmware download on reuse.
    repo = workspace / "ota"
    run("git", "-C", str(repo), "fetch", "origin", "gh-pages:refs/remotes/origin/gh-pages",
        capture_output=True)
    def previous(path):
        result = subprocess.run(["git", "-C", str(repo), "show", "origin/gh-pages:" + path],
                                capture_output=True)
        return result.stdout if result.returncode == 0 else None
    cached = previous("apatch/manifest.json")
    cached = json.loads(cached) if cached else {}
    env = os.environ.copy()
    for key in ("GITHUB_TOKEN", "GH_TOKEN", "MAGISK_DOWNLOAD_TOKEN"):
        env.pop(key, None)
    with tempfile.TemporaryDirectory(prefix="apatch-sign-", dir=workspace) as temp:
        temp = Path(temp)
        cert = temp / "ota.crt"
        cert.write_bytes(base64.b64decode(os.environ["CERT_OTA_BASE64"], validate=True))
        old_signature = previous("apatch/" + signature_name)
        reusable = all(cached.get(k) == v for k, v in record.items())
        if reusable and old_signature and hashlib.sha256(old_signature).hexdigest() == cached.get("csig_sha256"):
            signature.write_bytes(old_signature)
            # Verify the actual CMS signature against the current repository OTA certificate.
            run("openssl", "cms", "-verify", "-inform", "DER", "-binary", "-noverify",
                "-nointern", "-certfile", str(cert), "-in", str(signature),
                "-out", str(temp / "verified.json"), env=env, capture_output=True)
        else:
            if cached.get("grapheneos", "") > version:
                raise RuntimeError("Refusing APatch feed downgrade")
            builder = workspace / "builder"
            script = builder / "rooted-ota.sh"
            blob = run("git", "-C", str(builder), "hash-object", str(script),
                       capture_output=True, text=True).stdout.strip()
            head = run("git", "-C", str(builder), "rev-parse", "HEAD",
                       capture_output=True, text=True).stdout.strip()
            if head != BUILDER or blob != BLOB:
                raise RuntimeError("Custota downloader is not the inspected builder")
            local = workspace / "apatch-builder/dist" / name
            ota = local if local.exists() else temp / name
            if not local.exists():
                url = f"https://github.com/{REPO}/releases/download/{tag}/{name}"
                if release["draft"]:
                    auth = os.environ.copy()
                    auth["GH_TOKEN"] = auth.get("GITHUB_TOKEN") or auth["GH_TOKEN"]
                    asset = next(a for a in release["assets"] if a["name"] == name)
                    with ota.open("wb") as stream:
                        run("gh", "api", f"repos/{REPO}/releases/assets/{asset['id']}",
                            "-H", "Accept: application/octet-stream", env=auth, stdout=stream)
                else:
                    run("curl", "--fail", "--silent", "--show-error", "--location",
                        "--retry", "3", "--proto", "=https", "--proto-redir", "=https",
                        "--output", str(ota), url, env=env)
            if ota.stat().st_size != meta["size"] or digest(ota) != meta["sha256"]:
                raise RuntimeError("APatch OTA does not match verified release digest")
            verify_zip(ota, version)
            key = temp / "ota.key"
            key.write_bytes(base64.b64decode(os.environ["KEY_OTA_BASE64"], validate=True))
            key.chmod(0o600)
            # Upstream downloader verifies the author's SSH signature for custota-tool 6.6.
            run("bash", "-euo", "pipefail", "-c",
                'source rooted-ota.sh; downloadCusotaTool', cwd=builder, env=env)
            tool = builder / ".tmp/custota-tool"
            run(str(tool), "gen-csig", "--input", str(ota), "--output", str(signature),
                "--key", str(key), "--cert", str(cert),
                "--passphrase-env-var", "PASSPHRASE_OTA", env=env)
            run(str(tool), "show-csig", "--input", str(signature), "--cert", str(cert),
                "--raw", env=env, stdout=subprocess.DEVNULL)
    record["csig_sha256"] = digest(signature)
    location = f"https://github.com/{REPO}/releases/download/{tag}/{name}"
    feed = {"version": 2, "full": {"location_ota": location,
            "location_csig": f"{SITE}/apatch/{signature_name}"}, "incremental": {}}
    (output / "blazer.json").write_text(json.dumps(feed, indent=2) + "\n")
    (output / "manifest.json").write_text(json.dumps(record, indent=2) + "\n")
    print("Verified APatch Custota metadata:", location, flush=True)
    return output

def write_feed(repo, prepared):
    target = Path(repo) / "apatch"
    old = target / "manifest.json"
    record = json.loads((prepared / "manifest.json").read_text())
    if old.exists() and json.loads(old.read_text())["grapheneos"] > record["grapheneos"]:
        raise RuntimeError("Refusing APatch feed downgrade")
    target.mkdir(exist_ok=True)
    paths = []
    for name in ("blazer.json", "manifest.json", record["signature"]):
        shutil.copyfile(prepared / name, target / name)
        paths.append("apatch/" + name)
    return paths
