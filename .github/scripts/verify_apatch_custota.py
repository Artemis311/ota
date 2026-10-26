"""Verify Custota contents, both SELinux policy copies and all filesystem changes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

CUSTOTA_SHA = "e5a1480b53bfedc20e702541573683d6a68dacb7804792621dd7248c37ad97b6"
AUTHOR_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDOe6/tBnO7xZhAWXRj3ApUYgn+XZ0wnQiXM8B7tPgv4"

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def inventory(root):
    result = {}
    for path in root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_symlink():
            result[name] = ("link", os.readlink(path))
        elif path.is_file():
            result[name] = ("file", sha(path))
        elif not path.is_dir():
            result[name] = ("special", path.lstat().st_mode)
    return result

def compare(expected, actual, label):
    left, right = inventory(expected), inventory(actual)
    differences = [key for key in sorted(left.keys() | right.keys()) if left.get(key) != right.get(key)]
    if differences:
        raise RuntimeError(label + " contains unexpected differences: " + repr(differences))

def verify(stock, patched, module, cert):
    stock, patched, module, cert = [Path(p).resolve() for p in (stock, patched, module, cert)]
    tools = Path(".tmp").resolve()
    if sha(module) != CUSTOTA_SHA:
        raise RuntimeError("Unexpected Custota 6.7 ZIP digest")
    with tempfile.TemporaryDirectory(prefix="custota-verify-", dir=tools) as tmp:
        tmp = Path(tmp)
        trusted = tmp / "allowed_signers"
        trusted.write_text("chenxiaolong " + AUTHOR_KEY + "\n")
        with module.open("rb") as incoming:
            run("ssh-keygen", "-Y", "verify", "-I", "chenxiaolong", "-f", str(trusted),
                "-n", "file", "-s", str(module) + ".sig", stdin=incoming)
        with zipfile.ZipFile(module) as archive:
            entries = [n for n in archive.namelist() if n.endswith((".apk", ".xml"))]
            if not any(n.endswith(".apk") and "com.chiller3.custota" in n for n in entries):
                raise RuntimeError("Custota application is missing")
            if not any("/permissions/" in n for n in entries):
                raise RuntimeError("Custota privileged permission file is missing")
            for name in entries:
                if not name.startswith("system/") or ".." in Path(name).parts:
                    raise RuntimeError("Unexpected Custota injection path")
            binary = tmp / "custota-selinux"
            binary.write_bytes(archive.read("custota-selinux.x86_64"))
            binary.chmod(0o700)
            seapp = archive.read("plat_seapp_contexts") + b"\n"
            policy_hashes = {}
            for part in ("system", "product", "vendor", "vendor_boot"):
                base = tmp / part
                for label, ota in (("expected", stock), ("actual", patched)):
                    folder = base / label
                    folder.mkdir(parents=True)
                    run(str(tools / "avbroot"), "ota", "extract", "--input", str(ota),
                        "--directory", str(folder), "--partition", part)
                    image = folder / (part + ".img")
                    run(str(tools / "avbroot"), "avb", "unpack", "--quiet",
                        "--input", str(image), cwd=folder)
                    image.unlink()
                    if part == "vendor_boot":
                        run(str(tools / "avbroot"), "boot", "unpack", "--quiet",
                            "--input", str(folder / "raw.img"), cwd=folder)
                        run(str(tools / "avbroot"), "cpio", "unpack", "--quiet",
                            "--input", str(folder / "ramdisk.img.0"), cwd=folder)
                    else:
                        run(str(tools / "afsr"), "unpack", "--input", str(folder / "raw.img"), cwd=folder)
                    (folder / "raw.img").unlink()
                tree = "cpio_tree" if part == "vendor_boot" else "fs_tree"
                expected, actual = base / "expected" / tree, base / "actual" / tree
                if part == "system":
                    for name in entries:
                        path = expected / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_bytes(archive.read(name))
                    context = expected / "system/etc/selinux/plat_seapp_contexts"
                    context.write_bytes(context.read_bytes() + seapp)
                    for source, dest in (("private_bbr.rc", "system/etc/init/private_bbr.rc"),
                                         ("BBR-PROFILE.json", "system/etc/private-bbr.json")):
                        shutil.copyfile(tools / "private-bbr" / source, expected / dest)
                # avbroot replaces the OTA trust store in both Android and the recovery ramdisk.
                if part in ("system", "vendor_boot"):
                    relative = "system/etc/security/otacerts.zip"
                    with zipfile.ZipFile(actual / relative) as certificates:
                        contents = [certificates.read(n) for n in certificates.namelist() if not n.endswith("/")]
                    if contents != [cert.read_bytes()]:
                        raise RuntimeError("Installed OTA trust certificate does not match this repository: " + part)
                    shutil.copyfile(actual / relative, expected / relative)
                if part in ("vendor", "vendor_boot"):
                    policy = "etc/selinux/precompiled_sepolicy" if part == "vendor" else "sepolicy"
                    run(str(binary), "--source", str(expected / policy), "--target", str(expected / policy))
                    policy_hashes[part] = sha(actual / policy)
                compare(expected, actual, part)
                print("Verified exact Custota integration:", part, flush=True)
                shutil.rmtree(base)
            # Android and recovery policies can legitimately differ. Each copy was
            # checked above against its own stock policy plus the exact Custota rules.
            report = {"custota": "6.7", "module_sha256": CUSTOTA_SHA,
                      "apk_xml_files": entries, "selinux_policies": policy_hashes,
                      "server": "https://artemis311.github.io/ota/apatch/",
                      "verified": True}
            (tools / "CUSTOTA-INTEGRATION.json").write_text(json.dumps(report, indent=2) + "\n")

if __name__ == "__main__":
    verify(*sys.argv[1:])
