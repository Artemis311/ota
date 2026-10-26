#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Verify final OTA module bytes and preserve all unrelated files/permissions."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tomllib

PARTS = ("vendor_kernel_boot", "system_dlkm", "vendor_dlkm")

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def unpack(tools, ota, root, partition):
    run(str(tools / "avbroot"), "ota", "extract", "--input", str(ota),
        "--directory", str(root), "--partition", partition)
    folder = root / partition
    folder.mkdir()
    run(str(tools / "avbroot"), "avb", "unpack", "--quiet",
        "--input", str(root / (partition + ".img")), cwd=folder)
    if partition == "vendor_kernel_boot":
        run(str(tools / "avbroot"), "boot", "unpack", "--quiet",
            "--input", "raw.img", cwd=folder)
        run(str(tools / "avbroot"), "cpio", "unpack", "--quiet",
            "--input", "ramdisk.img.0", cwd=folder)
        tree, metadata = folder / "cpio_tree", folder / "cpio.toml"
    else:
        run(str(tools / "afsr"), "unpack", "--input", "raw.img", cwd=folder)
        tree, metadata = folder / "fs_tree", folder / "fs_metadata.toml"
    with metadata.open("rb") as stream:
        entries = tomllib.load(stream)["entries"]
    permissions = {}
    for entry in entries:
        path = entry["path"].lstrip("/")
        permissions[path] = {key: entry.get(key) for key in (
            "file_type", "file_mode", "uid", "gid", "xattrs", "symlink_target")}
    files = {}
    for path in tree.rglob("*"):
        name = str(path.relative_to(tree))
        if path.is_symlink():
            files[name] = ["symlink", str(path.readlink())]
        elif path.is_file():
            files[name] = ["file", sha(path)]
        elif path.is_dir():
            files[name] = ["directory"]
        else:
            # Device nodes are represented through the metadata, not file bytes.
            files[name] = ["special"]
    return files, permissions

def main():
    tools, stock, patched, result = map(lambda value: Path(value).resolve(), sys.argv[1:5])
    plan = json.loads((result / "installed-module-plan.json").read_text())
    root = tools / "pixel-modules-final-verification"
    root.mkdir()
    results = {}
    for partition in PARTS:
        before_root = root / (partition + "-stock")
        after_root = root / (partition + "-patched")
        before_root.mkdir()
        after_root.mkdir()
        old, old_meta = unpack(tools, stock, before_root, partition)
        new, new_meta = unpack(tools, patched, after_root, partition)
        if old_meta != new_meta or set(old) != set(new):
            raise RuntimeError("Module partition path/permission/SELinux metadata changed: " + partition)
        expected = {record["path"].lstrip("/"): record for record in plan["files"]
                    if record["partition"] == partition}
        actual_modules = {name for name in old if name.endswith(".ko")}
        if actual_modules != set(expected):
            raise RuntimeError("Final module slot set differs: " + partition)
        for name in old:
            if name in expected:
                record = expected[name]
                if old[name] != ["file", record["old_sha256"]] or new[name] != ["file", record["new_sha256"]]:
                    raise RuntimeError("Final OTA module digest mismatch: " + name)
            elif old[name] != new[name]:
                raise RuntimeError("Unexpected module-partition modification: " + name)
        results[partition] = {"modules_verified": len(expected), "other_files_and_metadata_preserved": True}
        shutil.rmtree(before_root)
        shutil.rmtree(after_root)
    (result / "FINAL-MODULE-VERIFICATION.json").write_text(json.dumps(results, indent=2) + "\n")
    print("PASS: final signed OTA contains the complete intended module replacement and no unrelated partition changes")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
