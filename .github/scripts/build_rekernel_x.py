#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the reviewed dynamic ReKernel-X KPM, never a generic baseline template."""
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess
import sys

COMMIT = "6ef236d224217a298c112d198c0e0f84c004ea6c"
VERSION = "1.6-20261010"

def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)

def main():
    kp, prefix, output = Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve()
    output.mkdir(parents=True, exist_ok=True)
    source = output / "rekernel-x-source"
    run("git", "init", str(source))
    run("git", "-C", str(source), "remote", "add", "origin", "https://github.com/lzghzr/APatch_kpm.git")
    run("git", "-C", str(source), "fetch", "--depth", "1", "origin", COMMIT)
    run("git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD")
    actual = run("git", "-C", str(source), "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    if actual != COMMIT:
        raise RuntimeError("ReKernel-X source revision differs")
    # Dynamic release only; upstream baseline artifacts contain device-specific offsets.
    run("make", "-C", str(source / "re_kernel_x"), "dynamic",
        "KP_DIR=" + str(kp), "TARGET_COMPILE=" + prefix)
    original = source / "re_kernel_x" / f"re_kernel_x_{VERSION}.kpm"
    target = output / "re_kernel_x.kpm"
    shutil.copyfile(original, target)
    data = target.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<HH", data, 16) != (1, 183):
        raise RuntimeError("ReKernel-X must be an AArch64 relocatable ELF")
    if b"name=re_kernel_x\x00" not in data:
        raise RuntimeError("Unexpected ReKernel-X KPM identity")
    report = {
        "source": "https://github.com/lzghzr/APatch_kpm",
        "commit": COMMIT,
        "version": VERSION,
        "variant": "dynamic; BTF or upstream inference; no static baseline offsets",
        "kernelpatch_source": run("git", "-C", str(kp), "rev-parse", "HEAD",
                                  capture_output=True, text=True).stdout.strip(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "hardware_tested": False,
        "purpose": "Freezer event integration, not root hiding",
        "requires": "ReKernel-X compatible controller; kernel module alone does not select apps to freeze",
        "boot_event": "post-kernel-init",
    }
    (output / "re_kernel_x.build.json").write_text(json.dumps(report, indent=2) + "\n")
    run("git", "-C", str(source), "archive", "--format=tar.gz", "--prefix=rekernel-x-upstream/",
        "--output=" + str(output / "re_kernel_x-source.tar.gz"), "HEAD")
    print("PASS: pinned dynamic ReKernel-X built; AArch64 ELF and KPM identity verified")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
