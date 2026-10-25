#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and test an exact-payload, exact-kernel SUSFS signature KPM."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
KERNEL = "6.6.144-android15-8-g92137a1ac9ec-4k"
PAYLOAD_SHA = "84bfe5d4b9b8989a4413061c95d92aa157e4851df0492a70d2e458397dc55e90"
HOST_TEST = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fingerprint.h"
static int rd(void *dst, const void *src, unsigned long n) { memcpy(dst, src, n); return 1; }
static int fail_rd(void *dst, const void *src, unsigned long n) { return 0; }
int main(int argc, char **argv) {
    unsigned char *image = malloc(SUSFS_IMAGE_SIZE);
    FILE *f = fopen(argv[1], "rb");
    if (!f || !image || fread(image, 1, SUSFS_IMAGE_SIZE, f) != SUSFS_IMAGE_SIZE) return 2;
    fclose(f);
    if (!susfs_fingerprint_matches(image, SUSFS_IMAGE_SIZE, rd)) return 3;
    for (unsigned int i = 0; i < SUSFS_RANGE_COUNT; i++)
        memset(image + susfs_ranges[i][0], 0xa5, susfs_ranges[i][1]);
    if (!susfs_fingerprint_matches(image, SUSFS_IMAGE_SIZE, rd)) return 4;
    if (susfs_fingerprint_matches(image, SUSFS_IMAGE_SIZE - 1, rd)) return 5;
    if (susfs_fingerprint_matches(image, SUSFS_IMAGE_SIZE, fail_rd)) return 6;
    image[0] ^= 1;
    if (susfs_fingerprint_matches(image, SUSFS_IMAGE_SIZE, rd)) return 7;
    free(image);
    puts("PASS: original/mutated loader fields accepted; code changes, wrong size and failed reads rejected");
    return 0;
}
'''

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def main():
    kp = Path(sys.argv[1]).resolve()
    prefix = sys.argv[2]
    dest = Path(sys.argv[3]).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    work = dest / "sig-adapter-source"
    work.mkdir()
    payload = Path(".tmp/private-susfs/susfs_guard_lkm.ko").resolve()
    data = payload.read_bytes()
    if hashlib.sha256(data).hexdigest() != PAYLOAD_SHA or len(data) != 2489936:
        raise RuntimeError("Unexpected SUSFS input")
    shoff = struct.unpack_from("<Q", data, 40)[0]
    shentsize, shnum, shstridx = struct.unpack_from("<HHH", data, 58)
    if shentsize != 64 or shoff + shnum * 64 > len(data):
        raise RuntimeError("Bad ELF sections")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * 64) for i in range(shnum)]
    shstr = sections[shstridx]
    names = data[shstr[4]:shstr[4] + shstr[5]]
    ranges = []
    for entry in sections:
        name = names[entry[0]:].split(b"\0", 1)[0]
        off, size = entry[4:6]
        if entry[1] == 2:
            if entry[9] != 24 or size % 24: raise RuntimeError("Bad ELF symbol table")
            for pos in range(off, off + size, 24):
                st_name, _, _, index, _, _ = struct.unpack_from("<IBBHQQ", data, pos)
                if index == 0 and st_name:
                    ranges.append((pos + 6, 10))
        if name == b".modinfo":
            start = off
            for value in data[off:off + size].split(b"\0"):
                if value.startswith(b"vermagic="):
                    ranges.append((start + len(b"vermagic="), len(value) - len(b"vermagic=")))
                start += len(value) + 1
    ranges.sort()
    if len(ranges) != 103:
        raise RuntimeError(f"Unexpected mutable-field set: {len(ranges)}")
    normalized = bytearray(data)
    previous = 0
    for start, size in ranges:
        if start < previous or start + size > len(data):
            raise RuntimeError("Invalid normalization range")
        normalized[start:start + size] = bytes(size)
        previous = start + size
    digest = hashlib.sha256(normalized).digest()
    header = (
        f'#define SUSFS_IMAGE_SIZE {len(data)}UL\n'
        f'#define SUSFS_RANGE_COUNT {len(ranges)}\n'
        f'#define SUSFS_KERNEL_PREFIX "Linux version {KERNEL} "\n'
        'static const unsigned long susfs_ranges[SUSFS_RANGE_COUNT][2] = {\n'
        + "".join(f"    {{{start}UL, {size}UL}},\n" for start, size in ranges)
        + '};\nstatic const unsigned char susfs_expected_sha[32] = {'
        + ",".join(str(x) for x in digest) + '};\n')
    (work / "payload_ranges.h").write_text(header)
    for filename in ("fingerprint.h", "susfs_sig_allow.c"):
        shutil.copyfile(ROOT / ".github/kpm" / filename, work / filename)
    # Keep the reused SHA implementation and its original attribution.
    for filename in ("sha256.c", "sha256.h"):
        shutil.copyfile(kp / "tools/lib/sha" / filename, work / filename)
    (work / "host_test.c").write_text(HOST_TEST)
    run("cc", "-O1", "-g", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
        "-I", str(work), str(work / "host_test.c"), str(work / "sha256.c"),
        "-o", str(work / "host_test"))
    run(str(work / "host_test"), str(payload))
    includes = [work] + [kp / "kernel" / part for part in
        (".", "include", "patch/include", "linux/include",
         "linux/arch/arm64/include", "linux/tools/arch/arm64/include")]
    flags = [flag for path in includes for flag in ("-I", str(path))]
    objects = []
    for name in ("susfs_sig_allow", "sha256"):
        obj = work / f"{name}.o"
        run(prefix + "gcc", "-O2", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
            "-fno-pic", "-mgeneral-regs-only", "-mno-outline-atomics",
            *flags, "-c", str(work / f"{name}.c"), "-o", str(obj))
        objects.append(str(obj))
    run(prefix + "gcc", "-nostdlib", "-r", "-o", str(dest / "susfs_sig_allow.kpm"), *objects)
    undefined = run(prefix + "nm", "-u", str(dest / "susfs_sig_allow.kpm"),
                    capture_output=True, text=True).stdout
    expected = {"compat_copy_to_user", "current_uid", "hook_wrap", "kallsyms_lookup_name", "kver", "printk", "hook_unwrap_remove"}
    found = {line.split()[-1] for line in undefined.splitlines() if line.split()}
    if found - expected:
        raise RuntimeError("Unexpected KPM dependencies: " + repr(found - expected))
    (dest / "susfs_sig_allow.build.json").write_text(json.dumps({
        "tested_kernel": KERNEL, "original_payload_sha256": PAYLOAD_SHA,
        "normalized_payload_sha256": digest.hex(), "normalized_ranges": ranges,
        "scope": "only original EKEYREJECTED, uid 0, exact size and exact normalized payload",
        "global_signature_enforcement_changed": False, "hardware_tested": False,
        "host_security_tests": "pass", "undefined_symbols": sorted(found),
    }, indent=2) + "\n")
    import tarfile
    with tarfile.open(dest / "susfs_sig_allow-source.tar.gz", "w:gz") as archive:
        for path in sorted(work.iterdir()):
            if path.suffix in {".c", ".h"}:
                archive.add(path, arcname="susfs_sig_allow/" + path.name)
    print("PASS: scoped signature KPM compiled and fingerprint security tests passed")

if __name__ == "__main__":
    main()
