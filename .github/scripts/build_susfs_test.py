#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a pinned SUSFS LKM companion for private APatch hardware testing."""
import hashlib
import json
import re
from pathlib import Path
import struct
import subprocess
import sys
import urllib.request
import zipfile

REPO = "inforcqb/susfs4ksu-lkm"
COMMIT = "8b65f13f3eff4e9d530c92a92dde6133b0700ae7"
TAG = "v2.3.0-r18.4"
ASSETS = {
    "susfs_guard_lkm-android15-6.6.ko":
        "84bfe5d4b9b8989a4413061c95d92aa157e4851df0492a70d2e458397dc55e90",
    "susfs_insmod":
        "16a722d2158ff629e9e3d6d056e8333f15971410965ce5894216ed80dbfa44a4",
}
MODULE_ID = "susfs_apatch_test"
ZIP_NAME = "SUSFS-APatch-test2-v2.3.0-r18.4-blazer.zip"

CUSTOMIZE = r'''#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
[ "$APATCH" = true ] || [ -n "$APATCH_VER_CODE" ] || abort "- APatch required."
[ "$ARCH" = arm64 ] || abort "- arm64 only."
[ "$(getprop ro.product.device)" = blazer ] || abort "- This private test is for blazer only."
REL=$(cat /proc/sys/kernel/osrelease) || abort "- Cannot read kernel release."
. "$MODPATH/kmi.sh"
KMI=$(select_kmi "$REL" "$MODPATH") || abort "- No matching KMI for $REL (requires android15-6.6)."
(cd "$MODPATH" && sha256sum -c SHA256SUMS) || abort "- Payload integrity check failed."
set_perm_recursive "$MODPATH" 0 0 0755 0644
for f in boot-completed.sh load.sh action.sh rearm.sh bbr.sh; do
  set_perm "$MODPATH/$f" 0 0 0755
done
set_perm "$MODPATH/bin/susfs_insmod" 0 0 0755
set_perm "$MODPATH/bin/susfs_sc" 0 0 0755
touch "$MODPATH/skip_mount"
ui_print "- SUSFS LKM $KMI; APatch test wrapper by Artemis311."
ui_print "- One automatic attempt AFTER boot completed; no early-boot hooks."
ui_print "- Failed/interrupted attempts stay disarmed across reboots."
ui_print "- Not sidex15's module. Do not stack with another SUSFS loader."
ui_print "- After reboot: module Action displays and exports diagnostics."
'''

BOOT_COMPLETED = r'''#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=$(dirname "$0")
# APatch 11282 supports this non-blocking stage; never use post-fs-data here.
(cd "$MODDIR" && sha256sum -c SHA256SUMS) || exit 1
/system/bin/sh "$MODDIR/bbr.sh"
exec /system/bin/sh "$MODDIR/load.sh"
'''

LOAD = r'''#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=$(dirname "$0")
umask 077
[ "$(id -u)" = 0 ] || exit 1
[ ! -e "$MODDIR/disable" ] && [ ! -e "$MODDIR/remove" ] || exit 0
[ "$(getprop sys.boot_completed)" = 1 ] || exit 0
[ "$(getprop persist.sys.safemode)" != 1 ] || exit 0
[ "$(getprop ro.sys.safemode)" != 1 ] || exit 0
[ "$(getprop ro.product.device)" = blazer ] || exit 1
# Atomic lock persists through a panic/reboot. A failed first attempt is not retried.
mkdir "$MODDIR/attempt.lock" 2>/dev/null || exit 0
exec >>"$MODDIR/load.log" 2>&1
status() {
  printf '%s\n' "$1" > "$MODDIR/status.txt"
  sed -i "s#^description=.*#description=$1#" "$MODDIR/module.prop"
}
snapshot() {
  dmesg > "$MODDIR/dmesg-after.txt" 2>&1
  for n in susfs_path susfs_hide_mounts susfs_kstat susfs_opath; do
    if [ -r "/proc/$n" ]; then
      cat "/proc/$n" > "$MODDIR/$n.txt" 2>&1
    fi
  done
}
echo "SUSFS APatch test: $(date)"
id
cat /proc/sys/kernel/osrelease
if [ -e /proc/susfs_path ] || [ -d /sys/module/susfs_guard_lkm ]; then
  status "SKIPPED: SUSFS already present; no second load attempted"
  exit 0
fi
if grep -q '^susfs_guard_lkm ' /proc/modules; then
  status "SKIPPED: SUSFS module already listed"
  exit 0
fi
REL=$(cat /proc/sys/kernel/osrelease) || exit 1
. "$MODDIR/kmi.sh"
KMI=$(select_kmi "$REL" "$MODDIR") || {
  status "FAILED: unsupported kernel KMI; retry disarmed"
  exit 1
}
(cd "$MODDIR" && sha256sum -c SHA256SUMS) || {
  status "FAILED: checksum mismatch; retry disarmed"
  exit 1
}
dmesg > "$MODDIR/dmesg-before.txt" 2>&1
/system/bin/truncate su module info susfs_sig_allow > "$MODDIR/adapter-info.txt" 2>&1
if ! grep -q 'susfs_sig_allow' "$MODDIR/adapter-info.txt"; then
  status "BLOCKED: signature adapter missing; install the matching test2 OTA first"
  snapshot
  exit 1
fi
status "ATTEMPTING: $KMI; interrupted attempts are not retried"
sync
"$MODDIR/bin/susfs_insmod" "$MODDIR/lib/susfs_guard_lkm-$KMI.ko" expose_proc=1
rc=$?
echo "susfs_insmod exit=$rc"
if [ "$rc" != 0 ]; then
  status "FAILED: susfs_insmod rc=$rc; retry disarmed"
  snapshot
  exit 1
fi
if ! "$MODDIR/bin/susfs_sc" 0x555e1 0000000000000000000000000000000000000000 > "$MODDIR/abi-version.txt" 2>&1; then
  status "PARTIAL: loader returned success but SUSFS ABI probe failed; retry disarmed"
  snapshot
  exit 1
fi
cat "$MODDIR/abi-version.txt"
"$MODDIR/bin/susfs_sc" 0x555e3 0000000000000000000000000000000000000000 > "$MODDIR/abi-variant.txt" 2>&1
if [ ! -w /proc/susfs_path ] || [ ! -w /proc/susfs_hide_mounts ]; then
  status "PARTIAL: SUSFS ABI works but proc controls unavailable; retry disarmed"
  snapshot
  exit 1
fi
# Small first rule set: no uname/bootconfig spoofing or SELinux audit changes.
rules_ok=1
printf 'set /data/adb/\n' > /proc/susfs_hide_mounts || rules_ok=0
while IFS= read -r target; do
  case "$target" in ''|'#'*) continue ;; esac
  [ -e "$target" ] || continue
  printf 'add %s\n' "$target" > /proc/susfs_path || rules_ok=0
done < "$MODDIR/paths.txt"
if ! "$MODDIR/bin/susfs_sc" 0x55561 0100000000000000 > "$MODDIR/mount-command.txt" 2>&1; then
  rules_ok=0
fi
cat "$MODDIR/mount-command.txt"
snapshot
if [ "$rules_ok" != 1 ]; then
  status "PARTIAL: SUSFS loaded; one or more hiding rules failed; retry disarmed"
  exit 1
fi
status "LOADED: ABI and rule commands accepted; app hiding still needs testing"
echo "No further automatic attempts. A reboot unloads this LKM."
echo "APatch has no KernelSU exclusion predicate; upstream falls back to app UID gating."
exit 0
'''

ACTION = r'''#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=$(dirname "$0")
umask 077
OUT="$MODDIR/diagnostics.txt"
{
  echo "SUSFS APatch private hardware test"
  date
  id
  cat /proc/sys/kernel/osrelease
  echo "--- BBR live settings ---"
  for key in tcp_available_congestion_control tcp_congestion_control; do
    printf '%s=' "$key"; cat "/proc/sys/net/ipv4/$key"
  done
  printf 'default_qdisc='; cat /proc/sys/net/core/default_qdisc
  cat /system/etc/private-bbr.json "$MODDIR/bbr.log" 2>/dev/null
  echo "--- Module loading restrictions ---"
  cat /proc/sys/kernel/modules_disabled /sys/module/module/parameters/sig_enforce 2>/dev/null
  echo "--- Last attempt ---"
  cat "$MODDIR/status.txt" 2>/dev/null
  if [ -e /proc/susfs_path ]; then
    echo "Live SUSFS control node: present"
  else
    echo "Live SUSFS control node: absent or inaccessible"
  fi
  echo "--- Loader and ABI logs ---"
  cat "$MODDIR/load.log" "$MODDIR/abi-version.txt" "$MODDIR/abi-variant.txt" "$MODDIR/mount-command.txt" "$MODDIR/adapter-info.txt" 2>/dev/null
  echo "--- Saved control-node snapshots ---"
  for f in susfs_path susfs_hide_mounts susfs_kstat susfs_opath; do
    cat "$MODDIR/$f.txt" 2>/dev/null
  done
  echo "--- Kernel diagnostics around the attempt ---"
  grep -iE 'susfs|kprobe|cfi|module.*(fail|denied|reject)|avc:.*(module|susfs)' "$MODDIR/dmesg-after.txt" 2>/dev/null
} > "$OUT"
cat "$OUT"
if [ -d /sdcard/Download ]; then
  cp "$OUT" /sdcard/Download/susfs-apatch-test-log.txt &&
    echo "Exported: Download/susfs-apatch-test-log.txt"
fi
echo "This action does not load or unload kernel code."
'''

REARM = r'''#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=$(dirname "$0")
[ "$(id -u)" = 0 ] || exit 1
if [ -e /proc/susfs_path ] || [ -d /sys/module/susfs_guard_lkm ]; then
  echo "SUSFS is loaded. Reboot first; do not rearm a live LKM."
  exit 1
fi
rmdir "$MODDIR/attempt.lock" 2>/dev/null || {
  echo "No empty attempt marker to rearm."
  exit 1
}
printf '%s\n' "ARMED: one attempt after the next completed boot" > "$MODDIR/status.txt"
echo "One test attempt armed for the next reboot."
'''


BBR = r'''#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
MODDIR=$(dirname "$0")
umask 077
exec > "$MODDIR/bbr.log" 2>&1
[ "$(id -u)" = 0 ] || exit 1
echo "BBR runtime verification: $(date)"
available=$(cat /proc/sys/net/ipv4/tcp_available_congestion_control)
echo "Available: $available"
chosen=""
for candidate in bbr3 bbr2 bbr; do
  case " $available " in *" $candidate "*) ;; *) continue ;; esac
  if printf '%s\n' "$candidate" > /proc/sys/net/ipv4/tcp_congestion_control; then
    chosen="$candidate"
    break
  fi
done
if [ -z "$chosen" ]; then
  echo "FAILED: no available BBR variant accepted; current setting unchanged"
  exit 1
fi
# The OTA profile identifies bbr as v1 for this exact kernel. The sysctl name
# alone cannot distinguish a future BBRv3 implementation also called bbr.
printf 'fq\n' > /proc/sys/net/core/default_qdisc || echo "fq default write failed"
actual=$(cat /proc/sys/net/ipv4/tcp_congestion_control)
echo "Selected: $chosen; readback: $actual"
echo "qdisc default: $(cat /proc/sys/net/core/default_qdisc)"
[ "$actual" = "$chosen" ]
'''

NOTES = """SUSFS signature-adapter test2 + automatic BBR for blazer

Install the matching NEW test2 signed APatch OTA before installing this AP module.
The OTA embeds SELinux filter + susfs_sig_allow and configures bbr/fq through init.
The rootless OTA has neither KPMs nor the BBR startup actions.

SUSFS-APatch-test2-v2.3.0-r18.4-blazer.zip is an AP module, NOT a KPM or OTA.
Update/install it in APatch AndroidPatch Modules after snapshot merge is finished.
It replaces test1 (same module ID), provides a rebuilt static-PIE loader, verifies
the signature adapter is present, and attempts SUSFS once after boot completed.
The signature KPM is restricted to the EXACT normalized SUSFS .ko fingerprint
and the tested kernel 6.6.144-android15-8-g92137a1ac9ec-4k. It changes no global
signature setting. Other images retain the original signature-check result.
The kernel may still log the ORIGINAL signature rejection immediately before the
adapter's explicit acceptance line. Read the full sequence, not one line alone.

Test2 fixes the loader's missing static-PIE self-relocation and smoke-tests its
error-reporting path under QEMU. The underlying SUSFS LKM is still the pinned
inforcqb v2.3.0-r18.4 release. It has not been tested on this physical phone.
Overcoming the signature gate does NOT prove kernel ABI/CFI/hook compatibility.
On failure/interruption the attempt remains disarmed across reboots.
Do not hot-unload the embedded signature adapter or the LKM.

BBR:
- The actual OTA kernel config and exact GrapheneOS source commit are inspected.
- The existing implementation is BBRv1. No BBRv2/v3 code is added.
- Init selects bbr + fq at post-fs-data and boot-completed on EVERY boot.
- The AP module separately checks runtime availability, selects the highest
  available named variant bbr3/bbr2/bbr and logs readback on every completed boot.
- BBR configuration is independent of the one-shot SUSFS attempt.
- This does not change QUIC/UDP congestion control or force existing socket choices.
- The compiled kernel default remains untouched; startup sets the running default.
- default_qdisc does not replace existing per-interface qdiscs.

Use the module Action button after reboot. It exports:
  Download/susfs-apatch-test-log.txt
including BBR readback, signature-adapter info, loader and kernel diagnostics.
Module logs also remain at /data/adb/modules/susfs_apatch_test/.

The first SUSFS attempt remains disarmed even after success. After a reboot,
as root, run sh /data/adb/modules/susfs_apatch_test/rearm.sh, then reboot again
to arm one more test. BBR startup settings do not need rearming.
Existing SUSFS is skipped. No second SUSFS loader or sidex15 helper is installed.
APatch exclusion lists are not used by the LKM: upstream app-UID gating applies.
NoHello, ReKernel and demo-hello remain removed.
Disable/remove this AP module and reboot to stop runtime SUSFS attempts.
Removing the embedded signature adapter or OTA BBR settings requires a newly
signed OTA; the supplied rootless OTA contains neither. Data modules persist.
Keep this release a draft and verify SHA256SUMS before installation.
"""

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def get(url):
    request = urllib.request.Request(url, headers={"User-Agent": "Artemis311-private-SUSFS-build"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return response.read()

def validate_elf(data, etype, label):
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError(f"{label}: expected little-endian ELF64")
    if struct.unpack_from("<HH", data, 16) != (etype, 183):
        raise RuntimeError(f"{label}: expected AArch64 ELF type {etype}")

def main():
    dist = Path(sys.argv[1])
    dist.mkdir(parents=True, exist_ok=True)
    work = Path(".tmp/private-susfs")
    work.mkdir(parents=True, exist_ok=True)
    source = work / "source"
    run("git", "init", str(source))
    run("git", "-C", str(source), "remote", "add", "origin", f"https://github.com/{REPO}.git")
    run("git", "-C", str(source), "fetch", "--depth", "1", "origin", COMMIT)
    run("git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD")
    actual = run("git", "-C", str(source), "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    if actual != COMMIT:
        raise RuntimeError("SUSFS source commit mismatch")
    files = {}
    for name, expected in ASSETS.items():
        data = get(f"https://github.com/{REPO}/releases/download/{TAG}/{name}")
        if sha(data) != expected:
            raise RuntimeError(f"Digest mismatch: {name}")
        validate_elf(data, 1 if name.endswith(".ko") else 3, name)
        files[("lib/" if name.endswith(".ko") else "bin/") + name] = data
    ko = files["lib/susfs_guard_lkm-android15-6.6.ko"]
    vermagic = re.search(rb"vermagic=([^\x00]+)", ko)
    if vermagic:
        print("SUSFS vermagic:", vermagic.group(1).decode(errors="replace"))
        if not vermagic.group(1).startswith(b"6.6."):
            raise RuntimeError("Wrong kernel version in the pinned asset")
    else:
        print("NOTE: pinned upstream asset has no vermagic record; generation is identified by release asset and SHA-256, not inferred from ELF metadata.")
    inspected_ko = work / "susfs_guard_lkm.ko"
    inspected_ko.write_bytes(ko)
    run("readelf", "-h", str(inspected_ko))
    subprocess.run(["readelf", "-p", ".modinfo", str(inspected_ko)], check=False)
    client = work / "susfs_sc"
    run("clang", "--target=aarch64-linux-gnu", "-O2", "-nostdlib", "-static-pie",
        "-fno-stack-protector", "-fno-builtin", "-fuse-ld=lld", "-Wl,-e,_start",
        "-o", str(client), str(source / "tools/susfs_sc.c"))
    # Freestanding -static-pie has no CRT to apply .rela.dyn. The upstream
    # entry called C directly, so global string-pointer tables could fault.
    loader_source = (source / "tools/susfs_insmod.c").read_text()
    old_entry = '"\\tmov\\tx29, #0\\n"\n"\\tldr\\tx0, [sp]\\n"'
    new_entry = (
        '"\\tmov\\tx29, #0\\n"\n'
        '"\\tadrp\\tx0, __ehdr_start\\n"\n'
        '"\\tadd\\tx0, x0, :lo12:__ehdr_start\\n"\n'
        '"\\tadrp\\tx1, _DYNAMIC\\n"\n'
        '"\\tadd\\tx1, x1, :lo12:_DYNAMIC\\n"\n'
        '"\\tbl\\tsusfs_relocate\\n"\n'
        '"\\tldr\\tx0, [sp]\\n"')
    if loader_source.count(old_entry) != 1:
        raise RuntimeError("Upstream loader entry differs from reviewed source")
    loader_source = loader_source.replace(old_entry, new_entry, 1)
    relocator = r'''
/* Private wrapper addition: apply ELF64 R_AARCH64_RELATIVE before using C data. */
void susfs_relocate(unsigned long base, long *dyn)
{
    unsigned long rela = 0, size = 0;
    for (; dyn[0]; dyn += 2) {
        if (dyn[0] == 7) rela = (unsigned long)dyn[1];
        if (dyn[0] == 8) size = (unsigned long)dyn[1];
    }
    if (!rela) return;
    unsigned long *r = (unsigned long *)(base + rela);
    for (unsigned long off = 0; off < size; off += 24, r += 3) {
        if ((unsigned int)r[1] == 1027)
            *(unsigned long *)(base + r[0]) = base + r[2];
    }
}
'''
    loader_source += relocator
    selftest = r'''
    /* Does not open a module, read kallsyms, or call init_module. */
    if (argc == 2 && s_eq_n(argv[1], "--selftest", 11)) {
        static const char record[] = "module verification failed: selftest\n";
        for (u64 t = 0; t < sizeof(record); ++t) kbuf[t] = record[t];
        kbuf_len = sizeof(record) - 1;
        kmsg_report();
        o_put(P "SELFTEST OK: relocated pointer tables and error reporting\n");
        o_flush();
        finish(0);
    }
'''
    anchor = "\t/* ---- argv ---- */"
    if loader_source.count(anchor) != 1:
        raise RuntimeError("Upstream loader argument block differs")
    loader_source = loader_source.replace(anchor, selftest + "\n" + anchor, 1)
    patched_loader = work / "susfs_insmod-pie.c"
    patched_loader.write_text(loader_source)
    loader = work / "susfs_insmod"
    run("clang", "--target=aarch64-linux-gnu", "-O2", "-nostdlib", "-static-pie",
        "-fPIC", "-fno-stack-protector", "-fno-builtin", "-fuse-ld=lld",
        "-Wl,-Bsymbolic", "-Wl,-e,_start", "-o", str(loader), str(patched_loader))
    relocations = run("readelf", "-rW", str(loader), capture_output=True, text=True).stdout
    if any("R_AARCH64_" in line and "R_AARCH64_RELATIVE" not in line for line in relocations.splitlines()):
        raise RuntimeError("Loader has relocations not supported by its self-relocator")
    for attempt in range(3):
        result = run("qemu-aarch64", str(loader), "--selftest", capture_output=True, text=True)
        if "SELFTEST OK" not in result.stdout:
            raise RuntimeError("Loader self-test output missing")
    bad_file = subprocess.run(["qemu-aarch64", str(loader), "/nonexistent/susfs.ko"],
                              capture_output=True, text=True)
    if bad_file.returncode != 2 or "ENOENT" not in bad_file.stdout:
        raise RuntimeError("Loader missing-file error path is broken: " + repr(bad_file))
    files["bin/susfs_insmod"] = loader.read_bytes()
    validate_elf(files["bin/susfs_insmod"], 3, "rebuilt susfs_insmod")
    print("PASS: loader static-PIE relocation and error paths under QEMU")

    files["bin/susfs_sc"] = client.read_bytes()
    validate_elf(files["bin/susfs_sc"], 3, "susfs_sc")
    strings = {
        "module.prop": f"id={MODULE_ID}\nname=SUSFS APatch - private test\nversion={TAG}-apatch-test2\n"
                       "versionCode=2026102502\nauthor=inforcqb; APatch test wrapper: Artemis311\n"
                       "description=ARMED: one SUSFS load attempt after boot completed; hardware untested\n",
        "customize.sh": CUSTOMIZE, "boot-completed.sh": BOOT_COMPLETED,
        "load.sh": LOAD, "action.sh": ACTION, "rearm.sh": REARM, "bbr.sh": BBR,
        "paths.txt": "/data/adb\n/debug_ramdisk\n/sbin/.magisk\n/dev/.magisk\n",
        "kmis": "android15-6.6\n", "skip_mount": "", "README.txt": NOTES,
    }
    files.update({name: data.encode() for name, data in strings.items()})
    files["kmi.sh"] = (source / "module/kmi.sh").read_bytes()
    files["LICENSE"] = (source / "LICENSE").read_bytes()
    files["sources/susfs_sc.c"] = (source / "tools/susfs_sc.c").read_bytes()
    files["sources/susfs_insmod.c"] = patched_loader.read_bytes()
    provenance = {
        "repository": f"https://github.com/{REPO}", "tag": TAG, "commit": COMMIT,
        "upstream_assets_sha256": ASSETS, "tested_on_hardware": False,
        "integration": "separately installed APatch APM; boot-completed, single attempt",
        "kmi": "android15-6.6", "root_manager": "APatch 11282",
        "loader": "locally rebuilt with static-PIE self-relocation; QEMU smoke tests passed",
        "requires_embedded_kpm": "susfs_sig_allow",
        "loader_sha256": sha(files["bin/susfs_insmod"]),
        "uses_apatch_exclusion_list": False,
        "client_build": "clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start",
    }
    files["provenance.json"] = (json.dumps(provenance, indent=2) + "\n").encode()
    # APatch deletes customize.sh after installation and module.prop is a mutable status card.
    files["SHA256SUMS"] = "".join(
        f"{sha(data)}  {name}\n" for name, data in sorted(files.items())
        if name not in {"customize.sh", "module.prop"}).encode()
    for name, data in files.items():
        if name.endswith(".sh"):
            run("sh", "-n", input=data)
    target = dist / ZIP_NAME
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            info = zipfile.ZipInfo(name, (2026, 10, 25, 0, 0, 0))
            mode = 0o755 if name.endswith(".sh") or name.startswith("bin/") else 0o644
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    with zipfile.ZipFile(target) as archive:
        if archive.testzip() is not None or set(archive.namelist()) != set(files):
            raise RuntimeError("Module ZIP verification failed")
        for name, data in files.items():
            if archive.read(name) != data:
                raise RuntimeError(f"Module ZIP differs: {name}")
    # Exercise checksums after the exact installer mutations, before shipping the ZIP.
    installed = work / "installed-fixture"
    installed.mkdir()
    with zipfile.ZipFile(target) as archive:
        archive.extractall(installed)
    (installed / "customize.sh").unlink()
    (installed / "module.prop").write_text("description=runtime status changed\\n")
    run("sha256sum", "-c", "SHA256SUMS", cwd=installed)
    run("git", "-C", str(source), "archive", "--format=tar.gz", "--prefix=susfs4ksu-lkm/",
        f"--output={str((dist / 'SUSFS-upstream-source-v2.3.0-r18.4.tar.gz').resolve())}", "HEAD")
    (dist / "SUSFS-TEST-INSTRUCTIONS.txt").write_text(NOTES)
    (dist / "SUSFS-PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Verified APatch companion: {target} sha256={sha(target.read_bytes())}")
    print("PASS: source commit, payload hashes, AArch64 ELF/KMI, shell syntax, ZIP contents.")
    print("Hardware loading and root detection remain untested.")

if __name__ == "__main__":
    main()
