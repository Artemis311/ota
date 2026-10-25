#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a pinned SUSFS LKM companion for private APatch hardware testing."""
import hashlib
import json
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
ZIP_NAME = "SUSFS-APatch-test-v2.3.0-r18.4-blazer.zip"

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
for f in boot-completed.sh load.sh action.sh rearm.sh; do
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
  echo "--- Last attempt ---"
  cat "$MODDIR/status.txt" 2>/dev/null
  if [ -e /proc/susfs_path ]; then
    echo "Live SUSFS control node: present"
  else
    echo "Live SUSFS control node: absent or inaccessible"
  fi
  echo "--- Loader and ABI logs ---"
  cat "$MODDIR/load.log" "$MODDIR/abi-version.txt" "$MODDIR/abi-variant.txt" "$MODDIR/mount-command.txt" 2>/dev/null
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

NOTES = """SUSFS LKM + APatch private test for Pixel 10 Pro (blazer)

This is an APatch AndroidPatch Module (APM), NOT a .kpm and NOT an OTA.
It uses inforcqb/susfs4ksu-lkm v2.3.0-r18.4, not sidex15's helper module.
The OTA in this release embeds only the existing SELinux filter KPM.
Installing the OTA alone does NOT install or load SUSFS.

1. Install the signed APatch OTA only if you still need that OS/root build.
   If already running this same SELinux-only APatch build, an OTA reflash
   is not required just to test the companion module.
2. Wait for any virtual A/B update/snapshot merge to finish.
3. In APatch, install SUSFS-APatch-test-v2.3.0-r18.4-blazer.zip under
   AndroidPatch Modules / AP modules, NOT under KernelPatch Modules.
4. Reboot. The module makes ONE load attempt after sys.boot_completed=1.
5. Use the module's Action button to show/export diagnostics:
   Download/susfs-apatch-test-log.txt.
   Logs also remain at /data/adb/modules/susfs_apatch_test/.

Scope and checks:
- Only blazer, arm64, KMI android15-6.6 (or unambiguous tagless 6.6).
  The Android tag is the KMI generation, not the installed Android release.
- Upstream loader and .ko downloads are pinned by SHA-256.
- Checksums are also verified on installation and before a runtime load.
- Existing SUSFS is skipped; no second load is attempted.
- Attempt marker is persisted before loading, preventing repeated panics
  from the same automatic test on subsequent boots.
- Loader exit code, SUSFS ABI response, rule command results and kernel
  diagnostics are recorded separately. They do not prove apps are fooled.
- Minimal rules: /data/adb plus existing /debug_ramdisk, /sbin/.magisk,
  /dev/.magisk paths; mount hiding limited to /data/adb/.
- No uname/bootconfig spoofing, audit-log spoofing, permissive SELinux,
  Zygisk injection or sidex15 scripts are added.
- APatch has no KernelSU exclusion predicate. The upstream LKM falls back
  to app UID based hiding; APatch's per-app grant/exclusion list is NOT used.
- This build does NOT fix the previously observed APatch apd crash.
  If AP modules/boot-completed scripts do not run, SUSFS will not autoload.
- A normal userspace load failure is logged. A kernel panic is still
  possible: loading third-party kernel hooks is not made safe by logging.

The first load attempt remains disarmed even after success: this is a
hardware test, not persistent production hiding. After reboot the LKM is
gone. To run another test AFTER that reboot, as root:
  sh /data/adb/modules/susfs_apatch_test/rearm.sh
Then reboot once more. No live hot-unload or same-boot retry is provided.

To stop: disable/remove this AP module and reboot. The rootless OTA cannot
delete /data/adb modules, so disable this module before switching back to
a rooted build. Preserve diagnostics before removal.
Keep the release private (draft) and check SHA256SUMS.
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
    if b"vermagic=6.6." not in ko or b"android15" not in ko:
        raise RuntimeError("Wrong kernel generation in SUSFS module")
    client = work / "susfs_sc"
    run("clang", "--target=aarch64-linux-gnu", "-O2", "-nostdlib", "-static-pie",
        "-fno-stack-protector", "-fuse-ld=lld", "-Wl,-e,_start",
        "-o", str(client), str(source / "tools/susfs_sc.c"))
    files["bin/susfs_sc"] = client.read_bytes()
    validate_elf(files["bin/susfs_sc"], 3, "susfs_sc")
    strings = {
        "module.prop": f"id={MODULE_ID}\nname=SUSFS APatch - private test\nversion={TAG}-apatch-test1\n"
                       "versionCode=2026102501\nauthor=inforcqb; APatch test wrapper: Artemis311\n"
                       "description=ARMED: one SUSFS load attempt after boot completed; hardware untested\n",
        "customize.sh": CUSTOMIZE, "boot-completed.sh": BOOT_COMPLETED,
        "load.sh": LOAD, "action.sh": ACTION, "rearm.sh": REARM,
        "paths.txt": "/data/adb\n/debug_ramdisk\n/sbin/.magisk\n/dev/.magisk\n",
        "kmis": "android15-6.6\n", "skip_mount": "", "README.txt": NOTES,
    }
    files.update({name: data.encode() for name, data in strings.items()})
    files["kmi.sh"] = (source / "module/kmi.sh").read_bytes()
    files["LICENSE"] = (source / "LICENSE").read_bytes()
    files["sources/susfs_sc.c"] = (source / "tools/susfs_sc.c").read_bytes()
    files["sources/susfs_insmod.c"] = (source / "tools/susfs_insmod.c").read_bytes()
    provenance = {
        "repository": f"https://github.com/{REPO}", "tag": TAG, "commit": COMMIT,
        "upstream_assets_sha256": ASSETS, "tested_on_hardware": False,
        "integration": "separately installed APatch APM; boot-completed, single attempt",
        "kmi": "android15-6.6", "root_manager": "APatch 11282",
        "uses_apatch_exclusion_list": False,
        "client_build": "clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie -fno-stack-protector -fuse-ld=lld -Wl,-e,_start",
    }
    files["provenance.json"] = (json.dumps(provenance, indent=2) + "\n").encode()
    files["SHA256SUMS"] = "".join(f"{sha(data)}  {name}\n" for name, data in sorted(files.items())).encode()
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
    run("git", "-C", str(source), "archive", "--format=tar.gz", "--prefix=susfs4ksu-lkm/",
        f"--output={str((dist / 'SUSFS-upstream-source-v2.3.0-r18.4.tar.gz').resolve())}", "HEAD")
    (dist / "SUSFS-TEST-INSTRUCTIONS.txt").write_text(NOTES)
    (dist / "SUSFS-PROVENANCE.json").write_text(json.dumps(provenance, indent=2) + "\n")
    print(f"Verified APatch companion: {target} sha256={sha(target.read_bytes())}")
    print("PASS: source commit, payload hashes, AArch64 ELF/KMI, shell syntax, ZIP contents.")
    print("Hardware loading and root detection remain untested.")

if __name__ == "__main__":
    main()
