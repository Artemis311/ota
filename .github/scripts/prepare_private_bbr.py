#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Inspect the actual boot kernel before choosing its TCP default."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

KERNEL = "6.6.144-android15-8-g92137a1ac9ec-4k"
COMMIT = "92137a1ac9ec89ead97b5695114ed250c03f3f48"

def main():
    kernel, tool, dest = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    dest.mkdir(parents=True, exist_ok=True)
    data = kernel.read_bytes()
    if ("Linux version " + KERNEL + " ").encode() not in data:
        raise RuntimeError("This test's signature adapter requires the exact tested kernel")
    config = subprocess.run([tool, "-i", str(kernel), "-f"], check=True,
                            capture_output=True, text=True).stdout
    settings = dict(re.findall(r"(?m)^(CONFIG_[A-Z0-9_]+)=(.*)$", config))
    if settings.get("CONFIG_TCP_CONG_BBR") != "y":
        raise RuntimeError("BBR is not built into this OTA kernel")
    if any(settings.get(k) in {"y", "m"} for k in
           ("CONFIG_TCP_CONG_BBR2", "CONFIG_TCP_CONG_BBR3")):
        raise RuntimeError("Additional BBR implementations require version identification before selecting")
    # Confirm implementation from the exact common-kernel commit in its banner.
    url = f"https://raw.githubusercontent.com/GrapheneOS/kernel_common-6.6/{COMMIT}/net/ipv4/tcp_bbr.c"
    with urllib.request.urlopen(url, timeout=60) as response:
        source = response.read()
    if b"bbr_lt_bw_sampling" not in source or b"bbr_pacing_gain[]" not in source or b"BBR_VERSION" in source:
        raise RuntimeError("BBR implementation differs from the reviewed v1 source")
    fq = settings.get("CONFIG_NET_SCH_FQ") == "y"
    actions = "    write /proc/sys/net/ipv4/tcp_congestion_control bbr\n"
    if fq:
        actions += "    write /proc/sys/net/core/default_qdisc fq\n"
    rc = ("# Private test: select the existing BBRv1 implementation, without new TCP code.\n"
          "on post-fs-data\n" + actions + "\n"
          "on property:sys.boot_completed=1\n" + actions)
    report = {
        "kernel": KERNEL, "source_commit": COMMIT, "source_url": url,
        "source_sha256": hashlib.sha256(source).hexdigest(),
        "selected_algorithm": "bbr", "implementation": "BBRv1",
        "reason": "highest BBR generation present in the reviewed stock kernel",
        "bbr2_present": False, "bbr3_present": False, "fq_built_in": fq,
        "setting_method": "init writes at post-fs-data and boot-completed",
        "compiled_kernel_default_changed": False,
        "config": {key: value for key, value in settings.items()
                   if "TCP_CONG" in key or key in {"CONFIG_DEFAULT_TCP_CONG", "CONFIG_NET_SCH_FQ"}},
        "hardware_verified": False,
    }
    (dest / "private_bbr.rc").write_text(rc)
    (dest / "BBR-PROFILE.json").write_text(json.dumps(report, indent=2) + "\n")
    (dest / "tcp_bbr-source.c").write_bytes(source)
    print("PASS: exact OTA kernel inspected; BBRv1 is present, BBRv2/v3 absent. Automatic bbr + fq configured.")
    print(json.dumps(report, indent=2))

if __name__ == "__main__":
    main()
