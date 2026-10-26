#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Identify the stock kernel by its banner; retain only the reviewed BBRv1 code."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import urllib.request

REVIEWED_BBR_SHA = "ba7d0706259dfef5bf455f26ac4bab65f43b9209b9cfd4f761c64c89816bdfe4"

def identify_kernel(data):
    match = re.search(rb"Linux version ([^\x00\s]+)", data)
    if not match:
        raise RuntimeError("Cannot identify the actual OTA kernel")
    kernel = match.group(1).decode("ascii")
    identity = re.fullmatch(r"6\.6\.\d+-android\d+-\d+-g([0-9a-f]{12,40})(?:-[A-Za-z0-9._-]+)?", kernel)
    if not identity:
        raise RuntimeError("Unreviewed kernel family or banner: " + kernel)
    if "dirty" in kernel:
        raise RuntimeError("Cannot bind a dirty kernel to immutable source")
    return kernel, identity.group(1)

def validate_config(settings):
    if settings.get("CONFIG_TCP_CONG_BBR") != "y" or settings.get("CONFIG_NET_SCH_FQ") != "y":
        raise RuntimeError("The stock kernel must include BBRv1 and fq")
    if any(settings.get(k) in {"y", "m"} for k in ("CONFIG_TCP_CONG_BBR2", "CONFIG_TCP_CONG_BBR3")):
        raise RuntimeError("Additional BBR generations need review")

def read_url(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()

def main():
    kernel_path, tool, dest = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3])
    kernel, prefix = identify_kernel(kernel_path.read_bytes())
    # Preserve the already tested profile byte-for-byte for the original base.
    if kernel == "6.6.144-android15-8-g92137a1ac9ec-4k":
        from prepare_private_bbr import main as reviewed_main
        reviewed_main()
        return
    config = subprocess.run([tool, "-i", str(kernel_path), "-f"], check=True,
                            capture_output=True, text=True).stdout
    settings = dict(re.findall(r"(?m)^(CONFIG_[A-Z0-9_]+)=(.*)$", config))
    validate_config(settings)
    repo = "GrapheneOS/kernel_common-6.6"
    resolved = json.loads(read_url(f"https://api.github.com/repos/{repo}/commits/{prefix}"))
    commit = resolved.get("sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not commit.startswith(prefix):
        raise RuntimeError("Kernel source commit does not match the actual image")
    url = f"https://raw.githubusercontent.com/{repo}/{commit}/net/ipv4/tcp_bbr.c"
    source = read_url(url)
    if hashlib.sha256(source).hexdigest() != REVIEWED_BBR_SHA:
        raise RuntimeError("Stock BBR code changed; review required before automatic publication")
    actions = ("    write /proc/sys/net/ipv4/tcp_congestion_control bbr\n"
               "    write /proc/sys/net/core/default_qdisc fq\n")
    rc = ("# Select the reviewed stock BBRv1 implementation.\non post-fs-data\n" + actions +
          "\non property:sys.boot_completed=1\n" + actions)
    report = {
        "kernel": kernel, "source_commit": commit, "source_url": url,
        "source_sha256": REVIEWED_BBR_SHA, "selected_algorithm": "bbr",
        "implementation": "BBRv1", "fq_built_in": True, "bbr2_present": False,
        "bbr3_present": False, "compiled_kernel_default_changed": False,
        "setting_method": "init writes at post-fs-data and boot-completed",
        "hardware_verified": False,
        "config": {k: v for k, v in settings.items() if "TCP_CONG" in k or k == "CONFIG_NET_SCH_FQ"},
    }
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "private_bbr.rc").write_text(rc)
    (dest / "BBR-PROFILE.json").write_text(json.dumps(report, indent=2) + "\n")
    (dest / "tcp_bbr-source.c").write_bytes(source)
    print("PASS: actual stock OTA kernel and exact BBRv1 source verified:", kernel)

if __name__ == "__main__":
    main()
