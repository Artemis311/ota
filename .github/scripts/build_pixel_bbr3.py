#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a complete Pixel muzel kernel/module set; do not weaken module signing."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request

PATCH_REPO = "https://github.com/WildKernels/kernel_patches.git"
PATCH_COMMIT = "159a8f3b93af582b07d0d44bfa7d08b96d667ec0"
PATCH_PATH = "common/bbrv3/0001-net-tcp-backport-BBRv3-to-android15-6.6.patch"
STOCK_COMMIT = "2069f4e6645302bf3504b81a77c72545b04912f5"
STOCK_BBR_SHA = "ba7d0706259dfef5bf455f26ac4bab65f43b9209b9cfd4f761c64c89816bdfe4"
PIXEL_URL = "https://gitlab.com/grapheneos/kernel_pixel_6.6.git"
EXPECTED = {
    "include/linux/tcp.h", "include/net/tcp.h", "include/uapi/linux/inet_diag.h",
    "include/uapi/linux/rtnetlink.h", "net/ipv4/Kconfig", "net/ipv4/Makefile",
    "net/ipv4/tcp.c", "net/ipv4/tcp_bbr3.c", "net/ipv4/tcp_cong.c",
    "net/ipv4/tcp_input.c", "net/ipv4/tcp_minisocks.c", "net/ipv4/tcp_output.c",
    "net/ipv4/tcp_rate.c",
}

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def checkout(url, commit, dest):
    run("git", "init", str(dest))
    run("git", "-C", str(dest), "remote", "add", "origin", url)
    run("git", "-C", str(dest), "fetch", "--depth", "1", "origin", commit)
    run("git", "-C", str(dest), "checkout", "--detach", "FETCH_HEAD")
    actual = run("git", "-C", str(dest), "rev-parse", "HEAD", capture_output=True, text=True).stdout.strip()
    if actual != commit:
        raise RuntimeError("Source pin mismatch")
    return actual

def main():
    dest = Path(sys.argv[1]).resolve()
    dest.mkdir(parents=True, exist_ok=True)
    workspace = dest.parent
    root = workspace / "pixel-source"
    # Resolve the official monolithic source once, then fetch only that immutable
    # commit. The exact pin and all recursive submodule pins are retained below.
    pin = os.environ.get("PIXEL_KERNEL_COMMIT", "").strip()
    if not pin:
        listing = run("git", "ls-remote", PIXEL_URL, "refs/heads/17",
                      capture_output=True, text=True).stdout.split()
        if len(listing) != 2:
            raise RuntimeError("Cannot resolve official Pixel source")
        pin = listing[0]
    if not re.fullmatch(r"[0-9a-f]{40}", pin):
        raise RuntimeError("Invalid Pixel source commit")
    checkout(PIXEL_URL, pin, root)
    run("git", "-C", str(root), "submodule", "update", "--init", "--recursive", "--depth", "1", "--jobs", "2")
    common = root / "common"
    if sha(common / "net/ipv4/tcp_bbr.c") != STOCK_BBR_SHA:
        raise RuntimeError("Pixel common TCP source differs from the reviewed 6.6.144 base")
    if not re.search(r"(?m)^SUBLEVEL = 144$", (common / "Makefile").read_text()):
        raise RuntimeError("This experiment is restricted to the reviewed 6.6.144 base")
    stock = workspace / "pixel-stock"
    checkout("https://github.com/GrapheneOS/device_google_laguna-kernels_6.6.git",
             STOCK_COMMIT, stock)
    stock = stock / "grapheneos/muzel"
    stock_modules = {p.name: sha(p) for p in stock.glob("*.ko")}
    if len(stock_modules) < 300:
        raise RuntimeError("Incomplete stock Pixel module inventory")
    patch_repo = workspace / "pixel-bbr-patches"
    checkout(PATCH_REPO, PATCH_COMMIT, patch_repo)
    patch = patch_repo / PATCH_PATH
    patch_text = patch.read_text()
    paths = set(re.findall(r"(?m)^diff --git a/(\S+) b/\S+$", patch_text))
    if paths != EXPECTED:
        raise RuntimeError("BBRv3 backport changes unexpected source paths")
    run("patch", "--dry-run", "--batch", "--fuzz=0", "-p1", "-d", str(common), "-i", str(patch))
    run("patch", "--batch", "--fuzz=0", "-p1", "-d", str(common), "-i", str(patch))
    source = common / "net/ipv4/tcp_bbr3.c"
    # The upstream Android backport moves BBR state out of icsk_ca_priv.
    # Its void init callback previously returned on kmalloc failure while leaving
    # BBR callbacks installed, which would dereference a NULL state later.
    # This build requires BBR3=y: both BBR3 and Reno are built-in (owner=NULL),
    # so no module/BPF owner reference is transferred by this local fallback.
    before = source.read_text()
    old_alloc = "\tbbr = kmalloc(sizeof(struct bbr3), GFP_ATOMIC);\n\tif (unlikely(!bbr))\n\t\treturn;"
    new_alloc = (
        "\t*bbr3_ptr = NULL;\n"
        "\tbbr = kmalloc(sizeof(struct bbr3), GFP_ATOMIC);\n"
        "\tif (unlikely(!bbr)) {\n"
        "\t\tinet_csk(sk)->icsk_ca_ops = &tcp_reno;\n"
        "\t\tmemset(inet_csk(sk)->icsk_ca_priv, 0, sizeof(inet_csk(sk)->icsk_ca_priv));\n"
        "\t\tpr_warn_ratelimited(\"bbr3: state allocation failed; this socket uses Reno\\n\");\n"
        "\t\treturn;\n"
        "\t}"
    )
    if before.count(old_alloc) != 1:
        raise RuntimeError("BBRv3 allocation path differs from the reviewed source")
    after = before.replace(old_alloc, new_alloc, 1)
    source.write_text(after)
    import difflib
    (dest / "BBRv3-private-oom.patch").write_text("".join(difflib.unified_diff(
        before.splitlines(True), after.splitlines(True),
        fromfile="a/net/ipv4/tcp_bbr3.c", tofile="b/net/ipv4/tcp_bbr3.c")))
    if not re.search(r'\.name\s*=\s*"bbr3"', source.read_text()):
        raise RuntimeError("Backport does not register bbr3")
    config = common / "arch/arm64/configs/gki_defconfig"
    config_text = config.read_text()
    config_text = re.sub(r"(?m)^(?:CONFIG_DEFAULT_(?:CUBIC|BBR|RENO)=.*|CONFIG_DEFAULT_TCP_CONG=.*)\n?", "", config_text)
    for name in ("CONFIG_TCP_CONG_ADVANCED", "CONFIG_TCP_CONG_BBR3", "CONFIG_DEFAULT_BBR3", "CONFIG_NET_SCH_FQ"):
        config_text = re.sub(r"(?m)^(?:" + name + r"=.*|# " + name + r" is not set)\n?", "", config_text)
        config_text += name + "=y\n"
    config.write_text(config_text)
    shutil.copyfile(patch, dest / "BBRv3-android15-6.6.patch")
    shutil.copyfile(source, dest / "tcp_bbr3-source.c")
    (dest / "pixel-source.patch").write_text(run("git", "-C", str(root), "diff",
                                                capture_output=True, text=True).stdout)
    submodules = run("git", "-C", str(root), "submodule", "status", "--recursive",
                     capture_output=True, text=True).stdout
    report = {
        "pixel_source_url": PIXEL_URL, "pixel_source_commit": pin,
        "submodules": submodules.splitlines(),
        "stock_prebuilts_commit": STOCK_COMMIT, "stock_modules": stock_modules,
        "patch_source": PATCH_REPO, "patch_commit": PATCH_COMMIT,
        "patch_sha256": sha(patch), "bbr3_source_sha256": sha(source),
        "local_oom_fix_sha256": sha(dest / "BBRv3-private-oom.patch"),
        "allocation_failure": "per-socket Reno fallback, logged; BBRv3 remains global default",
        "hardware_tested": False, "validated": False,
        "scope": "blazer / muzel, GrapheneOS 2026102101; compiled BBRv3 + matching modules",
    }
    (dest / "BBR3-BUILD.json").write_text(json.dumps(report, indent=2) + "\n")
    # Official GrapheneOS Pixel 10 build command; keep full LTO and hardening.
    # Limit parallel actions for the memory available on a hosted runner.
    run("./build_muzel.sh", "--lto=full",
        "--repo_manifest=" + str(root) + ":" + str(root / "aosp_manifest.xml"),
        "--jobs=2", cwd=root)
    dist = root / "out/muzel/dist"
    image = dist / "Image"
    if image.is_file():
        shutil.copyfile(image, dest / "Image")
    elif (dist / "Image.lz4").is_file():
        with (dest / "Image").open("wb") as output:
            run("lz4", "-d", "-c", str(dist / "Image.lz4"), stdout=output)
    else:
        raise RuntimeError("Official Pixel build did not produce a kernel image")
    if not (dist / "vmlinux").is_file():
        raise RuntimeError("vmlinux is required to verify module trust certificates")
    shutil.copyfile(dist / "vmlinux", dest / "vmlinux")
    modules = {}
    for path in dist.rglob("*.ko"):
        if path.name in modules and sha(path) != sha(modules[path.name]):
            raise RuntimeError("Ambiguous rebuilt module: " + path.name)
        modules[path.name] = path
    if set(stock_modules) - set(modules):
        raise RuntimeError("Missing rebuilt stock modules: " + repr(sorted(set(stock_modules) - set(modules))))
    exports = {}
    symvers_files = list(dist.glob("*symvers"))
    if not symvers_files:
        symvers_files = list((root / "out/muzel").rglob("Module.symvers"))
    if not symvers_files:
        raise RuntimeError("No modpost export table from the official Pixel build")
    for table in symvers_files:
        for line in table.read_text().splitlines():
            fields = line.split()
            if len(fields) < 2:
                continue
            crc, name = int(fields[0], 16), fields[1]
            if name in exports and exports[name] != crc:
                raise RuntimeError("Conflicting modpost export CRC: " + name)
            exports[name] = crc
    (dest / "module-exports.json").write_text(json.dumps(exports, sort_keys=True) + "\n")
    target = dest / "modules"
    target.mkdir()
    for name in stock_modules:
        shutil.copyfile(modules[name], target / name)
    # Retain exact corresponding kernel/device source, excluding build products,
    # toolchain binaries, repository internals and generated signing material.
    def filter_source(info):
        parts = Path(info.name).parts
        if any(p in {".git", ".repo", "out", "prebuilts", "__pycache__"} for p in parts):
            return None
        if info.name.endswith((".pem", ".key", ".p12", ".pfx")):
            return None
        return info
    with tarfile.open(dest / "pixel-kernel-source.tar.gz", "w:gz") as archive:
        archive.add(root, arcname="pixel-kernel", filter=filter_source)
    report["kernel_sha256"] = sha(dest / "Image")
    report["rebuilt_modules"] = {p.name: sha(p) for p in sorted(target.glob("*.ko"))}
    (dest / "BBR3-BUILD.json").write_text(json.dumps(report, indent=2) + "\n")
    print("Compiled BBRv3 Pixel image and complete module set; validation still required")

if __name__ == "__main__":
    main()
