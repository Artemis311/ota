#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fail closed before replacing the stock kernel: config, modules, keys, BBR identity."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys

def run(*args, **kw):
    return subprocess.run(args, check=True, **kw)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def config(tool, path):
    result = run(tool, "-i", str(path), "-f", capture_output=True, text=True).stdout
    return dict(re.findall(r"(?m)^(CONFIG_[A-Z0-9_]+)=(.*)$", result))

def certificate_list(vmlinux):
    data = vmlinux.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        raise RuntimeError("Expected little-endian ELF64 vmlinux")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    entsize, count = struct.unpack_from("<HH", data, 54)
    segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * entsize) for i in range(count)]
    def read_va(address, size):
        for kind, flags, offset, va, pa, filesz, memsz, alignment in segments:
            if kind == 1 and va <= address and address + size <= va + filesz:
                return data[offset + address - va:offset + address - va + size]
        raise RuntimeError("Kernel certificate address is outside file-backed segments")
    symbols = {}
    for line in run("nm", "--defined-only", str(vmlinux), capture_output=True, text=True).stdout.splitlines():
        fields = line.split()
        if len(fields) == 3 and fields[2] in {"system_certificate_list", "system_certificate_list_size"}:
            symbols[fields[2]] = int(fields[0], 16)
    if len(symbols) != 2:
        raise RuntimeError("Cannot locate compiled-in trusted certificate list")
    size = int.from_bytes(read_va(symbols["system_certificate_list_size"], 8), "little")
    if not 0 < size < 1024 * 1024:
        raise RuntimeError("Invalid kernel trusted certificate list size")
    return read_va(symbols["system_certificate_list"], size)

def der_certificates(data):
    position = 0
    while position < len(data):
        if data[position] != 0x30 or position + 2 > len(data):
            raise RuntimeError("Invalid certificate DER header")
        length = data[position + 1]
        header = 2
        if length & 0x80:
            n = length & 0x7f
            if not 1 <= n <= 4 or position + 2 + n > len(data):
                raise RuntimeError("Invalid certificate DER length")
            length = int.from_bytes(data[position + 2:position + 2 + n], "big")
            header += n
        end = position + header + length
        if end > len(data):
            raise RuntimeError("Truncated kernel certificate")
        yield data[position:end]
        position = end

def check_signature(path, trusted, work):
    data = path.read_bytes()
    marker = b"~Module signature appended~\n"
    if not data.endswith(marker):
        raise RuntimeError("Rebuilt module is unsigned: " + path.name)
    end = len(data) - len(marker)
    header = data[end - 12:end]
    if header[2] != 2 or header[3] or header[4]:
        raise RuntimeError("Unsupported module signature format")
    size = int.from_bytes(header[8:12], "big")
    start = end - 12 - size
    if size <= 0 or start < 64:
        raise RuntimeError("Invalid module signature bounds")
    (work / "signature.der").write_bytes(data[start:end - 12])
    (work / "payload.bin").write_bytes(data[:start])
    run("openssl", "cms", "-verify", "-binary", "-inform", "DER", "-nointern",
        "-certfile", str(trusted), "-noverify", "-in", str(work / "signature.der"),
        "-content", str(work / "payload.bin"), "-out", os.devnull,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def main():
    stock_kernel, tool, result, output = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4])
    report = json.loads((result / "BBR3-BUILD.json").read_text())
    stock_image = result.parent / "pixel-stock/grapheneos/muzel/Image.lz4"
    stock_data = run("lz4", "-d", "-c", str(stock_image), capture_output=True).stdout
    if sha(stock_kernel.read_bytes()) != sha(stock_data):
        raise RuntimeError("Pinned Pixel module set does not match the OTA's stock kernel image")
    image = result / "Image"
    old, new = config(tool, stock_kernel), config(tool, image)
    if new.get("CONFIG_TCP_CONG_BBR3") != "y" or new.get("CONFIG_DEFAULT_TCP_CONG") != '"bbr3"':
        raise RuntimeError("BBRv3 is not compiled in and selected as the kernel default")
    for key in ("CONFIG_MODULE_SIG_FORCE", "CONFIG_MODVERSIONS", "CONFIG_NET_SCH_FQ"):
        if new.get(key) != "y":
            raise RuntimeError("Required kernel option absent: " + key)
    allowed = {"CONFIG_TCP_CONG_BBR3", "CONFIG_DEFAULT_BBR3", "CONFIG_DEFAULT_CUBIC",
               "CONFIG_DEFAULT_BBR", "CONFIG_DEFAULT_TCP_CONG", "CONFIG_BUILD_SALT",
               "CONFIG_LOCALVERSION"}
    changes = {k: [old.get(k), new.get(k)] for k in set(old) | set(new)
               if old.get(k) != new.get(k)}
    unexpected = set(changes) - allowed
    if unexpected:
        raise RuntimeError("Unexpected stock kernel configuration differences: " + repr({k: changes[k] for k in sorted(unexpected)}))
    data = image.read_bytes()
    banner = re.search(rb"Linux version ([^\x00\n]+)", data)
    if not banner or not banner.group(1).startswith(b"6.6.144-android15-"):
        raise RuntimeError("Wrong rebuilt kernel release")
    release = banner.group(1).split(b" ", 1)[0].decode()
    work = result / "module-validation"
    work.mkdir(exist_ok=True)
    trusted = work / "trusted.pem"
    pem = b""
    for certificate in der_certificates(certificate_list(result / "vmlinux")):
        pem += run("openssl", "x509", "-inform", "DER", input=certificate, capture_output=True).stdout
    trusted.write_bytes(pem)
    if not pem:
        raise RuntimeError("No trusted kernel certificate was extracted")
    # Combined modpost exports from the completed official device build.
    symbols = json.loads((result / "module-exports.json").read_text())
    count = 0
    for path in sorted((result / "modules").glob("*.ko")):
        if sha(path.read_bytes()) != report["rebuilt_modules"][path.name]:
            raise RuntimeError("Rebuilt module digest changed")
        magic = re.search(rb"(?:^|\x00)vermagic=([^\x00]+)", path.read_bytes())
        if not magic or magic.group(1).split(b" ", 1)[0].decode() != release:
            raise RuntimeError("Rebuilt module/kernel release mismatch: " + path.name)
        original = result.parent / "pixel-stock/grapheneos/muzel" / path.name
        for field in ("name", "depends", "alias", "softdep", "import_ns", "license"):
            before = run("modinfo", "-F", field, str(original), capture_output=True, text=True).stdout.splitlines()
            after = run("modinfo", "-F", field, str(path), capture_output=True, text=True).stdout.splitlines()
            if sorted(before) != sorted(after):
                raise RuntimeError("Driver metadata/depmod compatibility changed: " + path.name + ":" + field)
        check_signature(path, trusted, work)
        imports = run("modprobe", "--dump-modversions", str(path), capture_output=True, text=True).stdout
        for line in imports.splitlines():
            crc, name = line.split()
            if name not in symbols or symbols[name] != int(crc, 16):
                raise RuntimeError("Module import CRC mismatch: " + path.name + ":" + name)
        count += 1
    if count != len(report["stock_modules"]):
        raise RuntimeError("Incomplete kernel module replacement set")
    report.update(validated=True, kernel_release=release, config_changes=changes,
                  validation={"module_count": count, "signatures": "verified against certificates extracted from rebuilt vmlinux",
                              "modversions": "all rebuilt imports checked",
                              "stock_image": "exact byte match to pinned Pixel module set"},
                  hardware_tested=False)
    (result / "BBR3-BUILD.json").write_text(json.dumps(report, indent=2) + "\n")
    output.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(image, output)
    profile = {
        "kernel": release, "implementation": "BBRv3", "selected_algorithm": "bbr3",
        "compiled_kernel_default_changed": True, "hardware_verified": False,
        "fq_built_in": True, "source": report,
    }
    dest = output.parent / "../private-bbr"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "BBR-PROFILE.json").write_text(json.dumps(profile, indent=2) + "\n")
    actions = "    write /proc/sys/net/ipv4/tcp_congestion_control bbr3\n    write /proc/sys/net/core/default_qdisc fq\n"
    (dest / "private_bbr.rc").write_text("# Private BBRv3 test; compiled default also bbr3\non post-fs-data\n" + actions + "\non property:sys.boot_completed=1\n" + actions)
    shutil.copyfile(result / "tcp_bbr3-source.c", dest / "tcp_bbr-source.c")
    print("PASS: real compiled BBRv3 default, exact stock baseline, full signed module set and config verified")

if __name__ == "__main__":
    main()
