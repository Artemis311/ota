# SPDX-License-Identifier: GPL-3.0-only
"""Replace only matching stock kernel-module bytes while preserving paths/metadata."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
from typing import override
from lib.filesystem import CpioFs, ExtFs
from lib.modules import MissingArgs, Module, ModuleRequirements

class PrivatePixelModules(Module):
    NAME = "private-pixel-modules"

    @classmethod
    @override
    def add_args(cls, parser: argparse.ArgumentParser):
        parser.add_argument("--module-private-pixel-modules", type=Path)

    def __init__(self, args):
        self.source = getattr(args, "module_private_pixel_modules", None)
        if self.source is None:
            raise MissingArgs()
        self.report = json.loads((self.source / "BBR3-BUILD.json").read_text())
        if self.report.get("validated") is not True:
            raise RuntimeError("Refusing unvalidated Pixel module set")

    @override
    def requirements(self):
        return ModuleRequirements(boot_images={"vendor_kernel_boot"},
                                  ext_images={"system_dlkm", "vendor_dlkm"},
                                  selinux_patching=False)

    @override
    def inject(self, boot_fs: dict[str, CpioFs], ext_fs: dict[str, ExtFs], sepolicies):
        records = []
        counts = {}
        for partition in ("vendor_kernel_boot", "system_dlkm", "vendor_dlkm"):
            fs = (boot_fs if partition == "vendor_kernel_boot" else ext_fs)[partition]
            count = 0
            for entry in fs.info.entries:
                path = entry.path
                if path.suffix != ".ko":
                    continue
                if str(entry.file_type) not in {"Regular", "RegularFile"}:
                    raise RuntimeError("Kernel module entry is not a regular file")
                name = path.name
                relative = str(path).lstrip("/")
                target = fs.tree / relative
                if target.is_symlink() or not target.is_file():
                    raise RuntimeError("Missing or symlinked module slot: " + relative)
                old = hashlib.sha256(target.read_bytes()).hexdigest()
                if self.report["stock_modules"].get(name) != old:
                    raise RuntimeError("OTA driver differs from pinned Pixel base: " + name)
                replacement = self.source / "modules" / name
                expected = self.report["rebuilt_modules"].get(name)
                if expected is None or hashlib.sha256(replacement.read_bytes()).hexdigest() != expected:
                    raise RuntimeError("Invalid rebuilt driver: " + name)
                # Do not alter file ownership, SELinux labels, mode, path, load
                # order, depmod files, or any other ramdisk/filesystem content.
                with replacement.open("rb") as incoming, target.open("wb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing)
                records.append({"partition": partition, "path": str(path),
                                "old_sha256": old, "new_sha256": expected})
                count += 1
            if not count:
                raise RuntimeError("Expected Pixel module partition has no drivers: " + partition)
            counts[partition] = count
        (self.source / "installed-module-plan.json").write_text(json.dumps(
            {"counts": counts, "files": records}, indent=2) + "\n")
