# SPDX-License-Identifier: GPL-3.0-only
"""Inject only the reviewed init actions and their build provenance."""
import argparse
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
import shutil
from typing import override
from lib.filesystem import CpioFs, ExtFs
from lib.modules import MissingArgs, Module, ModuleRequirements

class PrivateBbrModule(Module):
    NAME = "private-bbr"

    @classmethod
    @override
    def add_args(cls, parser: argparse.ArgumentParser):
        parser.add_argument("--module-private-bbr", type=Path)

    def __init__(self, args):
        self.source = getattr(args, "module_private_bbr", None)
        if self.source is None:
            raise MissingArgs()

    @override
    def requirements(self):
        return ModuleRequirements(boot_images=set(), ext_images={"system"}, selinux_patching=False)

    @override
    def inject(self, boot_fs: dict[str, CpioFs], ext_fs: dict[str, ExtFs], sepolicies: Iterable[Path]):
        fs = ext_fs["system"]
        for source, dest in (
            ("private_bbr.rc", "system/etc/init/private_bbr.rc"),
            ("BBR-PROFILE.json", "system/etc/private-bbr.json"),
        ):
            path = PurePosixPath(dest)
            fs.mkdir(path.parent, mode=0o755, parents=True, exist_ok=True)
            with (self.source / source).open("rb") as incoming, fs.open(path, "wb", mode=0o644) as outgoing:
                shutil.copyfileobj(incoming, outgoing)
