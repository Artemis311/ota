"""Apply the existing wide SP_EL0 verifier to the banner-based lookup path."""
import hashlib
from pathlib import Path
import sys

SOURCE_BLOB = "1005077c3c7c3a200df53795f8f6ad146b1d0a86"
OLD = "if (arm64_verify_pid_vnr(info, img, imglen, pid_vnr_offset, 0)) {"
NEW = ("if (arm64_verify_pid_vnr(info, img, imglen, pid_vnr_offset, 0) &&\n"
       "            arm64_verify_pid_vnr(info, img, imglen, pid_vnr_offset, 1)) {")


def patched_source(data):
    blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    if blob != SOURCE_BLOB:
        raise RuntimeError("Unexpected pinned KernelPatch kallsyms source")
    text = data.decode("utf-8")
    if text.count(OLD) != 1:
        raise RuntimeError("KernelPatch verifier location changed")
    return text.replace(OLD, NEW, 1).encode("utf-8")


def main():
    path = Path(sys.argv[1]) / "tools/kallsym.c"
    path.write_bytes(patched_source(path.read_bytes()))
    print("Applied pinned KernelPatch banner-path SP_EL0 fallback; failure checks retained")


if __name__ == "__main__":
    main()
