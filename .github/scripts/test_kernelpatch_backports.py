"""Integration checks for the pinned upstream backports and MTE scan bounds."""
import copy
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import patch_kernelpatch_tools as kp

PIN = "280d32d967feb7ddc0fd1848aa1d1388807945d5"
SOURCE = Path(sys.argv.pop(1)).resolve()
FILES = ("tools/kallsym.c", "tools/kallsym.h",
         "kernel/linux/arch/arm64/include/asm/current.h",
         "kernel/patch/ksyms/task_cred.c", "kernel/base/setup1.S")


def pinned_files():
    return {name: subprocess.run(["git", "-C", str(SOURCE), "show", f"{PIN}:{name}"],
                                check=True, capture_output=True).stdout for name in FILES}


def fixture(root, files):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


class BackportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = pinned_files()

    def test_official_outputs_match_before_graphene_register_adaptation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, self.original)
            kp.apply_official_backports(root)
            for name, expected in kp.BACKPORT_RESULTS.items():
                self.assertEqual(kp.git_blob((root / name).read_bytes()), expected)

    def test_combined_patch_retains_graphene_runtime_and_kpm_support(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, self.original)
            kp.apply_all(root)
            cred = (root / "kernel/patch/ksyms/task_cred.c").read_text()
            header = (root / "kernel/linux/arch/arm64/include/asm/current.h").read_text()
            self.assertEqual(cred.count("live_cred_scan_len(new_cred)"), 3)
            self.assertIn("current register: tpidrro_el0 (matches init_task)", cred)
            self.assertIn("KP_EXPORT_SYMBOL(current_uses_tpidrro_el0)", cred)
            self.assertIn('msr tpidrro_el0, %0', header)
            self.assertEqual(kp.git_blob((root / "kernel/base/setup1.S").read_bytes()),
                             kp.BACKPORT_RESULTS["kernel/base/setup1.S"])

    def test_source_drift_fails_before_any_file_is_patched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = copy.deepcopy(self.original)
            files["kernel/base/setup1.S"] += b"\n// changed\n"
            fixture(root, files)
            with self.assertRaisesRegex(RuntimeError, "Unexpected pinned"):
                kp.apply_all(root)
            self.assertEqual({name: (root / name).read_bytes() for name in FILES}, files)

    def test_invalid_hunk_is_rejected_before_backport_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, self.original)
            with patch.object(kp, "UPSTREAM_PATCH",
                              kp.UPSTREAM_PATCH.replace("__NR_setresuid, 0, 0, 1158", "__NR_setresuid, 0, 0, 1159")):
                with self.assertRaises(RuntimeError):
                    kp.apply_official_backports(root)
            self.assertEqual({name: (root / name).read_bytes() for name in FILES}, self.original)

    def test_native_mte_scan_bounds_on_actual_upstream_function(self):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            self.skipTest("Native C compiler unavailable; this test runs on the Linux CI runner")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixture(root, self.original)
            kp.apply_all(root)
            text = (root / "kernel/patch/ksyms/task_cred.c").read_text()
            function = text.split("static int live_cred_scan_len", 1)[1].split("\nint resolve_cred_offset", 1)[0]
            source = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CRED_MAX_SIZE 256
#define MTE_GRANULE 16
#define log_boot(...) ((void)0)
struct cred { int unused; };
static unsigned long test_size;
static bool test_mte;
static int tagged_bytes, tag_reads;
static uint8_t pointer_tag;
static uintptr_t address_base;
static unsigned long fake_ksize(const void *ptr) { (void)ptr; return test_size; }
static uintptr_t kallsyms_lookup_name(const char *name)
{ assert(!strcmp(name, "ksize")); return (uintptr_t)fake_ksize; }
static bool mte_tag_access_enabled(void) { return test_mte; }
static uint8_t mte_alloc_tag(uintptr_t addr)
{
    tag_reads++;
    unsigned long offset = (addr & 0x00ffffffffffffffUL) - address_base;
    assert(offset < (test_size ? test_size : CRED_MAX_SIZE));
    return offset < (unsigned long)tagged_bytes ? pointer_tag : (pointer_tag ^ 1);
}
''' + "static int live_cred_scan_len" + function + r'''
static void check(unsigned long size, bool mte, unsigned top, int valid, int expected, int reads)
{
    test_size = size; test_mte = mte; tagged_bytes = valid; tag_reads = 0;
    pointer_tag = top & 15; address_base = 0x10000;
    uintptr_t address = ((uintptr_t)top << 56) | address_base;
    assert(live_cred_scan_len((const struct cred *)address) == expected);
    assert(tag_reads == reads);
}
int main(void)
{
    check(192, true, 0xf9, 176, 176, 12); // Object ends before the slab slot.
    check(192, true, 0xf9, 16, 16, 2);   // One valid granule.
    check(192, true, 0xf9, 192, 192, 12);
    check(512, true, 0xf9, 512, 256, 16); // Never exceed CRED_MAX_SIZE.
    check(192, false, 0xf9, 176, 192, 0);
    check(192, true, 0xff, 176, 192, 0); // Match-all pointer preserves old behavior.
    check(192, true, 0xf9, 0, 192, 1);  // Software tag mismatch.
    check(0, false, 0xf9, 0, 256, 0);   // Unknown slot size uses bounded default.
    puts("PASS: 8 native credential scan boundary cases");
    return 0;
}
'''
            path, binary = root / "bounds.c", root / "bounds"
            path.write_text(source, encoding="utf-8")
            subprocess.run([compiler, "-std=gnu11", "-Wall", "-Wextra", "-Werror",
                            str(path), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
