"""Pinned official MTE/BTI fixes plus GrapheneOS TPIDRRO_EL0 compatibility."""
import hashlib
import subprocess
from pathlib import Path
import sys

# Exact upstream fixes, kept separate from the GrapheneOS register adaptation.
# https://github.com/bmax121/KernelPatch/commit/406c85ce79a5e1c19b53be34c04baadc1ec68bc5
# https://github.com/bmax121/KernelPatch/commit/60020829dc5e5fab357356b9e545e4d80728af3e
UPSTREAM_FIXES = (
    "406c85ce79a5e1c19b53be34c04baadc1ec68bc5",
    "60020829dc5e5fab357356b9e545e4d80728af3e",
)
BACKPORT_RESULTS = {
    "kernel/patch/ksyms/task_cred.c": "6e7ddbf9bedea765ad23f4f9e91d083f1482087c",
    "kernel/base/setup1.S": "1dcf2ce4b8552dd571929e99d522e319cac1847d",
}
UPSTREAM_PATCH = r'''diff --git a/kernel/patch/ksyms/task_cred.c b/kernel/patch/ksyms/task_cred.c
--- a/kernel/patch/ksyms/task_cred.c
+++ b/kernel/patch/ksyms/task_cred.c
@@ -177,26 +177,59 @@
     }
 }
 
+#define MTE_GRANULE 16
+
+static bool mte_tag_access_enabled(void)
+{
+    uint64_t pfr1, sctlr;
+    asm volatile("mrs %0, id_aa64pfr1_el1" : "=r"(pfr1));
+    if (((pfr1 >> 8) & 0xf) < 2) return false; // FEAT_MTE2: memory carries allocation tags
+    asm volatile("mrs %0, sctlr_el1" : "=r"(sctlr));
+    return sctlr & (1ull << 43); // SCTLR_EL1.ATA: EL1 may access allocation tags
+}
+
+// Allocation tag of the granule holding addr; only valid if mte_tag_access_enabled().
+static uint8_t mte_alloc_tag(uintptr_t addr)
+{
+    register uintptr_t x0 asm("x0") = addr;
+    asm volatile(".inst 0xd9600000" : "+r"(x0)); // ldg x0, [x0]
+    return (x0 >> 56) & 0xf;
+}
+
 /*
- * Creds installed by setresuid/setresgid/prctl come from the cred_jar slab,
- * so they are smaller than CRED_MAX_SIZE. With MTE (KASAN_HW_TAGS, enforced
- * by GrapheneOS with kasan.fault=panic) a read past the object through its
- * tagged pointer is a fatal tag-check fault, even within the slab slot.
- * Scan only the slot (ksize) and access it through the match-all tag, which
- * is what the kernel itself uses for unchecked accesses. Without MTE the
- * kernel pointer already carries 0xff in the top byte and nothing changes.
+ * suid, sgid and cap_ambient are found in the cred that setresuid, setresgid
+ * or prctl has just committed. It comes from cred_jar, so it is only
+ * sizeof(struct cred) long, unlike our CRED_MAX_SIZE scratch copies.
+ *
+ * Under hardware tag-based KASAN only the object's own granules carry the
+ * pointer tag; the rest of the slab slot is tagged invalid, and reading it is
+ * a tag-check fault, fatal with kasan.fault=panic. ksize() is not a safe bound
+ * there: it returns the slot size, and since Linux 6.2 it no longer retags the
+ * slot to make that size readable. Walk the allocation tags instead.
  */
-static inline uintptr_t slab_cred_base(const struct cred *cred)
-{
-    return (uintptr_t)cred | (0xffUL << 56);
-}
-
-static int slab_cred_scan_len(const struct cred *cred)
-{
-    static unsigned long (*cred_size)(const void *) = 0;
-    if (!cred_size) cred_size = (typeof(cred_size))kallsyms_lookup_name("ksize");
-    unsigned long len = cred_size ? cred_size(cred) : CRED_MAX_SIZE;
-    return len < CRED_MAX_SIZE ? (int)len : CRED_MAX_SIZE;
+static int live_cred_scan_len(const struct cred *cred)
+{
+    uintptr_t addr = (uintptr_t)cred;
+    int len = CRED_MAX_SIZE;
+
+    unsigned long (*slot_size)(const void *) = (typeof(slot_size))kallsyms_lookup_name("ksize");
+    if (slot_size) {
+        unsigned long size = slot_size(cred);
+        if (size && size < (unsigned long)len) len = (int)size;
+    }
+
+    // The match-all tag 0xff is never checked: KASAN_HW_TAGS is off.
+    if ((addr >> 56) == 0xff || !mte_tag_access_enabled()) return len;
+    // A pointer tag the memory does not carry is a KASAN_SW_TAGS tag, which
+    // only instrumented code checks.
+    uint8_t tag = (addr >> 56) & 0xf;
+    if (mte_alloc_tag(addr) != tag) return len;
+
+    int end = MTE_GRANULE;
+    while (end < len && mte_alloc_tag(addr + end) == tag)
+        end += MTE_GRANULE;
+    log_boot("    tagged cred: %x bytes\n", end);
+    return end;
 }
 
 int resolve_cred_offset()
@@ -341,10 +374,10 @@
     // suid
     raw_syscall3(__NR_setresuid, 0, 0, 1158);
     new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
-    int scan_len = slab_cred_scan_len(new_cred);
+    int scan_len = live_cred_scan_len(new_cred);
     for (int i = 0; i + (int)sizeof(uid_t) <= scan_len; i += sizeof(uint32_t)) {
         if (is_bl(i)) continue;
-        uid_t *uidp = (uid_t *)(slab_cred_base(new_cred) + i);
+        uid_t *uidp = (uid_t *)((uintptr_t)new_cred + i);
         if (*uidp == 1158) {
             cred_offset.suid_offset = i;
             *uidp = 0;
@@ -357,10 +390,10 @@
     // sgid
     raw_syscall3(__NR_setresgid, 0, 0, 1158);
     new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
-    scan_len = slab_cred_scan_len(new_cred);
+    scan_len = live_cred_scan_len(new_cred);
     for (int i = 0; i + (int)sizeof(gid_t) <= scan_len; i += sizeof(uint32_t)) {
         if (is_bl(i)) continue;
-        gid_t *uidp = (gid_t *)(slab_cred_base(new_cred) + i);
+        gid_t *uidp = (gid_t *)((uintptr_t)new_cred + i);
         if (*uidp == 1158) {
             cred_offset.sgid_offset = i;
             *uidp = 0;
@@ -378,12 +411,11 @@
     *(unsigned *)((uintptr_t)new_cred + cred_offset.securebits_offset) = 0;
     cap_task_prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, 0xf, 0, 0);
     new_cred = *(struct cred **)((uintptr_t)task + task_struct_offset.cred_offset);
-    /* prctl installed a slab cred, not one of our CRED_MAX_SIZE scratch buffers. */
-    scan_len = slab_cred_scan_len(new_cred);
+    scan_len = live_cred_scan_len(new_cred);
     for (int i = 0; i + (int)sizeof(kernel_cap_t) <= scan_len; i += sizeof(uint32_t)) {
         if (is_bl(i)) continue;
         kernel_cap_t cap = *(kernel_cap_t *)((uintptr_t)cred + i);
-        kernel_cap_t new_cap = *(kernel_cap_t *)(slab_cred_base(new_cred) + i);
+        kernel_cap_t new_cap = *(kernel_cap_t *)((uintptr_t)new_cred + i);
         if (!cap.val && new_cap.val == (1 << 0xf)) {
             cred_offset.cap_ambient_offset = i;
             add_bll(i, sizeof(kernel_cap_t));
diff --git a/kernel/base/setup1.S b/kernel/base/setup1.S
--- a/kernel/base/setup1.S
+++ b/kernel/base/setup1.S
@@ -271,8 +271,12 @@ map_prepare:
     // if ((map_data.paging_init_backup & 0xFFFFFD1F) == 0xD503211F)
     cmp w0, w1
     b.ne .backup
-    // map_data.paging_init_backup = NOP
-    mov w12, w3
+    // map_data.paging_init_backup = BTI c
+    // The PAC instruction was also paging_init's BTI landing pad, and _paging_init
+    // calls paging_init through a register. BTI c keeps a landing pad and is a
+    // hint, so it executes as NOP where BTI is not implemented or not enabled.
+    mov w12, #0x245F
+    movk w12, #0xD503, lsl#16
     // uint32_t *p = (uint32_t *)paging_init_pa + 1;
     add x11, x13, #4
 .cmp_auti:
'''


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def apply_official_backports(root):
    # Check every hunk before changing either file; verify exact upstream outputs.
    for options in (["--check"], []):
        result = subprocess.run(["git", "-c", "core.autocrlf=false", "apply", *options, "-"], input=UPSTREAM_PATCH.encode("utf-8"),
                                cwd=root, capture_output=True)
        if result.returncode:
            raise RuntimeError("Official KernelPatch backport failed: " + result.stderr.decode("utf-8", errors="replace"))
    for name, expected in BACKPORT_RESULTS.items():
        if git_blob((root / name).read_bytes()) != expected:
            raise RuntimeError("Backport differs from the exact official source: " + name)
    print("Verified exact upstream MTE #336 and BTI #337 backports")



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
    text = text.replace(OLD, NEW, 1)
    anchor = '            if (aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0) {'
    addition = '''            // GrapheneOS arm64 current.h uses MRS TPIDRRO_EL0 on newer kernels.
            if ((insn & 0xfff00000) == 0xd5300000 &&
                aarch64_insn_extract_system_reg(insn) == 0xde83) {
                tools_logi("pid_vnr verfied tpidrro_el0, insn: 0x%x (off %+d)\\n", insn, i);
                info->current_type = TPIDRRO_EL0;
                return 0;
            }
'''
    if text.count(anchor) != 1:
        raise RuntimeError("KernelPatch register verifier changed")
    return text.replace(anchor, addition + anchor, 1).encode("utf-8")


def replace_checked(text, old, new, count=1):
    if text.count(old) != count:
        raise RuntimeError("Pinned KernelPatch runtime differs from reviewed source")
    return text.replace(old, new)


def runtime_header(text):
    text = replace_checked(text, "extern int sp_el0_is_current;",
                           "extern int sp_el0_is_current;\nextern int current_uses_tpidrro_el0;")
    helpers = '''static inline uint64_t read_current_register()
{
    uint64_t value;
    if (current_uses_tpidrro_el0)
        asm volatile("mrs %0, tpidrro_el0" : "=r"(value));
    else
        asm volatile("mrs %0, sp_el0" : "=r"(value));
    return value;
}

static inline void write_current_register(uint64_t value)
{
    if (current_uses_tpidrro_el0)
        asm volatile("msr tpidrro_el0, %0" ::"r"(value));
    else
        asm volatile("msr sp_el0, %0" ::"r"(value));
}

'''
    text = replace_checked(text, 'asm volatile("mrs %0, sp_el0" : "=r"(sp_el0));',
                           'sp_el0 = read_current_register();', 3)
    for value in ("task", "old"):
        text = replace_checked(text, f'asm volatile("msr sp_el0, %0" ::"r"({value}));',
                               f'write_current_register((uint64_t){value});')
    text = replace_checked(text, "static inline uint64_t current_sp_el0()", helpers + "static inline uint64_t current_sp_el0()")
    return text


def runtime_probe(text):
    text = replace_checked(text, "int sp_el0_is_current = 0;",
        "int current_uses_tpidrro_el0 = 0;\nKP_EXPORT_SYMBOL(current_uses_tpidrro_el0);\n\nint sp_el0_is_current = 0;")
    anchor = '    uint64_t init_thread_union_addr = kallsyms_lookup_name("init_thread_union");'
    probe = '''

    // Resolve against the known boot task before using either register as a pointer.
    // Keep SP_EL0 behavior for older kernels; TPIDRRO_EL0 is selected only on an
    // exact match to the independently resolved init_task symbol.
    uint64_t tpidrro_el0;
    asm volatile("mrs %0, tpidrro_el0" : "=r"(tpidrro_el0));
    current_uses_tpidrro_el0 = init_task && tpidrro_el0 == (uint64_t)init_task;
    if (current_uses_tpidrro_el0) {
        sp_el0 = tpidrro_el0;
        log_boot("    current register: tpidrro_el0 (matches init_task)\\n");
    }
'''
    return replace_checked(text, anchor, anchor + probe)


def apply_all(root):
    root = Path(root)
    sources = {
        "tools/kallsym.c": (SOURCE_BLOB, lambda text: patched_source(text.encode()).decode()),
        "tools/kallsym.h": ("9ab4a9f8b7bbeeb0dd1518c00bad637e655092ac",
            lambda text: replace_checked(text, "    SP_EL0,\n", "    SP_EL0,\n    TPIDRRO_EL0 = 2,\n")),
        "kernel/linux/arch/arm64/include/asm/current.h": ("5fb63fa2bf7b6a729bd1f92c38bc8f0c35312985", runtime_header),
        "kernel/patch/ksyms/task_cred.c": ("dcdc53ad24b325c2f45deb2383209aeb1550af59", runtime_probe),
        "kernel/base/setup1.S": ("9b44730e3014bd2155575b37bafd76abeee56033", lambda text: text),
    }
    for name, (expected, _) in sources.items():
        data = (root / name).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != expected:
            raise RuntimeError("Unexpected pinned KernelPatch source: " + name)
    apply_official_backports(root)
    outputs = {name: transform((root / name).read_text(encoding="utf-8")).encode("utf-8")
               for name, (_, transform) in sources.items()}
    for name, data in outputs.items():
        (root / name).write_bytes(data)
    print("Applied pinned TPIDRRO_EL0 support to verifier, runtime and KPM headers")


if __name__ == "__main__":
    apply_all(sys.argv[1])
