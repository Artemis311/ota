"""Pinned GrapheneOS TPIDRRO_EL0 support in kptools, kpimg and KPM headers."""
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


def main():
    root = Path(sys.argv[1])
    sources = {
        "tools/kallsym.c": (SOURCE_BLOB, lambda text: patched_source(text.encode()).decode()),
        "tools/kallsym.h": ("9ab4a9f8b7bbeeb0dd1518c00bad637e655092ac",
            lambda text: replace_checked(text, "    SP_EL0,\n", "    SP_EL0,\n    TPIDRRO_EL0 = 2,\n")),
        "kernel/linux/arch/arm64/include/asm/current.h": ("5fb63fa2bf7b6a729bd1f92c38bc8f0c35312985", runtime_header),
        "kernel/patch/ksyms/task_cred.c": ("dcdc53ad24b325c2f45deb2383209aeb1550af59", runtime_probe),
    }
    outputs = {}
    for name, (expected, transform) in sources.items():
        data = (root / name).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if blob != expected:
            raise RuntimeError("Unexpected pinned KernelPatch source: " + name)
        outputs[name] = transform(data.decode("utf-8")).encode("utf-8")
    for name, data in outputs.items():
        (root / name).write_bytes(data)
    print("Applied pinned TPIDRRO_EL0 support to verifier, runtime and KPM headers")


if __name__ == "__main__":
    main()
