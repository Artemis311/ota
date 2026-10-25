/* SPDX-License-Identifier: GPL-2.0-only */
/* Private test: retain the kernel's decision for every image except one
 * normalized SHA-256-pinned SUSFS payload, and only for the tested kernel. */
#include <compiler.h>
#include <kpmodule.h>
#include <common.h>
#include <hook.h>
#include <kallsyms.h>
#include <kputils.h>
#include <linux/printk.h>
#include "fingerprint.h"

KPM_NAME("susfs_sig_allow");
KPM_VERSION("0.1.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Artemis311");
KPM_DESCRIPTION("Private exact-payload SUSFS signature exception; original policy retained otherwise");

struct load_info_prefix {
    const char *name;
    void *mod;
    const unsigned char *hdr;
    unsigned long len;
};
typedef long (*nofault_fn)(void *, const void *, unsigned long);
static nofault_fn read_safe;
static void *sig_check;
static unsigned long accepted;
static unsigned long refused;

static int read_chunk(void *dst, const void *src, unsigned long len)
{
    return read_safe(dst, src, len) == 0;
}

static void after_sig_check(hook_fargs2_t *args, void *unused)
{
    struct load_info_prefix info;
    (void)unused;
    /* The original function already ran. Never modify signature success,
     * other errors, non-root loads, or any global enforcement setting. */
    if ((int)args->ret != -129 || current_uid() != 0)
        return;
    if (!read_safe || !read_chunk(&info, (void *)args->arg0, sizeof(info)) ||
        info.len != SUSFS_IMAGE_SIZE || !info.hdr)
        return;
    if (!susfs_fingerprint_matches(info.hdr, info.len, read_chunk)) {
        __atomic_add_fetch(&refused, 1, __ATOMIC_RELAXED);
        return;
    }
    __atomic_add_fetch(&accepted, 1, __ATOMIC_RELAXED);
    args->ret = 0;
    pr_info("susfs_sig_allow: accepted exact normalized SUSFS payload; global signature policy unchanged\n");
}

static long allow_init(const char *args, const char *event, void *reserved)
{
    char banner[sizeof(SUSFS_KERNEL_PREFIX)];
    unsigned long banner_addr;
    (void)args; (void)reserved;
    if (kver != VERSION(6, 6, 144))
        return -22;
    read_safe = (nofault_fn)kallsyms_lookup_name("copy_from_kernel_nofault");
    sig_check = (void *)kallsyms_lookup_name("module_sig_check");
    banner_addr = kallsyms_lookup_name("linux_banner");
    if (!read_safe || !sig_check || !banner_addr ||
        !read_chunk(banner, (void *)banner_addr, sizeof(banner) - 1))
        return -2;
    for (unsigned int i = 0; i < sizeof(banner) - 1; ++i)
        if (banner[i] != SUSFS_KERNEL_PREFIX[i])
            return -22;
    int rc = hook_wrap2(sig_check, 0, after_sig_check, 0);
    pr_info("susfs_sig_allow: hook result=%d event=%s; exact payload and tested kernel only\n", rc, event);
    return rc ? -rc : 0;
}

static long allow_status(const char *args, char *__user out, int size)
{
    static const char message[] = "Exact SUSFS payload signature adapter; counters in dmesg";
    (void)args;
    pr_info("susfs_sig_allow: status accepted=%lu refused=%lu\n",
            __atomic_load_n(&accepted, __ATOMIC_RELAXED),
            __atomic_load_n(&refused, __ATOMIC_RELAXED));
    if (size > 0)
        compat_copy_to_user(out, message, size < sizeof(message) ? size : sizeof(message));
    return 0;
}

static long allow_exit(void *reserved)
{
    (void)reserved;
    /* Embedded test module: removal is by a freshly signed OTA, not hot unload.
     * Keeping callback text alive avoids racing another signature check. */
    return -16;
}
KPM_INIT(allow_init);
KPM_CTL0(allow_status);
KPM_EXIT(allow_exit);
