/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SUSFS_FINGERPRINT_H
#define SUSFS_FINGERPRINT_H
#include "sha256.h"
#include "payload_ranges.h"

typedef int (*susfs_read_fn)(void *, const void *, unsigned long);
static int susfs_fingerprint_matches(const unsigned char *image, unsigned long len,
                                     susfs_read_fn reader)
{
    SHA256_CTX ctx;
    unsigned char block[512], actual[32];
    unsigned long pos = 0;
    if (len != SUSFS_IMAGE_SIZE)
        return 0;
    sha256_init(&ctx);
    while (pos < len) {
        unsigned long count = len - pos;
        if (count > sizeof(block)) count = sizeof(block);
        if (!reader(block, image + pos, count)) return 0;
        for (unsigned int i = 0; i < SUSFS_RANGE_COUNT; ++i) {
            unsigned long first = susfs_ranges[i][0], last = first + susfs_ranges[i][1];
            if (first >= pos + count) break;
            if (last <= pos) continue;
            unsigned long a = first > pos ? first : pos;
            unsigned long b = last < pos + count ? last : pos + count;
            for (unsigned long j = a; j < b; ++j) block[j - pos] = 0;
        }
        sha256_update(&ctx, block, count);
        pos += count;
    }
    sha256_final(&ctx, actual);
    for (unsigned int i = 0; i < sizeof(actual); ++i)
        if (actual[i] != susfs_expected_sha[i]) return 0;
    return 1;
}
#endif
