// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 RS-Key contributors
#include "mbedtls_wrapper.h"
#include <stdio.h>
#include <string.h>

void raw_to_der(signature_t *sig);
void der_to_raw(signature_t *sig);

static void check(int ok, const char *direction, unsigned r, unsigned s) {
    if (!ok) {
        fprintf(stderr, "picotool %s: scalar cases %u/%u differ\n", direction, r, s);
        exit(1);
    }
}

static size_t scalar(unsigned value, uint8_t raw[32], uint8_t der[33]) {
    // Start with a 31-byte scalar: this reproduces the observed damaged signature.
    static const unsigned lengths[] = {31, 32, 30, 1};
    unsigned length = lengths[value / 2];
    unsigned padded = value % 2;
    memset(raw, 0, 32);
    memset(raw + 32 - length, 0x35, length);
    raw[32 - length] = padded ? 0x80 : 0x01;
    der[0] = 0;
    memcpy(der + padded, raw + 32 - length, length);
    return length + padded;
}

int main(void) {
    for (unsigned r = 0; r < 9; ++r) {
        for (unsigned s = 0; s < 9; ++s) {
            uint8_t raw[64] = {0}, der[72] = {0x30};
            uint8_t ri[33] = {0}, si[33] = {0};
            size_t rn = r == 8 ? 1 : scalar(r, raw, ri);
            size_t sn = s == 8 ? 1 : scalar(s, raw + 32, si);
            size_t length = 6 + rn + sn;
            der[1] = (uint8_t)(length - 2);
            der[2] = 0x02;
            der[3] = (uint8_t)rn;
            memcpy(der + 4, ri, rn);
            der[4 + rn] = 0x02;
            der[5 + rn] = (uint8_t)sn;
            memcpy(der + 6 + rn, si, sn);

            signature_t sig = {0};
            memcpy(sig.der, der, length);
            sig.der_len = length;
            der_to_raw(&sig);
            check(memcmp(sig.bytes, raw, sizeof(raw)) == 0, "DER to RAW", r, s);

            memset(&sig, 0, sizeof(sig));
            memcpy(sig.bytes, raw, sizeof(raw));
            raw_to_der(&sig);
            check(sig.der_len == length, "RAW to DER length", r, s);
            check(memcmp(sig.der, der, length) == 0, "RAW to DER bytes", r, s);
        }
    }
    puts("picotool ECDSA: 81 independent DER/RAW vectors passed");
    return 0;
}
