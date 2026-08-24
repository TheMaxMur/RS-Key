/*
* Copyright (c) 2025 Emil Lenngren
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bignum_config.h"
#include "bignum_high_level.h"

void bignum_to_mont(uint32_t *input_output, const uint32_t *modulus, size_t modulus_length_bytes, uint32_t *temp);
void bignum_modular_inverse(uint32_t output[4], const uint32_t *input);
void bignum_mulacc(uint32_t *accumulator, const uint32_t *a, const uint32_t *b, size_t operand_length_bytes);
void bignum_sqracc(uint32_t *accumulator, const uint32_t *a, size_t operand_length_bytes);
void bignum_mont_redc(uint32_t *input, size_t modulus_length_bytes, const uint32_t *modulus, const uint32_t modulus_prim[4], const uint32_t *modulus_bitwise_inv, uint32_t *out);
int bignum_submod(uint32_t *output, const uint32_t *subtrahend_bitwise_inv, const uint32_t *modulus, const uint32_t *minuend, size_t modulus_length_bytes);
void bignum_table_select(uint32_t *output, const uint32_t *table_input, const uint32_t *table_input_end_pointer, uint32_t chosen_index);

// returns 0 if reduction was needed, 1 if already reduced
// output may not overlap with modulus
static inline int bignum_reduce_once(uint32_t *output, const uint32_t *modulus_bitwise_inv, const uint32_t *modulus, const uint32_t *input, size_t modulus_length_bytes) {
    return bignum_submod(output, modulus_bitwise_inv, modulus, input, modulus_length_bytes);
}

/* RS-Key: the keygen Fermat filter drives bignum_modexp_private_exponent on
 * BOTH RP2350 cores at once; executed from XIP the cores throttle each other
 * on the shared flash cache. The .data.* section name puts the hot call chain
 * in SRAM (cortex-m-rt copies .data.* into RAM at boot — the same trick as
 * embassy-rp's flash RAM-functions). Only the chain the prime search uses is
 * moved; the CRT/public/endian paths stay in flash. */
#define BIGNUM_RAMFUNC __attribute__((section(".data.bignum_hl"), noinline))

static BIGNUM_RAMFUNC void ones_complement(uint32_t *output, const uint32_t *input, size_t byte_length) {
    do {
        *output++ = ~*input++;
        byte_length -= 4;
    } while (byte_length != 0);
}

bool bignum_check_less_than(const uint32_t *value, const uint32_t *modulus, size_t modulus_length_bytes, uint32_t *temp) {
    uint32_t *modulus_bitwise_inv = (void *)temp + modulus_length_bytes;
    ones_complement(modulus_bitwise_inv, modulus, modulus_length_bytes);
    return bignum_reduce_once(temp, modulus_bitwise_inv, modulus, value, modulus_length_bytes);
}

int bignum_modexp_public_exponent(
    uint32_t *result,
    const uint32_t *base,
    const uint8_t *exponent,
    const uint32_t *modulus,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp)
{
    // result can point to the same memory location as base
    // result may not overlap with modulus
    // temp has space for 5 modulus-sized values
    
    uint32_t *A1 = (uint32_t *)((void *)temp + modulus_length_bytes);
    uint32_t *T0 = (uint32_t *)((void *)temp + 2 * modulus_length_bytes);
    uint32_t *T1 = (uint32_t *)((void *)temp + 3 * modulus_length_bytes);
    uint32_t *modulus_bitwise_inv = (uint32_t *)((void *)temp + 4 * modulus_length_bytes);

    if (modulus_length_bytes == 0 || modulus_length_bytes % 32 != 0) {
        return -1;
    }
    
    ones_complement(modulus_bitwise_inv, modulus, modulus_length_bytes);
    if (bignum_reduce_once(A1, modulus_bitwise_inv, modulus, base, modulus_length_bytes) == 0) {
        // base >= modulus
        return -2;
    }

    while (exponent_length_bytes >= 2 && exponent[0] == 0) {
        ++exponent;
        --exponent_length_bytes;
    }
    if (exponent_length_bytes > modulus_length_bytes) {
        // e >= modulus
        return -3;
    }
    if (!(exponent_length_bytes <= 31 && ((uint8_t *)modulus)[modulus_length_bytes - 1] != 0)) {
        // This following check can be skipped for most common key sizes
        bignum_big_to_little_endian(T0, modulus_length_bytes, exponent, exponent_length_bytes);
        if (bignum_reduce_once(T0, modulus_bitwise_inv, modulus, T0, modulus_length_bytes) == 0) {
            // e >= modulus
            return -3;
        }
    }

    if (modulus[0] % 2 == 0) {
        // Montgomery multiplication doesn't work with even modulus
        return -4;
    }

    bignum_to_mont(temp, modulus, modulus_length_bytes, T0);
    
    uint32_t N_prim[4];
    bignum_modular_inverse(N_prim, modulus);
    
    memcpy(A1, temp, modulus_length_bytes);
    
    memset(T0, 0, modulus_length_bytes);
    
    size_t exponent_bit_length = 8 * exponent_length_bytes;
    size_t exponent_bit_pos = 0;
    for (; exponent_bit_pos < exponent_bit_length; exponent_bit_pos++) {
        if (exponent[exponent_bit_pos / 8] & (0x80 >> (exponent_bit_pos % 8))) {
            break;
        }
    }
    if (exponent_bit_pos == exponent_bit_length) {
        // We have a zero exponent
        memset(result, 0, modulus_length_bytes);
        result[0] = 1;
        return 0;
    }
    ++exponent_bit_pos;
    for (; exponent_bit_pos < exponent_bit_length; exponent_bit_pos++) {
        bignum_sqracc(T0, temp, modulus_length_bytes);
        bignum_mont_redc(T0, modulus_length_bytes, modulus, N_prim, modulus_bitwise_inv, temp);
        
        if (exponent[exponent_bit_pos / 8] & (0x80 >> (exponent_bit_pos % 8))) {
            bignum_mulacc(T0, temp, (exponent_bit_pos + 1 != exponent_bit_length) ? A1 : base, modulus_length_bytes);
            bignum_mont_redc(T0, modulus_length_bytes, modulus, N_prim, modulus_bitwise_inv, temp);
        }
    }
    --exponent_bit_pos;
    if ((exponent[exponent_bit_pos / 8] & 1) == 0) {
        // even exponent, not needed for RSA use cases since exponents are always odd, but keep this code for other use cases
        memset(T1, 0, modulus_length_bytes);
        memcpy(T0, temp, modulus_length_bytes);
        bignum_mont_redc(T0, modulus_length_bytes, modulus, N_prim, modulus_bitwise_inv, temp);
    }
    bignum_reduce_once(result, modulus_bitwise_inv, modulus, temp, modulus_length_bytes);
    return 0;
}

int bignum_modexp_public_exponent_big_endian_input(
    const uint8_t *base,
    const uint8_t *exponent,
    const uint8_t *modulus,
    size_t base_length_bytes,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp)
{
    if (modulus_length_bytes == 0 || modulus[0] == 0) {
        return -1;
    }

    if (base_length_bytes > modulus_length_bytes) {
        return -2;
    }
    
    size_t aligned_length = (modulus_length_bytes + 31) & ~(size_t)31;
    
    uint32_t *base_little_endian = temp;
    uint32_t *modulus_little_endian = (void *)temp + aligned_length;
    
    bignum_big_to_little_endian(modulus_little_endian, aligned_length, modulus, modulus_length_bytes);
    bignum_big_to_little_endian(base_little_endian, aligned_length, base, base_length_bytes);
    
    uint32_t *temp_inner = (void *)temp + 2 * aligned_length;
    return bignum_modexp_public_exponent(temp, base_little_endian, exponent, modulus_little_endian, exponent_length_bytes, aligned_length, temp_inner);
}

static BIGNUM_RAMFUNC void modulo(uint32_t *value, size_t modulus_length_bytes, const uint32_t *modulus, const uint32_t modulus_prim[4], const uint32_t *modulus_bitwise_inv, uint32_t *temp) {
    // The value parameter (must be less than R*N) is twice the modulus length for input, and the modulus length for output.
    // We calculate x = value * R^-1 mod N, followed by x * R mod N, where R = 2^bitlen. The result is thus value mod N.
    uint32_t *high_half = (uint32_t *)((void *)value + modulus_length_bytes);
    bignum_mont_redc(value, modulus_length_bytes, modulus, modulus_prim, modulus_bitwise_inv, high_half);
    bignum_reduce_once(high_half, modulus_bitwise_inv, modulus, high_half, modulus_length_bytes);
    bignum_to_mont(value, modulus, modulus_length_bytes, temp);
}

static BIGNUM_RAMFUNC void bignum_modexp_private_exponent_internal(
    uint32_t *result,
    const uint8_t *exponent,
    const uint32_t *modulus,
    const uint32_t modulus_prim[4],
    const uint32_t *modulus_bitwise_inv,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp)
{
    // The base (must be less than modulus) must be placed by the caller at temp + two modulus sizes
    // The temp area is at least 18 modulus in size
    
    uint32_t *T = (void *)temp + 16 * modulus_length_bytes;
    
    bignum_to_mont((void *)temp + modulus_length_bytes, modulus, modulus_length_bytes, T);
    
    memset(T, 0, modulus_length_bytes);
    
    bignum_reduce_once(temp, modulus_bitwise_inv, T, T, modulus_length_bytes);
    
    memcpy(result, temp, modulus_length_bytes);
    
    for (int i = 2; i < 16; i++) {
        bignum_mulacc(T, (void *)temp + modulus_length_bytes, (void *)temp + (i - 1) * modulus_length_bytes, modulus_length_bytes);
        bignum_mont_redc(T, modulus_length_bytes, modulus, modulus_prim, modulus_bitwise_inv, (void *)temp + i * modulus_length_bytes);
    }
    
#if CONSTANT_MEMORY_ACCESS_PATTERN
    // "Transpose" the table to match what the lookup function expects
    // using in-place matrix transposition.
    uint32_t num_8_word_blocks_per_item = modulus_length_bytes / 32;
    const uint32_t mod = 16 * num_8_word_blocks_per_item - 1;
    uint8_t *visited = (uint8_t *)T;
    for (uint32_t i = 1; i < mod; i++) {
        if (visited[i]) {
            continue;
        }
        uint32_t new_pos = 16 * i % mod;
        uint32_t prev[8];
        memcpy(prev, temp + 8 * i, sizeof(prev));
        while (new_pos != i) {
            for (int j = 0; j < 8; j++) {
                uint32_t tmp = prev[j];
                prev[j] = temp[8 * new_pos + j];
                temp[8 * new_pos + j] = tmp;
            }
            visited[new_pos] = true;
            new_pos = 16 * new_pos % mod;
        }
        memcpy(temp + 8 * i, prev, sizeof(prev));
    }
    memset(visited, 0, 16 * num_8_word_blocks_per_item);
#endif

    for (uint32_t i = 0; i < 8 * exponent_length_bytes; i += 4) {
        if (i != 0) {
            for (int j = 0; j < 4; j++) {
                bignum_sqracc(T, result, modulus_length_bytes);
                bignum_mont_redc(T, modulus_length_bytes, modulus, modulus_prim, modulus_bitwise_inv, result);
            }
        }
        
        uint32_t four_bits = (exponent[i / 8] >> (4 - (i % 8))) & 0xf;
#if CONSTANT_MEMORY_ACCESS_PATTERN
        uint32_t *table_entry = (void *)T + modulus_length_bytes;
        bignum_table_select(table_entry, temp, T, four_bits);
#else
        const uint32_t *table_entry = (void *)temp + four_bits * modulus_length_bytes;
#endif
        
        bignum_mulacc(T, table_entry, result, modulus_length_bytes);
        bignum_mont_redc(T, modulus_length_bytes, modulus, modulus_prim, modulus_bitwise_inv, result);
    }
    
    memcpy((void *)temp + 15 * modulus_length_bytes, result, modulus_length_bytes);
    bignum_mont_redc((void *)temp + 15 * modulus_length_bytes, modulus_length_bytes, modulus, modulus_prim, modulus_bitwise_inv, result);
    bignum_reduce_once(result, modulus_bitwise_inv, modulus, result, modulus_length_bytes);
}

BIGNUM_RAMFUNC void bignum_modexp_private_exponent(
    uint32_t *result,
    const uint8_t *exponent,
    const uint32_t *modulus,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp)
{
    uint32_t modulus_prim[4];
    bignum_modular_inverse(modulus_prim, modulus);
    
    uint32_t *modulus_bitwise_inv = (void *)temp + 18 * modulus_length_bytes;
    
    bignum_modexp_private_exponent_internal(result, exponent, modulus, modulus_prim, modulus_bitwise_inv, exponent_length_bytes, modulus_length_bytes, temp);
}

void rsa_private_exp_crt(
    uint32_t *result,
    const uint32_t *c,
    const uint8_t *dP,
    size_t dP_length_bytes,
    const uint8_t *dQ,
    size_t dQ_length_bytes,
    const uint32_t *p,
    const uint32_t *q,
    const uint32_t *q_modular_inv,
    size_t small_modulus_length_bytes,
    uint32_t *temp)
{
    // The caller must ensure that the c value is less than p*q
    // The temp area must be at least 20 small modulus in size
    // The result and c values can point to the same location, but must not overlap with temp
    
    uint32_t modulus_prim[4];
    
    uint32_t *modulus_bitwise_inv = (void *)temp + 19 * small_modulus_length_bytes;
    uint32_t *T = (void *)temp + 8 * small_modulus_length_bytes;
    uint32_t *T2 = (void *)temp + 16 * small_modulus_length_bytes;
    uint32_t *temp_inner = (void *)temp + 1 * small_modulus_length_bytes;
    
    const uint32_t *m[] = {q, p};
    const uint8_t *d[] = {dQ, dP};
    const size_t d_lengths[] = {dQ_length_bytes, dP_length_bytes};
    uint32_t *dest[] = {temp, result}; // m_2, m_1
    for (int i = 0; i < 2; i++) {
        bignum_modular_inverse(modulus_prim, m[i]);
        ones_complement(modulus_bitwise_inv, m[i], small_modulus_length_bytes);
        
        memcpy((void *)temp + 3 * small_modulus_length_bytes, c, 2 * small_modulus_length_bytes);
        modulo((void *)temp + 3 * small_modulus_length_bytes, small_modulus_length_bytes, m[i], modulus_prim, modulus_bitwise_inv, T);
        
        bignum_modexp_private_exponent_internal(dest[i], d[i], m[i], modulus_prim, modulus_bitwise_inv, d_lengths[i], small_modulus_length_bytes, temp_inner);
    }
    
    memcpy(T2, temp, small_modulus_length_bytes); // copy m_2 to T2
    memset(temp_inner, 0, small_modulus_length_bytes); // set upper half to 0, since our modulo function works on double-sized input
    modulo(temp, small_modulus_length_bytes, p, modulus_prim, modulus_bitwise_inv, T); // m_2 mod p
    ones_complement(temp, temp, small_modulus_length_bytes);
    bignum_submod(result, temp, p, result, small_modulus_length_bytes); // (m_1 - m_2) mod p
    memset(temp, 0, small_modulus_length_bytes); // set accumulator to 0
    bignum_mulacc(temp, result, q_modular_inv, small_modulus_length_bytes); // ((m_1 - m_2) mod p) * q_inv
    modulo(temp, small_modulus_length_bytes, p, modulus_prim, modulus_bitwise_inv, result); // (m_1 - m_2) * q_inv mod p
    memcpy(result, T2, small_modulus_length_bytes);
    bignum_mulacc(result, q, temp, small_modulus_length_bytes); // m_2 + q * ((m_1 - m_2) * q_inv mod p)
}

void bignum_endian_reverse(void *value, size_t length_bytes) {
    uint8_t *val = value;
    for (size_t i = 0; i < length_bytes / 2; i++) {
        uint8_t tmp = val[i];
        val[i] = val[length_bytes - 1 - i];
        val[length_bytes - 1 - i] = tmp;
    }
}

void bignum_big_to_little_endian(void *output, size_t output_length_bytes, const void *input, size_t input_length_bytes) {
    uint8_t *dest = output;
    const uint8_t *src = input;
    for (size_t i = 0; i < input_length_bytes; i++) {
        dest[i] = src[input_length_bytes - 1 - i];
    }
    for (size_t i = input_length_bytes; i < output_length_bytes; i++) {
        dest[i] = 0;
    }
}

void bignum_little_to_big_endian(void *output, size_t output_length_bytes, const void *input) {
    uint8_t *dest = output;
    const uint8_t *src = input;
    for (size_t i = 0; i < output_length_bytes; i++) {
        dest[output_length_bytes - 1 - i] = src[i];
    }
}

void rsa_private_exp_crt_big_endian_key(
    size_t private_key_n_length_bytes,
    const uint8_t *private_key_p, size_t private_key_p_length_bytes,
    const uint8_t *private_key_q, size_t private_key_q_length_bytes,
    const uint8_t *private_key_q_inv, size_t private_key_q_inv_length_bytes,
    const uint8_t *private_key_dp, size_t private_key_dp_length_bytes,
    const uint8_t *private_key_dq, size_t private_key_dq_length_bytes,
    size_t p_q_len_aligned,
    uint32_t *temp_area)
{
    uint32_t *p = (void *)temp_area + 2 * p_q_len_aligned;
    uint32_t *q = (void *)temp_area + 3 * p_q_len_aligned;
    uint32_t *q_inv = (void *)temp_area + 4 * p_q_len_aligned;
    bignum_big_to_little_endian(p, p_q_len_aligned, private_key_p, private_key_p_length_bytes);
    bignum_big_to_little_endian(q, p_q_len_aligned, private_key_q, private_key_q_length_bytes);
    bignum_big_to_little_endian(q_inv, p_q_len_aligned, private_key_q_inv, private_key_q_inv_length_bytes);
    
    if (2 * p_q_len_aligned > private_key_n_length_bytes) {
        memset((uint8_t *)temp_area + private_key_n_length_bytes, 0x00, 2 * p_q_len_aligned - private_key_n_length_bytes);
    }
    
    uint32_t *temp = (void *)temp_area + 5 * p_q_len_aligned;
    rsa_private_exp_crt(temp_area, temp_area, private_key_dp, private_key_dp_length_bytes, private_key_dq, private_key_dq_length_bytes, p, q, q_inv, p_q_len_aligned, temp);
}
