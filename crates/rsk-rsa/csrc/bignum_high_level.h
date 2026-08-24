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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Checks if a number is smaller than the modulus.
 * 
 * All parameters in little endian.
 * 
 * @param[in] value The value to check.
 * @param[in] modulus The non-zero modulus.
 * @param[in] modulus_length_bytes The length of \p value and \p modulus in bytes. Must be a multiple of 16.
 * @param[in,out] temp A temporary area having at least twice the length of the modulus.
 * 
 * @return true if the value is less than the modulus, otherwise false.
 */
bool bignum_check_less_than(const uint32_t *value, const uint32_t *modulus, size_t modulus_length_bytes, uint32_t *temp);

/**
 * @brief Performs modular exponentiation with an odd modulus where the exponent is public (non-secret).
 * 
 * All parameters in little endian except \p exponent.
 *
 * Input parameters must satisfy certain preconditions.
 * See the negative return values for the invalid input conditions that will be caught.
 * 
 * @param[out] result The result.
 * @param[in] base The base. Can point to the same location as \p result.
 * @param[in] exponent The exponent in big endian byte order.
 * @param[in] modulus The modulus. Must not overlap with \p result.
 * @param[in] exponent_length_bytes The number of bytes in the exponent.
 * @param[in] modulus_length_bytes The number of bytes in each of \p result, \p base, \p modulus. Must be a multiple of 32.
 * @param[in,out] temp A temporary area that is at least 5 times the modulus length in bytes.
 * 
 * @retval  0 Success.
 * @retval -1 \p modulus_length_bytes is 0 or not a multiple of 32.
 * @retval -2 The base is not less than modulus.
 * @retval -3 The exponent is not less than modulus.
 * @retval -4 The modulus is even.
 */
int bignum_modexp_public_exponent(
    uint32_t *result,
    const uint32_t *base,
    const uint8_t *exponent,
    const uint32_t *modulus,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp);

/**
 * @brief Performs modular exponentiation with an odd modulus where the exponent
 * is public (non-secret) for big endian input.
 * 
 * All input values have big endian byte order.
 * 
 * The little endian output will be placed at the beginning of \p temp and have
 * the same length as the modulus.
 * 
 * Input parameters must satisfy certain preconditions.
 * See the negative return values for the invalid input conditions that will be caught.
 * 
 * @param[in] base The base.
 * @param[in] exponent The exponent.
 * @param[in] modulus The modulus.
 * @param[in] base_length_bytes The number of bytes in the base.
 * @param[in] exponent_length_bytes The number of bytes in the exponent.
 * @param[in] modulus_length_bytes The number of bytes in the modulus.
 * @param[in,out] temp A temporary area that is at least \p modulus_length_bytes rounded up to the nearest multiple of 32, times 7.
 * 
 * @retval  0 Success.
 * @retval -1 Either \p modulus_length_bytes is 0 or the first byte in the \p modulus is 0.
 * @retval -2 The base is not less than modulus, or \p base_length_bytes is more than \p modulus_length_bytes.
 * @retval -3 The exponent is not less than modulus.
 * @retval -4 The modulus is even.
 */
int bignum_modexp_public_exponent_big_endian_input(
    const uint8_t *base,
    const uint8_t *exponent,
    const uint8_t *modulus,
    size_t base_length_bytes,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp);


/**
 * @brief Performs modular exponentiation with an odd modulus where the exponent is private (secret).
 * 
 * All parameters in little endian except \p exponent.
 * 
 * The base shall be placed in the temporary buffer at the offset of two times \p modulus_length_bytes (in bytes).
 * 
 * This function assumes all parameters are valid.
 * 
 * @param[out] result The result.
 * @param[in] exponent The exponent in big endian byte order.
 * @param[in] modulus The odd modulus. Must not overlap with \p result.
 * @param[in] exponent_length_bytes The length of the exponent in bytes.
 * @param[in] modulus_length_bytes The length of the modulus in bytes. Must be a multiple of 32.
 * @param[in,out] temp A temporary area that is at least 19 times the modulus length in bytes.
 */
void bignum_modexp_private_exponent(
    uint32_t *result,
    const uint8_t *exponent,
    const uint32_t *modulus,
    size_t exponent_length_bytes,
    size_t modulus_length_bytes,
    uint32_t *temp);

/**
 * @brief Performs modular exponentiation using the CRT optimization.
 * 
 * All parameters are in little endian except the exponents \p dP and \p dQ.
 * 
 * See RFC 8017 for information about the parameters.
 * 
 * This function assumes all parameters are valid.
 * 
 * @param[out] result The result. Twice the size of \p p or \p q.
 * @param[in] c The base, less than the modulus. Twice the size of \p p or \p q.
 * @param[in] dP The first exponent.
 * @param[in] dP_length_bytes The length in bytes of the first exponent.
 * @param[in] dQ The second exponent.
 * @param[in] dQ_length_bytes The length in bytes of the second exponent.
 * @param[in] p The first prime.
 * @param[in] q The second prime.
 * @param[in] q_modular_inv The modular inverse of \p q modulo \p p. Same size as \p p.
 * @param[in] small_modulus_length_bytes The length in bytes of each of \p p and \p q. Must be a multiple of 32.
 * @param[in,out] temp A temporary area that is at least 20 times the length of \p p or \p q in bytes.
 */
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
    uint32_t *temp);

/**
 * @brief Performs modular exponentiation using the CRT optimization with big endian private key.
 * 
 * See RFC 8017 for information about the parameters.
 * 
 * The base (little endian) shall be placed at the beginning of \p temp_area and has size \p private_key_n_length_bytes.
 * The result (little endian) will be placed at the same location.
 * 
 * This function assumes all parameters are valid.
 * 
 * @param[in] private_key_n_length_bytes
 *     Length of the modulus \c n of the private key in bytes,
 *     such that when written in big-endian byte order,
 *     the first byte (most significant) is non-zero.
 *
 * @param[in] private_key_p
 *     Pointer to the first prime factor \c p, in big-endian byte order.
 *
 * @param[in] private_key_p_length_bytes
 *     Length of \p private_key_p in bytes.
 *
 * @param[in] private_key_q
 *     Pointer to the second prime factor \c q, in big-endian byte order.
 *
 * @param[in] private_key_q_length_bytes
 *     Length of \p private_key_q in bytes.
 *
 * @param[in] private_key_q_inv
 *     Pointer to the modular inverse of \c q mod \c p, in big-endian byte order.
 *
 * @param[in] private_key_q_inv_length_bytes
 *     Length of \p private_key_q_inv in bytes.
 *
 * @param[in] private_key_dp
 *     Pointer to the CRT exponent \c dP = d mod (p-1), in big-endian byte order.
 *
 * @param[in] private_key_dp_length_bytes
 *     Length of \p private_key_dp in bytes.
 *
 * @param[in] private_key_dq
 *     Pointer to the CRT exponent \c dQ = d mod (q-1), in big-endian byte order.
 *
 * @param[in] private_key_dq_length_bytes
 *     Length of \p private_key_dq in bytes.
 * 
 * @param[in] p_q_len_aligned
 *     The length of the biggest of p and q in bytes, rounded up to the nearest multiple of 32 bytes.
 * 
 * @param[in,out] temp_area
 *     Pointer to an array of \c uint32_t (temporary workspace).
 *     The size in bytes shall be at least 25 times \p p_q_len_aligned.
 */
void rsa_private_exp_crt_big_endian_key(
    size_t private_key_n_length_bytes,
    const uint8_t *private_key_p, size_t private_key_p_length_bytes,
    const uint8_t *private_key_q, size_t private_key_q_length_bytes,
    const uint8_t *private_key_q_inv, size_t private_key_q_inv_length_bytes,
    const uint8_t *private_key_dp, size_t private_key_dp_length_bytes,
    const uint8_t *private_key_dq, size_t private_key_dq_length_bytes,
    size_t p_q_len_aligned,
    uint32_t *temp_area);


/**
 * @brief Reverses the byte order of a byte array.
 * 
 * @param[in,out] value The value to reverse.
 * @param[in] length_bytes The length of value in bytes.
 */
void bignum_endian_reverse(void *value, size_t length_bytes);

/**
 * @brief Converts a value from big to little endian.
 * 
 * The value will be zero-padded at the end, if necessary.
 * 
 * @param[out] output Pointer to the output, which must not overlap with the input.
 * @param[in] output_length_bytes The length of the output in bytes.
 * @param[in] input Pointer to the input.
 * @param[in] input_length_bytes The length of the input in bytes.
 */
void bignum_big_to_little_endian(void *output, size_t output_length_bytes, const void *input, size_t input_length_bytes);

/**
 * @brief Converts a value from little to big endian.
 * 
 * The length of the input and the output must be the same.
 * 
 * @param[out] output Pointer to the output, which must not overlap with the input.
 * @param[in] output_length_bytes The length of the output (and input) in bytes.
 * @param[in] input Pointer to the input.
 */
void bignum_little_to_big_endian(void *output, size_t output_length_bytes, const void *input);

#ifdef __cplusplus
}
#endif
