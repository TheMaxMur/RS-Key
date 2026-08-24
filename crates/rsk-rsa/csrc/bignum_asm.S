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

#include "bignum_config.h"

#define START_FUNC(name) \
    .thumb_func ;\
    .type name, %function ;\
name: ;\
    .cfi_startproc
#define START_GLOBAL_FUNC(name) \
    .global name ;\
    START_FUNC(name)
#define END_FUNC(name) \
    .cfi_endproc ;\
    .size name, .-name

    .syntax unified
    // RS-Key: SRAM-resident — the .data.* name makes cortex-m-rt copy this
    // section into RAM at boot (the same mechanism as embassy-rp's flash RAM
    // functions). The keygen Fermat filter runs these loops on BOTH cores
    // concurrently; executed from XIP the cores throttle each other on the
    // shared flash cache (~40% per-core slowdown measured on the RP2350).
    .section .data.bignum_asm,"awx",%progbits
    .eabi_attribute Tag_ABI_align_preserved, 1 // only internal functions called, so ok
    .cfi_sections .debug_frame
    .thumb
    .balign 4

//in: A words in r0-r3, B word pointer in r4, accumulate pointer in/out in r5, length in r6 (in bytes)
//at exit: r4 and r5 have been increased by r6, r6 is zero, r7-r10 contain carry, r12 contains the highest B word, lr is left unmodified
START_FUNC(mulacc_inner)
    movs r7,#0
    mov r8,r7
    umull r9,r10,r7,r7
mulacc_inner_with_carry:
    push {lr}
    .cfi_def_cfa_offset 4
    .cfi_offset lr,-4
    
    ldr r12,[r4],#4
    ldr lr,[r5]
    b 1f

0:
mulacc_inner1:
    ldr r12,[r4],#4
    ldr lr,[r5,#4]
    str.w r11,[r5],#4
1:

#define UMAAL_BLOCK(first_reg) \
    umaal first_reg,r7,r12,r0 ;\
    umaal r7,r8,r12,r1 ;\
    umaal r8,r9,r12,r2 ;\
    umaal r9,r10,r12,r3

#define BLOCK0 \
    UMAAL_BLOCK(lr) ;\
    ldr r12,[r4],#4 ;\
    ldr r11,[r5,#4] ;\
    str.w lr,[r5],#4

#define BLOCK1 \
    UMAAL_BLOCK(r11) ;\
    ldr r12,[r4],#4 ;\
    ldr lr,[r5,#4] ;\
    str.w r11,[r5],#4

    BLOCK0
    BLOCK1
    BLOCK0
    
    UMAAL_BLOCK(r11)
mulacc_inner2:
    ldr r12,[r4],#4
    ldr lr,[r5,#4]
    str.w r11,[r5],#4
    
    BLOCK0
    BLOCK1
    BLOCK0
    UMAAL_BLOCK(r11)
    subs r6,r6,#32
    bhi 0b
    
    ldr lr,[sp],#4
    .cfi_def_cfa_offset 0
    .cfi_restore lr
    str r11,[r5],#4
    bx lr
END_FUNC(mulacc_inner)

// *r0: acc (lower num bytes only)/out (2x num bytes), *r1: A, *r2: B, r3: num bytes per operand (> 0 and a multiple of 32)
// A (but not B) may point to the same location as the upper half of *r0
START_GLOBAL_FUNC(bignum_mulacc)
    add r12,r1,r3 // end of A address
    push {r3-r12,lr}
    .cfi_def_cfa_offset 44
    .cfi_offset r4,-40
    .cfi_offset r5,-36
    .cfi_offset r6,-32
    .cfi_offset r7,-28
    .cfi_offset r8,-24
    .cfi_offset r9,-20
    .cfi_offset r10,-16
    .cfi_offset r11,-12
    .cfi_offset lr,-4
    
    mov r4,r2
    mov r6,r3
    mov r7,r1
    mov r5,r0
    ldm r7!,{r0-r3}
    push {r7}            // A
    .cfi_def_cfa_offset 48
    bl mulacc_inner

1:
    stm r5!,{r7-r10}
    ldr r7,[sp]          // A
    ldr r6,[sp,#4*10]    // A end
    ldm r7!,{r0-r3}
    cmp r6,r7
    it eq
    addeq lr,lr,2f-1b
    ldr r6,[sp,#4*1]     // num bytes
    str r7,[sp]          // A
    subs r5,r5,r6
    subs r4,r4,r6
    b mulacc_inner      // will use the already set lr as return address

2:
    stm r5!,{r7-r10}
    
    pop {r2-r12,pc}
END_FUNC(bignum_mulacc)

// *r0: acc (lower num bytes only)/out (2x num bytes), *r1: operand, r2: num bytes of operand (> 0 and a multiple of 32)
START_GLOBAL_FUNC(bignum_sqracc)
    movs r3,#0
    push {r2-r11,lr}
    .cfi_def_cfa_offset 44
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    mov r4,r1
    mov r5,r0
    bl 0f // lr gets set here to the address of the following instruction

    // return from mulacc_inner will end up here
    stm r5!,{r7-r10}
    ldr r6,[sp] // num bytes
    subs r5,r5,r6
    subs r4,r4,r6

0:
    ldr r7,[sp,#4] // operand doubling carry
    ldr r6,[r5]
    lsrs r0,r7,#1
    ldm r4!,{r0-r3}
    muls r7,r0,r7
    umaal r6,r7,r0,r0

    and r8,r1,r0, asr #31
    adcs r0,r0,r0

    ldr r11,[r5,#4]
    str r6,[r5],#4

    umaal r11,r7,r1,r0
    umaal r7,r8,r1,r1

    and r9,r2,r1, asr #31
    adcs r1,r1,r1

    ldr r6,[r5,#4]
    str r11,[r5],#4

    umaal r6,r7,r2,r0
    umaal r7,r8,r2,r1
    umaal r8,r9,r2,r2

    and r10,r3,r2, asr #31
    adcs r2,r2,r2

    ldr r11,[r5,#4]
    str r6,[r5],#4

    umaal r11,r7,r3,r0
    umaal r7,r8,r3,r1
    umaal r8,r9,r3,r2
    umaal r9,r10,r3,r3

    adcs r3,r3,r3
    movs r6,#0
    adcs r6,r6,r6
    str r6,[sp,#4] // operand doubling carry

    ldr r6,[sp] // num bytes, and 16 less for every iteration
    subs r6,r6,#16
    str r6,[sp] // update value
    beq 0f
    lsls r12,r6,#27
    push {lr} // prologue of mulacc_inner duplicated here
    .cfi_def_cfa_offset 48
    bmi mulacc_inner2
    b mulacc_inner1
    //now jump into fourth BLOCK row, i.e. in the middle of a BLOCK1, or at label 0: depending on pos modulo 16
0:
    .cfi_def_cfa_offset 44
    mov r6,r11
    stm r5!,{r6-r10}
    pop {r1,r2,r4-r11,pc}
END_FUNC(bignum_sqracc)


// *r0 = input value, r1 = num bytes in modulus (input value is double sized), *r2 = N, *r3 = N' (four words), *sp[0] = ~N, *sp[1] = output
// num bytes in modulus must be positive and a multiple of 32
// if output overlaps with input, output must point to either the lower or upper half of the input, but output must not overlap with N
// the upper half of input value will be clobbered but the lower half will be set to zero (unless input pointer equals output pointer)
// if the most significant bit in the modulus buffer is set:
//   the output is not fully reduced (one extra subtraction of N might be required)
// otherwise:
//   the input must be less than R*N, where R is 2^(8*r1)
///  the output is fully reduced
START_GLOBAL_FUNC(bignum_mont_redc)
    push {r1-r11,lr}
    .cfi_def_cfa_offset 48
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    
    mov r5,r0
    movs r4,#0 // init carry word
    add r0,r5,r1
    push {r0,r4}
    .cfi_def_cfa_offset 56

0:
    ldr r7,[sp,#4*4] // N'
    ldm r7,{r4,r6,r12,lr}
    ldm r5,{r8-r11}
    umull r0,r1,r4,r8    // 0 00
    umull r2,r3,r4,r9    // 1 01
    umaal r1,r2,r6,r8    // 1 10
    umaal r2,r3,r4,r10    // 2 02
    umull r4,r11,r4,r11    // 3 03
    umull r7,r11,r6,r9    // 2 11
    umaal r3,r4,r6,r10    // 3 12
    umaal r2,r7,r12,r8    // 2 20
    umaal r3,r11,r12,r9    // 3 21
    umaal r3,r7,lr,r8    // 3 30
    ldr r4,[sp,#4*3] // N
    ldr r6,[sp,#4*2] // num bytes
    bl mulacc_inner
    // accumulate r7-r10 into T, save highest carry word for next iteration
    ldr r0,[sp,#4*1] // saved carry
    ldm r5,{r1-r4}
    movs r6,#1
    umaal r1,r0,r6,r7
    umaal r2,r0,r6,r8
    umaal r3,r0,r6,r9
    umaal r4,r0,r6,r10
    stm r5!,{r1-r4}
    ldr r6,[sp,#4*2] // num bytes
    ldr r7,[sp] // end of half tmp
    str r0,[sp,#4*1] // saved carry
    subs r5,r5,r6
    cmp r5,r7
    bne 0b
    
    ldr r1,[sp,#4*14] // ~N
    ldr lr,[sp,#4*15] // out
    mov r11,r0
    cmp r12,#0 // Check if the highest bit in the modulus is set
    blt 1f // If this branch is taken, we subtract N once in case the result overflowed

.L_reduce_once:
    // If (value >= N) value -= N
    // We instead perform (in constant time): value -= N, if (value < 0) value += N
    // The subtraction is performed as: value + (2^bitlength - 1 - N) - 2^bitlength + 1
    movs r0,#1
    mov r11,r0
0:
    ldm r7!,{r2-r5}
    ldm r1!,{r8-r10,r12}
    umaal r2,r11,r0,r8
    umaal r3,r11,r0,r9
    umaal r4,r11,r0,r10
    umaal r5,r11,r0,r12
    stm lr!,{r2-r5}
    subs r6,r6,#16
    bne 0b
    ldr r2,[sp,#4*1] // saved carry
    add r2,r2,r11 // r2 is after this either 0 or 1
    eors r0,r0,r2 // perform the -2^bitlength operation combined with a negation
    mov r11,r6
    ldr r6,[sp,#4*2] // num bytes
    ldr r1,[sp,#4*3] // N
    sub lr,lr,r6
    mov r7,lr
1:
    ldm r7!,{r2-r5}
    ldm r1!,{r8-r10,r12}
    umaal r2,r11,r0,r8
    umaal r3,r11,r0,r9
    umaal r4,r11,r0,r10
    umaal r5,r11,r0,r12
    stm lr!,{r2-r5}
    subs r6,r6,#16
    bne 1b
    
    add sp,sp,#20
    .cfi_def_cfa_offset 36
    pop {r4-r11,pc}
END_FUNC(bignum_mont_redc)

/*
Arguments:
0: *r0=input/output value (input is placed at byte offset r2 and output will be placed at offset 0)
1: *r1=modulus > 0
2: r2=modulus length in bytes (must be a multiple of 32 bytes, any number of highest bits can be 0)
3: *r3=temp area (at least as long as modulus, times two)
Note: *r0 is 2*r2 bytes; the output consists of the first r2 bytes
Note: the (input) integer that makes up the most significant r2 bytes in r0 (i.e. upper half) must be less than modulus
Note: the input value *r0 may have any number of zero bits as most significant bits
Note: the input value in *r0 (upper half) will be clobbered when the function is complete
*/
START_GLOBAL_FUNC(bignum_to_mont)
    push {r0,r2-r11,lr}
    .cfi_def_cfa_offset 48
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    
    // This function uses a variant of Barrett reduction. The dividend is reduced 128 bits per division step.
    
    // Before start, we left-shift the modulus so that the most significant bit is set.
    // The input value must be left-shifted the same amonut of bits.
    // When the remainder has been computed, we right-shift it by the same amount of bits to get the correct result.
    
    // Initially, we use Newton's method to calculate an approximation to the inverse of the modulus (133 fraction bits).
    // In each division step, we look at the upper 5 words and the approximation to the inverse of the modulus to quickly
    // obtain a candidate quotient for the division, which will at most be overestimated by 1.
    
    sub sp,sp,#16
    .cfi_def_cfa_offset 64
    
    add r6,r0,r2, lsl #1
    str r6,[sp,#12]

    add r9,r1,r2
    ldr r8,[r9,#-4]!
    cmp r8,#0
    blt 0f

    sub r0,r6,#4
    add r3,r3,r2
    str r3,[sp] // D
    add r3,r3,r2

    mov r4,r9

    bne 2f
    // find most significant non-zero word
1:
    ldr r8,[r9,#-4]!
    subs r0,r0,#4
    cmp r8,#0
    beq 1b
2:
    subs r4,r4,r9 // number of most significant zero words (in bytes)
    clz r5,r8
    str r4,[sp,#4] // offset word
    str r5,[sp,#8] // offset bit
    rsbs r2,r2,#0

    // start to left shift D such that the most significant bit is set, and A as many steps
    ldr r7,[r0]
    lsls r7,r7,r5
    movs r10,#1
    lsls r10,r10,r5
    umull r5,r4,r10,r8

    b 4f
5:
    umull r11,r12,r4,r4
    
    ldr r8,[r9,#-4]! // load D
    ldr lr,[r0,#-4]! // load A
    
    umlal r12,r5,r10,r8
    str r5,[r3,#-4]! // store D
    mvns r5,r5
    str r5,[r3,r2]     // store D bitwise inverted
    mov r5,r12
    
    umlal r11,r7,r10,lr
    str r7,[r6,#-4]! // store A
    mov r7,r11
    
    str r4,[r6,r2]   // store A lower end (zero fill)
4:
    cmp r9,r1
    bne 5b

    str r5,[r3,#-4]!
    mvns r5,r5
    str r5,[r3,r2]
    str r7,[r6,#-4]!
    str r4,[r6,r2]
    mvns r7,r4
    ldr r1,[sp,#24] // pointer to temp area
    subs r1,r1,r2
    b 7f

6:
    str r4,[r3,#-4]!
    str r7,[r3,r2]
    str r4,[r6,#-4]!
    str r4,[r6,r2]
7:
    cmp r3,r1
    bne 6b
    subs r1,r1,r2
    b 1f

0:
    movs r4,#0
    umull r8,r12,r4,r4
    umull r10,r11,r4,r4
    stm sp,{r1,r4,r8} // D, offset word (0), offset bit (0)
0:
    ldm r1!,{r4-r7}
    mvns r4,r4
    mvns r5,r5
    mvns r6,r6
    mvns r7,r7
    stm r3!,{r4-r7}
    stm r0!,{r8,r10-r12}
    cmp r1,r9
    blt 0b

1:

    // Here we extract the highest 133 bits and store them into r7,r6,r5,r4,r12 (lsw to msw)
    // We also extract the highest 21 bits and store them into r0
    ldmdb r1,{r0-r4}
    mov lr,#32
    lsrs r7,r0,#27
    umull r6,r5,lr,r2
    lsrs r0,r4,#11
    umull r4,r12,lr,r4
    umlal r7,r6,lr,r1
    umlal r5,r4,lr,r3
    
    
    // For Newton's Method, we follow "Fast Division of Large Integers: A Comparison of Algorithms" by Karl Hasselström, Algorithm 4.2:
    // https://web.archive.org/web/20170708221722/https://static1.squarespace.com/static/5692a9ad7086d724272eb00a/t/5692dbe6b204d50df79e577f/1452465127528/masters-thesis.pdf
    // with the following adjustments and parameters:
    
    /*
    The initial guess z_0 is hardcoded to 1.5. With k_0 = 1, that will result in Theorem 4.2 is valid for all cases except v=0.5.
    In that special case, however, the requirement is fulfilled after one iteration.
    
    Table of Newton's method iterations:
    
    i   k_i     z_i         s_i         t_i         t_i*s_i     u_i         w_i         w_i(scaled) z_{i+1}
                            z_i^2       v truncated                         2*z_i                   w_i-u_i
    0   1       Q1.1        Q2.2        Q0.5        Q2.7        Q2.3        Q2.0        Q2.3        Q2.3
    1   2       Q2.3        Q3.6        Q0.7        Q2.13       Q2.5        Q3.2        Q3.5        Q2.5
    2   3       Q2.5        Q3.10       Q0.9        Q2.19       Q2.7        Q3.4        Q3.7        Q2.7
    3   5       Q2.7        Q3.14       Q0.13       Q2.27       Q2.11       Q3.6        Q3.11       Q2.11
    4   9       Q2.11       Q3.22       Q0.21       Q2.43       Q2.19       Q3.10       Q3.19       Q2.19
    5   17      Q2.19       Q3.38       Q0.37       Q2.75       Q2.39*      Q3.18       Q3.39       Q2.39
    6   33      Q2.39       Q3.78       Q0.69       Q2.147      Q2.70*      Q3.38       Q3.70       Q2.70
    7   65      Q2.70       Q3.140      Q0.133      Q2.273      Q2.133*     Q3.69       Q3.133      Q2.133
    8   130     Q2.133
    
    *=we use a few bits more than strictly needed, so that we later can shift more easily (it can be done implicitly when the shift amount is a multiple of 32)

    When calculating t_7*s_7, we should have performed "schoolbook multiplication" with t_7 having 5 words and s_i having 5 words, in total 5*5=25 32-bit multiplications.
    The result uses 10 32-bit words, but since we know the result will fit in 275 bits, the top word will be 0 and can be discarded. Also, we want to skip the three lowest
    "columns", i.e. the rightmost six 32-bit multiplications, to save some code space. But those could have contributed an integer up to ((3*0xffffffff^2 << 64) +
    (2*0xffffffff^2 << 32) + 0xffffffff^2) < 2^130. Adjusted to the correct fraction bit position, considering 273 fraction bits, it corresponds to < 2^-143.
    We thus have that the final error after i=8 is |e| < 2^-130 + 2^-143.

    Alternatively, if we say we calculate 2^128/v with 5 fraction bits instead of 1/v with 133 fraction bits, we have that |e| < 2^-2 + 2^-15.
    
    */

    /*
    Each iteration is z_(i+1) = 2*z_i - t_i*(z_i)^2
    Initial guess z_0 is 1.5

    uint32_t z1 = 3*8 - ((num >> 27) * 9 >> 4);
    uint32_t z2 = (z1 << 3) - ((num >> 25) * (z1*z1) >> 8);
    uint32_t z3 = (z2 << 3) - ((num >> 23) * (z2*z2) >> 12);
    uint32_t z4 = (z3 << 5) - ((num >> 19) * (z3*z3) >> 16);
    uint32_t z5 = (z4 << 9) - ((uint64_t)(num >> 11) * (z4*z4) >> 24);
    ...
    */

    // Iteration k_i = 1
    add r1,r12,r12, lsl #3
    movs r2,#24
    sub r1,r2,r1, lsr #4

    // Iteration k_i = 2
    lsrs r3,r0,#(25-11)
    muls r3,r1,r3
    lsls r2,r1,#3
    muls r1,r3,r1
    sub r1,r2,r1, lsr #8

    // Iteration k_i = 3
    lsrs r3,r0,#(23-11)
    muls r3,r1,r3
    lsls r2,r1,#3
    muls r1,r3,r1
    sub r1,r2,r1, lsr #12

    // Iteration k_i = 5
    lsrs r3,r0,#(19-11)
    muls r3,r1,r3
    lsls r2,r1,#5
    muls r1,r3,r1
    sub r1,r2,r1, lsr #16

    // Iteration k_i = 9
    umull r2,r8,r1,r1
    umull r3,r2,r2,r0
    lsrs r3,r3,#24
    orr r3,r3,r2, lsl #8
    rsb r3,r3,r1, lsl #9

    // Iteration k_i = 17
    umull r1,lr,r3,r4
    mla lr,r3,r12,lr
    umull r10,r11,r1,r3
    umlal r11,r8,lr,r3
    lsrs r11,r11,#4
    orr r11,r11,r8, lsl #28
    lsrs r2,r3,#11
    rsbs r3,r11,r3, lsl #21
    sbc r11,r2,r8, lsr #4

    // Iteration k_i = 33
    umull r8,r9,r3,r3
    umull r10,r1,r3,r11
    umaal r9,r10,r3,r11
    umaal r10,r1,r11,r11

    umull r0,lr,r5,r8
    umull r1,r2,r5,r9
    umaal r1,lr,r4,r8
    umull r0,r1,r5,r10
    umaal r0,lr,r4,r9
    umaal r1,lr,r4,r10
    umaal r0,r2,r12,r8
    umaal r1,r2,r12,r9
    umaal r2,lr,r12,r10

    lsrs r0,r0,#13
    orr r0,r0,r1, lsl #19
    lsrs r1,r1,#13
    orr r1,r1,r2, lsl #19

    rsbs r0,r0,#0
    sbcs r3,r3,r1
    sbc r11,r11,r2, lsr #13
    push {r0,r3,r11}
    .cfi_def_cfa_offset 76

    // Iteration k_i = 65
    umull r1,r2,r0,r0
    umull r8,r9,r0,r3
    umull r10,lr,r0,r11
    umaal r2,r8,r3,r0
    umaal r8,r9,r3,r3
    umaal r9,lr,r3,r11
    umaal r8,r10,r11,r0
    umaal r9,r10,r11,r3
    umaal r10,lr,r11,r11
    // s_7 = r1,r2,r8,r9,r10 (lr=0)
    // t_7 = r7,r6,r5,r4,r12

/*
            Multiplication sequence (_ indicates umull rather than umaal):

                                            9       7       4       2_      1_
                                    12      11      8       5_      3
                            16      15      14      10_     6
                    20      19      18      17_     13
            25      24      23      22      21

            Optimized sequence:

                                            9       7_
                                    12      11      8
                            16      15      14      10_
                    20      19      18      17_     13
            25      24      23      22      21
*/

    //umull r0,r3,r1,r7
    //umull r0,lr,r1,r6
    //umaal r0,r3,r2,r7
    //umaal r3,lr,r1,r5
    //umull r0,r11,r2,r6
    //umaal r0,r3,r8,r7
    umull r3,r11,r1,r4
    umaal r3,lr,r2,r5
    umaal r11,lr,r1,r12
    umull r0,r1,r8,r6
    umaal r11,r1,r2,r4
    umaal r1,lr,r2,r12
    umaal r0,r3,r9,r7
    umaal r3,r11,r8,r5
    umaal r1,r11,r8,r4
    umaal r11,lr,r8,r12
    umull r0,r2,r9,r6
    umaal r1,r2,r9,r5
    umaal r2,r11,r9,r4
    umaal r11,lr,r9,r12
    umaal r0,r3,r10,r7
    umaal r1,r3,r10,r6
    umaal r2,r3,r10,r5
    umaal r3,r11,r10,r4
    umaal r11,lr,r10,r12
    // t_i*s_i-e in _,_,_,_,r0,r1,r2,r3,r11,(lr=0), where e represents the 6 skipped partial multiplications

    mov r12,#(1<<(32-12))
    umull r10,r0,r12,r0
    umull r4,r5,r12,r2
    umull r6,r7,r12,r11
    umlal r0,r4,r12,r1
    umlal r5,r6,r12,r3

    rsbs r0,r0,#0
    sbcs r1,lr,r4

    pop {r2-r4}
    .cfi_def_cfa_offset 64
    sbcs r2,r2,r5
    sbcs r3,r3,r6
    sbcs r4,r4,r7
    push {r0-r4}
    .cfi_def_cfa_offset 84
    // We are now done calculating approximation of 1/D with 133 fraction bits

    // Now, iteratively divide the 1+n highest 128-bit blocks in A (denoted A_window) by D and compute the remainder
    ldr r5,[sp,#32] // location for A end
    ldmdb r5!,{r7-r11}
    adds r5,r5,#4
0:
    /*
    In each step we want to compute A/D and get the remainder.
    Let N be the number of significant bits in D.
    Let B be 128.
    Let M be B + N.
    Assume A < 2^B*D.
    
    Let k be approximation of 2^M/D with 5 fraction bits (0 < k <= 2^(B+1))
    Let K be 2^M/D and write that as k - e (with the error e of k such that abs(e) < 0.25 + 2^-15)
    Let A_low be the N - 5 lowest bits in A (or even fewer than N - 5 bits)
    Let A_high be A - A_low
    
    Let's now rewrite A/D as follows:
    A/D =
    A * (K / 2^M) =
    A * (k - e) / 2^M =
    A * k / 2^M - A * e / 2^M =
    A_high * k / 2^M + A_low * k / 2^M - A * e / 2^M =
    ((A_high / 2^M) * k - skipped) + (skipped + A_low / 2^M * k - A / 2^M * e)
    
    with "skipped" representing skipped partial multiplications when we compute (A_high / 2^M) * k.
    
    Assume 0 <= skipped < 2^-3.
    
    We have
    0 <= A_low / 2^M < 2^(N-5) / 2^M = 2^-(B+5)
    and thus
    abs(A_low / 2^M * k) < 2^-(B+5) * 2^(B+1) = 2^-4.
    
    We have
    0 <= A / 2^M < 1
    and thus
    abs(A / 2^M * e) < 0.25 + 2^-15 = 2^-2 + 2^-15
    
    In total, (skipped + A_low / 2^M * k - A / 2^M * e) is bounded by
    abs(skipped + A_low / 2^M * k - A / 2^M * e) < 2^-3 + 2^-4 + 2^-2 + 2^-15 < 2^-1 = 0.5
    
    Therefore, if we calculate an approximate division result of A / D as q_approx = ((A_high / 2^M) * k - skipped),
    the error will be less than 0.5.
    
    -0.5 < q_approx - A/D < 0.5
    0 < (q_approx + 0.5) - A/D < 1
    -1 < floor(q_approx + 0.5) - A/D < 1
    -1 < floor(q_approx + 0.5) - floor(A/D) < 2
    0 <= floor(q_approx + 0.5) - floor(A/D) <= 1 (since floor(.) returns an integer)
    
    This means that q = floor(q_approx + 0.5) will always be at most 1 more than the true quotient floor(A/D).
    
    Below, we will use A_low with N - 32 bits, so that the top 160 bits in A_high can be non-zero.
    
    */
    
    // Try to find quotient candidate q for A_window/D by looking at the most significant 5 words
    ldm sp,{r0-r4} // k
    
    
    /*
    Note: k is stored in Q130.5 format and (A_high / 2^M) is stored in Q0.160 format.
    With k' = k * 2^5, which more closely represents what we actually have stored,
    we can say that we calculate floor((k' * (A_high / 2^M) - skipped * 2^5 + 0.5 * 2^5) / 2^5).

    The multiplication k' * (A_high / 2^M) is carried out as follows, Q135.0 * Q0.160 results in a Q135.160 number:

                     0.  a   b   c   d   e    <- 5 most significant words in A_high
     f   g   h   i   j.  0                    <- (2^5)*k (5 as exponent is needed if we want to cut off umaals)

    We should have done this:
                        aj  bj  cj  dj  ej
                    ai. bi  ci  di  ei
                ah  bh. ch  dh  eh
            ag  bg  cg. dg  eg
        af  bf  cf  df. ef

    But since we don't need all the precision, we do this instead (_ indicates umull rather than umaal):
                        aj_
                    ai. bi_
                ah  bh. ch
            ag  bg  cg. dg_
        af  bf  cf  df. ef

    With w = (2^32 - 1)^2 / 2^160, the skipped partial multiplications are at most 4*w*2^96 + 3*w*2^64 + 2*w*2^32 + w < 2^162 / 2^160 = 2^2.
    Adjusted after division by 2^5, we obtain that the error is less than 2^-3, which is what we assumed earlier as the bound for "skipped".
    */

    umull r12,r0,r11,r0
    umull r6,lr,r10,r1
    umaal r0,lr,r11,r1
    umaal r12,r6,r9,r2
    umaal r0,r6,r10,r2
    umaal r6,lr,r11,r2
    umull r1,r2,r8,r3
    umaal r0,r2,r9,r3
    umaal r6,r2,r10,r3
    umaal lr,r2,r11,r3
    umaal r12,r1,r7,r4
    adds r1,r1,#(1<<4) // Add 0.5 to q_approx (round up); this doesn't overflow r1 since f < 2^7
    umaal r0,r1,r8,r4
    umaal r6,r1,r9,r4
    umaal r1,lr,r10,r4
    umaal lr,r2,r11,r4

    // Right-shift by 5, discard lower 5 bits
    mov r12,#(1<<27)
    lsrs r0,r0,#5
    umull r3,r4,r12,r2
    umull r1,r2,r12,r1
    umlal r0,r1,r12,r6
    umlal r2,r3,r12,lr

    // If q=2^128, then q--, since we know that floor(A/D) definitely fits in 128 bits.
    subs r0,r0,r4
    movs r4,#0
    sbcs r1,r1,r4
    sbcs r2,r2,r4
    sbcs r3,r3,r4
    
    // We want the remainder A_window mod D, so we need to compute A_window - q*D
    // For efficiency, instead compute A_window + q*(2^n - 1 - D) - q*2^n + q (= A_window - q*D)
    // We know that the quotient is either correct or 1 larger than the true quotient, so the result can become negative

    // Here we calculate one word of -(A_window - q*2^n) at bit position n
    sub r7,r0,r8

    ldr r4,[sp,#44] /// one's complement of D (at temp area)
    ldr r6,[sp,#40] // length of D
    str r7,[sp,#32] // spill
    subs r5,r5,r6
    mov r7,r0 // prepare +q also as carry
    mov r8,r1
    mov r9,r2
    mov r10,r3
    bl mulacc_inner_with_carry
    ldr r2,[sp,#32] // restore
    ldr r4,[sp,#20] // D
    // r5 now points at the new end of A
    ldr r0,[sp,#40] // length of D
    sub lr,r2,r7
    // lr now contains -(A_window - q*D) at bit position n, the (negation of) the three higher words would be 0, if we were to compute them
    // lr is now 0 (don't add D) or 1 (we need to add D now), since our quotient was at most 1 too big
    
    subs r5,r5,r0
    mov r12,r5

1:
    ldm r4!,{r1,r2,r3,r7}
    ldm r5,{r8-r11}
    umaal r8,r6,lr,r1
    umaal r9,r6,lr,r2
    umaal r10,r6,lr,r3
    umaal r11,r6,lr,r7
    stm r5!,{r8-r11}
    subs r0,r0,#16
    bne 1b
    
    subs r5,r5,#20
    ldr r3,[sp,#36] // location for A
    ldm r5!,{r7}
    cmp r3,r12
    bne 0b

    // Now shift the result, if necessary
    ldr r2,[sp,#24] // offset word
    ldr r7,[sp,#28] // offset bit
    adds r6,r2,r7
    cbz r6,1f
    
    adds r5,r5,#16
    adds r4,r3,r2
0:
    str r0,[r5,r2] // zero-fill "offset word" (in bytes) + 1 word since we need to shift this in
    subs r2,r2,#4
    bpl 0b
    rsb r6,r7,#32
    ldm r4!,{r0}
    lsrs r0,r0,r7
0:
    ldm r4!,{r1}
    lsls r2,r1,r6
    orrs r0,r0,r2
    stm r3!,{r0}
    lsrs r0,r1,r7
    cmp r3,r5
    bne 0b
1:

    add sp,sp,#48
    .cfi_def_cfa_offset 36
    pop {r4-r11,pc}
END_FUNC(bignum_to_mont)

// Calculates -N^-1 mod 2^128 for an odd N
// *r0 = output, *r1 = input
START_GLOBAL_FUNC(bignum_modular_inverse)
    push {r4-r11,lr}
    .cfi_def_cfa_offset 36
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4

    /*
    Based on https://groups.google.com/g/sci.crypt/c/UI-UMbUnYGk/m/hX2-wQVyE3oJ.

    Given a positive odd integer a, we want to calculate an integer x such that a*x = -1 (mod 2^w) for some integer w.

    Using the iteration formula "set x_(i+1) to any value such that x_(i+1) = 2*x_i + a*x_i^2 (mod 2^(2*w_i))"
    and w_(i+1) = 2*w_i with starting values w_0 = 3 and any x_0 such that x_0 = -a (mod 8), we want to prove that
    after n iterations, it is true that a*x_n = -1 (mod 2^(3*2^n)) for any positive odd integer a.

    First, note that w_i = 3*2^i, since a factor 2 is added in every iteration.

    Let P(n) be the statement that a*x_n = -1 (mod 2^w_n).

    1. Base case:
    For n=0, we need to prove that P(0) is correct, i.e. that a*-a = -1 (mod 8) for all positive odd integers a.
    1*-1 = -1 (mod 8), 3*-3 = -9 = -1 (mod 8), 5*-5 = -25 = -1 (mod 8), 7*-7 = -49 = -1 (mod 8). Done.

    2. Induction hypothesis:
    Assume that P(i) is correct for some integer i >= 0, i.e. a*x_i = -1 (mod 2^w_i).

    3. Induction step:
    We will show that P(i + 1) is correct, i.e., a*x_(i+1) = -1 (mod 2^w_(i+1)).

    Proof: Following the iteration formula, we have a*x_(i+1) = a*(2*x_i + a*x_i^2) = 2*(a*x_i) + (a*x_i)^2 (mod 2^(2*w_i)).
    Substituting a*x_i with -1 + k*2^w_i (per the induction hypothesis), for some integer k, we get:
    2*(-1 + k*2^w_i) + (-1 + k*2^w_i)^2 = -2 + 2*k*2^w_i + 1 - 2*k*2^w_i + k^2*2^(2*w_i) = -1 + k^2*2^(2*w_i),
    which is congruent to -1 modulo 2^(2*w_i).
    Hence, a*x_(i+1) is congruent to -1 modulo 2^(2*w_i).

    Hence, by induction, P(n) is correct for all non-negative integers n.

    Note: Before the first iteration, between iterations, and after the last iteration, we can always replace x_i with
    any other value such that the new value is congruent to x_i modulo 2^w_i. If we use two's complement storage format,
    we can simply discard excessive upper bits and keep the lower w_i bits. In the iteration that produces x_(i+1),
    note that it is enough to use the lower w_(i+1) bits of a.

    Alternatively, if we target a word size w that is a power of two, we can change the starting value of w_0 to 2 instead,
    so that w_i = 2*2^i. The base case can then be proved in the same way, only verifying for a = 1 (mod 4) and a = 3 (mod 4).
    The proof for the induction step remains intact.

    x_next = x + x + a*x*x = x(2 + a*x)
    */

    ldm r1!,{r2-r5}
    movs r1,#2
    rsbs r7,r2,#0 // Initial iteration x_0 = -a

    mla r6,r2,r7,r1
    muls r6,r7,r6

    mla r7,r2,r6,r1
    muls r7,r6,r7

    mla r6,r2,r7,r1
    muls r6,r7,r6

    mla r7,r2,r6,r1
    muls r7,r6,r7

    mul r8,r3,r7
    umlal r1,r8,r2,r7
    umull r6,r9,r1,r7
    mla r9,r8,r7,r9
    // x: r6 (lo), r9 (hi)

    /*
    2*x + a*x*x

    x*x (64x64):
        01_ 00_
    11  10

    a*(x*x) + x + x:
    03  02  01(1) 00(0)
    12  11_ 10
    21_ 20
    30

    0: x_0+x_0
    1: x_1+x_1
    */

    // x*x
    umull r7,r8,r6,r6
    umull r10,r11,r6,r9
    umaal r8,r10,r9,r6
    umaal r10,r11,r9,r9

    // a*(x*x) + x + x
    mov r1,r6
    mov r12,r9
    umaal r1,r6,r2,r7
    umaal r9,r12,r2,r8
    umaal r6,r9,r3,r7
    umaal r9,r12,r2,r10
    stm r0!,{r1,r6}
    umull r1,r6,r3,r8
    umaal r1,r9,r4,r7
    umaal r6,r12,r2,r11
    umaal r6,r9,r3,r10
    mla r6,r4,r8,r6
    mla r6,r5,r7,r6
    stm r0!,{r1,r6}
    pop {r4-r11,pc}
END_FUNC(bignum_modular_inverse)

// *r0 = output, *r1 = ~b, *r2 = N, *r3 = a, sp[0] = num bytes (> 0 and multiple of 16)
// calculates output = a - b; if result is negative, adds N.
// at exit: r0 contains 1 if N needed to be added, otherwise 0
// input and output can point to the same location, but output may not overlap with N
START_GLOBAL_FUNC(bignum_submod)
    push {r4-r11,lr}
    .cfi_def_cfa_offset 36
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    movs r5,#0
    ldr r6,[sp,#4*9]
    mov r7,r2
    push {r4-r7,lr}
    .cfi_def_cfa_offset 56
    mov lr,r0
    mov r7,r3
    b .L_reduce_once
END_FUNC(bignum_submod)

#if CONSTANT_MEMORY_ACCESS_PATTERN
// *r0 = output, *r1 = table input, r2 = table input end pointer, r3 = chosen index (0-15)
START_GLOBAL_FUNC(bignum_table_select)
    push {r0,r2,r4-r11,lr}
    .cfi_def_cfa_offset 44
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4

    mov r4,#0x01010101
    adds r3,r3,#0xf0
    muls r3,r4,r3

0:
    mov r4,#0xf0f0f0f0
1:
    ldm r1!,{r0,r2}
    usub8 r5,r3,r4
    sel r6,r0,r6
    sel r7,r2,r7
    ldm r1!,{r0,r2,r5}
    sel r8,r0,r8
    sel r9,r2,r9
    sel r10,r5,r10
    ldm r1!,{r0,r2,r5}
    sel r11,r0,r11
    sel r12,r2,r12
    sel lr,r5,lr
    adds r4,r4,#0x01010101
    bcc 1b

    ldrd r0,r2,[sp]
    stm r0!,{r6-r12,lr}
    cmp r1,r2
    str r0,[sp]
    bne 0b

    pop {r0,r2,r4-r11,pc}
END_FUNC(bignum_table_select)
#endif

    .section .note.GNU-stack,"",%progbits
