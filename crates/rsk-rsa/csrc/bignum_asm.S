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
