/**
DryGascon128 'v7m_fpu implementation'
Sebastien Riou, May 27th 2020

Implementation optimized for ARM-Cortex-M7/M4/M3 (Size and Speed)
Safe against timing attack on X look up operations under
the following conditions: (safe if at least one line is true)
- System without cache
- State stored in non cacheable memory (like DTCM)
- Cache lines are 16 bytes or larger AND X is 16 bytes aligned


Notes:
- Arm Cortex-M7 Processor Technical Reference Manual Revision r1p2 states
  that data cache line size is 32 bytes.
- Microchip app note TB3186 shows that Microchip use 16 bytes cache lines.
- ST does not give a general statement about cache lines for its products based
on M3 and M4. That said STM32F411xC/E datasheet (RM0383
Reference manual) shows data cache lines of 16 bytes.
- In the unlikely case in which none of the condition can be met,
the 'v7m_fpu_x' can be used to prevent this attack.
*/
//define __DRYGASCON_ARM_SELECTOR_V7M_FPU__ or add drygascon128_arm_selector.h to includes

#ifndef __DRYGASCON_ARM_SELECTOR_V7M_FPU__
#include "drygascon128_arm_selector.h"
#endif
#if defined(__DRYGASCON_ARM_SELECTOR_V7M_FPU__)
.cpu cortex-m4
.syntax unified
.code	16
.thumb_func

.align	1
.global	drygascon128_g_v7m_fpu
.global	drygascon128_f_v7m_fpu
.global	drygascon128_g0_v7m_fpu

    .equ C0, 0
    .equ C1, C0+8
    .equ C2, C0+16
    .equ C3, C0+24
    .equ C4, C0+32
    .equ R0, 48
    .equ R1, R0+8
    .equ X0, 64
    .equ X1, X0+8

    .equ X0L, X0
    .equ X1L, X1
    .equ C0L, C0
    .equ C1L, C1
    .equ C2L, C2
    .equ C3L, C3
    .equ C4L, C4
    .equ R0L, R0
    .equ R1L, R1

    .equ X0H, X0+4
    .equ X1H, X1+4
    .equ C0H, C0+4
    .equ C1H, C1+4
    .equ C2H, C2+4
    .equ C3H, C3+4
    .equ C4H, C4+4
    .equ R0H, R0+4
    .equ R1H, R1+4

    .equ R32_0, R0L
    .equ R32_1, R0H
    .equ R32_2, R1L
    .equ R32_3, R1H



.type	drygascon128_g_v7m_fpu, %function
drygascon128_g_v7m_fpu:
    //r0: state: c,r,x
    //r1: rounds
    push {r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}
    //stack vars:
    // 8 round
    // 4 rounds (base address for lookups)
    // 0 state address

    //r=0
    movs    r10,#0
    vmov    S10,r10
    vmov    S11,r10
    vmov    S12,r10
    vmov    S13,r10

    //round=r10=rounds-1;
    subs    r11,r1,#1
    //base = round_cst+12-rounds
    adr     r10, round_cst
    adds    r10,r10,#12
    subs    r10,r10,r1

    push	{r0,r10,r11}

    //Load C
    adds    r14,r0,#C0
    LDMIA.W r14,{r0,r1,r2,r3,r4,r5,r6,r7,r8,r9}

    //loop entry
    //assume r11>0 at entry
drygascon128_g_v7m_fpu_main_loop:
    //r0~r9: c
    //r10: base for round constants
    //r11: round, counting from rounds-1 to 0

    //r11 = ((0xf - r11) << 4) | r11;
    ldrb    r11,[r10,r11]
    //state:
    //r0 to r9: c
    //r11: constant to add as round constant
    //FPU:
    //s11 to s14: r

    // addition of round constant
    //C2L ^= round constant;
    eors    r4,r4,r11

    eor r0, r0, r8
    eor r1, r1, r9
    eor r8, r8, r6
    eor r9, r9, r7
    eor r4, r4, r2
    eor r5, r5, r3
    bic r10, r0, r8
    bic r11, r8, r6
    bic r12, r4, r2
    bic r14, r2, r0
    eor r4, r4, r11
    eor r0, r0, r12
    eor r8, r8, r14
    bic r14, r6, r4
    eor r6, r6, r10
    bic r12, r1, r9
    bic r10, r5, r3
    bic r11, r9, r7
    eor r2, r2, r14
    eor r1, r1, r10
    eor r5, r5, r11
    bic r14, r3, r1
    bic r10, r7, r5
    eor r7, r7, r12
    eor r7, r7, r5
    eor r9, r9, r14
    eor r3, r3, r10
    eor r6, r6, r4
    eor r2, r2, r0
    eor r3, r3, r1
    eor r0, r0, r8
    eor r1, r1, r9
    mvn r4, r4
    mvn r5, r5

    // linear diffusion layer

    //c0 ^= gascon_rotr64_interleaved(c0, 28) ^ gascon_rotr64_interleaved(c0, 19);
    //c0 step 1
    eor   r11, r1, r0, ror #10
    eor   r10, r0, r1, ror #9
    //c1 ^= gascon_rotr64_interleaved(c1, 38) ^ gascon_rotr64_interleaved(c1, 61);
    //c1 step 1
    eor   r14, r3, r2, ror #31
    eor   r12, r2, r3, ror #30
    //c0 step 2
    eor   r1, r11, r1, ror #14
    eor   r0, r10, r0, ror #14
    //c1 step 2
    eor   r3, r14, r3, ror #19
    eor   r2, r12, r2, ror #19
    //c2 ^= gascon_rotr64_interleaved(c2, 6) ^ gascon_rotr64_interleaved(c2, 1);
    //c2 step 1
    eor   r11, r5, r4, ror #1
    eor   r10, r4, r5, ror #0
    //c3 ^= gascon_rotr64_interleaved(c3, 10) ^ gascon_rotr64_interleaved(c3, 17);
    //c3 step 1
    eor   r14, r7, r6, ror #9
    eor   r12, r6, r7, ror #8
    //c2 step 2
    eor   r5, r11, r5, ror #3
    eor   r4, r10, r4, ror #3
    //c3 step 2
    eor   r7, r14, r7, ror #5
    eor   r6, r12, r6, ror #5
    //c4 ^= gascon_rotr64_interleaved(c4, 40) ^ gascon_rotr64_interleaved(c4, 7);
    //c4 step 1
    eor   r11, r9, r8, ror #4
    eor   r10, r8, r9, ror #3
    //c4 step 2
    eor   r9, r11, r9, ror #20
    eor   r8, r10, r8, ror #20

    // accumulate
    vmov r10,S10
    vmov r11,S11
    vmov r12,S12
    vmov r14,S13
    eor  r10,r10,r0
    eor  r11,r11,r1
    eor  r12,r12,r2
    eor  r14,r14,r3
    eor  r10,r10,r5
    eor  r11,r11,r6
    eor  r12,r12,r7
    eor  r14,r14,r4
    vmov S10,r10
    vmov S11,r11
    vmov S12,r12
    vmov S13,r14

    //state:
    //r0 to r9: c
    //r10,r11,r12,r14 destroyed

    ldr     r10,[sp,#4]

    ldr     r11,[sp,#8]
    subs    r11,#1
    bmi     drygascon128_g_v7m_fpu_exit

    str     r11,[sp,#8]
    b       drygascon128_g_v7m_fpu_main_loop
drygascon128_g_v7m_fpu_exit:
    //update C
    ldr     r14,[sp,#0]
    STMIA.W r14,{r0,r1,r2,r3,r4,r5,r6,r7,r8,r9}

    //update R
    ldr        r11,[sp,#0]
    adds       r11,r11,#R0
    VSTMIA.F32 r11, {S10,S11,S12,S13}

    add    sp,sp,#12
    pop    {r4, r5, r6, r7, r8, r9, r10, r11, r12, pc}
.size	drygascon128_g_v7m_fpu, .-drygascon128_g_v7m_fpu

.align 2
.type	drygascon128_f_v7m_fpu, %function
drygascon128_f_v7m_fpu:
    //r0:state
    //r1:input
    //r2:ds
    //r3:rounds
    push	{r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}

    //stack frame:
    //0: pointer on input
    //4: DS value
    //8 :pointer on state
    //12 : rounds for g
    //16 :mix round / g round

    movs    r10,#0 //init of input bit counter
    push    {r0,r3,r10} //make the same stack frame as drygascon128_g_cm7
    push    {r1,r2}
    //r=0
    vmov    S10,r10
    vmov    S11,r10
    vmov    S12,r10
    vmov    S13,r10

    //Load C
    adds	r11,r0,#C0
    LDMIA.W r11,{r0,r1,r2,r3,r4,r5,r6,r7,r8,r9}


drygascon128_f_v7m_fpu_mix128_main_loop:
    //r10 is input bit counter
    ldr     r11,[sp,#0] //r11 is pointer on input

    //r10 r12 shift
    // 0   0   0
    // 10  1   2
    // 20  2   4
    // 30  3   6
    // 40  5   0
    // 50  6   2
    // 60  7   4
    // 70  8   6
    // 80  10  0
    // 90  11  2
    // 100 12  4
    // 110 13  6
    // 120 15  0
    // 130 16  2 --> we do that operation for 2 last bits in a special last loop

    cmp     r10,#120
    bne     drygascon128_f_v7m_fpu_mix128_main_loop.regular

    //we execute this only during the pen-ultimate operation
    //we add the 2 lsb from DS to r14
    ldrb    r14,[r11,#15]
    ldr     r10,[sp,#4]
    lsl     r10,r10,#8
    eors    r14,r14,r10
    b       drygascon128_f_v7m_fpu_mix128_main_loop.core

drygascon128_f_v7m_fpu_mix128_main_loop.regular:
    //r12 is base byte: byte offset to read from input buffer
    lsr     r12,r10,#3  //divide by 8 to get base byte
    //r10 becomes shift
    lsl     r14,r12,#3
    sub     r10,r10,r14

    ldr     r14,[r11,r12] //M7 supports unalign access with ldr
    lsr     r14,r14,r10

drygascon128_f_v7m_fpu_mix128_main_loop.core:
    ldr     r10,[sp,#8]
    adds    r10,r10,#X0
    
    lsls    r11,r14,#2
    ands    r11,r11,#0xc
    ldr     r11,[r10,r11]
    eors    r0,r0,r11
    
    lsrs    r11,r14,#0
    ands    r11,r11,#0xc
    ldr     r11,[r10,r11]
    eors    r2,r2,r11
    
    lsrs    r11,r14,#2
    ands    r11,r11,#0xc
    ldr     r11,[r10,r11]
    eors    r4,r4,r11
    
    lsrs    r11,r14,#4
    ands    r11,r11,#0xc
    ldr     r11,[r10,r11]
    eors    r6,r6,r11
    
    lsrs    r11,r14,#6
    ands    r11,r11,#0xc
    ldr     r11,[r10,r11]
    eors    r8,r8,r11

    ldr		r10,[sp,#16]
    adds    r10,#10
    cmp     r10,#140
    beq     drygascon128_f_v7m_fpu_mix128_exit
drygascon128_f_v7m_fpu_mix128_coreround:
    str     r10,[sp,#16]

    movs    r11,#0xf0

    //state:
    //r0 to r9: c
    //r11: constant to add as round constant

    // addition of round constant
    //C2L ^= round constant;
    eors    r4,r4,r11

    eor r0, r0, r8
    eor r1, r1, r9
    eor r8, r8, r6
    eor r9, r9, r7
    eor r4, r4, r2
    eor r5, r5, r3
    bic r10, r0, r8
    bic r11, r8, r6
    bic r12, r4, r2
    bic r14, r2, r0
    eor r4, r4, r11
    eor r0, r0, r12
    eor r8, r8, r14
    bic r14, r6, r4
    eor r6, r6, r10
    bic r12, r1, r9
    bic r10, r5, r3
    bic r11, r9, r7
    eor r2, r2, r14
    eor r1, r1, r10
    eor r5, r5, r11
    bic r14, r3, r1
    bic r10, r7, r5
    eor r7, r7, r12
    eor r7, r7, r5
    eor r9, r9, r14
    eor r3, r3, r10
    eor r6, r6, r4
    eor r2, r2, r0
    eor r3, r3, r1
    eor r0, r0, r8
    eor r1, r1, r9
    mvn r4, r4
    mvn r5, r5

    // linear diffusion layer

    //c0 ^= gascon_rotr64_interleaved(c0, 28) ^ gascon_rotr64_interleaved(c0, 19);
    //c0 step 1
    eor   r11, r1, r0, ror #10
    eor   r10, r0, r1, ror #9
    //c1 ^= gascon_rotr64_interleaved(c1, 38) ^ gascon_rotr64_interleaved(c1, 61);
    //c1 step 1
    eor   r14, r3, r2, ror #31
    eor   r12, r2, r3, ror #30
    //c0 step 2
    eor   r1, r11, r1, ror #14
    eor   r0, r10, r0, ror #14
    //c1 step 2
    eor   r3, r14, r3, ror #19
    eor   r2, r12, r2, ror #19
    //c2 ^= gascon_rotr64_interleaved(c2, 6) ^ gascon_rotr64_interleaved(c2, 1);
    //c2 step 1
    eor   r11, r5, r4, ror #1
    eor   r10, r4, r5, ror #0
    //c3 ^= gascon_rotr64_interleaved(c3, 10) ^ gascon_rotr64_interleaved(c3, 17);
    //c3 step 1
    eor   r14, r7, r6, ror #9
    eor   r12, r6, r7, ror #8
    //c2 step 2
    eor   r5, r11, r5, ror #3
    eor   r4, r10, r4, ror #3
    //c3 step 2
    eor   r7, r14, r7, ror #5
    eor   r6, r12, r6, ror #5
    //c4 ^= gascon_rotr64_interleaved(c4, 40) ^ gascon_rotr64_interleaved(c4, 7);
    //c4 step 1
    eor   r11, r9, r8, ror #4
    eor   r10, r8, r9, ror #3
    //c4 step 2
    eor   r9, r11, r9, ror #20
    eor   r8, r10, r8, ror #20


    //state:
    //r0 to r9: c
    //r10,r11,r12,r14 destroyed

    ldr		r10,[sp,#16]
    cmp     r10,#130
    bne     drygascon128_f_v7m_fpu_mix128_main_loop
    //prepare the last loop: load DS 2 msb
    ldr     r14,[sp,4]
    lsr     r14,r14,#2
    b       drygascon128_f_v7m_fpu_mix128_main_loop.core

drygascon128_f_v7m_fpu_mix128_exit:
    ldr     r14,[sp,#12]
    //round=r10=rounds-1;
    subs    r11,r14,#1
    //base = round_cst+12-rounds
    adr		r10, round_cst
    adds    r10,r10,#12
    subs    r10,r10,r14

    str     r10,[sp,#12]
    str     r11,[sp,#16]

    add		sp,sp,#8
    b       drygascon128_g_v7m_fpu_main_loop

.align 2
round_cst:
.byte 0x4b
.byte 0x5a
.byte 0x69
.byte 0x78
.byte 0x87
.byte 0x96
.byte 0xa5
.byte 0xb4
.byte 0xc3
.byte 0xd2
.byte 0xe1
.byte 0xf0
.align 2

.size	drygascon128_f_v7m_fpu, .-drygascon128_f_v7m_fpu

.type	drygascon128_g0_v7m_fpu, %function
drygascon128_g0_v7m_fpu:
    //perform a single round without accumulate
    //r0: state
    push {r4, r5, r6, r7, r8, r9, r10, r11, r12, lr}

    //Load C
    adds    r14,r0,#C0
    LDMIA.W r14,{r0,r1,r2,r3,r4,r5,r6,r7,r8,r9}

    //r0~r9: c

    //r11 = ((0xf - 0) << 4) | 0;
    movs    r11,#0xf0
    push    {r14}
    //state:
    //r0 to r9: c
    //r11: constant to add as round constant

    // addition of round constant
    //C2L ^= round constant;
    eors    r4,r4,r11

    eor r0, r0, r8
    eor r1, r1, r9
    eor r8, r8, r6
    eor r9, r9, r7
    eor r4, r4, r2
    eor r5, r5, r3
    bic r10, r0, r8
    bic r11, r8, r6
    bic r12, r4, r2
    bic r14, r2, r0
    eor r4, r4, r11
    eor r0, r0, r12
    eor r8, r8, r14
    bic r14, r6, r4
    eor r6, r6, r10
    bic r12, r1, r9
    bic r10, r5, r3
    bic r11, r9, r7
    eor r2, r2, r14
    eor r1, r1, r10
    eor r5, r5, r11
    bic r14, r3, r1
    bic r10, r7, r5
    eor r7, r7, r12
    eor r7, r7, r5
    eor r9, r9, r14
    eor r3, r3, r10
    eor r6, r6, r4
    eor r2, r2, r0
    eor r3, r3, r1
    eor r0, r0, r8
    eor r1, r1, r9
    mvn r4, r4
    mvn r5, r5

    // linear diffusion layer

    //c0 ^= gascon_rotr64_interleaved(c0, 28) ^ gascon_rotr64_interleaved(c0, 19);
    //c0 step 1
    eor   r11, r1, r0, ror #10
    eor   r10, r0, r1, ror #9
    //c1 ^= gascon_rotr64_interleaved(c1, 38) ^ gascon_rotr64_interleaved(c1, 61);
    //c1 step 1
    eor   r14, r3, r2, ror #31
    eor   r12, r2, r3, ror #30
    //c0 step 2
    eor   r1, r11, r1, ror #14
    eor   r0, r10, r0, ror #14
    //c1 step 2
    eor   r3, r14, r3, ror #19
    eor   r2, r12, r2, ror #19
    //c2 ^= gascon_rotr64_interleaved(c2, 6) ^ gascon_rotr64_interleaved(c2, 1);
    //c2 step 1
    eor   r11, r5, r4, ror #1
    eor   r10, r4, r5, ror #0
    //c3 ^= gascon_rotr64_interleaved(c3, 10) ^ gascon_rotr64_interleaved(c3, 17);
    //c3 step 1
    eor   r14, r7, r6, ror #9
    eor   r12, r6, r7, ror #8
    //c2 step 2
    eor   r5, r11, r5, ror #3
    eor   r4, r10, r4, ror #3
    //c3 step 2
    eor   r7, r14, r7, ror #5
    eor   r6, r12, r6, ror #5
    //c4 ^= gascon_rotr64_interleaved(c4, 40) ^ gascon_rotr64_interleaved(c4, 7);
    //c4 step 1
    eor   r11, r9, r8, ror #4
    eor   r10, r8, r9, ror #3
    //c4 step 2
    eor   r9, r11, r9, ror #20
    eor   r8, r10, r8, ror #20


    //state:
    //r0 to r9: c
    //r10,r11,r12,r14 destroyed
    pop     {r14}

    //update C
    STMIA.W r14,{r0,r1,r2,r3,r4,r5,r6,r7,r8,r9}

    pop    {r4, r5, r6, r7, r8, r9, r10, r11, r12, pc}
.size	drygascon128_g0_v7m_fpu, .-drygascon128_g0_v7m_fpu
#endif
