/**
DryGascon128 'v6m implementation'
Sebastien Riou, May 27th 2020

Implementation optimized for ARM-Cortex-M0 (Size and Speed)
*/
//define __DRYGASCON_ARM_SELECTOR_V6M__ or add drygascon128_arm_selector.h to includes

#ifndef __DRYGASCON_ARM_SELECTOR_V6M__
#include "drygascon128_arm_selector.h"
#endif
#if defined(__DRYGASCON_ARM_SELECTOR_V6M__)
.cpu cortex-m0
.syntax unified
.code	16
.thumb_func

.align	1
.global	drygascon128_g_v6m
.global	drygascon128_f_v6m

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


.type	drygascon128_g_v6m, %function
drygascon128_g_v6m:
	//r0: state: c,r,x
	//r1: rounds
	push	{r4, r5, r6, r7, lr}
	//stack vars:
    // 8 round
	// 4 rounds
	// 0 state address

    //r=0
    movs    r5,#0
    str     r5,[r0,#R32_0]
    str     r5,[r0,#R32_1]
    str     r5,[r0,#R32_2]
    str     r5,[r0,#R32_3]

    //round=r5=rounds-1;
    subs    r6,r1,#1
    //base = round_cst+12-rounds
    adr		r5, round_cst
    adds    r5,r5,#12
    subs    r5,r5,r1

    push	{r0,r5,r6}

	ldr		r4,[r0,#C4L]
	ldr		r3,[r0,#C3L]
	ldr		r2,[r0,#C2L]
	ldr		r1,[r0,#C1L]
	ldr		r0,[r0,#C0L]

    //loop entry
	//assume r1>0 at entry
drygascon128_g_v6m_main_loop:
    //r0~r4: lower half of each words of the state
    //r5: base for round constants
    //r6: round, counting from rounds-1 to 0

    //r6 = ((0xf - r6) << 4) | r6;
    ldrb 	r6,[r5,r6]
        // addition of round constant
    //r2 ^= r6;
    eors	r2,r2,r6

    // substitution layer, lower half
	eors	r0,r0,r4
    eors	r4,r4,r3
    eors	r2,r2,r1

	mvns	r5,r0
    mvns	r6,r3
    mvns	r7,r4
	ands	r5,r5,r1
    ands	r6,r6,r4
    eors	r4,r4,r5

    ands	r7,r7,r0
    mvns	r5,r2
    ands	r5,r5,r3
    eors	r3,r3,r7

    mvns	r7,r1
    ands	r7,r7,r2
    eors	r2,r2,r6

    eors	r3,r3,r2
    mvns	r2,r2

    eors	r0,r0,r7
    eors	r1,r1,r5
	eors	r1,r1,r0
    eors	r0,r0,r4

    ldr		r7,[sp,#0]
    str		r4,[r7,#C4L]
    str		r3,[r7,#C3L]
    str		r2,[r7,#C2L]
    str		r1,[r7,#C1L]
    str		r0,[r7,#C0L]

    ldr		r4,[r7,#C4H]
    ldr		r3,[r7,#C3H]
    ldr		r2,[r7,#C2H]
    ldr		r1,[r7,#C1H]
    ldr		r0,[r7,#C0H]

    // substitution layer, upper half
	eors	r0,r0,r4
    eors	r4,r4,r3
    eors	r2,r2,r1

	mvns	r5,r0
    mvns	r6,r3
    mvns	r7,r4
	ands	r5,r5,r1
    ands	r6,r6,r4
    eors	r4,r4,r5

    ands	r7,r7,r0
    mvns	r5,r2
    ands	r5,r5,r3
    eors	r3,r3,r7

    mvns	r7,r1
    ands	r7,r7,r2
    eors	r2,r2,r6

    eors	r3,r3,r2
    mvns	r2,r2

    eors	r0,r0,r7
    eors	r1,r1,r5
	eors	r1,r1,r0
    eors	r0,r0,r4

    // linear diffusion layer
    ldr		r7,[sp,#0]

    //c4 ^= gascon_rotr64_interleaved(c4, 40) ^ gascon_rotr64_interleaved(c4, 7);
    //c4 high part
    movs    r6,r4
    movs    r5,#(20)
    rors    r4,r4,r5
    eors    r6,r6,r4
    ldr     r5,[r7,#C4L]
    movs    r7,#(4)
    rors    r5,r5,r7
    eors    r6,r6,r5
    ldr		r7,[sp,#0]
    str     r6,[r7,#C4H]
    //c4 low part
    movs    r7,#(32-4)
    rors    r5,r5,r7
    movs    r6,r5
    movs    r7,#((32-20+3)%32)
    rors    r4,r4,r7
    eors    r4,r4,r6
    movs    r7,#(20)
    rors    r5,r5,r7
    eors    r4,r4,r5
    ldr		r7,[sp,#0]
    str     r4,[r7,#C4L]

    //c0 ^= gascon_rotr64_interleaved(c0, 28) ^ gascon_rotr64_interleaved(c0, 19);
    //c0 high part
    movs    r6,r0
    movs    r5,#(14)
    rors    r0,r0,r5
    eors    r6,r6,r0
    ldr     r5,[r7,#C0L]
    movs    r4,#(10)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C0H]
    ldr    r4,[r7,#R32_1]
    eors    r4,r4,r6
    str     r4,[r7,#R32_1]
    //c0 low part
    movs    r4,#(32-10)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-14+9)%32)
    rors    r0,r0,r4
    eors    r0,r0,r6
    movs    r4,#(14)
    rors    r5,r5,r4
    eors    r0,r0,r5
    ldr    r4,[r7,#R32_0]
    eors    r4,r4,r0
    str    r4,[r7,#R32_0]

    //c1 ^= gascon_rotr64_interleaved(c1, 38) ^ gascon_rotr64_interleaved(c1, 61);
    //c1 high part
    movs    r6,r1
    movs    r5,#(19)
    rors    r1,r1,r5
    eors    r6,r6,r1
    ldr     r5,[r7,#C1L]
    movs    r4,#(31)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C1H]
    ldr    r4,[r7,#R32_3]
    eors    r4,r4,r6
    str     r4,[r7,#R32_3]
    //c1 low part
    movs    r4,#(32-31)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-19+30)%32)
    rors    r1,r1,r4
    eors    r1,r1,r6
    movs    r4,#(19)
    rors    r5,r5,r4
    eors    r1,r1,r5
    ldr    r4,[r7,#R32_2]
    eors    r4,r4,r1
    str    r4,[r7,#R32_2]

    //c2 ^= gascon_rotr64_interleaved(c2, 6) ^ gascon_rotr64_interleaved(c2, 1);
    //c2 high part
    movs    r6,r2
    movs    r5,#(3)
    rors    r2,r2,r5
    eors    r6,r6,r2
    ldr     r5,[r7,#C2L]
    movs    r4,#(1)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C2H]
    ldr    r4,[r7,#R32_0]
    eors    r4,r4,r6
    str     r4,[r7,#R32_0]
    //c2 low part
    movs    r4,#(32-1)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-3+0)%32)
    rors    r2,r2,r4
    eors    r2,r2,r6
    movs    r4,#(3)
    rors    r5,r5,r4
    eors    r2,r2,r5
    ldr    r4,[r7,#R32_3]
    eors    r4,r4,r2
    str    r4,[r7,#R32_3]

    //c3 ^= gascon_rotr64_interleaved(c3, 10) ^ gascon_rotr64_interleaved(c3, 17);
    //c3 high part
    movs    r6,r3
    movs    r5,#(5)
    rors    r3,r3,r5
    eors    r6,r6,r3
    ldr     r5,[r7,#C3L]
    movs    r4,#(9)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C3H]
    ldr    r4,[r7,#R32_2]
    eors    r4,r4,r6
    str     r4,[r7,#R32_2]
    //c3 low part
    movs    r4,#(32-9)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-5+8)%32)
    rors    r3,r3,r4
    eors    r3,r3,r6
    movs    r4,#(5)
    rors    r5,r5,r4
    eors    r3,r3,r5
    ldr    r4,[r7,#R32_1]
    eors    r4,r4,r3
    str    r4,[r7,#R32_1]

    ldr     r4,[r7,#C4L]
    ldr     r5,[sp,#4]

    ldr		r6,[sp,#8]
    subs    r6,#1
    bmi     drygascon128_g_v6m_exit

    str     r6,[sp,#8]
	b    	drygascon128_g_v6m_main_loop
drygascon128_g_v6m_exit:

    str		r3,[r7,#C3L]
	str		r2,[r7,#C2L]
	str		r1,[r7,#C1L]
	str		r0,[r7,#C0L]

	add		sp,sp,#12
	pop 	{r4, r5, r6, r7, pc}
.size	drygascon128_g_v6m, .-drygascon128_g_v6m

.align 2
.type	drygascon128_f_v6m, %function
drygascon128_f_v6m:
    //r0:state c r x
    //r1:input -> shall be 32 bit aligned
    //r2:ds
    //r3:rounds
    push	{r4, r5, r6, r7, lr}

    //stack frame:
    //0 ~ 28-1: buf
    //28 :pointer on c
    //32 : rounds for g
    //36 :mix round / g round

    movs    r4,#26
    push    {r0,r3,r4}
    sub     sp,sp,#28

    //load 10 bit mask in r4 = 0x3FF
    movs    r4,#0xFF
    lsls    r4,r4,#2
    adds    r4,r4,#3

    movs    r7,#0
    //r=0
    str     r7,[r0,#R32_0]
    str     r7,[r0,#R32_1]
    str     r7,[r0,#R32_2]
    str     r7,[r0,#R32_3]

    //r7 = sp
    add     r7,r7,sp

    ldr     r3,[r1]
    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+26]

    lsrs    r3,r3,#10
    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+24]

    lsrs    r3,r3,#10
    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+22]

    lsrs    r5,r3,#10
    ldr     r3,[r1,#4]
    lsls    r6,r3,#2
    lsrs    r3,r3,#8
    orrs    r6,r6,r5
    movs    r5,r4
    ands    r5,r5,r6
    strh    r5,[r7,#0+20]

    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+18]

    lsrs    r3,r3,#10
    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+16]

    lsrs    r5,r3,#10
    ldr     r3,[r1,#8]
    lsls    r6,r3,#4
    lsrs    r3,r3,#6
    orrs    r6,r6,r5
    movs    r5,r4
    ands    r5,r5,r6
    strh    r5,[r7,#0+14]

    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+12]

    lsrs    r3,r3,#10
    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+10]

    lsrs    r5,r3,#10
    ldr     r3,[r1,#12]
    lsls    r6,r3,#6
    lsrs    r3,r3,#4
    orrs    r6,r6,r5
    movs    r5,r4
    ands    r5,r5,r6
    strh    r5,[r7,#0+8]

    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+6]

    lsrs    r3,r3,#10
    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+4]

    lsrs    r5,r3,#10
    lsls    r6,r2,#8
    lsrs    r3,r2,#2
    orrs    r6,r6,r5
    movs    r5,r4
    ands    r5,r5,r6
    strh    r5,[r7,#0+2]

    movs    r5,r4
    ands    r5,r5,r3
    strh    r5,[r7,#0+0]

    movs    r7,#26

drygascon128_f_v6m_mix128_main_loop:
    movs    r6,#0
    add     r6,r6,sp
    ldrh 	r6,[r6,r7]

    ldr     r5,[sp,#28]
    movs    r7,r5
    adds    r5,r5,#X0
    movs    r4,#0xc

    lsls    r0,r6,#2
    ands    r0,r0,r4
    ldr     r1,[r5,r0]
    ldr     r0,[r7,#0*8]
    eors    r0,r0,r1

    lsrs    r1,r6,#0
    ands    r1,r1,r4
    ldr     r2,[r5,r1]
    ldr     r1,[r7,#1*8]
    eors    r1,r1,r2

    lsrs    r2,r6,#2
    ands    r2,r2,r4
    ldr     r3,[r5,r2]
    ldr     r2,[r7,#2*8]
    eors    r2,r2,r3

    lsrs    r3,r6,#4
    ands    r3,r3,r4
    ldr     r4,[r5,r3]
    ldr     r3,[r7,#3*8]
    eors    r3,r3,r4

    lsrs    r4,r6,#6+2
    lsls    r4,r4,#2
    ldr     r6,[r5,r4]
    ldr     r4,[r7,#4*8]
    eors    r4,r4,r6

    ldr		r6,[sp,#36]
    subs    r6,#2
    bpl     drygascon128_f_v6m_mix128_coreround
    b		drygascon128_f_v6m_mix128_exit
drygascon128_f_v6m_mix128_coreround:
    str     r6,[sp,#36]

    movs    r6,#0xf0
        // addition of round constant
    //r2 ^= r6;
    eors	r2,r2,r6

    // substitution layer, lower half
	eors	r0,r0,r4
    eors	r4,r4,r3
    eors	r2,r2,r1

	mvns	r5,r0
    mvns	r6,r3
    mvns	r7,r4
	ands	r5,r5,r1
    ands	r6,r6,r4
    eors	r4,r4,r5

    ands	r7,r7,r0
    mvns	r5,r2
    ands	r5,r5,r3
    eors	r3,r3,r7

    mvns	r7,r1
    ands	r7,r7,r2
    eors	r2,r2,r6

    eors	r3,r3,r2
    mvns	r2,r2

    eors	r0,r0,r7
    eors	r1,r1,r5
	eors	r1,r1,r0
    eors	r0,r0,r4

    ldr		r7,[sp,#28]
    str		r4,[r7,#C4L]
    str		r3,[r7,#C3L]
    str		r2,[r7,#C2L]
    str		r1,[r7,#C1L]
    str		r0,[r7,#C0L]

    ldr		r4,[r7,#C4H]
    ldr		r3,[r7,#C3H]
    ldr		r2,[r7,#C2H]
    ldr		r1,[r7,#C1H]
    ldr		r0,[r7,#C0H]

    // substitution layer, upper half
	eors	r0,r0,r4
    eors	r4,r4,r3
    eors	r2,r2,r1

	mvns	r5,r0
    mvns	r6,r3
    mvns	r7,r4
	ands	r5,r5,r1
    ands	r6,r6,r4
    eors	r4,r4,r5

    ands	r7,r7,r0
    mvns	r5,r2
    ands	r5,r5,r3
    eors	r3,r3,r7

    mvns	r7,r1
    ands	r7,r7,r2
    eors	r2,r2,r6

    eors	r3,r3,r2
    mvns	r2,r2

    eors	r0,r0,r7
    eors	r1,r1,r5
	eors	r1,r1,r0
    eors	r0,r0,r4

    // linear diffusion layer
    ldr		r7,[sp,#28]

    //c4 ^= gascon_rotr64_interleaved(c4, 40) ^ gascon_rotr64_interleaved(c4, 7);
    //c4 high part
    movs    r6,r4
    movs    r5,#(20)
    rors    r4,r4,r5
    eors    r6,r6,r4
    ldr     r5,[r7,#C4L]
    movs    r7,#(4)
    rors    r5,r5,r7
    eors    r6,r6,r5
    ldr		r7,[sp,#28]
    str     r6,[r7,#C4H]
    //c4 low part
    movs    r7,#(32-4)
    rors    r5,r5,r7
    movs    r6,r5
    movs    r7,#((32-20+3)%32)
    rors    r4,r4,r7
    eors    r4,r4,r6
    movs    r7,#(20)
    rors    r5,r5,r7
    eors    r4,r4,r5
    ldr		r7,[sp,#28]
    str     r4,[r7,#C4L]

    //c0 ^= gascon_rotr64_interleaved(c0, 28) ^ gascon_rotr64_interleaved(c0, 19);
    //c0 high part
    movs    r6,r0
    movs    r5,#(14)
    rors    r0,r0,r5
    eors    r6,r6,r0
    ldr     r5,[r7,#C0L]
    movs    r4,#(10)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C0H]
    //c0 low part
    movs    r4,#(32-10)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-14+9)%32)
    rors    r0,r0,r4
    eors    r0,r0,r6
    movs    r4,#(14)
    rors    r5,r5,r4
    eors    r0,r0,r5

    //c1 ^= gascon_rotr64_interleaved(c1, 38) ^ gascon_rotr64_interleaved(c1, 61);
    //c1 high part
    movs    r6,r1
    movs    r5,#(19)
    rors    r1,r1,r5
    eors    r6,r6,r1
    ldr     r5,[r7,#C1L]
    movs    r4,#(31)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C1H]
    //c1 low part
    movs    r4,#(32-31)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-19+30)%32)
    rors    r1,r1,r4
    eors    r1,r1,r6
    movs    r4,#(19)
    rors    r5,r5,r4
    eors    r1,r1,r5

    //c2 ^= gascon_rotr64_interleaved(c2, 6) ^ gascon_rotr64_interleaved(c2, 1);
    //c2 high part
    movs    r6,r2
    movs    r5,#(3)
    rors    r2,r2,r5
    eors    r6,r6,r2
    ldr     r5,[r7,#C2L]
    movs    r4,#(1)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C2H]
    //c2 low part
    movs    r4,#(32-1)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-3+0)%32)
    rors    r2,r2,r4
    eors    r2,r2,r6
    movs    r4,#(3)
    rors    r5,r5,r4
    eors    r2,r2,r5

    //c3 ^= gascon_rotr64_interleaved(c3, 10) ^ gascon_rotr64_interleaved(c3, 17);
    //c3 high part
    movs    r6,r3
    movs    r5,#(5)
    rors    r3,r3,r5
    eors    r6,r6,r3
    ldr     r5,[r7,#C3L]
    movs    r4,#(9)
    rors    r5,r5,r4
    eors    r6,r6,r5
    str     r6,[r7,#C3H]
    //c3 low part
    movs    r4,#(32-9)
    rors    r5,r5,r4
    movs    r6,r5
    movs    r4,#((32-5+8)%32)
    rors    r3,r3,r4
    eors    r3,r3,r6
    movs    r4,#(5)
    rors    r5,r5,r4
    eors    r3,r3,r5

    str		r3,[r7,#C3L]
    str		r2,[r7,#C2L]
    str		r1,[r7,#C1L]
    str		r0,[r7,#C0L]

    ldr		r7,[sp,#36]

    b    	drygascon128_f_v6m_mix128_main_loop
drygascon128_f_v6m_mix128_exit:
    ldr     r7,[sp,#32]
    //round=r5=rounds-1;
    subs    r6,r7,#1
    //base = round_cst+12-rounds
    adr		r5, round_cst
    adds    r5,r5,#12
    subs    r5,r5,r7

    add		sp,sp,#28
    str     r5,[sp,#4]
    str     r6,[sp,#8]

    //push    {r0,r1,r2,r3}
    //ldr     r0,[sp,#16]
    //bl      print_state
    //pop     {r0,r1,r2,r3}

    b       drygascon128_g_v6m_main_loop

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

.size	drygascon128_f_v6m, .-drygascon128_f_v6m


#endif
