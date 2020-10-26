#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-gift128-config.h"
#if GIFT128_VARIANT == GIFT128_VARIANT_FULL
	.syntax unified
	.thumb
	.text

	.align	4
	.type	rconst, %object
rconst:
	.word	0x80000001
	.word	0x80000003
	.word	0x80000007
	.word	0x8000000f
	.word	0x8000001f
	.word	0x8000003e
	.word	0x8000003d
	.word	0x8000003b
	.word	0x80000037
	.word	0x8000002f
	.word	0x8000001e
	.word	0x8000003c
	.word	0x80000039
	.word	0x80000033
	.word	0x80000027
	.word	0x8000000e
	.word	0x8000001d
	.word	0x8000003a
	.word	0x80000035
	.word	0x8000002b
	.word	0x80000016
	.word	0x8000002c
	.word	0x80000018
	.word	0x80000030
	.word	0x80000021
	.word	0x80000002
	.word	0x80000005
	.word	0x8000000b
	.word	0x80000017
	.word	0x8000002e
	.word	0x8000001c
	.word	0x80000038
	.word	0x80000031
	.word	0x80000023
	.word	0x80000006
	.word	0x8000000d
	.word	0x8000001b
	.word	0x80000036
	.word	0x8000002d
	.word	0x8000001a
	.size	rconst, .-rconst

	.align	2
	.global	gift128b_init
	.thumb
	.thumb_func
	.type	gift128b_init, %function
gift128b_init:
	push	{r4, r5}
	ldr	r2, [r1, #0]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	rev	r2, r2
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	str	r2, [r0, #12]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #0]
	pop	{r4, r5}
	bx	lr
	.size	gift128b_init, .-gift128b_init

	.align	2
	.global	gift128b_encrypt
	.thumb
	.thumb_func
	.type	gift128b_encrypt, %function
gift128b_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	mov	lr, #40
	adr	fp, rconst
.L1:
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r4, r3
	orr	r0, r4, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r4, r5
	eors	r6, r0
	eor	r0, r2, r2, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r4, r4, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #3
	eor	r4, r4, r3, lsl #3
	eor	r0, r2, r2, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r4, r4, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #6
	eor	r4, r4, r3, lsl #6
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	ror	r2, r2, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r8
	eor	r5, r10
	eors	r4, r0
	lsr	r0, r10, #18
	lsl	r0, r0, #18
	and	r3, r10, #196608
	lsl	ip, r10, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r10, r10, #12, #4
	orrs	r10, r10, r0
	and	r0, r2, r6
	eors	r5, r0
	and	r3, r5, r4
	eors	r2, r3
	orr	r0, r2, r5
	eors	r6, r0
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r0, r2, r5
	eors	r6, r0
	eor	r0, r4, r4, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r2, r2, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #3
	eor	r2, r2, r3, lsl #3
	eor	r0, r4, r4, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r2, r2, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #6
	eor	r2, r2, r3, lsl #6
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eors	r6, r7
	eor	r5, r9
	eors	r2, r0
	lsr	r0, r9, #18
	lsl	r0, r0, #18
	and	r3, r9, #196608
	lsl	ip, r9, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r9, r9, #12, #4
	orrs	r9, r9, r0
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r4, r3
	orr	r0, r4, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r4, r5
	eors	r6, r0
	eor	r0, r2, r2, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r4, r4, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #3
	eor	r4, r4, r3, lsl #3
	eor	r0, r2, r2, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r4, r4, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #6
	eor	r4, r4, r3, lsl #6
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	ror	r2, r2, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r10
	eor	r5, r8
	eors	r4, r0
	lsr	r0, r8, #18
	lsl	r0, r0, #18
	and	r3, r8, #196608
	lsl	ip, r8, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r8, r8, #12, #4
	orrs	r8, r8, r0
	and	r0, r2, r6
	eors	r5, r0
	and	r3, r5, r4
	eors	r2, r3
	orr	r0, r2, r5
	eors	r6, r0
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r0, r2, r5
	eors	r6, r0
	eor	r0, r4, r4, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r2, r2, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #3
	eor	r2, r2, r3, lsl #3
	eor	r0, r4, r4, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r2, r2, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #6
	eor	r2, r2, r3, lsl #6
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r9
	eors	r5, r7
	eors	r2, r0
	lsr	r0, r7, #18
	lsl	r0, r0, #18
	and	r3, r7, #196608
	lsl	ip, r7, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r7, r7, #12, #4
	orrs	r7, r7, r0
	subs	lr, lr, #4
	bne	.L1
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128b_encrypt, .-gift128b_encrypt

	.align	2
	.global	gift128b_encrypt_preloaded
	.thumb
	.thumb_func
	.type	gift128b_encrypt_preloaded, %function
gift128b_encrypt_preloaded:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	mov	lr, #40
	adr	fp, rconst
.L2:
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r4, r3
	orr	r0, r4, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r4, r5
	eors	r6, r0
	eor	r0, r2, r2, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r4, r4, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #3
	eor	r4, r4, r3, lsl #3
	eor	r0, r2, r2, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r4, r4, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #6
	eor	r4, r4, r3, lsl #6
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	ror	r2, r2, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r8
	eor	r5, r10
	eors	r4, r0
	lsr	r0, r10, #18
	lsl	r0, r0, #18
	and	r3, r10, #196608
	lsl	ip, r10, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r10, r10, #12, #4
	orrs	r10, r10, r0
	and	r0, r2, r6
	eors	r5, r0
	and	r3, r5, r4
	eors	r2, r3
	orr	r0, r2, r5
	eors	r6, r0
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r0, r2, r5
	eors	r6, r0
	eor	r0, r4, r4, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r2, r2, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #3
	eor	r2, r2, r3, lsl #3
	eor	r0, r4, r4, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r2, r2, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #6
	eor	r2, r2, r3, lsl #6
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eors	r6, r7
	eor	r5, r9
	eors	r2, r0
	lsr	r0, r9, #18
	lsl	r0, r0, #18
	and	r3, r9, #196608
	lsl	ip, r9, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r9, r9, #12, #4
	orrs	r9, r9, r0
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r4, r3
	orr	r0, r4, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r4, r5
	eors	r6, r0
	eor	r0, r2, r2, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r4, r4, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #3
	eor	r4, r4, r3, lsl #3
	eor	r0, r2, r2, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r4, r4, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #6
	eor	r4, r4, r3, lsl #6
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	ror	r2, r2, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r10
	eor	r5, r8
	eors	r4, r0
	lsr	r0, r8, #18
	lsl	r0, r0, #18
	and	r3, r8, #196608
	lsl	ip, r8, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r8, r8, #12, #4
	orrs	r8, r8, r0
	and	r0, r2, r6
	eors	r5, r0
	and	r3, r5, r4
	eors	r2, r3
	orr	r0, r2, r5
	eors	r6, r0
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r0, r2, r5
	eors	r6, r0
	eor	r0, r4, r4, lsr #3
	eor	r3, r5, r5, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #3
	eor	r5, r5, r3, lsl #3
	eor	r0, r6, r6, lsr #3
	eor	r3, r2, r2, lsr #3
	and	r0, r0, #168430090
	and	r3, r3, #168430090
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #3
	eor	r2, r2, r3, lsl #3
	eor	r0, r4, r4, lsr #6
	eor	r3, r5, r5, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #6
	eor	r5, r5, r3, lsl #6
	eor	r0, r6, r6, lsr #6
	eor	r3, r2, r2, lsr #6
	and	r0, r0, #13369548
	and	r3, r3, #13369548
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #6
	eor	r2, r2, r3, lsl #6
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	movw	ip, #61680
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	ror	r4, r4, #24
	ror	r5, r5, #16
	ror	r6, r6, #8
	ldr	r0, [fp], #4
	eor	r6, r9
	eors	r5, r7
	eors	r2, r0
	lsr	r0, r7, #18
	lsl	r0, r0, #18
	and	r3, r7, #196608
	lsl	ip, r7, #4
	lsr	r0, r0, #2
	orr	r0, r0, r3, lsl #14
	uxth	ip, ip
	orr	r0, r0, ip
	ubfx	r7, r7, #12, #4
	orrs	r7, r7, r0
	subs	lr, lr, #4
	bne	.L2
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128b_encrypt_preloaded, .-gift128b_encrypt_preloaded

	.align	2
	.global	gift128b_decrypt
	.thumb
	.thumb_func
	.type	gift128b_decrypt, %function
gift128b_decrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	lsr	r0, r7, #20
	lsl	r0, r0, #20
	and	r3, r7, #983040
	lsl	ip, r7, #8
	lsr	r0, r0, #4
	orr	r0, r0, r3, lsl #12
	uxth	ip, ip
	orr	r0, ip
	ubfx	r7, r7, #8, #8
	orrs	r7, r0
	lsr	r0, r8, #20
	lsl	r0, r0, #20
	and	r3, r8, #983040
	lsl	ip, r8, #8
	lsr	r0, r0, #4
	orr	r0, r0, r3, lsl #12
	uxth	ip, ip
	orr	r0, ip
	ubfx	r8, r8, #8, #8
	orr	r8, r0
	lsr	r0, r9, #20
	lsl	r0, r0, #20
	and	r3, r9, #983040
	lsl	ip, r9, #8
	lsr	r0, r0, #4
	orr	r0, r0, r3, lsl #12
	uxth	ip, ip
	orr	r0, ip
	ubfx	r9, r9, #8, #8
	orr	r9, r0
	lsr	r0, r10, #20
	lsl	r0, r0, #20
	and	r3, r10, #983040
	lsl	ip, r10, #8
	lsr	r0, r0, #4
	orr	r0, r0, r3, lsl #12
	uxth	ip, ip
	orr	r0, ip
	ubfx	r10, r10, #8, #8
	orr	r10, r0
	mov	lr, #40
	adr	fp, rconst
	add	fp, fp, #160
.L3:
	movw	r0, #0
	movt	r0, #16383
	and	r3, r7, #-1073741824
	ands	r0, r7
	lsl	r0, r0, #2
	orr	r0, r0, r3, lsr #14
	ubfx	r3, r7, #4, #12
	lsl	r7, r7, #12
	orrs	r0, r3
	uxth	r7, r7
	orrs	r7, r0
	ldr	r0, [fp, #-4]!
	eor	r6, r9
	eors	r5, r7
	eors	r2, r0
	ror	r4, r4, #8
	ror	r5, r5, #16
	ror	r6, r6, #24
	eor	r0, r4, r4, lsr #9
	eor	r3, r5, r5, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #9
	eor	r5, r5, r3, lsl #9
	eor	r0, r6, r6, lsr #9
	eor	r3, r2, r2, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #9
	eor	r2, r2, r3, lsl #9
	eor	r0, r4, r4, lsr #18
	eor	r3, r5, r5, lsr #18
	movw	ip, #13107
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #18
	eor	r5, r5, r3, lsl #18
	eor	r0, r6, r6, lsr #18
	eor	r3, r2, r2, lsr #18
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #18
	eor	r2, r2, r3, lsl #18
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	and	r0, r2, r5
	eors	r6, r0
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r0, r2, r5
	and	r3, r5, r4
	eors	r6, r0
	eors	r2, r3
	and	r0, r2, r6
	eors	r5, r0
	movw	r0, #0
	movt	r0, #16383
	and	r3, r8, #-1073741824
	and	r0, r8
	lsl	r0, r0, #2
	orr	r0, r0, r3, lsr #14
	ubfx	r3, r8, #4, #12
	lsl	r8, r8, #12
	orrs	r0, r3
	uxth	r8, r8
	orr	r8, r0
	ldr	r0, [fp, #-4]!
	eor	r6, r10
	eor	r5, r8
	eors	r4, r0
	ror	r2, r2, #8
	ror	r5, r5, #16
	ror	r6, r6, #24
	eor	r0, r2, r2, lsr #9
	eor	r3, r5, r5, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #9
	eor	r5, r5, r3, lsl #9
	eor	r0, r6, r6, lsr #9
	eor	r3, r4, r4, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #9
	eor	r4, r4, r3, lsl #9
	eor	r0, r2, r2, lsr #18
	eor	r3, r5, r5, lsr #18
	movw	ip, #13107
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #18
	eor	r5, r5, r3, lsl #18
	eor	r0, r6, r6, lsr #18
	eor	r3, r4, r4, lsr #18
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #18
	eor	r4, r4, r3, lsl #18
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	and	r0, r4, r5
	eors	r6, r0
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r0, r4, r5
	and	r3, r5, r2
	eors	r6, r0
	eors	r4, r3
	and	r0, r4, r6
	eors	r5, r0
	movw	r0, #0
	movt	r0, #16383
	and	r3, r9, #-1073741824
	and	r0, r9
	lsl	r0, r0, #2
	orr	r0, r0, r3, lsr #14
	ubfx	r3, r9, #4, #12
	lsl	r9, r9, #12
	orrs	r0, r3
	uxth	r9, r9
	orr	r9, r0
	ldr	r0, [fp, #-4]!
	eors	r6, r7
	eor	r5, r9
	eors	r2, r0
	ror	r4, r4, #8
	ror	r5, r5, #16
	ror	r6, r6, #24
	eor	r0, r4, r4, lsr #9
	eor	r3, r5, r5, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #9
	eor	r5, r5, r3, lsl #9
	eor	r0, r6, r6, lsr #9
	eor	r3, r2, r2, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #9
	eor	r2, r2, r3, lsl #9
	eor	r0, r4, r4, lsr #18
	eor	r3, r5, r5, lsr #18
	movw	ip, #13107
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #18
	eor	r5, r5, r3, lsl #18
	eor	r0, r6, r6, lsr #18
	eor	r3, r2, r2, lsr #18
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #18
	eor	r2, r2, r3, lsl #18
	eor	r0, r4, r4, lsr #12
	eor	r3, r5, r5, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r2, r2, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #12
	eor	r2, r2, r3, lsl #12
	eor	r0, r4, r4, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r4, r4, r0
	eor	r5, r5, r3
	eor	r4, r4, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r2, r2, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r2, r2, r3
	eor	r6, r6, r0, lsl #24
	eor	r2, r2, r3, lsl #24
	and	r0, r2, r5
	eors	r6, r0
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r0, r2, r5
	and	r3, r5, r4
	eors	r6, r0
	eors	r2, r3
	and	r0, r2, r6
	eors	r5, r0
	movw	r0, #0
	movt	r0, #16383
	and	r3, r10, #-1073741824
	and	r0, r10
	lsl	r0, r0, #2
	orr	r0, r0, r3, lsr #14
	ubfx	r3, r10, #4, #12
	lsl	r10, r10, #12
	orrs	r0, r3
	uxth	r10, r10
	orr	r10, r0
	ldr	r0, [fp, #-4]!
	eor	r6, r8
	eor	r5, r10
	eors	r4, r0
	ror	r2, r2, #8
	ror	r5, r5, #16
	ror	r6, r6, #24
	eor	r0, r2, r2, lsr #9
	eor	r3, r5, r5, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #9
	eor	r5, r5, r3, lsl #9
	eor	r0, r6, r6, lsr #9
	eor	r3, r4, r4, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #9
	eor	r4, r4, r3, lsl #9
	eor	r0, r2, r2, lsr #18
	eor	r3, r5, r5, lsr #18
	movw	ip, #13107
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #18
	eor	r5, r5, r3, lsl #18
	eor	r0, r6, r6, lsr #18
	eor	r3, r4, r4, lsr #18
	and	r0, r0, ip
	and	r3, r3, ip
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #18
	eor	r4, r4, r3, lsl #18
	eor	r0, r2, r2, lsr #12
	eor	r3, r5, r5, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #12
	eor	r5, r5, r3, lsl #12
	eor	r0, r6, r6, lsr #12
	eor	r3, r4, r4, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #12
	eor	r4, r4, r3, lsl #12
	eor	r0, r2, r2, lsr #24
	eor	r3, r5, r5, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r2, r2, r0
	eor	r5, r5, r3
	eor	r2, r2, r0, lsl #24
	eor	r5, r5, r3, lsl #24
	eor	r0, r6, r6, lsr #24
	eor	r3, r4, r4, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r6, r6, r0
	eor	r4, r4, r3
	eor	r6, r6, r0, lsl #24
	eor	r4, r4, r3, lsl #24
	and	r0, r4, r5
	eors	r6, r0
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r0, r4, r5
	and	r3, r5, r2
	eors	r6, r0
	eors	r4, r3
	and	r0, r4, r6
	eors	r5, r0
	subs	lr, lr, #4
	bne	.L3
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128b_decrypt, .-gift128b_decrypt

#endif
#endif
