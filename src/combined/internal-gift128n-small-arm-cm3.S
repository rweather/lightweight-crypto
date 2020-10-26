#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-gift128-config.h"
#if GIFT128_VARIANT == GIFT128_VARIANT_SMALL
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
	.global	gift128n_init
	.thumb
	.thumb_func
	.type	gift128n_init, %function
gift128n_init:
	push	{r4, r5}
	ldr	r2, [r1, #12]
	ldr	r3, [r1, #8]
	ldr	r4, [r1, #4]
	ldr	r5, [r1, #0]
	str	r2, [r0, #12]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #0]
	pop	{r4, r5}
	bx	lr
	.size	gift128n_init, .-gift128n_init

	.align	2
	.global	gift128n_encrypt
	.thumb
	.thumb_func
	.type	gift128n_encrypt, %function
gift128n_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r0, [r2, #12]
	ldr	r3, [r2, #8]
	ldr	ip, [r2, #4]
	ldr	fp, [r2, #0]
	eor	r4, r0, r0, lsr #3
	eor	r5, r3, r3, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #3
	eor	r3, r3, r5, lsl #3
	eor	r4, ip, ip, lsr #3
	eor	r5, fp, fp, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #3
	eor	fp, fp, r5, lsl #3
	eor	r4, r0, r0, lsr #6
	eor	r5, r3, r3, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #6
	eor	r3, r3, r5, lsl #6
	eor	r4, ip, ip, lsr #6
	eor	r5, fp, fp, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #6
	eor	fp, fp, r5, lsl #6
	eor	r4, r0, r0, lsr #12
	eor	r5, r3, r3, lsr #12
	movw	r6, #61680
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #12
	eor	r3, r3, r5, lsl #12
	eor	r4, ip, ip, lsr #12
	eor	r5, fp, fp, lsr #12
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #12
	eor	fp, fp, r5, lsl #12
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	bfi	r4, r0, #24, #8
	bfi	r4, r3, #16, #8
	bfi	r4, ip, #8, #8
	bfi	r4, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r5, r0, #24, #8
	bfi	r5, r3, #16, #8
	bfi	r5, ip, #8, #8
	bfi	r5, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r6, r0, #24, #8
	bfi	r6, r3, #16, #8
	bfi	r6, ip, #8, #8
	bfi	r6, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r2, r0, #24, #8
	bfi	r2, r3, #16, #8
	bfi	r2, ip, #8, #8
	bfi	r2, fp, #0, #8
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
	bfi	fp, r2, #24, #8
	bfi	fp, r6, #16, #8
	bfi	fp, r5, #8, #8
	bfi	fp, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	ip, r2, #24, #8
	bfi	ip, r6, #16, #8
	bfi	ip, r5, #8, #8
	bfi	ip, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r3, r2, #24, #8
	bfi	r3, r6, #16, #8
	bfi	r3, r5, #8, #8
	bfi	r3, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r0, r2, #24, #8
	bfi	r0, r6, #16, #8
	bfi	r0, r5, #8, #8
	bfi	r0, r4, #0, #8
	eor	r4, r0, r0, lsr #7
	eor	r5, r3, r3, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #7
	eor	r3, r3, r5, lsl #7
	eor	r4, ip, ip, lsr #7
	eor	r5, fp, fp, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #7
	eor	fp, fp, r5, lsl #7
	eor	r4, r0, r0, lsr #14
	eor	r5, r3, r3, lsr #14
	movw	r6, #52428
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #14
	eor	r3, r3, r5, lsl #14
	eor	r4, ip, ip, lsr #14
	eor	r5, fp, fp, lsr #14
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #14
	eor	fp, fp, r5, lsl #14
	eor	r4, r0, r0, lsr #4
	eor	r5, r3, r3, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #4
	eor	r3, r3, r5, lsl #4
	eor	r4, ip, ip, lsr #4
	eor	r5, fp, fp, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #4
	eor	fp, fp, r5, lsl #4
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	str	r0, [r1, #12]
	str	r3, [r1, #8]
	str	ip, [r1, #4]
	str	fp, [r1, #0]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128n_encrypt, .-gift128n_encrypt

	.align	2
	.global	gift128n_decrypt
	.thumb
	.thumb_func
	.type	gift128n_decrypt, %function
gift128n_decrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r0, [r2, #12]
	ldr	r3, [r2, #8]
	ldr	ip, [r2, #4]
	ldr	fp, [r2, #0]
	eor	r4, r0, r0, lsr #3
	eor	r5, r3, r3, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #3
	eor	r3, r3, r5, lsl #3
	eor	r4, ip, ip, lsr #3
	eor	r5, fp, fp, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #3
	eor	fp, fp, r5, lsl #3
	eor	r4, r0, r0, lsr #6
	eor	r5, r3, r3, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #6
	eor	r3, r3, r5, lsl #6
	eor	r4, ip, ip, lsr #6
	eor	r5, fp, fp, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #6
	eor	fp, fp, r5, lsl #6
	eor	r4, r0, r0, lsr #12
	eor	r5, r3, r3, lsr #12
	movw	r6, #61680
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #12
	eor	r3, r3, r5, lsl #12
	eor	r4, ip, ip, lsr #12
	eor	r5, fp, fp, lsr #12
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #12
	eor	fp, fp, r5, lsl #12
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	bfi	r4, r0, #24, #8
	bfi	r4, r3, #16, #8
	bfi	r4, ip, #8, #8
	bfi	r4, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r5, r0, #24, #8
	bfi	r5, r3, #16, #8
	bfi	r5, ip, #8, #8
	bfi	r5, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r6, r0, #24, #8
	bfi	r6, r3, #16, #8
	bfi	r6, ip, #8, #8
	bfi	r6, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r2, r0, #24, #8
	bfi	r2, r3, #16, #8
	bfi	r2, ip, #8, #8
	bfi	r2, fp, #0, #8
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
.L2:
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
	bne	.L2
	bfi	fp, r2, #24, #8
	bfi	fp, r6, #16, #8
	bfi	fp, r5, #8, #8
	bfi	fp, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	ip, r2, #24, #8
	bfi	ip, r6, #16, #8
	bfi	ip, r5, #8, #8
	bfi	ip, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r3, r2, #24, #8
	bfi	r3, r6, #16, #8
	bfi	r3, r5, #8, #8
	bfi	r3, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r0, r2, #24, #8
	bfi	r0, r6, #16, #8
	bfi	r0, r5, #8, #8
	bfi	r0, r4, #0, #8
	eor	r4, r0, r0, lsr #7
	eor	r5, r3, r3, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #7
	eor	r3, r3, r5, lsl #7
	eor	r4, ip, ip, lsr #7
	eor	r5, fp, fp, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #7
	eor	fp, fp, r5, lsl #7
	eor	r4, r0, r0, lsr #14
	eor	r5, r3, r3, lsr #14
	movw	r6, #52428
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #14
	eor	r3, r3, r5, lsl #14
	eor	r4, ip, ip, lsr #14
	eor	r5, fp, fp, lsr #14
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #14
	eor	fp, fp, r5, lsl #14
	eor	r4, r0, r0, lsr #4
	eor	r5, r3, r3, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #4
	eor	r3, r3, r5, lsl #4
	eor	r4, ip, ip, lsr #4
	eor	r5, fp, fp, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #4
	eor	fp, fp, r5, lsl #4
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	str	r0, [r1, #12]
	str	r3, [r1, #8]
	str	ip, [r1, #4]
	str	fp, [r1, #0]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128n_decrypt, .-gift128n_decrypt

	.align	4
	.type	rconst2, %object
rconst2:
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
	.size	rconst2, .-rconst2

	.align	2
	.global	gift128t_encrypt
	.thumb
	.thumb_func
	.type	gift128t_encrypt, %function
gift128t_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	push	{r3}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r0, [r2, #12]
	ldr	r3, [r2, #8]
	ldr	ip, [r2, #4]
	ldr	fp, [r2, #0]
	eor	r4, r0, r0, lsr #3
	eor	r5, r3, r3, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #3
	eor	r3, r3, r5, lsl #3
	eor	r4, ip, ip, lsr #3
	eor	r5, fp, fp, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #3
	eor	fp, fp, r5, lsl #3
	eor	r4, r0, r0, lsr #6
	eor	r5, r3, r3, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #6
	eor	r3, r3, r5, lsl #6
	eor	r4, ip, ip, lsr #6
	eor	r5, fp, fp, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #6
	eor	fp, fp, r5, lsl #6
	eor	r4, r0, r0, lsr #12
	eor	r5, r3, r3, lsr #12
	movw	r6, #61680
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #12
	eor	r3, r3, r5, lsl #12
	eor	r4, ip, ip, lsr #12
	eor	r5, fp, fp, lsr #12
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #12
	eor	fp, fp, r5, lsl #12
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	bfi	r4, r0, #24, #8
	bfi	r4, r3, #16, #8
	bfi	r4, ip, #8, #8
	bfi	r4, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r5, r0, #24, #8
	bfi	r5, r3, #16, #8
	bfi	r5, ip, #8, #8
	bfi	r5, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r6, r0, #24, #8
	bfi	r6, r3, #16, #8
	bfi	r6, ip, #8, #8
	bfi	r6, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r2, r0, #24, #8
	bfi	r2, r3, #16, #8
	bfi	r2, ip, #8, #8
	bfi	r2, fp, #0, #8
	mov	lr, #40
	adr	fp, rconst2
.L3:
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
	and	r0, r4, r6
	eors	r5, r0
	and	r3, r5, r2
	eors	r3, r4
	orr	r0, r3, r5
	eors	r6, r0
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r0, r3, r5
	eors	r6, r0
	movs	r4, r2
	movs	r2, r3
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
	eor	r6, r8
	eor	r5, r10
	eors	r2, r0
	mov	ip, r10
	mov	r10, r9
	mov	r9, r8
	mov	r8, r7
	mov	r7, ip
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
	pop	{r3}
	subs	lr, lr, #5
	beq	.L4
	eors	r4, r3
	push	{r3}
	b	.L3
.L4:
	bfi	fp, r2, #24, #8
	bfi	fp, r6, #16, #8
	bfi	fp, r5, #8, #8
	bfi	fp, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	ip, r2, #24, #8
	bfi	ip, r6, #16, #8
	bfi	ip, r5, #8, #8
	bfi	ip, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r3, r2, #24, #8
	bfi	r3, r6, #16, #8
	bfi	r3, r5, #8, #8
	bfi	r3, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r0, r2, #24, #8
	bfi	r0, r6, #16, #8
	bfi	r0, r5, #8, #8
	bfi	r0, r4, #0, #8
	eor	r4, r0, r0, lsr #7
	eor	r5, r3, r3, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #7
	eor	r3, r3, r5, lsl #7
	eor	r4, ip, ip, lsr #7
	eor	r5, fp, fp, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #7
	eor	fp, fp, r5, lsl #7
	eor	r4, r0, r0, lsr #14
	eor	r5, r3, r3, lsr #14
	movw	r6, #52428
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #14
	eor	r3, r3, r5, lsl #14
	eor	r4, ip, ip, lsr #14
	eor	r5, fp, fp, lsr #14
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #14
	eor	fp, fp, r5, lsl #14
	eor	r4, r0, r0, lsr #4
	eor	r5, r3, r3, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #4
	eor	r3, r3, r5, lsl #4
	eor	r4, ip, ip, lsr #4
	eor	r5, fp, fp, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #4
	eor	fp, fp, r5, lsl #4
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	str	r0, [r1, #12]
	str	r3, [r1, #8]
	str	ip, [r1, #4]
	str	fp, [r1, #0]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128t_encrypt, .-gift128t_encrypt

	.align	2
	.global	gift128t_decrypt
	.thumb
	.thumb_func
	.type	gift128t_decrypt, %function
gift128t_decrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	push	{r3}
	ldr	r7, [r0, #12]
	ldr	r8, [r0, #4]
	ldr	r9, [r0, #8]
	ldr	r10, [r0, #0]
	ldr	r0, [r2, #12]
	ldr	r3, [r2, #8]
	ldr	ip, [r2, #4]
	ldr	fp, [r2, #0]
	eor	r4, r0, r0, lsr #3
	eor	r5, r3, r3, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #3
	eor	r3, r3, r5, lsl #3
	eor	r4, ip, ip, lsr #3
	eor	r5, fp, fp, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #3
	eor	fp, fp, r5, lsl #3
	eor	r4, r0, r0, lsr #6
	eor	r5, r3, r3, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #6
	eor	r3, r3, r5, lsl #6
	eor	r4, ip, ip, lsr #6
	eor	r5, fp, fp, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #6
	eor	fp, fp, r5, lsl #6
	eor	r4, r0, r0, lsr #12
	eor	r5, r3, r3, lsr #12
	movw	r6, #61680
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #12
	eor	r3, r3, r5, lsl #12
	eor	r4, ip, ip, lsr #12
	eor	r5, fp, fp, lsr #12
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #12
	eor	fp, fp, r5, lsl #12
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	bfi	r4, r0, #24, #8
	bfi	r4, r3, #16, #8
	bfi	r4, ip, #8, #8
	bfi	r4, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r5, r0, #24, #8
	bfi	r5, r3, #16, #8
	bfi	r5, ip, #8, #8
	bfi	r5, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r6, r0, #24, #8
	bfi	r6, r3, #16, #8
	bfi	r6, ip, #8, #8
	bfi	r6, fp, #0, #8
	lsr	r0, r0, #8
	lsr	r3, r3, #8
	lsr	ip, ip, #8
	lsr	fp, fp, #8
	bfi	r2, r0, #24, #8
	bfi	r2, r3, #16, #8
	bfi	r2, ip, #8, #8
	bfi	r2, fp, #0, #8
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
	adr	fp, rconst2
	add	fp, fp, #160
.L5:
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
	mov	ip, r7
	mov	r7, r8
	mov	r8, r9
	mov	r9, r10
	mov	r10, ip
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
	movs	r3, r4
	movs	r4, r2
	movs	r2, r3
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
	pop	{r3}
	subs	lr, lr, #5
	beq	.L6
	eors	r4, r3
	push	{r3}
	b	.L5
.L6:
	bfi	fp, r2, #24, #8
	bfi	fp, r6, #16, #8
	bfi	fp, r5, #8, #8
	bfi	fp, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	ip, r2, #24, #8
	bfi	ip, r6, #16, #8
	bfi	ip, r5, #8, #8
	bfi	ip, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r3, r2, #24, #8
	bfi	r3, r6, #16, #8
	bfi	r3, r5, #8, #8
	bfi	r3, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r0, r2, #24, #8
	bfi	r0, r6, #16, #8
	bfi	r0, r5, #8, #8
	bfi	r0, r4, #0, #8
	eor	r4, r0, r0, lsr #7
	eor	r5, r3, r3, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #7
	eor	r3, r3, r5, lsl #7
	eor	r4, ip, ip, lsr #7
	eor	r5, fp, fp, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #7
	eor	fp, fp, r5, lsl #7
	eor	r4, r0, r0, lsr #14
	eor	r5, r3, r3, lsr #14
	movw	r6, #52428
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #14
	eor	r3, r3, r5, lsl #14
	eor	r4, ip, ip, lsr #14
	eor	r5, fp, fp, lsr #14
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #14
	eor	fp, fp, r5, lsl #14
	eor	r4, r0, r0, lsr #4
	eor	r5, r3, r3, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #4
	eor	r3, r3, r5, lsl #4
	eor	r4, ip, ip, lsr #4
	eor	r5, fp, fp, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #4
	eor	fp, fp, r5, lsl #4
	eor	r4, r0, r0, lsr #8
	eor	r5, r3, r3, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r0, r0, r4
	eor	r3, r3, r5
	eor	r0, r0, r4, lsl #8
	eor	r3, r3, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, fp, fp, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	fp, fp, r5
	eor	ip, ip, r4, lsl #8
	eor	fp, fp, r5, lsl #8
	str	r0, [r1, #12]
	str	r3, [r1, #8]
	str	ip, [r1, #4]
	str	fp, [r1, #0]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128t_decrypt, .-gift128t_decrypt

#endif
#endif
