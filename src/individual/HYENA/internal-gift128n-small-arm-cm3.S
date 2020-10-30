#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-gift128-config.h"
#if GIFT128_VARIANT_ASM && GIFT128_VARIANT == GIFT128_VARIANT_SMALL
	.syntax unified
	.thumb
	.text

	.align	2
	.global	gift128n_init
	.thumb
	.thumb_func
	.type	gift128n_init, %function
gift128n_init:
	push	{r4, r5, r6, r7, r8, r9}
	ldr	r2, [r1, #12]
	ldr	r3, [r1, #8]
	ldr	r4, [r1, #4]
	ldr	r5, [r1, #0]
	str	r2, [r0, #12]
	str	r3, [r0, #4]
	str	r4, [r0, #8]
	str	r5, [r0, #0]
	str	r3, [r0, #16]
	lsr	r6, r5, #18
	lsl	r6, r6, #18
	and	r7, r5, #196608
	lsl	r8, r5, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r5, r5, #12, #4
	orrs	r5, r5, r6
	str	r5, [r0, #20]
	str	r2, [r0, #24]
	lsr	r6, r4, #18
	lsl	r6, r6, #18
	and	r7, r4, #196608
	lsl	r8, r4, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r4, r4, #12, #4
	orrs	r4, r4, r6
	str	r4, [r0, #28]
	str	r5, [r0, #32]
	lsr	r6, r3, #18
	lsl	r6, r6, #18
	and	r7, r3, #196608
	lsl	r8, r3, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r3, r3, #12, #4
	orrs	r3, r3, r6
	str	r3, [r0, #36]
	str	r4, [r0, #40]
	lsr	r6, r2, #18
	lsl	r6, r6, #18
	and	r7, r2, #196608
	lsl	r8, r2, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r2, r2, #12, #4
	orrs	r2, r2, r6
	str	r2, [r0, #44]
	str	r3, [r0, #48]
	lsr	r6, r5, #18
	lsl	r6, r6, #18
	and	r7, r5, #196608
	lsl	r8, r5, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r5, r5, #12, #4
	orrs	r5, r5, r6
	str	r5, [r0, #52]
	str	r2, [r0, #56]
	lsr	r6, r4, #18
	lsl	r6, r6, #18
	and	r7, r4, #196608
	lsl	r8, r4, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r4, r4, #12, #4
	orrs	r4, r4, r6
	str	r4, [r0, #60]
	str	r5, [r0, #64]
	lsr	r6, r3, #18
	lsl	r6, r6, #18
	and	r7, r3, #196608
	lsl	r8, r3, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r3, r3, #12, #4
	orrs	r3, r3, r6
	str	r3, [r0, #68]
	str	r4, [r0, #72]
	lsr	r6, r2, #18
	lsl	r6, r6, #18
	and	r7, r2, #196608
	lsl	r8, r2, #4
	lsr	r6, r6, #2
	orr	r6, r6, r7, lsl #14
	uxth	r8, r8
	orr	r6, r6, r8
	ubfx	r2, r2, #12, #4
	orrs	r2, r2, r6
	str	r2, [r0, #76]
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	ldr	r4, [r0, #40]
	ldr	r5, [r0, #44]
	eor	r6, r2, r2, lsr #9
	eor	r7, r3, r3, lsr #9
	eor	r8, r4, r4, lsr #9
	eor	ip, r5, r5, lsr #9
	and	r6, r6, #5570645
	and	r7, r7, #5570645
	and	r8, r8, #5570645
	and	ip, ip, #5570645
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #9
	eor	r3, r3, r7, lsl #9
	eor	r4, r4, r8, lsl #9
	eor	r5, r5, ip, lsl #9
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	r8, r8, #983055
	and	ip, ip, #983055
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	movw	r9, #13107
	eor	r6, r2, r2, lsr #18
	eor	r7, r3, r3, lsr #18
	eor	r8, r4, r4, lsr #18
	eor	ip, r5, r5, lsr #18
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #18
	eor	r3, r3, r7, lsl #18
	eor	r4, r4, r8, lsl #18
	eor	r5, r5, ip, lsl #18
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #0]
	str	r3, [r0, #4]
	str	r4, [r0, #40]
	str	r5, [r0, #44]
	ldr	r2, [r0, #8]
	ldr	r3, [r0, #12]
	ldr	r4, [r0, #48]
	ldr	r5, [r0, #52]
	eor	r6, r2, r2, lsr #3
	eor	r7, r3, r3, lsr #3
	eor	r8, r4, r4, lsr #3
	eor	ip, r5, r5, lsr #3
	and	r6, r6, #286331153
	and	r7, r7, #286331153
	and	r8, r8, #286331153
	and	ip, ip, #286331153
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #3
	eor	r3, r3, r7, lsl #3
	eor	r4, r4, r8, lsl #3
	eor	r5, r5, ip, lsl #3
	eor	r6, r2, r2, lsr #6
	eor	r7, r3, r3, lsr #6
	eor	r8, r4, r4, lsr #6
	eor	ip, r5, r5, lsr #6
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #50529027
	and	ip, ip, #50529027
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #6
	eor	r3, r3, r7, lsl #6
	eor	r4, r4, r8, lsl #6
	eor	r5, r5, ip, lsl #6
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	r8, r8, #983055
	and	ip, ip, #983055
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #8]
	str	r3, [r0, #12]
	str	r4, [r0, #48]
	str	r5, [r0, #52]
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
	ldr	r4, [r0, #56]
	ldr	r5, [r0, #60]
	movw	r9, #43690
	eor	r6, r2, r2, lsr #15
	eor	r7, r3, r3, lsr #15
	eor	r8, r4, r4, lsr #15
	eor	ip, r5, r5, lsr #15
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #15
	eor	r3, r3, r7, lsl #15
	eor	r4, r4, r8, lsl #15
	eor	r5, r5, ip, lsl #15
	movw	r9, #13107
	eor	r6, r2, r2, lsr #18
	eor	r7, r3, r3, lsr #18
	eor	r8, r4, r4, lsr #18
	eor	ip, r5, r5, lsr #18
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #18
	eor	r3, r3, r7, lsl #18
	eor	r4, r4, r8, lsl #18
	eor	r5, r5, ip, lsl #18
	movw	r9, #61680
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #16]
	str	r3, [r0, #20]
	str	r4, [r0, #56]
	str	r5, [r0, #60]
	ldr	r2, [r0, #24]
	ldr	r3, [r0, #28]
	ldr	r4, [r0, #64]
	ldr	r5, [r0, #68]
	eor	r6, r2, r2, lsr #3
	eor	r7, r3, r3, lsr #3
	eor	r8, r4, r4, lsr #3
	eor	ip, r5, r5, lsr #3
	and	r6, r6, #168430090
	and	r7, r7, #168430090
	and	r8, r8, #168430090
	and	ip, ip, #168430090
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #3
	eor	r3, r3, r7, lsl #3
	eor	r4, r4, r8, lsl #3
	eor	r5, r5, ip, lsl #3
	eor	r6, r2, r2, lsr #6
	eor	r7, r3, r3, lsr #6
	eor	r8, r4, r4, lsr #6
	eor	ip, r5, r5, lsr #6
	and	r6, r6, #13369548
	and	r7, r7, #13369548
	and	r8, r8, #13369548
	and	ip, ip, #13369548
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #6
	eor	r3, r3, r7, lsl #6
	eor	r4, r4, r8, lsl #6
	eor	r5, r5, ip, lsl #6
	movw	r9, #61680
	eor	r6, r2, r2, lsr #12
	eor	r7, r3, r3, lsr #12
	eor	r8, r4, r4, lsr #12
	eor	ip, r5, r5, lsr #12
	and	r6, r6, r9
	and	r7, r7, r9
	and	r8, r8, r9
	and	ip, ip, r9
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #12
	eor	r3, r3, r7, lsl #12
	eor	r4, r4, r8, lsl #12
	eor	r5, r5, ip, lsl #12
	eor	r6, r2, r2, lsr #24
	eor	r7, r3, r3, lsr #24
	eor	r8, r4, r4, lsr #24
	eor	ip, r5, r5, lsr #24
	and	r6, r6, #255
	and	r7, r7, #255
	and	r8, r8, #255
	and	ip, ip, #255
	eors	r2, r6
	eors	r3, r7
	eor	r4, r8
	eor	r5, ip
	eor	r2, r2, r6, lsl #24
	eor	r3, r3, r7, lsl #24
	eor	r4, r4, r8, lsl #24
	eor	r5, r5, ip, lsl #24
	str	r2, [r0, #24]
	str	r3, [r0, #28]
	str	r4, [r0, #64]
	str	r5, [r0, #68]
	pop	{r4, r5, r6, r7, r8, r9}
	bx	lr
	.size	gift128n_init, .-gift128n_init

	.align	2
	.global	gift128n_encrypt
	.thumb
	.thumb_func
	.type	gift128n_encrypt, %function
gift128n_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp}
	mov	fp, sp
	sub	sp, sp, #80
	ldr	r7, [r2, #12]
	ldr	r8, [r2, #8]
	ldr	ip, [r2, #4]
	ldr	r9, [r2, #0]
	eor	r4, r7, r7, lsr #3
	eor	r5, r8, r8, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #3
	eor	r8, r8, r5, lsl #3
	eor	r4, ip, ip, lsr #3
	eor	r5, r9, r9, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #3
	eor	r9, r9, r5, lsl #3
	eor	r4, r7, r7, lsr #6
	eor	r5, r8, r8, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #6
	eor	r8, r8, r5, lsl #6
	eor	r4, ip, ip, lsr #6
	eor	r5, r9, r9, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #6
	eor	r9, r9, r5, lsl #6
	eor	r4, r7, r7, lsr #12
	eor	r5, r8, r8, lsr #12
	movw	r6, #61680
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #12
	eor	r8, r8, r5, lsl #12
	eor	r4, ip, ip, lsr #12
	eor	r5, r9, r9, lsr #12
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #12
	eor	r9, r9, r5, lsl #12
	eor	r4, r7, r7, lsr #8
	eor	r5, r8, r8, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #8
	eor	r8, r8, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, r9, r9, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #8
	eor	r9, r9, r5, lsl #8
	bfi	r4, r7, #24, #8
	bfi	r4, r8, #16, #8
	bfi	r4, ip, #8, #8
	bfi	r4, r9, #0, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	ip, ip, #8
	lsr	r9, r9, #8
	bfi	r5, r7, #24, #8
	bfi	r5, r8, #16, #8
	bfi	r5, ip, #8, #8
	bfi	r5, r9, #0, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	ip, ip, #8
	lsr	r9, r9, #8
	bfi	r6, r7, #24, #8
	bfi	r6, r8, #16, #8
	bfi	r6, ip, #8, #8
	bfi	r6, r9, #0, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	ip, ip, #8
	lsr	r9, r9, #8
	bfi	r2, r7, #24, #8
	bfi	r2, r8, #16, #8
	bfi	r2, ip, #8, #8
	bfi	r2, r9, #0, #8
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	movw	ip, #8
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #8]
	ldr	r8, [r0, #12]
	movw	ip, #32768
	movt	ip, #32769
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #16]
	ldr	r8, [r0, #20]
	movw	ip, #2
	movt	ip, #21504
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	movw	ip, #385
	movt	ip, #257
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [r0, #32]
	ldr	r8, [r0, #36]
	movw	ip, #31
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [r0, #40]
	ldr	r8, [r0, #44]
	movw	ip, #34944
	movt	ip, #4232
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #48]
	ldr	r8, [r0, #52]
	movw	ip, #57344
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #2
	movt	ip, #20816
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [r0, #64]
	ldr	r8, [r0, #68]
	movw	ip, #384
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [r0, #72]
	ldr	r8, [r0, #76]
	movw	ip, #47
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ldr	r3, [r0, #0]
	ldr	r10, [r0, #4]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-80]
	str	r3, [fp, #-76]
	ldr	r3, [r0, #8]
	ldr	r10, [r0, #12]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-72]
	str	r3, [fp, #-68]
	ldr	r3, [r0, #16]
	ldr	r10, [r0, #20]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-64]
	str	r3, [fp, #-60]
	ldr	r3, [r0, #24]
	ldr	r10, [r0, #28]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-56]
	str	r3, [fp, #-52]
	ldr	r3, [r0, #32]
	ldr	r10, [r0, #36]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-48]
	str	r3, [fp, #-44]
	ldr	r3, [r0, #40]
	ldr	r10, [r0, #44]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-40]
	str	r3, [fp, #-36]
	ldr	r3, [r0, #48]
	ldr	r10, [r0, #52]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	ldr	r3, [r0, #56]
	ldr	r10, [r0, #60]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	ldr	r3, [r0, #64]
	ldr	r10, [r0, #68]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-16]
	str	r3, [fp, #-12]
	ldr	r3, [r0, #72]
	ldr	r10, [r0, #76]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-8]
	str	r3, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #34944
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #24576
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #16720
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #39
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #34944
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #57344
	movt	ip, #16385
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #4432
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #384
	movt	ip, #770
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #43
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ldr	r3, [fp, #-80]
	ldr	r10, [fp, #-76]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-80]
	str	r3, [fp, #-76]
	ldr	r3, [fp, #-72]
	ldr	r10, [fp, #-68]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-72]
	str	r3, [fp, #-68]
	ldr	r3, [fp, #-64]
	ldr	r10, [fp, #-60]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-64]
	str	r3, [fp, #-60]
	ldr	r3, [fp, #-56]
	ldr	r10, [fp, #-52]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-56]
	str	r3, [fp, #-52]
	ldr	r3, [fp, #-48]
	ldr	r10, [fp, #-44]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-48]
	str	r3, [fp, #-44]
	ldr	r3, [fp, #-40]
	ldr	r10, [fp, #-36]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-40]
	str	r3, [fp, #-36]
	ldr	r3, [fp, #-32]
	ldr	r10, [fp, #-28]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	ldr	r3, [fp, #-24]
	ldr	r10, [fp, #-20]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	ldr	r3, [fp, #-16]
	ldr	r10, [fp, #-12]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-16]
	str	r3, [fp, #-12]
	ldr	r3, [fp, #-8]
	ldr	r10, [fp, #-4]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-8]
	str	r3, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #2176
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #16384
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #320
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #514
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #33
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #128
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #49152
	movt	ip, #1
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #20736
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #384
	movt	ip, #769
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #46
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ldr	r3, [fp, #-80]
	ldr	r10, [fp, #-76]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-80]
	str	r3, [fp, #-76]
	ldr	r3, [fp, #-72]
	ldr	r10, [fp, #-68]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-72]
	str	r3, [fp, #-68]
	ldr	r3, [fp, #-64]
	ldr	r10, [fp, #-60]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-64]
	str	r3, [fp, #-60]
	ldr	r3, [fp, #-56]
	ldr	r10, [fp, #-52]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-56]
	str	r3, [fp, #-52]
	ldr	r3, [fp, #-48]
	ldr	r10, [fp, #-44]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-48]
	str	r3, [fp, #-44]
	ldr	r3, [fp, #-40]
	ldr	r10, [fp, #-36]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, r3, #858993459
	and	r8, r3, #3435973836
	ror	r7, r7, #24
	orr	r3, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, r3, r3, lsr #1
	and	r7, r7, r9
	eors	r3, r7
	eor	r3, r3, r7, lsl #1
	str	r10, [fp, #-40]
	str	r3, [fp, #-36]
	ldr	r3, [fp, #-32]
	ldr	r10, [fp, #-28]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, r3, #6
	and	r7, r7, #50332416
	and	r8, r3, #1056980736
	lsl	r8, r8, #2
	lsr	ip, r3, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, r3, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-32]
	str	r3, [fp, #-28]
	ldr	r3, [fp, #-24]
	ldr	r10, [fp, #-20]
	and	r7, r10, #2863311530
	and	r9, r3, #2863311530
	and	r8, r10, #1431655765
	and	ip, r3, #1431655765
	ror	r10, r7, #24
	ror	r3, ip, #24
	orr	r10, r10, r8, ror #16
	orr	r3, r3, r9, ror #20
	str	r10, [fp, #-24]
	str	r3, [fp, #-20]
	ldr	r3, [fp, #-16]
	ldr	r10, [fp, #-12]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, r3, #18
	and	r7, r7, r9
	and	r8, r3, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, r3, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, r3, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, r3, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, r3, r9
	lsl	r8, r8, #19
	orr	r3, r7, ip
	orr	r3, r3, r8
	str	r10, [fp, #-16]
	str	r3, [fp, #-12]
	ldr	r3, [fp, #-8]
	ldr	r10, [fp, #-4]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, r3, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, r3, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, r3, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, r3, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	r3, r7, r8
	str	r10, [fp, #-8]
	str	r3, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #34816
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #8192
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #16464
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #259
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #6
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #34824
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #40960
	movt	ip, #49153
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #5200
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #385
	movt	ip, #258
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #26
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	bfi	r9, r2, #24, #8
	bfi	r9, r6, #16, #8
	bfi	r9, r5, #8, #8
	bfi	r9, r4, #0, #8
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
	bfi	r8, r2, #24, #8
	bfi	r8, r6, #16, #8
	bfi	r8, r5, #8, #8
	bfi	r8, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r7, r2, #24, #8
	bfi	r7, r6, #16, #8
	bfi	r7, r5, #8, #8
	bfi	r7, r4, #0, #8
	eor	r4, r7, r7, lsr #7
	eor	r5, r8, r8, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #7
	eor	r8, r8, r5, lsl #7
	eor	r4, ip, ip, lsr #7
	eor	r5, r9, r9, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #7
	eor	r9, r9, r5, lsl #7
	eor	r4, r7, r7, lsr #14
	eor	r5, r8, r8, lsr #14
	movw	r6, #52428
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #14
	eor	r8, r8, r5, lsl #14
	eor	r4, ip, ip, lsr #14
	eor	r5, r9, r9, lsr #14
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #14
	eor	r9, r9, r5, lsl #14
	eor	r4, r7, r7, lsr #4
	eor	r5, r8, r8, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #4
	eor	r8, r8, r5, lsl #4
	eor	r4, ip, ip, lsr #4
	eor	r5, r9, r9, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #4
	eor	r9, r9, r5, lsl #4
	eor	r4, r7, r7, lsr #8
	eor	r5, r8, r8, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #8
	eor	r8, r8, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, r9, r9, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #8
	eor	r9, r9, r5, lsl #8
	str	r7, [r1, #12]
	str	r8, [r1, #8]
	str	ip, [r1, #4]
	str	r9, [r1, #0]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp}
	bx	lr
	.size	gift128n_encrypt, .-gift128n_encrypt

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
	eor	r0, r7, r7, lsr #24
	eor	r3, r9, r9, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #24
	eor	r9, r9, r3, lsl #24
	eor	r0, r7, r7, lsr #12
	eor	r3, r9, r9, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #12
	eor	r9, r9, r3, lsl #12
	eor	r0, r7, r7, lsr #6
	eor	r3, r9, r9, lsr #6
	and	r0, r0, #50529027
	and	r3, r3, #50529027
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #6
	eor	r9, r9, r3, lsl #6
	eor	r0, r7, r7, lsr #3
	eor	r3, r9, r9, lsr #3
	and	r0, r0, #286331153
	and	r3, r3, #286331153
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #3
	eor	r9, r9, r3, lsl #3
	eor	r0, r8, r8, lsr #24
	eor	r3, r10, r10, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #24
	eor	r10, r10, r3, lsl #24
	movw	fp, #13107
	eor	r0, r8, r8, lsr #18
	eor	r3, r10, r10, lsr #18
	and	r0, r0, fp
	and	r3, r3, fp
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #18
	eor	r10, r10, r3, lsl #18
	eor	r0, r8, r8, lsr #12
	eor	r3, r10, r10, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #12
	eor	r10, r10, r3, lsl #12
	eor	r0, r8, r8, lsr #9
	eor	r3, r10, r10, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #9
	eor	r10, r10, r3, lsl #9
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
.L1:
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
	.size	gift128n_decrypt, .-gift128n_decrypt

	.align	2
	.global	gift128t_encrypt
	.thumb
	.thumb_func
	.type	gift128t_encrypt, %function
gift128t_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #80
	ldr	r7, [r2, #12]
	ldr	r8, [r2, #8]
	ldr	ip, [r2, #4]
	ldr	r9, [r2, #0]
	eor	r4, r7, r7, lsr #3
	eor	r5, r8, r8, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #3
	eor	r8, r8, r5, lsl #3
	eor	r4, ip, ip, lsr #3
	eor	r5, r9, r9, lsr #3
	and	r4, r4, #168430090
	and	r5, r5, #168430090
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #3
	eor	r9, r9, r5, lsl #3
	eor	r4, r7, r7, lsr #6
	eor	r5, r8, r8, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #6
	eor	r8, r8, r5, lsl #6
	eor	r4, ip, ip, lsr #6
	eor	r5, r9, r9, lsr #6
	and	r4, r4, #13369548
	and	r5, r5, #13369548
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #6
	eor	r9, r9, r5, lsl #6
	eor	r4, r7, r7, lsr #12
	eor	r5, r8, r8, lsr #12
	movw	r6, #61680
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #12
	eor	r8, r8, r5, lsl #12
	eor	r4, ip, ip, lsr #12
	eor	r5, r9, r9, lsr #12
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #12
	eor	r9, r9, r5, lsl #12
	eor	r4, r7, r7, lsr #8
	eor	r5, r8, r8, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #8
	eor	r8, r8, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, r9, r9, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #8
	eor	r9, r9, r5, lsl #8
	bfi	r4, r7, #24, #8
	bfi	r4, r8, #16, #8
	bfi	r4, ip, #8, #8
	bfi	r4, r9, #0, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	ip, ip, #8
	lsr	r9, r9, #8
	bfi	r5, r7, #24, #8
	bfi	r5, r8, #16, #8
	bfi	r5, ip, #8, #8
	bfi	r5, r9, #0, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	ip, ip, #8
	lsr	r9, r9, #8
	bfi	r6, r7, #24, #8
	bfi	r6, r8, #16, #8
	bfi	r6, ip, #8, #8
	bfi	r6, r9, #0, #8
	lsr	r7, r7, #8
	lsr	r8, r8, #8
	lsr	ip, ip, #8
	lsr	r9, r9, #8
	bfi	r2, r7, #24, #8
	bfi	r2, r8, #16, #8
	bfi	r2, ip, #8, #8
	bfi	r2, r9, #0, #8
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	movw	ip, #8
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #8]
	ldr	r8, [r0, #12]
	movw	ip, #32768
	movt	ip, #32769
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #16]
	ldr	r8, [r0, #20]
	movw	ip, #2
	movt	ip, #21504
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	movw	ip, #385
	movt	ip, #257
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [r0, #32]
	ldr	r8, [r0, #36]
	movw	ip, #31
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r2, r2, r3
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [r0, #40]
	ldr	r8, [r0, #44]
	movw	ip, #34944
	movt	ip, #4232
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #48]
	ldr	r8, [r0, #52]
	movw	ip, #57344
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #2
	movt	ip, #20816
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [r0, #64]
	ldr	r8, [r0, #68]
	movw	ip, #384
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [r0, #72]
	ldr	r8, [r0, #76]
	movw	ip, #47
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r4, r4, r3
	ldr	lr, [r0, #0]
	ldr	r10, [r0, #4]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, lr, #858993459
	and	r8, lr, #3435973836
	ror	r7, r7, #24
	orr	lr, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, lr, lr, lsr #1
	and	r7, r7, r9
	eor	lr, r7
	eor	lr, lr, r7, lsl #1
	str	r10, [fp, #-80]
	str	lr, [fp, #-76]
	ldr	lr, [r0, #8]
	ldr	r10, [r0, #12]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, lr, #6
	and	r7, r7, #50332416
	and	r8, lr, #1056980736
	lsl	r8, r8, #2
	lsr	ip, lr, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, lr, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-72]
	str	lr, [fp, #-68]
	ldr	lr, [r0, #16]
	ldr	r10, [r0, #20]
	and	r7, r10, #2863311530
	and	r9, lr, #2863311530
	and	r8, r10, #1431655765
	and	ip, lr, #1431655765
	ror	r10, r7, #24
	ror	lr, ip, #24
	orr	r10, r10, r8, ror #16
	orr	lr, lr, r9, ror #20
	str	r10, [fp, #-64]
	str	lr, [fp, #-60]
	ldr	lr, [r0, #24]
	ldr	r10, [r0, #28]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, lr, #18
	and	r7, r7, r9
	and	r8, lr, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, lr, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, lr, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, lr, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, lr, r9
	lsl	r8, r8, #19
	orr	lr, r7, ip
	orr	lr, lr, r8
	str	r10, [fp, #-56]
	str	lr, [fp, #-52]
	ldr	lr, [r0, #32]
	ldr	r10, [r0, #36]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, lr, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, lr, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, lr, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, lr, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-48]
	str	lr, [fp, #-44]
	ldr	lr, [r0, #40]
	ldr	r10, [r0, #44]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, lr, #858993459
	and	r8, lr, #3435973836
	ror	r7, r7, #24
	orr	lr, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, lr, lr, lsr #1
	and	r7, r7, r9
	eor	lr, r7
	eor	lr, lr, r7, lsl #1
	str	r10, [fp, #-40]
	str	lr, [fp, #-36]
	ldr	lr, [r0, #48]
	ldr	r10, [r0, #52]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, lr, #6
	and	r7, r7, #50332416
	and	r8, lr, #1056980736
	lsl	r8, r8, #2
	lsr	ip, lr, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, lr, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-32]
	str	lr, [fp, #-28]
	ldr	lr, [r0, #56]
	ldr	r10, [r0, #60]
	and	r7, r10, #2863311530
	and	r9, lr, #2863311530
	and	r8, r10, #1431655765
	and	ip, lr, #1431655765
	ror	r10, r7, #24
	ror	lr, ip, #24
	orr	r10, r10, r8, ror #16
	orr	lr, lr, r9, ror #20
	str	r10, [fp, #-24]
	str	lr, [fp, #-20]
	ldr	lr, [r0, #64]
	ldr	r10, [r0, #68]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, lr, #18
	and	r7, r7, r9
	and	r8, lr, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, lr, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, lr, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, lr, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, lr, r9
	lsl	r8, r8, #19
	orr	lr, r7, ip
	orr	lr, lr, r8
	str	r10, [fp, #-16]
	str	lr, [fp, #-12]
	ldr	lr, [r0, #72]
	ldr	r10, [r0, #76]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, lr, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, lr, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, lr, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, lr, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-8]
	str	lr, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #34944
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #24576
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #16720
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #39
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r2, r2, r3
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #34944
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #57344
	movt	ip, #16385
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #4432
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #384
	movt	ip, #770
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #43
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r4, r4, r3
	ldr	lr, [fp, #-80]
	ldr	r10, [fp, #-76]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, lr, #858993459
	and	r8, lr, #3435973836
	ror	r7, r7, #24
	orr	lr, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, lr, lr, lsr #1
	and	r7, r7, r9
	eor	lr, r7
	eor	lr, lr, r7, lsl #1
	str	r10, [fp, #-80]
	str	lr, [fp, #-76]
	ldr	lr, [fp, #-72]
	ldr	r10, [fp, #-68]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, lr, #6
	and	r7, r7, #50332416
	and	r8, lr, #1056980736
	lsl	r8, r8, #2
	lsr	ip, lr, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, lr, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-72]
	str	lr, [fp, #-68]
	ldr	lr, [fp, #-64]
	ldr	r10, [fp, #-60]
	and	r7, r10, #2863311530
	and	r9, lr, #2863311530
	and	r8, r10, #1431655765
	and	ip, lr, #1431655765
	ror	r10, r7, #24
	ror	lr, ip, #24
	orr	r10, r10, r8, ror #16
	orr	lr, lr, r9, ror #20
	str	r10, [fp, #-64]
	str	lr, [fp, #-60]
	ldr	lr, [fp, #-56]
	ldr	r10, [fp, #-52]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, lr, #18
	and	r7, r7, r9
	and	r8, lr, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, lr, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, lr, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, lr, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, lr, r9
	lsl	r8, r8, #19
	orr	lr, r7, ip
	orr	lr, lr, r8
	str	r10, [fp, #-56]
	str	lr, [fp, #-52]
	ldr	lr, [fp, #-48]
	ldr	r10, [fp, #-44]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, lr, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, lr, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, lr, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, lr, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-48]
	str	lr, [fp, #-44]
	ldr	lr, [fp, #-40]
	ldr	r10, [fp, #-36]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, lr, #858993459
	and	r8, lr, #3435973836
	ror	r7, r7, #24
	orr	lr, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, lr, lr, lsr #1
	and	r7, r7, r9
	eor	lr, r7
	eor	lr, lr, r7, lsl #1
	str	r10, [fp, #-40]
	str	lr, [fp, #-36]
	ldr	lr, [fp, #-32]
	ldr	r10, [fp, #-28]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, lr, #6
	and	r7, r7, #50332416
	and	r8, lr, #1056980736
	lsl	r8, r8, #2
	lsr	ip, lr, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, lr, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-32]
	str	lr, [fp, #-28]
	ldr	lr, [fp, #-24]
	ldr	r10, [fp, #-20]
	and	r7, r10, #2863311530
	and	r9, lr, #2863311530
	and	r8, r10, #1431655765
	and	ip, lr, #1431655765
	ror	r10, r7, #24
	ror	lr, ip, #24
	orr	r10, r10, r8, ror #16
	orr	lr, lr, r9, ror #20
	str	r10, [fp, #-24]
	str	lr, [fp, #-20]
	ldr	lr, [fp, #-16]
	ldr	r10, [fp, #-12]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, lr, #18
	and	r7, r7, r9
	and	r8, lr, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, lr, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, lr, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, lr, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, lr, r9
	lsl	r8, r8, #19
	orr	lr, r7, ip
	orr	lr, lr, r8
	str	r10, [fp, #-16]
	str	lr, [fp, #-12]
	ldr	lr, [fp, #-8]
	ldr	r10, [fp, #-4]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, lr, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, lr, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, lr, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, lr, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-8]
	str	lr, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #2176
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #16384
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #320
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #514
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #33
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r2, r2, r3
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #128
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #49152
	movt	ip, #1
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #20736
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #384
	movt	ip, #769
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #46
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r4, r4, r3
	ldr	lr, [fp, #-80]
	ldr	r10, [fp, #-76]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, lr, #858993459
	and	r8, lr, #3435973836
	ror	r7, r7, #24
	orr	lr, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, lr, lr, lsr #1
	and	r7, r7, r9
	eor	lr, r7
	eor	lr, lr, r7, lsl #1
	str	r10, [fp, #-80]
	str	lr, [fp, #-76]
	ldr	lr, [fp, #-72]
	ldr	r10, [fp, #-68]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, lr, #6
	and	r7, r7, #50332416
	and	r8, lr, #1056980736
	lsl	r8, r8, #2
	lsr	ip, lr, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, lr, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-72]
	str	lr, [fp, #-68]
	ldr	lr, [fp, #-64]
	ldr	r10, [fp, #-60]
	and	r7, r10, #2863311530
	and	r9, lr, #2863311530
	and	r8, r10, #1431655765
	and	ip, lr, #1431655765
	ror	r10, r7, #24
	ror	lr, ip, #24
	orr	r10, r10, r8, ror #16
	orr	lr, lr, r9, ror #20
	str	r10, [fp, #-64]
	str	lr, [fp, #-60]
	ldr	lr, [fp, #-56]
	ldr	r10, [fp, #-52]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, lr, #18
	and	r7, r7, r9
	and	r8, lr, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, lr, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, lr, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, lr, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, lr, r9
	lsl	r8, r8, #19
	orr	lr, r7, ip
	orr	lr, lr, r8
	str	r10, [fp, #-56]
	str	lr, [fp, #-52]
	ldr	lr, [fp, #-48]
	ldr	r10, [fp, #-44]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, lr, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, lr, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, lr, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, lr, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-48]
	str	lr, [fp, #-44]
	ldr	lr, [fp, #-40]
	ldr	r10, [fp, #-36]
	movw	r9, #13107
	eor	r7, r10, r10, lsr #16
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #16
	movw	r9, #17476
	movt	r9, #21845
	eor	r7, r10, r10, lsr #1
	and	r7, r7, r9
	eor	r10, r7
	eor	r10, r10, r7, lsl #1
	and	r7, lr, #858993459
	and	r8, lr, #3435973836
	ror	r7, r7, #24
	orr	lr, r7, r8, ror #16
	movw	r9, #4352
	movt	r9, #21845
	eor	r7, lr, lr, lsr #1
	and	r7, r7, r9
	eor	lr, r7
	eor	lr, lr, r7, lsl #1
	str	r10, [fp, #-40]
	str	lr, [fp, #-36]
	ldr	lr, [fp, #-32]
	ldr	r10, [fp, #-28]
	lsr	r7, r10, #4
	and	r7, r7, #251662080
	and	r8, r10, #251662080
	lsl	r8, r8, #4
	lsr	ip, r10, #6
	and	ip, ip, #196611
	orr	r7, r7, r8
	and	r8, r10, #4128831
	lsl	r8, r8, #2
	orr	r7, r7, ip
	orr	r10, r7, r8
	lsr	r7, lr, #6
	and	r7, r7, #50332416
	and	r8, lr, #1056980736
	lsl	r8, r8, #2
	lsr	ip, lr, #5
	and	ip, ip, #458759
	orr	r7, r7, r8
	and	r8, lr, #2031647
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-32]
	str	lr, [fp, #-28]
	ldr	lr, [fp, #-24]
	ldr	r10, [fp, #-20]
	and	r7, r10, #2863311530
	and	r9, lr, #2863311530
	and	r8, r10, #1431655765
	and	ip, lr, #1431655765
	ror	r10, r7, #24
	ror	lr, ip, #24
	orr	r10, r10, r8, ror #16
	orr	lr, lr, r9, ror #20
	str	r10, [fp, #-24]
	str	lr, [fp, #-20]
	ldr	lr, [fp, #-16]
	ldr	r10, [fp, #-12]
	lsr	r7, r10, #2
	and	r7, r7, #50529027
	and	r8, r10, #50529027
	lsl	r8, r8, #2
	lsr	ip, r10, #1
	and	ip, ip, #1886417008
	orr	r7, r7, r8
	and	r8, r10, #269488144
	lsl	r8, r8, #3
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #12336
	lsr	r7, lr, #18
	and	r7, r7, r9
	and	r8, lr, #16843009
	lsl	r8, r8, #3
	movw	r9, #49344
	lsr	ip, lr, #14
	and	ip, ip, r9
	orr	r7, r7, r8
	movw	r9, #57568
	and	r8, lr, r9
	lsl	r8, r8, #15
	orr	r7, r7, ip
	lsr	ip, lr, #1
	and	ip, ip, #117901063
	orr	r7, r7, r8
	movw	r9, #4112
	and	r8, lr, r9
	lsl	r8, r8, #19
	orr	lr, r7, ip
	orr	lr, lr, r8
	str	r10, [fp, #-16]
	str	lr, [fp, #-12]
	ldr	lr, [fp, #-8]
	ldr	r10, [fp, #-4]
	movw	r9, #0
	movt	r9, #4095
	lsr	r7, r10, #4
	and	r7, r7, r9
	and	r8, r10, #983040
	lsl	r8, r8, #12
	lsr	ip, r10, #8
	and	ip, ip, #255
	orr	r7, r7, r8
	and	r8, r10, #255
	lsl	r8, r8, #8
	orr	r7, r7, ip
	orr	r10, r7, r8
	movw	r9, #0
	movt	r9, #1023
	lsr	r7, lr, #6
	and	r7, r7, r9
	movw	r9, #0
	movt	r9, #63
	and	r8, lr, r9
	lsl	r8, r8, #10
	movw	r9, #4095
	lsr	ip, lr, #4
	and	ip, ip, r9
	orr	r7, r7, r8
	and	r8, lr, #15
	lsl	r8, r8, #12
	orr	r7, r7, ip
	orr	lr, r7, r8
	str	r10, [fp, #-8]
	str	lr, [fp, #-4]
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r2, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r2, r2, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r2, ip, r2, lsl #3
	ldr	r7, [fp, #-80]
	ldr	r8, [fp, #-76]
	movw	ip, #34816
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-72]
	ldr	r8, [fp, #-68]
	movw	ip, #8192
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r2, r2, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r9
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [fp, #-64]
	ldr	r8, [fp, #-60]
	movw	ip, #2
	movt	ip, #16464
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r4, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r4, r4, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r4, r7, r4, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-56]
	ldr	r8, [fp, #-52]
	movw	ip, #128
	movt	ip, #259
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r2, r2, #24
	ldr	r7, [fp, #-48]
	ldr	r8, [fp, #-44]
	movw	ip, #6
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r2, r2, r3
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	lsr	r7, r5, #2
	lsr	r8, r6, #3
	lsr	ip, r4, #1
	and	r5, r5, #858993459
	and	r6, r6, #2004318071
	and	r4, r4, #286331153
	and	r7, r7, #858993459
	and	r8, r8, #286331153
	and	ip, ip, #2004318071
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #1
	orr	r4, ip, r4, lsl #3
	ldr	r7, [fp, #-40]
	ldr	r8, [fp, #-36]
	movw	ip, #34824
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	mvn	r9, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r9
	and	r7, r7, r9
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [fp, #-32]
	ldr	r8, [fp, #-28]
	movw	ip, #40960
	movt	ip, #49153
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r6, r6, #16
	ror	r4, r4, #16
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r9, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r9
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r9, #0
	movt	r9, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r9
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [fp, #-24]
	ldr	r8, [fp, #-20]
	movw	ip, #2
	movt	ip, #5200
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	and	r7, r4, r6
	eors	r5, r7
	and	r8, r5, r2
	eor	r4, r8
	orr	r7, r4, r5
	eors	r6, r7
	eors	r2, r6
	eors	r5, r2
	mvns	r2, r2
	and	r7, r4, r5
	eors	r6, r7
	lsr	r7, r2, #6
	lsr	r8, r5, #4
	lsr	ip, r6, #2
	and	r2, r2, #1061109567
	and	r5, r5, #252645135
	and	r6, r6, #50529027
	and	r7, r7, #50529027
	and	r8, r8, #252645135
	and	ip, ip, #1061109567
	orr	r2, r7, r2, lsl #2
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #6
	ldr	r7, [fp, #-16]
	ldr	r8, [fp, #-12]
	movw	ip, #385
	movt	ip, #258
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	and	r7, r2, r6
	eors	r5, r7
	and	r8, r5, r4
	eor	r2, r8
	orr	r7, r2, r5
	eors	r6, r7
	eors	r4, r6
	eors	r5, r4
	mvns	r4, r4
	and	r7, r2, r5
	eors	r6, r7
	ror	r5, r5, #16
	ror	r6, r6, #8
	ror	r4, r4, #24
	ldr	r7, [fp, #-8]
	ldr	r8, [fp, #-4]
	movw	ip, #26
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	bfi	r9, r2, #24, #8
	bfi	r9, r6, #16, #8
	bfi	r9, r5, #8, #8
	bfi	r9, r4, #0, #8
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
	bfi	r8, r2, #24, #8
	bfi	r8, r6, #16, #8
	bfi	r8, r5, #8, #8
	bfi	r8, r4, #0, #8
	lsr	r2, r2, #8
	lsr	r6, r6, #8
	lsr	r5, r5, #8
	lsr	r4, r4, #8
	bfi	r7, r2, #24, #8
	bfi	r7, r6, #16, #8
	bfi	r7, r5, #8, #8
	bfi	r7, r4, #0, #8
	eor	r4, r7, r7, lsr #7
	eor	r5, r8, r8, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #7
	eor	r8, r8, r5, lsl #7
	eor	r4, ip, ip, lsr #7
	eor	r5, r9, r9, lsr #7
	and	r4, r4, #11141290
	and	r5, r5, #11141290
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #7
	eor	r9, r9, r5, lsl #7
	eor	r4, r7, r7, lsr #14
	eor	r5, r8, r8, lsr #14
	movw	r6, #52428
	and	r4, r4, r6
	and	r5, r5, r6
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #14
	eor	r8, r8, r5, lsl #14
	eor	r4, ip, ip, lsr #14
	eor	r5, r9, r9, lsr #14
	and	r4, r4, r6
	and	r5, r5, r6
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #14
	eor	r9, r9, r5, lsl #14
	eor	r4, r7, r7, lsr #4
	eor	r5, r8, r8, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #4
	eor	r8, r8, r5, lsl #4
	eor	r4, ip, ip, lsr #4
	eor	r5, r9, r9, lsr #4
	and	r4, r4, #15728880
	and	r5, r5, #15728880
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #4
	eor	r9, r9, r5, lsl #4
	eor	r4, r7, r7, lsr #8
	eor	r5, r8, r8, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	r7, r7, r4
	eor	r8, r8, r5
	eor	r7, r7, r4, lsl #8
	eor	r8, r8, r5, lsl #8
	eor	r4, ip, ip, lsr #8
	eor	r5, r9, r9, lsr #8
	and	r4, r4, #65280
	and	r5, r5, #65280
	eor	ip, ip, r4
	eor	r9, r9, r5
	eor	ip, ip, r4, lsl #8
	eor	r9, r9, r5, lsl #8
	str	r7, [r1, #12]
	str	r8, [r1, #8]
	str	ip, [r1, #4]
	str	r9, [r1, #0]
	mov	sp, fp
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gift128t_encrypt, .-gift128t_encrypt

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
	eor	r0, r7, r7, lsr #24
	eor	r3, r9, r9, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #24
	eor	r9, r9, r3, lsl #24
	eor	r0, r7, r7, lsr #12
	eor	r3, r9, r9, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #12
	eor	r9, r9, r3, lsl #12
	eor	r0, r7, r7, lsr #6
	eor	r3, r9, r9, lsr #6
	and	r0, r0, #50529027
	and	r3, r3, #50529027
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #6
	eor	r9, r9, r3, lsl #6
	eor	r0, r7, r7, lsr #3
	eor	r3, r9, r9, lsr #3
	and	r0, r0, #286331153
	and	r3, r3, #286331153
	eors	r7, r0
	eor	r9, r3
	eor	r7, r7, r0, lsl #3
	eor	r9, r9, r3, lsl #3
	eor	r0, r8, r8, lsr #24
	eor	r3, r10, r10, lsr #24
	and	r0, r0, #255
	and	r3, r3, #255
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #24
	eor	r10, r10, r3, lsl #24
	movw	fp, #13107
	eor	r0, r8, r8, lsr #18
	eor	r3, r10, r10, lsr #18
	and	r0, r0, fp
	and	r3, r3, fp
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #18
	eor	r10, r10, r3, lsl #18
	eor	r0, r8, r8, lsr #12
	eor	r3, r10, r10, lsr #12
	and	r0, r0, #983055
	and	r3, r3, #983055
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #12
	eor	r10, r10, r3, lsl #12
	eor	r0, r8, r8, lsr #9
	eor	r3, r10, r10, lsr #9
	and	r0, r0, #5570645
	and	r3, r3, #5570645
	eor	r8, r0
	eor	r10, r3
	eor	r8, r8, r0, lsl #9
	eor	r10, r10, r3, lsl #9
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
	beq	.L3
	eors	r4, r3
	push	{r3}
	b	.L2
.L3:
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
