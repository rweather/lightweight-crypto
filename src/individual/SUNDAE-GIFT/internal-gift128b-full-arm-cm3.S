#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#include "internal-gift128-config.h"
#if GIFT128_VARIANT_ASM && GIFT128_VARIANT == GIFT128_VARIANT_FULL
	.syntax unified
	.thumb
	.text

	.align	2
	.global	gift128b_init
	.thumb
	.thumb_func
	.type	gift128b_init, %function
gift128b_init:
	push	{r4, r5, r6, r7, r8, r9}
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
	mov	r9, #6
.L1:
	ldr	r2, [r0, #0]
	ldr	r3, [r0, #4]
	movw	ip, #13107
	eor	r6, r3, r3, lsr #16
	and	r6, r6, ip
	eors	r3, r6
	eor	r3, r3, r6, lsl #16
	movw	ip, #17476
	movt	ip, #21845
	eor	r6, r3, r3, lsr #1
	and	r6, r6, ip
	eors	r3, r6
	eor	r3, r3, r6, lsl #1
	and	r6, r2, #858993459
	and	r7, r2, #3435973836
	ror	r6, r6, #24
	orr	r2, r6, r7, ror #16
	movw	ip, #4352
	movt	ip, #21845
	eor	r6, r2, r2, lsr #1
	and	r6, r6, ip
	eors	r2, r6
	eor	r2, r2, r6, lsl #1
	str	r3, [r0, #80]
	str	r2, [r0, #84]
	ldr	r2, [r0, #8]
	ldr	r3, [r0, #12]
	lsr	r6, r3, #4
	and	r6, r6, #251662080
	and	r7, r3, #251662080
	lsl	r7, r7, #4
	lsr	r8, r3, #6
	and	r8, r8, #196611
	orr	r6, r6, r7
	and	r7, r3, #4128831
	lsl	r7, r7, #2
	orr	r6, r6, r8
	orr	r3, r6, r7
	lsr	r6, r2, #6
	and	r6, r6, #50332416
	and	r7, r2, #1056980736
	lsl	r7, r7, #2
	lsr	r8, r2, #5
	and	r8, r8, #458759
	orr	r6, r6, r7
	and	r7, r2, #2031647
	lsl	r7, r7, #3
	orr	r6, r6, r8
	orr	r2, r6, r7
	str	r3, [r0, #88]
	str	r2, [r0, #92]
	ldr	r2, [r0, #16]
	ldr	r3, [r0, #20]
	and	r6, r3, #2863311530
	and	ip, r2, #2863311530
	and	r7, r3, #1431655765
	and	r8, r2, #1431655765
	ror	r3, r6, #24
	ror	r2, r8, #24
	orr	r3, r3, r7, ror #16
	orr	r2, r2, ip, ror #20
	str	r3, [r0, #96]
	str	r2, [r0, #100]
	ldr	r2, [r0, #24]
	ldr	r3, [r0, #28]
	lsr	r6, r3, #2
	and	r6, r6, #50529027
	and	r7, r3, #50529027
	lsl	r7, r7, #2
	lsr	r8, r3, #1
	and	r8, r8, #1886417008
	orr	r6, r6, r7
	and	r7, r3, #269488144
	lsl	r7, r7, #3
	orr	r6, r6, r8
	orr	r3, r6, r7
	movw	ip, #12336
	lsr	r6, r2, #18
	and	r6, r6, ip
	and	r7, r2, #16843009
	lsl	r7, r7, #3
	movw	ip, #49344
	lsr	r8, r2, #14
	and	r8, r8, ip
	orr	r6, r6, r7
	movw	ip, #57568
	and	r7, r2, ip
	lsl	r7, r7, #15
	orr	r6, r6, r8
	lsr	r8, r2, #1
	and	r8, r8, #117901063
	orr	r6, r6, r7
	movw	ip, #4112
	and	r7, r2, ip
	lsl	r7, r7, #19
	orr	r2, r6, r8
	orr	r2, r2, r7
	str	r3, [r0, #104]
	str	r2, [r0, #108]
	ldr	r2, [r0, #32]
	ldr	r3, [r0, #36]
	movw	ip, #0
	movt	ip, #4095
	lsr	r6, r3, #4
	and	r6, r6, ip
	and	r7, r3, #983040
	lsl	r7, r7, #12
	lsr	r8, r3, #8
	and	r8, r8, #255
	orr	r6, r6, r7
	and	r7, r3, #255
	lsl	r7, r7, #8
	orr	r6, r6, r8
	orr	r3, r6, r7
	movw	ip, #0
	movt	ip, #1023
	lsr	r6, r2, #6
	and	r6, r6, ip
	movw	ip, #0
	movt	ip, #63
	and	r7, r2, ip
	lsl	r7, r7, #10
	movw	ip, #4095
	lsr	r8, r2, #4
	and	r8, r8, ip
	orr	r6, r6, r7
	and	r7, r2, #15
	lsl	r7, r7, #12
	orr	r6, r6, r8
	orr	r2, r6, r7
	str	r3, [r0, #112]
	str	r2, [r0, #116]
	add	r0, r0, #40
	subs	r9, r9, #1
	bne	.L1
	pop	{r4, r5, r6, r7, r8, r9}
	bx	lr
	.size	gift128b_init, .-gift128b_init

	.align	2
	.global	gift128b_encrypt
	.thumb
	.thumb_func
	.type	gift128b_encrypt, %function
gift128b_encrypt:
	push	{r4, r5, r6, r7, r8}
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
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
	ldr	r7, [r0, #80]
	ldr	r8, [r0, #84]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #88]
	ldr	r8, [r0, #92]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #96]
	ldr	r8, [r0, #100]
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
	ldr	r7, [r0, #104]
	ldr	r8, [r0, #108]
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
	ldr	r7, [r0, #112]
	ldr	r8, [r0, #116]
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
	ldr	r7, [r0, #120]
	ldr	r8, [r0, #124]
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #128]
	ldr	r8, [r0, #132]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #136]
	ldr	r8, [r0, #140]
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
	ldr	r7, [r0, #144]
	ldr	r8, [r0, #148]
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
	ldr	r7, [r0, #152]
	ldr	r8, [r0, #156]
	movw	ip, #43
	movt	ip, #32768
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
	ldr	r7, [r0, #160]
	ldr	r8, [r0, #164]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #168]
	ldr	r8, [r0, #172]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #176]
	ldr	r8, [r0, #180]
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
	ldr	r7, [r0, #184]
	ldr	r8, [r0, #188]
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
	ldr	r7, [r0, #192]
	ldr	r8, [r0, #196]
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
	ldr	r7, [r0, #200]
	ldr	r8, [r0, #204]
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #208]
	ldr	r8, [r0, #212]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #216]
	ldr	r8, [r0, #220]
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
	ldr	r7, [r0, #224]
	ldr	r8, [r0, #228]
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
	ldr	r7, [r0, #232]
	ldr	r8, [r0, #236]
	movw	ip, #46
	movt	ip, #32768
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
	ldr	r7, [r0, #240]
	ldr	r8, [r0, #244]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #248]
	ldr	r8, [r0, #252]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #256]
	ldr	r8, [r0, #260]
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
	ldr	r7, [r0, #264]
	ldr	r8, [r0, #268]
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
	ldr	r7, [r0, #272]
	ldr	r8, [r0, #276]
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
	ldr	r7, [r0, #280]
	ldr	r8, [r0, #284]
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #288]
	ldr	r8, [r0, #292]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #296]
	ldr	r8, [r0, #300]
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
	ldr	r7, [r0, #304]
	ldr	r8, [r0, #308]
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
	ldr	r7, [r0, #312]
	ldr	r8, [r0, #316]
	movw	ip, #26
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8}
	bx	lr
	.size	gift128b_encrypt, .-gift128b_encrypt

	.align	2
	.global	gift128b_encrypt_preloaded
	.thumb
	.thumb_func
	.type	gift128b_encrypt_preloaded, %function
gift128b_encrypt_preloaded:
	push	{r4, r5, r6, r7, r8}
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
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
	ldr	r7, [r0, #80]
	ldr	r8, [r0, #84]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #88]
	ldr	r8, [r0, #92]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #96]
	ldr	r8, [r0, #100]
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
	ldr	r7, [r0, #104]
	ldr	r8, [r0, #108]
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
	ldr	r7, [r0, #112]
	ldr	r8, [r0, #116]
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
	ldr	r7, [r0, #120]
	ldr	r8, [r0, #124]
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #128]
	ldr	r8, [r0, #132]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #136]
	ldr	r8, [r0, #140]
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
	ldr	r7, [r0, #144]
	ldr	r8, [r0, #148]
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
	ldr	r7, [r0, #152]
	ldr	r8, [r0, #156]
	movw	ip, #43
	movt	ip, #32768
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
	ldr	r7, [r0, #160]
	ldr	r8, [r0, #164]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #168]
	ldr	r8, [r0, #172]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #176]
	ldr	r8, [r0, #180]
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
	ldr	r7, [r0, #184]
	ldr	r8, [r0, #188]
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
	ldr	r7, [r0, #192]
	ldr	r8, [r0, #196]
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
	ldr	r7, [r0, #200]
	ldr	r8, [r0, #204]
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #208]
	ldr	r8, [r0, #212]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #216]
	ldr	r8, [r0, #220]
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
	ldr	r7, [r0, #224]
	ldr	r8, [r0, #228]
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
	ldr	r7, [r0, #232]
	ldr	r8, [r0, #236]
	movw	ip, #46
	movt	ip, #32768
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
	ldr	r7, [r0, #240]
	ldr	r8, [r0, #244]
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
	mvn	r3, #4026593280
	lsr	r7, r4, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r4, r4, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r4, r7, r4, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #248]
	ldr	r8, [r0, #252]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ldr	r7, [r0, #256]
	ldr	r8, [r0, #260]
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
	ldr	r7, [r0, #264]
	ldr	r8, [r0, #268]
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
	ldr	r7, [r0, #272]
	ldr	r8, [r0, #276]
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
	ldr	r7, [r0, #280]
	ldr	r8, [r0, #284]
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
	mvn	r3, #4026593280
	lsr	r7, r2, #4
	rev16	r5, r5
	lsr	ip, r6, #12
	and	r2, r2, #983055
	and	r6, r6, r3
	and	r7, r7, r3
	and	ip, ip, #983055
	orr	r2, r7, r2, lsl #12
	orr	r6, ip, r6, lsl #4
	ldr	r7, [r0, #288]
	ldr	r8, [r0, #292]
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
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ldr	r7, [r0, #296]
	ldr	r8, [r0, #300]
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
	ldr	r7, [r0, #304]
	ldr	r8, [r0, #308]
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
	ldr	r7, [r0, #312]
	ldr	r8, [r0, #316]
	movw	ip, #26
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8}
	bx	lr
	.size	gift128b_encrypt_preloaded, .-gift128b_encrypt_preloaded

	.align	2
	.global	gift128b_decrypt
	.thumb
	.thumb_func
	.type	gift128b_decrypt, %function
gift128b_decrypt:
	push	{r4, r5, r6, r7, r8}
	ldr	r4, [r2, #0]
	ldr	r5, [r2, #4]
	ldr	r6, [r2, #8]
	ldr	r2, [r2, #12]
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	ldr	r7, [r0, #312]
	ldr	r8, [r0, #316]
	movw	ip, #26
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r4, r4, #8
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #304]
	ldr	r8, [r0, #308]
	movw	ip, #385
	movt	ip, #258
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r2, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r2, r2, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r2, r7, r2, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #296]
	ldr	r8, [r0, #300]
	movw	ip, #2
	movt	ip, #5200
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ror	r6, r6, #16
	ror	r4, r4, #16
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #288]
	ldr	r8, [r0, #292]
	movw	ip, #40960
	movt	ip, #49153
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	mvn	r3, #4026593280
	lsr	r7, r2, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r2, r2, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r2, r7, r2, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #280]
	ldr	r8, [r0, #284]
	movw	ip, #34824
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r4, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r4, r4, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r4, ip, r4, lsl #1
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #272]
	ldr	r8, [r0, #276]
	movw	ip, #6
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r2, r2, #8
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #264]
	ldr	r8, [r0, #268]
	movw	ip, #128
	movt	ip, #259
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r4, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r4, r4, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r4, r7, r4, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #256]
	ldr	r8, [r0, #260]
	movw	ip, #2
	movt	ip, #16464
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ror	r6, r6, #16
	ror	r2, r2, #16
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #248]
	ldr	r8, [r0, #252]
	movw	ip, #8192
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	mvn	r3, #4026593280
	lsr	r7, r4, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r4, r4, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r4, r7, r4, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #240]
	ldr	r8, [r0, #244]
	movw	ip, #34816
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r2, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r2, r2, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r2, ip, r2, lsl #1
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #232]
	ldr	r8, [r0, #236]
	movw	ip, #46
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r4, r4, #8
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #224]
	ldr	r8, [r0, #228]
	movw	ip, #384
	movt	ip, #769
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r2, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r2, r2, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r2, r7, r2, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #216]
	ldr	r8, [r0, #220]
	movw	ip, #2
	movt	ip, #20736
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ror	r6, r6, #16
	ror	r4, r4, #16
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #208]
	ldr	r8, [r0, #212]
	movw	ip, #49152
	movt	ip, #1
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	mvn	r3, #4026593280
	lsr	r7, r2, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r2, r2, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r2, r7, r2, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #200]
	ldr	r8, [r0, #204]
	movw	ip, #128
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r4, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r4, r4, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r4, ip, r4, lsl #1
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #192]
	ldr	r8, [r0, #196]
	movw	ip, #33
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r2, r2, #8
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #184]
	ldr	r8, [r0, #188]
	movw	ip, #128
	movt	ip, #514
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r4, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r4, r4, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r4, r7, r4, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #176]
	ldr	r8, [r0, #180]
	movw	ip, #2
	movt	ip, #320
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ror	r6, r6, #16
	ror	r2, r2, #16
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #168]
	ldr	r8, [r0, #172]
	movw	ip, #16384
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	mvn	r3, #4026593280
	lsr	r7, r4, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r4, r4, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r4, r7, r4, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #160]
	ldr	r8, [r0, #164]
	movw	ip, #2176
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r2, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r2, r2, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r2, ip, r2, lsl #1
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #152]
	ldr	r8, [r0, #156]
	movw	ip, #43
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r4, r4, #8
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #144]
	ldr	r8, [r0, #148]
	movw	ip, #384
	movt	ip, #770
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r2, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r2, r2, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r2, r7, r2, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #136]
	ldr	r8, [r0, #140]
	movw	ip, #2
	movt	ip, #4432
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ror	r6, r6, #16
	ror	r4, r4, #16
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #128]
	ldr	r8, [r0, #132]
	movw	ip, #57344
	movt	ip, #16385
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	mvn	r3, #4026593280
	lsr	r7, r2, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r2, r2, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r2, r7, r2, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #120]
	ldr	r8, [r0, #124]
	movw	ip, #34944
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r4, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r4, r4, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r4, ip, r4, lsl #1
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #112]
	ldr	r8, [r0, #116]
	movw	ip, #39
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r2, r2, #8
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #104]
	ldr	r8, [r0, #108]
	movw	ip, #128
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r4, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r4, r4, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r4, r7, r4, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #96]
	ldr	r8, [r0, #100]
	movw	ip, #2
	movt	ip, #16720
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ror	r6, r6, #16
	ror	r2, r2, #16
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #88]
	ldr	r8, [r0, #92]
	movw	ip, #24576
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	mvn	r3, #4026593280
	lsr	r7, r4, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r4, r4, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r4, r7, r4, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #80]
	ldr	r8, [r0, #84]
	movw	ip, #34944
	movt	ip, #4104
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r2, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r2, r2, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r2, ip, r2, lsl #1
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #72]
	ldr	r8, [r0, #76]
	movw	ip, #47
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r4, r4, #8
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #64]
	ldr	r8, [r0, #68]
	movw	ip, #384
	movt	ip, #771
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r2, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r2, r2, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r2, r7, r2, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #2
	movt	ip, #20816
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r4, r4, lsr #1
	and	r7, r7, r3
	eors	r4, r7
	eor	r4, r4, r7, lsl #1
	ror	r6, r6, #16
	ror	r4, r4, #16
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #48]
	ldr	r8, [r0, #52]
	movw	ip, #57344
	movt	ip, #24577
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	mvn	r3, #4026593280
	lsr	r7, r2, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r2, r2, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r2, r7, r2, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #40]
	ldr	r8, [r0, #44]
	movw	ip, #34944
	movt	ip, #4232
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r4, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r4, r4, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r4, ip, r4, lsl #1
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #32]
	ldr	r8, [r0, #36]
	movw	ip, #31
	movt	ip, #32768
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	ror	r5, r5, #16
	ror	r6, r6, #24
	ror	r2, r2, #8
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	movw	ip, #385
	movt	ip, #257
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	lsr	r7, r4, #2
	lsr	r8, r5, #4
	lsr	ip, r6, #6
	and	r4, r4, #50529027
	and	r5, r5, #252645135
	and	r6, r6, #1061109567
	and	r7, r7, #1061109567
	and	r8, r8, #252645135
	and	ip, ip, #50529027
	orr	r4, r7, r4, lsl #6
	orr	r5, r8, r5, lsl #4
	orr	r6, ip, r6, lsl #2
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #16]
	ldr	r8, [r0, #20]
	movw	ip, #2
	movt	ip, #21504
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	eor	r7, r5, r5, lsr #1
	and	r7, r7, #1431655765
	eors	r5, r7
	eor	r5, r5, r7, lsl #1
	movw	r3, #21845
	eor	r7, r6, r6, lsr #1
	and	r7, r7, r3
	eors	r6, r7
	eor	r6, r6, r7, lsl #1
	movw	r3, #0
	movt	r3, #21845
	eor	r7, r2, r2, lsr #1
	and	r7, r7, r3
	eors	r2, r7
	eor	r2, r2, r7, lsl #1
	ror	r6, r6, #16
	ror	r2, r2, #16
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	ldr	r7, [r0, #8]
	ldr	r8, [r0, #12]
	movw	ip, #32768
	movt	ip, #32769
	eors	r5, r7
	eor	r6, r8
	eor	r2, ip
	mvn	r3, #4026593280
	lsr	r7, r4, #12
	rev16	r5, r5
	lsr	ip, r6, #4
	and	r4, r4, r3
	and	r6, r6, #983055
	and	r7, r7, #983055
	and	ip, ip, r3
	orr	r4, r7, r4, lsl #4
	orr	r6, ip, r6, lsl #12
	and	r7, r2, r5
	eors	r6, r7
	mvns	r4, r4
	eors	r5, r4
	eors	r4, r6
	orr	r7, r2, r5
	and	r8, r5, r4
	eors	r6, r7
	eor	r2, r8
	and	r7, r2, r6
	eors	r5, r7
	ldr	r7, [r0, #0]
	ldr	r8, [r0, #4]
	movw	ip, #8
	movt	ip, #4096
	eors	r5, r7
	eor	r6, r8
	eor	r4, ip
	lsr	r7, r5, #2
	lsr	r8, r6, #1
	lsr	ip, r2, #3
	and	r5, r5, #858993459
	and	r6, r6, #286331153
	and	r2, r2, #2004318071
	and	r7, r7, #858993459
	and	r8, r8, #2004318071
	and	ip, ip, #286331153
	orr	r5, r7, r5, lsl #2
	orr	r6, r8, r6, lsl #3
	orr	r2, ip, r2, lsl #1
	and	r7, r4, r5
	eors	r6, r7
	mvns	r2, r2
	eors	r5, r2
	eors	r2, r6
	orr	r7, r4, r5
	and	r8, r5, r2
	eors	r6, r7
	eor	r4, r8
	and	r7, r4, r6
	eors	r5, r7
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	rev	r2, r2
	str	r4, [r1, #0]
	str	r5, [r1, #4]
	str	r6, [r1, #8]
	str	r2, [r1, #12]
	pop	{r4, r5, r6, r7, r8}
	bx	lr
	.size	gift128b_decrypt, .-gift128b_decrypt

#endif
#endif
