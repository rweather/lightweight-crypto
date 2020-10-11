#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	gimli24_permute
	.thumb
	.thumb_func
	.type	gimli24_permute, %function
gimli24_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #4]
	ldr	r3, [r0, #8]
	ldr	r4, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r6, [r0, #20]
	ldr	r7, [r0, #24]
	ldr	r8, [r0, #28]
	ldr	r9, [r0, #32]
	ldr	r10, [r0, #36]
	ldr	fp, [r0, #40]
	ldr	lr, [r0, #44]
	push	{r0}
	ror	ip, r1, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	movw	r0, #31000
	movt	r0, #40503
	eors	r2, r0
	ror	ip, r2, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	movw	r0, #30996
	movt	r0, #40503
	eors	r3, r0
	ror	ip, r3, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	movw	r0, #30992
	movt	r0, #40503
	eors	r2, r0
	ror	ip, r2, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	movw	r0, #30988
	movt	r0, #40503
	eors	r3, r0
	ror	ip, r3, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	movw	r0, #30984
	movt	r0, #40503
	eors	r2, r0
	ror	ip, r2, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	movw	r0, #30980
	movt	r0, #40503
	eors	r3, r0
	ror	ip, r3, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	ror	ip, r1, #8
	ror	r0, r5, #23
	orr	r5, ip, r9
	eor	r5, r0, r5, lsl #1
	eor	r5, ip
	and	r1, ip, r0
	eor	r1, r0, r1, lsl #3
	eor	r1, r9
	and	r0, r0, r9
	eor	r9, ip, r9, lsl #1
	eor	r9, r9, r0, lsl #2
	ror	ip, r2, #8
	ror	r0, r6, #23
	orr	r6, ip, r10
	eor	r6, r0, r6, lsl #1
	eor	r6, ip
	and	r2, ip, r0
	eor	r2, r0, r2, lsl #3
	eor	r2, r10
	and	r0, r0, r10
	eor	r10, ip, r10, lsl #1
	eor	r10, r10, r0, lsl #2
	ror	ip, r3, #8
	ror	r0, r7, #23
	orr	r7, ip, fp
	eor	r7, r0, r7, lsl #1
	eor	r7, ip
	and	r3, ip, r0
	eor	r3, r0, r3, lsl #3
	eor	r3, fp
	and	r0, r0, fp
	eor	fp, ip, fp, lsl #1
	eor	fp, fp, r0, lsl #2
	ror	ip, r4, #8
	ror	r0, r8, #23
	orr	r8, ip, lr
	eor	r8, r0, r8, lsl #1
	eor	r8, ip
	and	r4, ip, r0
	eor	r4, r0, r4, lsl #3
	eor	r4, lr
	and	r0, r0, lr
	eor	lr, ip, lr, lsl #1
	eor	lr, lr, r0, lsl #2
	pop	{r0}
	str	r1, [r0, #0]
	str	r2, [r0, #4]
	str	r3, [r0, #8]
	str	r4, [r0, #12]
	str	r5, [r0, #16]
	str	r6, [r0, #20]
	str	r7, [r0, #24]
	str	r8, [r0, #28]
	str	r9, [r0, #32]
	str	r10, [r0, #36]
	str	fp, [r0, #40]
	str	lr, [r0, #44]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	gimli24_permute, .-gimli24_permute

#endif
