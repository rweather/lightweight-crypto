#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	tiny_jambu_permutation_128
	.thumb
	.thumb_func
	.type	tiny_jambu_permutation_128, %function
tiny_jambu_permutation_128:
	push	{r4, r5, r6, r7, r8, r9, r10}
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ldr	r7, [r1, #0]
	ldr	r8, [r1, #4]
	ldr	r9, [r1, #8]
	ldr	r10, [r1, #12]
.L128:
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r1, r5, #6
	lsr	ip, r5, #21
	eor	r1, r1, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r3, r1
	eors	r3, r7
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r1, r6, #6
	lsr	ip, r6, #21
	eor	r1, r1, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r4, r1
	eor	r4, r8
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r1, r3, #6
	lsr	ip, r3, #21
	eor	r1, r1, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r5, r1
	eor	r5, r9
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r1, r4, #6
	lsr	ip, r4, #21
	eor	r1, r1, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r6, r1
	eor	r6, r10
	subs	r2, r2, #1
	bne	.L128
	str	r3, [r0, #0]
	str	r4, [r0, #4]
	str	r5, [r0, #8]
	str	r6, [r0, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10}
	bx	lr
	.size	tiny_jambu_permutation_128, .-tiny_jambu_permutation_128

	.align	2
	.global	tiny_jambu_permutation_192
	.thumb
	.thumb_func
	.type	tiny_jambu_permutation_192, %function
tiny_jambu_permutation_192:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ldr	r7, [r1, #0]
	ldr	r8, [r1, #4]
	ldr	r9, [r1, #8]
	ldr	r10, [r1, #12]
	ldr	fp, [r1, #16]
	ldr	lr, [r1, #20]
.L1921:
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r1, r5, #6
	lsr	ip, r5, #21
	eor	r1, r1, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r3, r1
	eors	r3, r7
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r1, r6, #6
	lsr	ip, r6, #21
	eor	r1, r1, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r4, r1
	eor	r4, r8
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r1, r3, #6
	lsr	ip, r3, #21
	eor	r1, r1, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r5, r1
	eor	r5, r9
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r1, r4, #6
	lsr	ip, r4, #21
	eor	r1, r1, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r6, r1
	eor	r6, r10
	subs	r2, r2, #1
	beq	.L1922
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r1, r5, #6
	lsr	ip, r5, #21
	eor	r1, r1, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r3, r1
	eor	r3, fp
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r1, r6, #6
	lsr	ip, r6, #21
	eor	r1, r1, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r4, r1
	eor	r4, lr
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r1, r3, #6
	lsr	ip, r3, #21
	eor	r1, r1, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r5, r1
	eors	r5, r7
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r1, r4, #6
	lsr	ip, r4, #21
	eor	r1, r1, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r6, r1
	eor	r6, r8
	subs	r2, r2, #1
	beq	.L1922
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r1, r5, #6
	lsr	ip, r5, #21
	eor	r1, r1, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r3, r1
	eor	r3, r9
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r1, r6, #6
	lsr	ip, r6, #21
	eor	r1, r1, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r4, r1
	eor	r4, r10
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r1, r3, #6
	lsr	ip, r3, #21
	eor	r1, r1, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r5, r1
	eor	r5, fp
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r1, r4, #6
	lsr	ip, r4, #21
	eor	r1, r1, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r1, ip
	mvns	r1, r1
	eors	r6, r1
	eor	r6, lr
	subs	r2, r2, #1
	bne	.L1921
.L1922:
	str	r3, [r0, #0]
	str	r4, [r0, #4]
	str	r5, [r0, #8]
	str	r6, [r0, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	tiny_jambu_permutation_192, .-tiny_jambu_permutation_192

	.align	2
	.global	tiny_jambu_permutation_256
	.thumb
	.thumb_func
	.type	tiny_jambu_permutation_256, %function
tiny_jambu_permutation_256:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r3, [r0, #0]
	ldr	r4, [r0, #4]
	ldr	r5, [r0, #8]
	ldr	r6, [r0, #12]
	ldr	r8, [r1, #0]
	ldr	r9, [r1, #4]
	ldr	r10, [r1, #8]
	ldr	fp, [r1, #12]
	ldr	lr, [r1, #16]
.L2561:
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r7, r5, #6
	lsr	ip, r5, #21
	eor	r7, r7, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r3, r7
	eor	r3, r8
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r7, r6, #6
	lsr	ip, r6, #21
	eor	r7, r7, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r4, r7
	eor	r4, r9
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r7, r3, #6
	lsr	ip, r3, #21
	eor	r7, r7, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r5, r7
	eor	r5, r10
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r7, r4, #6
	lsr	ip, r4, #21
	eor	r7, r7, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r6, r7
	eor	r6, fp
	subs	r2, r2, #1
	beq	.L2562
	eor	r3, r3, r4, lsr #15
	eor	r3, r3, r5, lsl #17
	eor	r3, r3, r5, lsr #27
	eor	r3, r3, r6, lsl #5
	lsr	r7, r5, #6
	lsr	ip, r5, #21
	eor	r7, r7, r6, lsl #26
	eor	ip, ip, r6, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r3, r7
	eor	r3, lr
	eor	r4, r4, r5, lsr #15
	eor	r4, r4, r6, lsl #17
	eor	r4, r4, r6, lsr #27
	eor	r4, r4, r3, lsl #5
	lsr	r7, r6, #6
	lsr	ip, r6, #21
	eor	r7, r7, r3, lsl #26
	eor	ip, ip, r3, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r4, r7
	ldr	r7, [r1, #20]
	eors	r4, r7
	eor	r5, r5, r6, lsr #15
	eor	r5, r5, r3, lsl #17
	eor	r5, r5, r3, lsr #27
	eor	r5, r5, r4, lsl #5
	lsr	r7, r3, #6
	lsr	ip, r3, #21
	eor	r7, r7, r4, lsl #26
	eor	ip, ip, r4, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r5, r7
	ldr	r7, [r1, #24]
	eors	r5, r7
	eor	r6, r6, r3, lsr #15
	eor	r6, r6, r4, lsl #17
	eor	r6, r6, r4, lsr #27
	eor	r6, r6, r5, lsl #5
	lsr	r7, r4, #6
	lsr	ip, r4, #21
	eor	r7, r7, r5, lsl #26
	eor	ip, ip, r5, lsl #11
	and	r7, ip
	mvns	r7, r7
	eors	r6, r7
	ldr	r7, [r1, #28]
	eors	r6, r7
	subs	r2, r2, #1
	bne	.L2561
.L2562:
	str	r3, [r0, #0]
	str	r4, [r0, #4]
	str	r5, [r0, #8]
	str	r6, [r0, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	tiny_jambu_permutation_256, .-tiny_jambu_permutation_256

#endif
