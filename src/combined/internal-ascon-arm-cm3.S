#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	ascon_permute_sliced
	.thumb
	.thumb_func
	.type	ascon_permute_sliced, %function
ascon_permute_sliced:
	push	{r4, r5, r6, r7, r8, r9, r10, fp}
	ldr	r2, [r0, #0]
	ldr	r7, [r0, #4]
	ldr	r3, [r0, #8]
	ldr	r8, [r0, #12]
	ldr	r4, [r0, #16]
	ldr	r9, [r0, #20]
	ldr	r5, [r0, #24]
	ldr	r10, [r0, #28]
	ldr	r6, [r0, #32]
	ldr	fp, [r0, #36]
	push	{r0}
	cmp	r1, #6
	beq	.L6
	cmp	r1, #0
	beq	.L0
	cmp	r1, #4
	beq	.L4
	cmp	r1, #11
	beq	.L11
	cmp	r1, #10
	beq	.L10
	cmp	r1, #9
	beq	.L9
	cmp	r1, #8
	beq	.L8
	cmp	r1, #7
	beq	.L7
	cmp	r1, #5
	beq	.L5
	cmp	r1, #3
	beq	.L3
	cmp	r1, #2
	beq	.L2
	cmp	r1, #1
	beq	.L1
	b	.L12
.L0:
	eor	r4, r4, #12
	eor	r9, r9, #12
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L1:
	eor	r4, r4, #9
	eor	r9, r9, #12
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L2:
	eor	r4, r4, #12
	eor	r9, r9, #9
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L3:
	eor	r4, r4, #9
	eor	r9, r9, #9
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L4:
	eor	r4, r4, #6
	eor	r9, r9, #12
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L5:
	eor	r4, r4, #3
	eor	r9, r9, #12
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L6:
	eor	r4, r4, #6
	eor	r9, r9, #9
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L7:
	eor	r4, r4, #3
	eor	r9, r9, #9
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L8:
	eor	r4, r4, #12
	eor	r9, r9, #6
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L9:
	eor	r4, r4, #9
	eor	r9, r9, #6
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L10:
	eor	r4, r4, #12
	eor	r9, r9, #3
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L11:
	eor	r4, r4, #9
	eor	r9, r9, #3
	eors	r2, r6
	eors	r6, r5
	eors	r4, r3
	movs	r1, r2
	mvns	r0, r2
	ands	r0, r3
	mvn	ip, r3
	and	ip, r4
	eor	r2, ip
	mvn	ip, r4
	and	ip, r5
	eor	r3, ip
	mvn	ip, r5
	and	ip, r6
	eor	r4, ip
	mvn	ip, r6
	and	ip, r1
	eor	r5, ip
	eors	r6, r0
	eors	r3, r2
	eors	r2, r6
	eors	r5, r4
	mvns	r4, r4
	eor	r7, fp
	eor	fp, r10
	eor	r9, r8
	movs	r1, r7
	mvns	r0, r7
	and	r0, r8
	mvn	ip, r8
	and	ip, r9
	eor	r7, ip
	mvn	ip, r9
	and	ip, r10
	eor	r8, ip
	mvn	ip, r10
	and	ip, fp
	eor	r9, ip
	mvn	ip, fp
	and	ip, r1
	eor	r10, ip
	eor	fp, r0
	eor	r8, r7
	eor	r7, fp
	eor	r10, r9
	mvn	r9, r9
	eor	r0, r2, r7, ror #4
	eor	r1, r7, r2, ror #5
	eor	r7, r7, r0, ror #10
	eor	r2, r2, r1, ror #9
	eor	r0, r3, r3, ror #11
	eor	r1, r8, r8, ror #11
	eor	r8, r8, r0, ror #20
	eor	r3, r3, r1, ror #19
	eor	r0, r4, r9, ror #2
	eor	r1, r9, r4, ror #3
	eor	r9, r9, r0, ror #1
	eors	r4, r1
	eor	r0, r5, r10, ror #3
	eor	r1, r10, r5, ror #4
	eor	r5, r5, r0, ror #5
	eor	r10, r10, r1, ror #5
	eor	r0, r6, r6, ror #17
	eor	r1, fp, fp, ror #17
	eor	fp, fp, r0, ror #4
	eor	r6, r6, r1, ror #3
.L12:
	pop	{r0}
	str	r2, [r0, #0]
	str	r7, [r0, #4]
	str	r3, [r0, #8]
	str	r8, [r0, #12]
	str	r4, [r0, #16]
	str	r9, [r0, #20]
	str	r5, [r0, #24]
	str	r10, [r0, #28]
	str	r6, [r0, #32]
	str	fp, [r0, #36]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp}
	bx	lr
	.size	ascon_permute_sliced, .-ascon_permute_sliced

	.align	2
	.global	ascon_to_sliced
	.thumb
	.thumb_func
	.type	ascon_to_sliced, %function
ascon_to_sliced:
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #4]
	eor	r3, r1, r1, lsr #1
	eor	ip, r2, r2, lsr #1
	and	r3, r3, #572662306
	and	ip, ip, #572662306
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #1
	eor	r2, r2, ip, lsl #1
	eor	r3, r1, r1, lsr #2
	eor	ip, r2, r2, lsr #2
	and	r3, r3, #202116108
	and	ip, ip, #202116108
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #2
	eor	r2, r2, ip, lsl #2
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	and	r3, r3, #983055
	and	ip, ip, #983055
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	uxth	r3, r2
	orr	r3, r3, r1, lsl #16
	lsrs	r1, r1, #16
	str	r3, [r0, #0]
	lsls	ip, r1, #16
	orr	ip, ip, r2, lsr #16
	str	ip, [r0, #4]
	ldr	r1, [r0, #8]
	ldr	r2, [r0, #12]
	eor	r3, r1, r1, lsr #1
	eor	ip, r2, r2, lsr #1
	and	r3, r3, #572662306
	and	ip, ip, #572662306
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #1
	eor	r2, r2, ip, lsl #1
	eor	r3, r1, r1, lsr #2
	eor	ip, r2, r2, lsr #2
	and	r3, r3, #202116108
	and	ip, ip, #202116108
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #2
	eor	r2, r2, ip, lsl #2
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	and	r3, r3, #983055
	and	ip, ip, #983055
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	uxth	r3, r2
	orr	r3, r3, r1, lsl #16
	lsrs	r1, r1, #16
	str	r3, [r0, #8]
	lsls	ip, r1, #16
	orr	ip, ip, r2, lsr #16
	str	ip, [r0, #12]
	ldr	r1, [r0, #16]
	ldr	r2, [r0, #20]
	eor	r3, r1, r1, lsr #1
	eor	ip, r2, r2, lsr #1
	and	r3, r3, #572662306
	and	ip, ip, #572662306
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #1
	eor	r2, r2, ip, lsl #1
	eor	r3, r1, r1, lsr #2
	eor	ip, r2, r2, lsr #2
	and	r3, r3, #202116108
	and	ip, ip, #202116108
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #2
	eor	r2, r2, ip, lsl #2
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	and	r3, r3, #983055
	and	ip, ip, #983055
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	uxth	r3, r2
	orr	r3, r3, r1, lsl #16
	lsrs	r1, r1, #16
	str	r3, [r0, #16]
	lsls	ip, r1, #16
	orr	ip, ip, r2, lsr #16
	str	ip, [r0, #20]
	ldr	r1, [r0, #24]
	ldr	r2, [r0, #28]
	eor	r3, r1, r1, lsr #1
	eor	ip, r2, r2, lsr #1
	and	r3, r3, #572662306
	and	ip, ip, #572662306
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #1
	eor	r2, r2, ip, lsl #1
	eor	r3, r1, r1, lsr #2
	eor	ip, r2, r2, lsr #2
	and	r3, r3, #202116108
	and	ip, ip, #202116108
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #2
	eor	r2, r2, ip, lsl #2
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	and	r3, r3, #983055
	and	ip, ip, #983055
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	uxth	r3, r2
	orr	r3, r3, r1, lsl #16
	lsrs	r1, r1, #16
	str	r3, [r0, #24]
	lsls	ip, r1, #16
	orr	ip, ip, r2, lsr #16
	str	ip, [r0, #28]
	ldr	r1, [r0, #32]
	ldr	r2, [r0, #36]
	eor	r3, r1, r1, lsr #1
	eor	ip, r2, r2, lsr #1
	and	r3, r3, #572662306
	and	ip, ip, #572662306
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #1
	eor	r2, r2, ip, lsl #1
	eor	r3, r1, r1, lsr #2
	eor	ip, r2, r2, lsr #2
	and	r3, r3, #202116108
	and	ip, ip, #202116108
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #2
	eor	r2, r2, ip, lsl #2
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	and	r3, r3, #983055
	and	ip, ip, #983055
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	uxth	r3, r2
	orr	r3, r3, r1, lsl #16
	lsrs	r1, r1, #16
	str	r3, [r0, #32]
	lsls	ip, r1, #16
	orr	ip, ip, r2, lsr #16
	str	ip, [r0, #36]
	bx	lr
	.size	ascon_to_sliced, .-ascon_to_sliced

	.align	2
	.global	ascon_from_sliced
	.thumb
	.thumb_func
	.type	ascon_from_sliced, %function
ascon_from_sliced:
	push	{r4}
	ldr	r1, [r0, #0]
	ldr	r2, [r0, #4]
	lsrs	r3, r2, #16
	lsls	r3, r3, #16
	uxth	ip, r1
	orr	r1, r3, r1, lsr #16
	orr	r2, ip, r2, lsl #16
	movw	r4, #43690
	eor	r3, r1, r1, lsr #15
	eor	ip, r2, r2, lsr #15
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #15
	eor	r2, r2, ip, lsl #15
	movw	r4, #52428
	eor	r3, r1, r1, lsr #14
	eor	ip, r2, r2, lsr #14
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #14
	eor	r2, r2, ip, lsl #14
	movw	r4, #61680
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	str	r1, [r0, #0]
	str	r2, [r0, #4]
	ldr	r1, [r0, #8]
	ldr	r2, [r0, #12]
	lsrs	r3, r2, #16
	lsls	r3, r3, #16
	uxth	ip, r1
	orr	r1, r3, r1, lsr #16
	orr	r2, ip, r2, lsl #16
	movw	r4, #43690
	eor	r3, r1, r1, lsr #15
	eor	ip, r2, r2, lsr #15
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #15
	eor	r2, r2, ip, lsl #15
	movw	r4, #52428
	eor	r3, r1, r1, lsr #14
	eor	ip, r2, r2, lsr #14
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #14
	eor	r2, r2, ip, lsl #14
	movw	r4, #61680
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	str	r1, [r0, #8]
	str	r2, [r0, #12]
	ldr	r1, [r0, #16]
	ldr	r2, [r0, #20]
	lsrs	r3, r2, #16
	lsls	r3, r3, #16
	uxth	ip, r1
	orr	r1, r3, r1, lsr #16
	orr	r2, ip, r2, lsl #16
	movw	r4, #43690
	eor	r3, r1, r1, lsr #15
	eor	ip, r2, r2, lsr #15
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #15
	eor	r2, r2, ip, lsl #15
	movw	r4, #52428
	eor	r3, r1, r1, lsr #14
	eor	ip, r2, r2, lsr #14
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #14
	eor	r2, r2, ip, lsl #14
	movw	r4, #61680
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	str	r1, [r0, #16]
	str	r2, [r0, #20]
	ldr	r1, [r0, #24]
	ldr	r2, [r0, #28]
	lsrs	r3, r2, #16
	lsls	r3, r3, #16
	uxth	ip, r1
	orr	r1, r3, r1, lsr #16
	orr	r2, ip, r2, lsl #16
	movw	r4, #43690
	eor	r3, r1, r1, lsr #15
	eor	ip, r2, r2, lsr #15
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #15
	eor	r2, r2, ip, lsl #15
	movw	r4, #52428
	eor	r3, r1, r1, lsr #14
	eor	ip, r2, r2, lsr #14
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #14
	eor	r2, r2, ip, lsl #14
	movw	r4, #61680
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	str	r1, [r0, #24]
	str	r2, [r0, #28]
	ldr	r1, [r0, #32]
	ldr	r2, [r0, #36]
	lsrs	r3, r2, #16
	lsls	r3, r3, #16
	uxth	ip, r1
	orr	r1, r3, r1, lsr #16
	orr	r2, ip, r2, lsl #16
	movw	r4, #43690
	eor	r3, r1, r1, lsr #15
	eor	ip, r2, r2, lsr #15
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #15
	eor	r2, r2, ip, lsl #15
	movw	r4, #52428
	eor	r3, r1, r1, lsr #14
	eor	ip, r2, r2, lsr #14
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #14
	eor	r2, r2, ip, lsl #14
	movw	r4, #61680
	eor	r3, r1, r1, lsr #12
	eor	ip, r2, r2, lsr #12
	ands	r3, r4
	and	ip, r4
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #12
	eor	r2, r2, ip, lsl #12
	eor	r3, r1, r1, lsr #24
	eor	ip, r2, r2, lsr #24
	and	r3, r3, #255
	and	ip, ip, #255
	eors	r1, r3
	eor	r2, ip
	eor	r1, r1, r3, lsl #24
	eor	r2, r2, ip, lsl #24
	str	r1, [r0, #32]
	str	r2, [r0, #36]
	pop	{r4}
	bx	lr
	.size	ascon_from_sliced, .-ascon_from_sliced

#endif
