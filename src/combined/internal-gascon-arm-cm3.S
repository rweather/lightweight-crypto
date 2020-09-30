#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	gascon_permute
	.thumb
	.thumb_func
	.type	gascon_permute, %function
gascon_permute:
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
	eor	r4, r4, #240
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L1:
	eor	r4, r4, #225
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L2:
	eor	r4, r4, #210
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L3:
	eor	r4, r4, #195
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L4:
	eor	r4, r4, #180
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L5:
	eor	r4, r4, #165
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L6:
	eor	r4, r4, #150
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L7:
	eor	r4, r4, #135
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L8:
	eor	r4, r4, #120
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L9:
	eor	r4, r4, #105
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L10:
	eor	r4, r4, #90
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
.L11:
	eor	r4, r4, #75
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
	mov	r0, r7, ror #9
	mov	r1, r2, ror #10
	eor	r2, r2, r2, ror #14
	eor	r7, r7, r7, ror #14
	eors	r2, r0
	eors	r7, r1
	mov	r0, r8, ror #30
	mov	r1, r3, ror #31
	eor	r3, r3, r3, ror #19
	eor	r8, r8, r8, ror #19
	eors	r3, r0
	eor	r8, r1
	mov	r0, r9
	mov	r1, r4, ror #1
	eor	r4, r4, r4, ror #3
	eor	r9, r9, r9, ror #3
	eors	r4, r0
	eor	r9, r1
	mov	r0, r10, ror #8
	mov	r1, r5, ror #9
	eor	r5, r5, r5, ror #5
	eor	r10, r10, r10, ror #5
	eors	r5, r0
	eor	r10, r1
	mov	r0, fp, ror #3
	mov	r1, r6, ror #4
	eor	r6, r6, r6, ror #20
	eor	fp, fp, fp, ror #20
	eors	r6, r0
	eor	fp, r1
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
	.size	gascon_permute, .-gascon_permute

#endif
