#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	ascon_permute
	.thumb
	.thumb_func
	.type	ascon_permute, %function
ascon_permute:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	ldr	r7, [r0, #0]
	ldr	r2, [r0, #4]
	ldr	r8, [r0, #8]
	ldr	r3, [r0, #12]
	ldr	r9, [r0, #16]
	ldr	r4, [r0, #20]
	ldr	r10, [r0, #24]
	ldr	r5, [r0, #28]
	ldr	fp, [r0, #32]
	ldr	r6, [r0, #36]
	rev	r7, r7
	rev	r2, r2
	rev	r8, r8
	rev	r3, r3
	rev	r9, r9
	rev	r4, r4
	rev	r10, r10
	rev	r5, r5
	rev	fp, fp
	rev	r6, r6
	push	{r0}
	cmp	r1, #6
	beq	.LP6
	cmp	r1, #0
	beq	.LP0
	cmp	r1, #4
	beq	.LP4
	cmp	r1, #11
	beq	.LP11
	cmp	r1, #10
	beq	.LP10
	cmp	r1, #9
	beq	.LP9
	cmp	r1, #8
	beq	.LP8
	cmp	r1, #7
	beq	.LP7
	cmp	r1, #5
	beq	.LP5
	cmp	r1, #3
	beq	.LP3
	cmp	r1, #2
	beq	.LP2
	cmp	r1, #1
	beq	.LP1
	b	.LP12
.LP0:
	eor	r4, r4, #240
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP1:
	eor	r4, r4, #225
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP2:
	eor	r4, r4, #210
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP3:
	eor	r4, r4, #195
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP4:
	eor	r4, r4, #180
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP5:
	eor	r4, r4, #165
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP6:
	eor	r4, r4, #150
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP7:
	eor	r4, r4, #135
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP8:
	eor	r4, r4, #120
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP9:
	eor	r4, r4, #105
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP10:
	eor	r4, r4, #90
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP11:
	eor	r4, r4, #75
	eors	r2, r6
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
	mvn	r9, r9
	movs	r0, r2
	movs	r1, r7
	eor	r2, r2, r0, lsr #19
	eor	r7, r7, r1, lsr #19
	eor	r2, r2, r1, lsl #13
	eor	r7, r7, r0, lsl #13
	eor	r2, r2, r0, lsr #28
	eor	r7, r7, r1, lsr #28
	eor	r2, r2, r1, lsl #4
	eor	r7, r7, r0, lsl #4
	movs	r0, r3
	mov	r1, r8
	eor	r3, r3, r1, lsr #29
	eor	r8, r8, r0, lsr #29
	eor	r3, r3, r0, lsl #3
	eor	r8, r8, r1, lsl #3
	eor	r3, r3, r1, lsr #7
	eor	r8, r8, r0, lsr #7
	eor	r3, r3, r0, lsl #25
	eor	r8, r8, r1, lsl #25
	movs	r0, r4
	mov	r1, r9
	eor	r4, r4, r0, lsr #1
	eor	r9, r9, r1, lsr #1
	eor	r4, r4, r1, lsl #31
	eor	r9, r9, r0, lsl #31
	eor	r4, r4, r0, lsr #6
	eor	r9, r9, r1, lsr #6
	eor	r4, r4, r1, lsl #26
	eor	r9, r9, r0, lsl #26
	movs	r0, r5
	mov	r1, r10
	eor	r5, r5, r0, lsr #10
	eor	r10, r10, r1, lsr #10
	eor	r5, r5, r1, lsl #22
	eor	r10, r10, r0, lsl #22
	eor	r5, r5, r0, lsr #17
	eor	r10, r10, r1, lsr #17
	eor	r5, r5, r1, lsl #15
	eor	r10, r10, r0, lsl #15
	movs	r0, r6
	mov	r1, fp
	eor	r6, r6, r0, lsr #7
	eor	fp, fp, r1, lsr #7
	eor	r6, r6, r1, lsl #25
	eor	fp, fp, r0, lsl #25
	eor	r6, r6, r1, lsr #9
	eor	fp, fp, r0, lsr #9
	eor	r6, r6, r0, lsl #23
	eor	fp, fp, r1, lsl #23
.LP12:
	pop	{r0}
	rev	r7, r7
	rev	r2, r2
	rev	r8, r8
	rev	r3, r3
	rev	r9, r9
	rev	r4, r4
	rev	r10, r10
	rev	r5, r5
	rev	fp, fp
	rev	r6, r6
	str	r7, [r0, #0]
	str	r2, [r0, #4]
	str	r8, [r0, #8]
	str	r3, [r0, #12]
	str	r9, [r0, #16]
	str	r4, [r0, #20]
	str	r10, [r0, #24]
	str	r5, [r0, #28]
	str	fp, [r0, #32]
	str	r6, [r0, #36]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	ascon_permute, .-ascon_permute

	.align	2
	.global	ascon_permute_sliced
	.thumb
	.thumb_func
	.type	ascon_permute_sliced, %function
ascon_permute_sliced:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	eor	r7, fp
	eors	r6, r5
	eor	fp, r10
	eors	r4, r3
	eor	r9, r8
	bic	r0, r3, r2
	bic	ip, r4, r3
	bic	lr, r5, r4
	eor	r3, lr
	bic	lr, r2, r6
	eor	r2, ip
	bic	ip, r6, r5
	eor	r4, ip
	eor	r5, lr
	eors	r6, r0
	bic	r0, r8, r7
	bic	ip, r9, r8
	bic	lr, r10, r9
	eor	r8, lr
	bic	lr, r7, fp
	eor	r7, ip
	bic	ip, fp, r10
	eor	r9, ip
	eor	r10, lr
	eor	fp, r0
	eors	r3, r2
	eor	r8, r7
	eors	r2, r6
	eor	r7, fp
	eors	r5, r4
	eor	r10, r9
	mvns	r4, r4
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
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
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
