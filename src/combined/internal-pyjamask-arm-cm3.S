#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	pyjamask_128_setup_key
	.thumb
	.thumb_func
	.type	pyjamask_128_setup_key, %function
pyjamask_128_setup_key:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	rev	r2, r2
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	str	r2, [r0], #4
	str	r3, [r0], #4
	str	r4, [r0], #4
	str	r5, [r0], #4
	movw	r9, #27136
	movw	r10, #0
	movt	r10, #63
	movw	lr, #0
	movt	lr, #9216
	mov	r8, #128
.L1:
	eor	r1, r2, r3
	eor	r6, r4, r5
	eors	r1, r6
	eors	r2, r1
	eors	r3, r1
	eors	r4, r1
	eors	r5, r1
	movw	r7, #47562
	movt	r7, #47233
	sbfx	r1, r2, #31, #1
	sbfx	r6, r2, #30, #1
	and	ip, r1, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r1, r2, #29, #1
	sbfx	r6, r2, #28, #1
	and	r1, r1, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #27, #1
	sbfx	r6, r2, #26, #1
	and	r1, r1, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #25, #1
	sbfx	r6, r2, #24, #1
	and	r1, r1, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #23, #1
	sbfx	r6, r2, #22, #1
	and	r1, r1, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #21, #1
	sbfx	r6, r2, #20, #1
	and	r1, r1, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #19, #1
	sbfx	r6, r2, #18, #1
	and	r1, r1, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #17, #1
	sbfx	r6, r2, #16, #1
	and	r1, r1, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #15, #1
	sbfx	r6, r2, #14, #1
	and	r1, r1, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #13, #1
	sbfx	r6, r2, #12, #1
	and	r1, r1, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #11, #1
	sbfx	r6, r2, #10, #1
	and	r1, r1, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #9, #1
	sbfx	r6, r2, #8, #1
	and	r1, r1, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #7, #1
	sbfx	r6, r2, #6, #1
	and	r1, r1, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #5, #1
	sbfx	r6, r2, #4, #1
	and	r1, r1, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #3, #1
	sbfx	r6, r2, #2, #1
	and	r1, r1, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #1, #1
	sbfx	r6, r2, #0, #1
	and	r1, r1, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r1
	eor	ip, r6
	eor	r3, r9, r3, ror #8
	eor	r2, ip, r8
	eor	r4, r10, r4, ror #15
	eor	r5, lr, r5, ror #18
	str	r2, [r0], #4
	str	r3, [r0], #4
	str	r4, [r0], #4
	str	r5, [r0], #4
	add	r8, r8, #1
	cmp	r8, #142
	bne	.L1
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	pyjamask_128_setup_key, .-pyjamask_128_setup_key

	.align	2
	.global	pyjamask_96_setup_key
	.thumb
	.thumb_func
	.type	pyjamask_96_setup_key, %function
pyjamask_96_setup_key:
	push	{r4, r5, r6, r7, r8, r9, r10, lr}
	ldr	r2, [r1]
	ldr	r3, [r1, #4]
	ldr	r4, [r1, #8]
	ldr	r5, [r1, #12]
	rev	r2, r2
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	str	r2, [r0], #4
	str	r3, [r0], #4
	str	r4, [r0], #4
	movw	r9, #27136
	movw	r10, #0
	movt	r10, #63
	movw	lr, #0
	movt	lr, #9216
	mov	r8, #128
.L2:
	eor	r1, r2, r3
	eor	r6, r4, r5
	eors	r1, r6
	eors	r2, r1
	eors	r3, r1
	eors	r4, r1
	eors	r5, r1
	movw	r7, #47562
	movt	r7, #47233
	sbfx	r1, r2, #31, #1
	sbfx	r6, r2, #30, #1
	and	ip, r1, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r1, r2, #29, #1
	sbfx	r6, r2, #28, #1
	and	r1, r1, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #27, #1
	sbfx	r6, r2, #26, #1
	and	r1, r1, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #25, #1
	sbfx	r6, r2, #24, #1
	and	r1, r1, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #23, #1
	sbfx	r6, r2, #22, #1
	and	r1, r1, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #21, #1
	sbfx	r6, r2, #20, #1
	and	r1, r1, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #19, #1
	sbfx	r6, r2, #18, #1
	and	r1, r1, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #17, #1
	sbfx	r6, r2, #16, #1
	and	r1, r1, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #15, #1
	sbfx	r6, r2, #14, #1
	and	r1, r1, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #13, #1
	sbfx	r6, r2, #12, #1
	and	r1, r1, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #11, #1
	sbfx	r6, r2, #10, #1
	and	r1, r1, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #9, #1
	sbfx	r6, r2, #8, #1
	and	r1, r1, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #7, #1
	sbfx	r6, r2, #6, #1
	and	r1, r1, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #5, #1
	sbfx	r6, r2, #4, #1
	and	r1, r1, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #3, #1
	sbfx	r6, r2, #2, #1
	and	r1, r1, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r1
	eor	ip, r6
	sbfx	r1, r2, #1, #1
	sbfx	r6, r2, #0, #1
	and	r1, r1, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r1
	eor	ip, r6
	eor	r3, r9, r3, ror #8
	eor	r2, ip, r8
	eor	r4, r10, r4, ror #15
	eor	r5, lr, r5, ror #18
	str	r2, [r0], #4
	str	r3, [r0], #4
	str	r4, [r0], #4
	add	r8, r8, #1
	cmp	r8, #142
	bne	.L2
	pop	{r4, r5, r6, r7, r8, r9, r10, pc}
	.size	pyjamask_96_setup_key, .-pyjamask_96_setup_key

	.align	2
	.global	pyjamask_128_encrypt
	.thumb
	.thumb_func
	.type	pyjamask_128_encrypt, %function
pyjamask_128_encrypt:
	push	{r4, r5, r6, r7, r8, r9}
	ldr	r3, [r2]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	mov	r9, #14
.L3:
	ldr	r2, [r0], #4
	ldr	r7, [r0], #4
	ldr	r8, [r0], #4
	ldr	ip, [r0], #4
	eors	r3, r2
	eors	r4, r7
	eor	r5, r8
	eor	r6, ip
	eors	r3, r6
	and	r2, r3, r4
	and	r7, r4, r5
	eors	r6, r2
	eors	r3, r7
	and	r2, r5, r6
	and	r7, r3, r6
	eors	r4, r2
	eors	r5, r7
	eor	r2, r5, r4
	eors	r4, r3
	mvns	r5, r6
	movs	r6, r2
	movw	r8, #4229
	movt	r8, #41862
	sbfx	r2, r3, #31, #1
	sbfx	r7, r3, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r3, #29, #1
	sbfx	r7, r3, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #27, #1
	sbfx	r7, r3, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #25, #1
	sbfx	r7, r3, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #23, #1
	sbfx	r7, r3, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #21, #1
	sbfx	r7, r3, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #19, #1
	sbfx	r7, r3, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #17, #1
	sbfx	r7, r3, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #15, #1
	sbfx	r7, r3, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #13, #1
	sbfx	r7, r3, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #11, #1
	sbfx	r7, r3, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #9, #1
	sbfx	r7, r3, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #7, #1
	sbfx	r7, r3, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #5, #1
	sbfx	r7, r3, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #3, #1
	sbfx	r7, r3, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #1, #1
	sbfx	r7, r3, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r3, ip
	movw	r8, #28705
	movt	r8, #25409
	sbfx	r2, r4, #31, #1
	sbfx	r7, r4, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r4, #29, #1
	sbfx	r7, r4, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #27, #1
	sbfx	r7, r4, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #25, #1
	sbfx	r7, r4, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #23, #1
	sbfx	r7, r4, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #21, #1
	sbfx	r7, r4, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #19, #1
	sbfx	r7, r4, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #17, #1
	sbfx	r7, r4, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #15, #1
	sbfx	r7, r4, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #13, #1
	sbfx	r7, r4, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #11, #1
	sbfx	r7, r4, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #9, #1
	sbfx	r7, r4, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #7, #1
	sbfx	r7, r4, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #5, #1
	sbfx	r7, r4, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #3, #1
	sbfx	r7, r4, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #1, #1
	sbfx	r7, r4, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r4, ip
	movw	r8, #62080
	movt	r8, #26924
	sbfx	r2, r5, #31, #1
	sbfx	r7, r5, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r5, #29, #1
	sbfx	r7, r5, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #27, #1
	sbfx	r7, r5, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #25, #1
	sbfx	r7, r5, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #23, #1
	sbfx	r7, r5, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #21, #1
	sbfx	r7, r5, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #19, #1
	sbfx	r7, r5, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #17, #1
	sbfx	r7, r5, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #15, #1
	sbfx	r7, r5, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #13, #1
	sbfx	r7, r5, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #11, #1
	sbfx	r7, r5, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #9, #1
	sbfx	r7, r5, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #7, #1
	sbfx	r7, r5, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #5, #1
	sbfx	r7, r5, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #3, #1
	sbfx	r7, r5, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #1, #1
	sbfx	r7, r5, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r5, ip
	movw	r8, #18451
	movt	r8, #18597
	sbfx	r2, r6, #31, #1
	sbfx	r7, r6, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r6, #29, #1
	sbfx	r7, r6, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #27, #1
	sbfx	r7, r6, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #25, #1
	sbfx	r7, r6, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #23, #1
	sbfx	r7, r6, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #21, #1
	sbfx	r7, r6, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #19, #1
	sbfx	r7, r6, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #17, #1
	sbfx	r7, r6, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #15, #1
	sbfx	r7, r6, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #13, #1
	sbfx	r7, r6, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #11, #1
	sbfx	r7, r6, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #9, #1
	sbfx	r7, r6, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #7, #1
	sbfx	r7, r6, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #5, #1
	sbfx	r7, r6, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #3, #1
	sbfx	r7, r6, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #1, #1
	sbfx	r7, r6, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r6, ip
	subs	r9, r9, #1
	bne	.L3
	ldr	r2, [r0]
	ldr	r7, [r0, #4]
	ldr	r8, [r0, #8]
	ldr	ip, [r0, #12]
	eors	r3, r2
	eors	r4, r7
	eor	r5, r8
	eor	r6, ip
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9}
	bx	lr
	.size	pyjamask_128_encrypt, .-pyjamask_128_encrypt

	.align	2
	.global	pyjamask_128_decrypt
	.thumb
	.thumb_func
	.type	pyjamask_128_decrypt, %function
pyjamask_128_decrypt:
	push	{r4, r5, r6, r7, r8, r9}
	add	r0, r0, #224
	ldr	r3, [r2]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	ldr	r2, [r0]
	ldr	r7, [r0, #4]
	ldr	r8, [r0, #8]
	ldr	ip, [r0, #12]
	eors	r3, r2
	eors	r4, r7
	eor	r5, r8
	eor	r6, ip
	mov	r9, #14
.L4:
	movw	r8, #41249
	movt	r8, #8247
	sbfx	r2, r3, #31, #1
	sbfx	r7, r3, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r3, #29, #1
	sbfx	r7, r3, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #27, #1
	sbfx	r7, r3, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #25, #1
	sbfx	r7, r3, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #23, #1
	sbfx	r7, r3, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #21, #1
	sbfx	r7, r3, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #19, #1
	sbfx	r7, r3, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #17, #1
	sbfx	r7, r3, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #15, #1
	sbfx	r7, r3, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #13, #1
	sbfx	r7, r3, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #11, #1
	sbfx	r7, r3, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #9, #1
	sbfx	r7, r3, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #7, #1
	sbfx	r7, r3, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #5, #1
	sbfx	r7, r3, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #3, #1
	sbfx	r7, r3, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r3, #1, #1
	sbfx	r7, r3, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r3, ip
	movw	r8, #62112
	movt	r8, #4239
	sbfx	r2, r4, #31, #1
	sbfx	r7, r4, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r4, #29, #1
	sbfx	r7, r4, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #27, #1
	sbfx	r7, r4, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #25, #1
	sbfx	r7, r4, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #23, #1
	sbfx	r7, r4, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #21, #1
	sbfx	r7, r4, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #19, #1
	sbfx	r7, r4, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #17, #1
	sbfx	r7, r4, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #15, #1
	sbfx	r7, r4, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #13, #1
	sbfx	r7, r4, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #11, #1
	sbfx	r7, r4, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #9, #1
	sbfx	r7, r4, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #7, #1
	sbfx	r7, r4, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #5, #1
	sbfx	r7, r4, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #3, #1
	sbfx	r7, r4, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r4, #1, #1
	sbfx	r7, r4, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r4, ip
	movw	r8, #55488
	movt	r8, #36948
	sbfx	r2, r5, #31, #1
	sbfx	r7, r5, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r5, #29, #1
	sbfx	r7, r5, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #27, #1
	sbfx	r7, r5, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #25, #1
	sbfx	r7, r5, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #23, #1
	sbfx	r7, r5, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #21, #1
	sbfx	r7, r5, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #19, #1
	sbfx	r7, r5, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #17, #1
	sbfx	r7, r5, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #15, #1
	sbfx	r7, r5, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #13, #1
	sbfx	r7, r5, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #11, #1
	sbfx	r7, r5, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #9, #1
	sbfx	r7, r5, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #7, #1
	sbfx	r7, r5, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #5, #1
	sbfx	r7, r5, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #3, #1
	sbfx	r7, r5, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r5, #1, #1
	sbfx	r7, r5, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mov	r5, ip
	movw	r8, #45335
	movt	r8, #13140
	sbfx	r2, r6, #31, #1
	sbfx	r7, r6, #30, #1
	and	ip, r2, r8
	and	r7, r7, r8, ror #1
	eor	ip, r7
	sbfx	r2, r6, #29, #1
	sbfx	r7, r6, #28, #1
	and	r2, r2, r8, ror #2
	and	r7, r7, r8, ror #3
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #27, #1
	sbfx	r7, r6, #26, #1
	and	r2, r2, r8, ror #4
	and	r7, r7, r8, ror #5
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #25, #1
	sbfx	r7, r6, #24, #1
	and	r2, r2, r8, ror #6
	and	r7, r7, r8, ror #7
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #23, #1
	sbfx	r7, r6, #22, #1
	and	r2, r2, r8, ror #8
	and	r7, r7, r8, ror #9
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #21, #1
	sbfx	r7, r6, #20, #1
	and	r2, r2, r8, ror #10
	and	r7, r7, r8, ror #11
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #19, #1
	sbfx	r7, r6, #18, #1
	and	r2, r2, r8, ror #12
	and	r7, r7, r8, ror #13
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #17, #1
	sbfx	r7, r6, #16, #1
	and	r2, r2, r8, ror #14
	and	r7, r7, r8, ror #15
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #15, #1
	sbfx	r7, r6, #14, #1
	and	r2, r2, r8, ror #16
	and	r7, r7, r8, ror #17
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #13, #1
	sbfx	r7, r6, #12, #1
	and	r2, r2, r8, ror #18
	and	r7, r7, r8, ror #19
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #11, #1
	sbfx	r7, r6, #10, #1
	and	r2, r2, r8, ror #20
	and	r7, r7, r8, ror #21
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #9, #1
	sbfx	r7, r6, #8, #1
	and	r2, r2, r8, ror #22
	and	r7, r7, r8, ror #23
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #7, #1
	sbfx	r7, r6, #6, #1
	and	r2, r2, r8, ror #24
	and	r7, r7, r8, ror #25
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #5, #1
	sbfx	r7, r6, #4, #1
	and	r2, r2, r8, ror #26
	and	r7, r7, r8, ror #27
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #3, #1
	sbfx	r7, r6, #2, #1
	and	r2, r2, r8, ror #28
	and	r7, r7, r8, ror #29
	eor	ip, r2
	eor	ip, r7
	sbfx	r2, r6, #1, #1
	sbfx	r7, r6, #0, #1
	and	r2, r2, r8, ror #30
	and	r7, r7, r8, ror #31
	eor	ip, r2
	eor	ip, r7
	mvns	r6, r5
	mov	r5, ip
	eors	r4, r3
	eors	r5, r4
	and	r2, r3, r6
	eors	r5, r2
	and	r7, r5, r6
	eors	r4, r7
	and	r2, r4, r5
	eors	r3, r2
	and	r7, r3, r4
	eors	r6, r7
	eors	r3, r6
	ldr	ip, [r0, #-4]!
	ldr	r8, [r0, #-4]!
	ldr	r7, [r0, #-4]!
	ldr	r2, [r0, #-4]!
	eor	r6, ip
	eor	r5, r8
	eors	r4, r7
	eors	r3, r2
	subs	r9, r9, #1
	bne	.L4
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	rev	r6, r6
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9}
	bx	lr
	.size	pyjamask_128_decrypt, .-pyjamask_128_decrypt

	.align	2
	.global	pyjamask_96_encrypt
	.thumb
	.thumb_func
	.type	pyjamask_96_encrypt, %function
pyjamask_96_encrypt:
	push	{r4, r5, r6, r7, r8}
	ldr	r3, [r2]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	mov	r8, #14
.L5:
	ldr	r2, [r0], #4
	ldr	r6, [r0], #4
	ldr	r7, [r0], #4
	eors	r3, r2
	eors	r4, r6
	eors	r5, r7
	eors	r3, r4
	eors	r4, r5
	and	r2, r3, r4
	eors	r5, r2
	and	r6, r4, r5
	eors	r3, r6
	and	r2, r3, r5
	eors	r4, r2
	eors	r5, r3
	eors	r4, r3
	eors	r3, r4
	mvns	r5, r5
	movw	r7, #4229
	movt	r7, #41862
	sbfx	r2, r3, #31, #1
	sbfx	r6, r3, #30, #1
	and	ip, r2, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r2, r3, #29, #1
	sbfx	r6, r3, #28, #1
	and	r2, r2, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #27, #1
	sbfx	r6, r3, #26, #1
	and	r2, r2, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #25, #1
	sbfx	r6, r3, #24, #1
	and	r2, r2, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #23, #1
	sbfx	r6, r3, #22, #1
	and	r2, r2, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #21, #1
	sbfx	r6, r3, #20, #1
	and	r2, r2, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #19, #1
	sbfx	r6, r3, #18, #1
	and	r2, r2, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #17, #1
	sbfx	r6, r3, #16, #1
	and	r2, r2, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #15, #1
	sbfx	r6, r3, #14, #1
	and	r2, r2, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #13, #1
	sbfx	r6, r3, #12, #1
	and	r2, r2, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #11, #1
	sbfx	r6, r3, #10, #1
	and	r2, r2, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #9, #1
	sbfx	r6, r3, #8, #1
	and	r2, r2, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #7, #1
	sbfx	r6, r3, #6, #1
	and	r2, r2, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #5, #1
	sbfx	r6, r3, #4, #1
	and	r2, r2, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #3, #1
	sbfx	r6, r3, #2, #1
	and	r2, r2, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #1, #1
	sbfx	r6, r3, #0, #1
	and	r2, r2, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r2
	eor	ip, r6
	mov	r3, ip
	movw	r7, #28705
	movt	r7, #25409
	sbfx	r2, r4, #31, #1
	sbfx	r6, r4, #30, #1
	and	ip, r2, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r2, r4, #29, #1
	sbfx	r6, r4, #28, #1
	and	r2, r2, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #27, #1
	sbfx	r6, r4, #26, #1
	and	r2, r2, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #25, #1
	sbfx	r6, r4, #24, #1
	and	r2, r2, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #23, #1
	sbfx	r6, r4, #22, #1
	and	r2, r2, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #21, #1
	sbfx	r6, r4, #20, #1
	and	r2, r2, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #19, #1
	sbfx	r6, r4, #18, #1
	and	r2, r2, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #17, #1
	sbfx	r6, r4, #16, #1
	and	r2, r2, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #15, #1
	sbfx	r6, r4, #14, #1
	and	r2, r2, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #13, #1
	sbfx	r6, r4, #12, #1
	and	r2, r2, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #11, #1
	sbfx	r6, r4, #10, #1
	and	r2, r2, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #9, #1
	sbfx	r6, r4, #8, #1
	and	r2, r2, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #7, #1
	sbfx	r6, r4, #6, #1
	and	r2, r2, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #5, #1
	sbfx	r6, r4, #4, #1
	and	r2, r2, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #3, #1
	sbfx	r6, r4, #2, #1
	and	r2, r2, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #1, #1
	sbfx	r6, r4, #0, #1
	and	r2, r2, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r2
	eor	ip, r6
	mov	r4, ip
	movw	r7, #62080
	movt	r7, #26924
	sbfx	r2, r5, #31, #1
	sbfx	r6, r5, #30, #1
	and	ip, r2, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r2, r5, #29, #1
	sbfx	r6, r5, #28, #1
	and	r2, r2, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #27, #1
	sbfx	r6, r5, #26, #1
	and	r2, r2, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #25, #1
	sbfx	r6, r5, #24, #1
	and	r2, r2, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #23, #1
	sbfx	r6, r5, #22, #1
	and	r2, r2, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #21, #1
	sbfx	r6, r5, #20, #1
	and	r2, r2, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #19, #1
	sbfx	r6, r5, #18, #1
	and	r2, r2, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #17, #1
	sbfx	r6, r5, #16, #1
	and	r2, r2, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #15, #1
	sbfx	r6, r5, #14, #1
	and	r2, r2, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #13, #1
	sbfx	r6, r5, #12, #1
	and	r2, r2, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #11, #1
	sbfx	r6, r5, #10, #1
	and	r2, r2, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #9, #1
	sbfx	r6, r5, #8, #1
	and	r2, r2, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #7, #1
	sbfx	r6, r5, #6, #1
	and	r2, r2, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #5, #1
	sbfx	r6, r5, #4, #1
	and	r2, r2, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #3, #1
	sbfx	r6, r5, #2, #1
	and	r2, r2, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #1, #1
	sbfx	r6, r5, #0, #1
	and	r2, r2, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r2
	eor	ip, r6
	mov	r5, ip
	subs	r8, r8, #1
	bne	.L5
	ldr	r2, [r0]
	ldr	r6, [r0, #4]
	ldr	r7, [r0, #8]
	eors	r3, r2
	eors	r4, r6
	eors	r5, r7
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	pop	{r4, r5, r6, r7, r8}
	bx	lr
	.size	pyjamask_96_encrypt, .-pyjamask_96_encrypt

	.align	2
	.global	pyjamask_96_decrypt
	.thumb
	.thumb_func
	.type	pyjamask_96_decrypt, %function
pyjamask_96_decrypt:
	push	{r4, r5, r6, r7, r8}
	add	r0, r0, #168
	ldr	r3, [r2]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	ldr	r2, [r0]
	ldr	r6, [r0, #4]
	ldr	r7, [r0, #8]
	eors	r3, r2
	eors	r4, r6
	eors	r5, r7
	mov	r8, #14
.L6:
	movw	r7, #41249
	movt	r7, #8247
	sbfx	r2, r3, #31, #1
	sbfx	r6, r3, #30, #1
	and	ip, r2, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r2, r3, #29, #1
	sbfx	r6, r3, #28, #1
	and	r2, r2, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #27, #1
	sbfx	r6, r3, #26, #1
	and	r2, r2, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #25, #1
	sbfx	r6, r3, #24, #1
	and	r2, r2, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #23, #1
	sbfx	r6, r3, #22, #1
	and	r2, r2, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #21, #1
	sbfx	r6, r3, #20, #1
	and	r2, r2, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #19, #1
	sbfx	r6, r3, #18, #1
	and	r2, r2, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #17, #1
	sbfx	r6, r3, #16, #1
	and	r2, r2, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #15, #1
	sbfx	r6, r3, #14, #1
	and	r2, r2, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #13, #1
	sbfx	r6, r3, #12, #1
	and	r2, r2, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #11, #1
	sbfx	r6, r3, #10, #1
	and	r2, r2, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #9, #1
	sbfx	r6, r3, #8, #1
	and	r2, r2, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #7, #1
	sbfx	r6, r3, #6, #1
	and	r2, r2, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #5, #1
	sbfx	r6, r3, #4, #1
	and	r2, r2, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #3, #1
	sbfx	r6, r3, #2, #1
	and	r2, r2, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r3, #1, #1
	sbfx	r6, r3, #0, #1
	and	r2, r2, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r2
	eor	ip, r6
	mov	r3, ip
	movw	r7, #62112
	movt	r7, #4239
	sbfx	r2, r4, #31, #1
	sbfx	r6, r4, #30, #1
	and	ip, r2, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r2, r4, #29, #1
	sbfx	r6, r4, #28, #1
	and	r2, r2, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #27, #1
	sbfx	r6, r4, #26, #1
	and	r2, r2, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #25, #1
	sbfx	r6, r4, #24, #1
	and	r2, r2, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #23, #1
	sbfx	r6, r4, #22, #1
	and	r2, r2, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #21, #1
	sbfx	r6, r4, #20, #1
	and	r2, r2, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #19, #1
	sbfx	r6, r4, #18, #1
	and	r2, r2, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #17, #1
	sbfx	r6, r4, #16, #1
	and	r2, r2, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #15, #1
	sbfx	r6, r4, #14, #1
	and	r2, r2, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #13, #1
	sbfx	r6, r4, #12, #1
	and	r2, r2, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #11, #1
	sbfx	r6, r4, #10, #1
	and	r2, r2, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #9, #1
	sbfx	r6, r4, #8, #1
	and	r2, r2, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #7, #1
	sbfx	r6, r4, #6, #1
	and	r2, r2, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #5, #1
	sbfx	r6, r4, #4, #1
	and	r2, r2, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #3, #1
	sbfx	r6, r4, #2, #1
	and	r2, r2, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r4, #1, #1
	sbfx	r6, r4, #0, #1
	and	r2, r2, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r2
	eor	ip, r6
	mov	r4, ip
	movw	r7, #55488
	movt	r7, #36948
	sbfx	r2, r5, #31, #1
	sbfx	r6, r5, #30, #1
	and	ip, r2, r7
	and	r6, r6, r7, ror #1
	eor	ip, r6
	sbfx	r2, r5, #29, #1
	sbfx	r6, r5, #28, #1
	and	r2, r2, r7, ror #2
	and	r6, r6, r7, ror #3
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #27, #1
	sbfx	r6, r5, #26, #1
	and	r2, r2, r7, ror #4
	and	r6, r6, r7, ror #5
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #25, #1
	sbfx	r6, r5, #24, #1
	and	r2, r2, r7, ror #6
	and	r6, r6, r7, ror #7
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #23, #1
	sbfx	r6, r5, #22, #1
	and	r2, r2, r7, ror #8
	and	r6, r6, r7, ror #9
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #21, #1
	sbfx	r6, r5, #20, #1
	and	r2, r2, r7, ror #10
	and	r6, r6, r7, ror #11
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #19, #1
	sbfx	r6, r5, #18, #1
	and	r2, r2, r7, ror #12
	and	r6, r6, r7, ror #13
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #17, #1
	sbfx	r6, r5, #16, #1
	and	r2, r2, r7, ror #14
	and	r6, r6, r7, ror #15
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #15, #1
	sbfx	r6, r5, #14, #1
	and	r2, r2, r7, ror #16
	and	r6, r6, r7, ror #17
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #13, #1
	sbfx	r6, r5, #12, #1
	and	r2, r2, r7, ror #18
	and	r6, r6, r7, ror #19
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #11, #1
	sbfx	r6, r5, #10, #1
	and	r2, r2, r7, ror #20
	and	r6, r6, r7, ror #21
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #9, #1
	sbfx	r6, r5, #8, #1
	and	r2, r2, r7, ror #22
	and	r6, r6, r7, ror #23
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #7, #1
	sbfx	r6, r5, #6, #1
	and	r2, r2, r7, ror #24
	and	r6, r6, r7, ror #25
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #5, #1
	sbfx	r6, r5, #4, #1
	and	r2, r2, r7, ror #26
	and	r6, r6, r7, ror #27
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #3, #1
	sbfx	r6, r5, #2, #1
	and	r2, r2, r7, ror #28
	and	r6, r6, r7, ror #29
	eor	ip, r2
	eor	ip, r6
	sbfx	r2, r5, #1, #1
	sbfx	r6, r5, #0, #1
	and	r2, r2, r7, ror #30
	and	r6, r6, r7, ror #31
	eor	ip, r2
	eor	ip, r6
	mvn	r5, ip
	eors	r3, r4
	eors	r4, r3
	eors	r5, r3
	and	r2, r3, r5
	eors	r4, r2
	and	r6, r4, r5
	eors	r3, r6
	and	r2, r3, r4
	eors	r5, r2
	eors	r4, r5
	eors	r3, r4
	ldr	r7, [r0, #-4]!
	ldr	r6, [r0, #-4]!
	ldr	r2, [r0, #-4]!
	eors	r5, r7
	eors	r4, r6
	eors	r3, r2
	subs	r8, r8, #1
	bne	.L6
	rev	r3, r3
	rev	r4, r4
	rev	r5, r5
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	pop	{r4, r5, r6, r7, r8}
	bx	lr
	.size	pyjamask_96_decrypt, .-pyjamask_96_decrypt

#endif
