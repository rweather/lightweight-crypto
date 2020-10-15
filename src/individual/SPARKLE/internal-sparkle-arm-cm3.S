#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	sparkle_256
	.thumb
	.thumb_func
	.type	sparkle_256, %function
sparkle_256:
	push	{r4, r5, r6, r7, r8, r9, r10}
	ldr	r3, [r0, #0]
	ldr	r7, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r8, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r9, [r0, #20]
	ldr	r6, [r0, #24]
	ldr	r10, [r0, #28]
	movw	r2, #20834
	movt	r2, #47073
	eors	r7, r2
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	eor	r2, r3, r4
	eor	ip, r7, r8
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r9, r2
	eor	r5, ip
	eor	r2, r10
	eor	ip, r6
	eor	r9, r7
	eors	r5, r3
	eor	r10, r8, r2
	eor	r6, r4, ip
	movw	r2, #22656
	movt	r2, #49009
	eor	r10, r2
	eor	r9, r9, #1
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #20834
	movt	r2, #47073
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	eor	r2, r6, r5
	eor	ip, r10, r9
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eors	r7, r2
	eor	r3, ip
	eor	r2, r8
	eor	ip, r4
	eor	r7, r10
	eors	r3, r6
	eor	r8, r9, r2
	eor	r4, r5, ip
	movw	r2, #55894
	movt	r2, #14516
	eor	r8, r2
	eor	r7, r7, #2
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #20834
	movt	r2, #47073
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	eor	r2, r4, r3
	eor	ip, r8, r7
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r10, r2
	eor	r6, ip
	eor	r2, r9
	eor	ip, r5
	eor	r10, r8
	eors	r6, r4
	eor	r9, r7, r2
	eor	r5, r3, ip
	movw	r2, #30520
	movt	r2, #12878
	eor	r9, r2
	eor	r10, r10, #3
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #20834
	movt	r2, #47073
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	eor	r2, r5, r6
	eor	ip, r9, r10
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r8, r2
	eor	r4, ip
	eors	r2, r7
	eor	ip, r3
	eor	r8, r9
	eors	r4, r5
	eor	r7, r10, r2
	eor	r3, r6, ip
	movw	r2, #34283
	movt	r2, #47889
	eors	r7, r2
	eor	r8, r8, #4
	movw	r2, #20834
	movt	r2, #47073
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	eor	r2, r3, r4
	eor	ip, r7, r8
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r9, r2
	eor	r5, ip
	eor	r2, r10
	eor	ip, r6
	eor	r9, r7
	eors	r5, r3
	eor	r10, r8, r2
	eor	r6, r4, ip
	movw	r2, #31575
	movt	r2, #20348
	eor	r10, r2
	eor	r9, r9, #5
	movw	r2, #20834
	movt	r2, #47073
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	eor	r2, r6, r5
	eor	ip, r10, r9
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eors	r7, r2
	eor	r3, ip
	eor	r2, r8
	eor	ip, r4
	eor	r7, r10
	eors	r3, r6
	eor	r8, r9, r2
	eor	r4, r5, ip
	movw	r2, #41416
	movt	r2, #53183
	eor	r8, r2
	eor	r7, r7, #6
	movw	r2, #20834
	movt	r2, #47073
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	eor	r2, r4, r3
	eor	ip, r8, r7
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r10, r2
	eor	r6, ip
	eor	r2, r9
	eor	ip, r5
	eor	r10, r8
	eors	r6, r4
	eor	r9, r7, r2
	eor	r5, r3, ip
	cmp	r1, #7
	bne	.L2561
	str	r5, [r0, #0]
	str	r9, [r0, #4]
	str	r6, [r0, #8]
	str	r10, [r0, #12]
	str	r4, [r0, #16]
	str	r8, [r0, #20]
	str	r3, [r0, #24]
	str	r7, [r0, #28]
	b	.L2563
.L2561:
	movw	r2, #10557
	movt	r2, #49843
	eor	r9, r2
	eor	r10, r10, #7
	movw	r2, #20834
	movt	r2, #47073
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	eor	r2, r5, r6
	eor	ip, r9, r10
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r8, r2
	eor	r4, ip
	eors	r2, r7
	eor	ip, r3
	eor	r8, r9
	eors	r4, r5
	eor	r7, r10, r2
	eor	r3, r6, ip
	movw	r2, #20834
	movt	r2, #47073
	eors	r7, r2
	eor	r8, r8, #8
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #22656
	movt	r2, #49009
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	eor	r2, r3, r4
	eor	ip, r7, r8
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eor	r9, r2
	eor	r5, ip
	eor	r2, r10
	eor	ip, r6
	eor	r9, r7
	eors	r5, r3
	eor	r10, r8, r2
	eor	r6, r4, ip
	movw	r2, #22656
	movt	r2, #49009
	eor	r10, r2
	eor	r9, r9, #9
	add	r5, r5, r9, ror #31
	eor	r9, r9, r5, ror #24
	eors	r5, r2
	add	r5, r5, r9, ror #17
	eor	r9, r9, r5, ror #17
	eors	r5, r2
	add	r5, r9
	eor	r9, r9, r5, ror #31
	eors	r5, r2
	add	r5, r5, r9, ror #24
	eor	r9, r9, r5, ror #16
	eors	r5, r2
	movw	r2, #20834
	movt	r2, #47073
	add	r6, r6, r10, ror #31
	eor	r10, r10, r6, ror #24
	eors	r6, r2
	add	r6, r6, r10, ror #17
	eor	r10, r10, r6, ror #17
	eors	r6, r2
	add	r6, r10
	eor	r10, r10, r6, ror #31
	eors	r6, r2
	add	r6, r6, r10, ror #24
	eor	r10, r10, r6, ror #16
	eors	r6, r2
	movw	r2, #55894
	movt	r2, #14516
	add	r3, r3, r7, ror #31
	eor	r7, r7, r3, ror #24
	eors	r3, r2
	add	r3, r3, r7, ror #17
	eor	r7, r7, r3, ror #17
	eors	r3, r2
	adds	r3, r7
	eor	r7, r7, r3, ror #31
	eors	r3, r2
	add	r3, r3, r7, ror #24
	eor	r7, r7, r3, ror #16
	eors	r3, r2
	movw	r2, #30520
	movt	r2, #12878
	add	r4, r4, r8, ror #31
	eor	r8, r8, r4, ror #24
	eors	r4, r2
	add	r4, r4, r8, ror #17
	eor	r8, r8, r4, ror #17
	eors	r4, r2
	add	r4, r8
	eor	r8, r8, r4, ror #31
	eors	r4, r2
	add	r4, r4, r8, ror #24
	eor	r8, r8, r4, ror #16
	eors	r4, r2
	eor	r2, r6, r5
	eor	ip, r10, r9
	eor	r2, r2, r2, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r2, r2, #16
	ror	ip, ip, #16
	eors	r7, r2
	eor	r3, ip
	eor	r2, r8
	eor	ip, r4
	eor	r7, r10
	eors	r3, r6
	eor	r8, r9, r2
	eor	r4, r5, ip
.L2562:
	str	r4, [r0, #0]
	str	r8, [r0, #4]
	str	r3, [r0, #8]
	str	r7, [r0, #12]
	str	r6, [r0, #16]
	str	r10, [r0, #20]
	str	r5, [r0, #24]
	str	r9, [r0, #28]
.L2563:
	pop	{r4, r5, r6, r7, r8, r9, r10}
	bx	lr
	.size	sparkle_256, .-sparkle_256

	.align	2
	.global	sparkle_384
	.thumb
	.thumb_func
	.type	sparkle_384, %function
sparkle_384:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	push	{r0}
	push	{r1}
	ldr	r3, [r0, #0]
	ldr	r9, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r10, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	fp, [r0, #20]
	ldr	r6, [r0, #24]
	ldr	lr, [r0, #28]
	ldr	r7, [r0, #32]
	ldr	r2, [r0, #36]
	ldr	r8, [r0, #40]
	ldr	r1, [r0, #44]
	movw	r0, #20834
	movt	r0, #47073
	eor	r9, r0
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	eor	r0, r3, r4
	eor	ip, r9, r10
	eors	r0, r5
	eor	ip, fp
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	lr, r0
	eor	r6, ip
	eors	r2, r0
	eor	r7, ip
	eors	r0, r1
	eor	ip, r8
	eor	lr, r9
	eors	r6, r3
	eor	r2, r10
	eors	r7, r4
	eor	r1, fp, r0
	eor	r8, r5, ip
	movw	r0, #22656
	movt	r0, #49009
	eors	r2, r0
	eor	r1, r1, #1
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	eor	r0, r7, r8
	eor	ip, r2, r1
	eors	r0, r6
	eor	ip, lr
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	r9, r0
	eor	r3, ip
	eor	r10, r0
	eor	r4, ip
	eor	r0, fp
	eor	ip, r5
	eor	r9, r2
	eors	r3, r7
	eor	r10, r1
	eor	r4, r8
	eor	fp, lr, r0
	eor	r5, r6, ip
	movw	r0, #55894
	movt	r0, #14516
	eor	r10, r0
	eor	fp, fp, #2
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	eor	r0, r4, r5
	eor	ip, r10, fp
	eors	r0, r3
	eor	ip, r9
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eors	r2, r0
	eor	r7, ip
	eors	r1, r0
	eor	r8, ip
	eor	r0, lr
	eor	ip, r6
	eor	r2, r10
	eors	r7, r4
	eor	r1, fp
	eor	r8, r5
	eor	lr, r9, r0
	eor	r6, r3, ip
	movw	r0, #30520
	movt	r0, #12878
	eors	r1, r0
	eor	lr, lr, #3
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	eor	r0, r8, r6
	eor	ip, r1, lr
	eors	r0, r7
	eor	ip, r2
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	r10, r0
	eor	r4, ip
	eor	fp, r0
	eor	r5, ip
	eor	r0, r9
	eor	ip, r3
	eor	r10, r1
	eor	r4, r8
	eor	fp, lr
	eors	r5, r6
	eor	r9, r2, r0
	eor	r3, r7, ip
	movw	r0, #34283
	movt	r0, #47889
	eor	fp, r0
	eor	r9, r9, #4
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	eor	r0, r5, r3
	eor	ip, fp, r9
	eors	r0, r4
	eor	ip, r10
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eors	r1, r0
	eor	r8, ip
	eor	lr, r0
	eor	r6, ip
	eors	r0, r2
	eor	ip, r7
	eor	r1, fp
	eor	r8, r5
	eor	lr, r9
	eors	r6, r3
	eor	r2, r10, r0
	eor	r7, r4, ip
	movw	r0, #31575
	movt	r0, #20348
	eor	lr, r0
	eor	r2, r2, #5
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	eor	r0, r6, r7
	eor	ip, lr, r2
	eor	r0, r8
	eor	ip, r1
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	fp, r0
	eor	r5, ip
	eor	r9, r0
	eor	r3, ip
	eor	r0, r10
	eor	ip, r4
	eor	fp, lr
	eors	r5, r6
	eor	r9, r2
	eors	r3, r7
	eor	r10, r1, r0
	eor	r4, r8, ip
	movw	r0, #41416
	movt	r0, #53183
	eor	r9, r0
	eor	r10, r10, #6
	movw	r0, #20834
	movt	r0, #47073
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	eor	r0, r3, r4
	eor	ip, r9, r10
	eors	r0, r5
	eor	ip, fp
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	lr, r0
	eor	r6, ip
	eors	r2, r0
	eor	r7, ip
	eors	r0, r1
	eor	ip, r8
	eor	lr, r9
	eors	r6, r3
	eor	r2, r10
	eors	r7, r4
	eor	r1, fp, r0
	eor	r8, r5, ip
	pop	{r0}
	cmp	r0, #7
	bne	.L3841
	pop	{r0}
	str	r7, [r0, #0]
	str	r2, [r0, #4]
	str	r8, [r0, #8]
	str	r1, [r0, #12]
	str	r6, [r0, #16]
	str	lr, [r0, #20]
	str	r3, [r0, #24]
	str	r9, [r0, #28]
	str	r4, [r0, #32]
	str	r10, [r0, #36]
	str	r5, [r0, #40]
	str	fp, [r0, #44]
	b	.L3843
.L3841:
	movw	r0, #10557
	movt	r0, #49843
	eors	r2, r0
	eor	r1, r1, #7
	movw	r0, #20834
	movt	r0, #47073
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	eor	r0, r7, r8
	eor	ip, r2, r1
	eors	r0, r6
	eor	ip, lr
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	r9, r0
	eor	r3, ip
	eor	r10, r0
	eor	r4, ip
	eor	r0, fp
	eor	ip, r5
	eor	r9, r2
	eors	r3, r7
	eor	r10, r1
	eor	r4, r8
	eor	fp, lr, r0
	eor	r5, r6, ip
	movw	r0, #20834
	movt	r0, #47073
	eor	r10, r0
	eor	fp, fp, #8
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	eor	r0, r4, r5
	eor	ip, r10, fp
	eors	r0, r3
	eor	ip, r9
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eors	r2, r0
	eor	r7, ip
	eors	r1, r0
	eor	r8, ip
	eor	r0, lr
	eor	ip, r6
	eor	r2, r10
	eors	r7, r4
	eor	r1, fp
	eor	r8, r5
	eor	lr, r9, r0
	eor	r6, r3, ip
	movw	r0, #22656
	movt	r0, #49009
	eors	r1, r0
	eor	lr, lr, #9
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #55894
	movt	r0, #14516
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	eor	r0, r8, r6
	eor	ip, r1, lr
	eors	r0, r7
	eor	ip, r2
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eor	r10, r0
	eor	r4, ip
	eor	fp, r0
	eor	r5, ip
	eor	r0, r9
	eor	ip, r3
	eor	r10, r1
	eor	r4, r8
	eor	fp, lr
	eors	r5, r6
	eor	r9, r2, r0
	eor	r3, r7, ip
	movw	r0, #55894
	movt	r0, #14516
	eor	fp, r0
	eor	r9, r9, #10
	add	r4, r4, r10, ror #31
	eor	r10, r10, r4, ror #24
	eors	r4, r0
	add	r4, r4, r10, ror #17
	eor	r10, r10, r4, ror #17
	eors	r4, r0
	add	r4, r10
	eor	r10, r10, r4, ror #31
	eors	r4, r0
	add	r4, r4, r10, ror #24
	eor	r10, r10, r4, ror #16
	eors	r4, r0
	movw	r0, #20834
	movt	r0, #47073
	add	r5, r5, fp, ror #31
	eor	fp, fp, r5, ror #24
	eors	r5, r0
	add	r5, r5, fp, ror #17
	eor	fp, fp, r5, ror #17
	eors	r5, r0
	add	r5, fp
	eor	fp, fp, r5, ror #31
	eors	r5, r0
	add	r5, r5, fp, ror #24
	eor	fp, fp, r5, ror #16
	eors	r5, r0
	movw	r0, #22656
	movt	r0, #49009
	add	r3, r3, r9, ror #31
	eor	r9, r9, r3, ror #24
	eors	r3, r0
	add	r3, r3, r9, ror #17
	eor	r9, r9, r3, ror #17
	eors	r3, r0
	add	r3, r9
	eor	r9, r9, r3, ror #31
	eors	r3, r0
	add	r3, r3, r9, ror #24
	eor	r9, r9, r3, ror #16
	eors	r3, r0
	movw	r0, #30520
	movt	r0, #12878
	add	r8, r8, r1, ror #31
	eor	r1, r1, r8, ror #24
	eor	r8, r0
	add	r8, r8, r1, ror #17
	eor	r1, r1, r8, ror #17
	eor	r8, r0
	add	r8, r1
	eor	r1, r1, r8, ror #31
	eor	r8, r0
	add	r8, r8, r1, ror #24
	eor	r1, r1, r8, ror #16
	eor	r8, r0
	movw	r0, #34283
	movt	r0, #47889
	add	r6, r6, lr, ror #31
	eor	lr, lr, r6, ror #24
	eors	r6, r0
	add	r6, r6, lr, ror #17
	eor	lr, lr, r6, ror #17
	eors	r6, r0
	add	r6, lr
	eor	lr, lr, r6, ror #31
	eors	r6, r0
	add	r6, r6, lr, ror #24
	eor	lr, lr, r6, ror #16
	eors	r6, r0
	movw	r0, #31575
	movt	r0, #20348
	add	r7, r7, r2, ror #31
	eor	r2, r2, r7, ror #24
	eors	r7, r0
	add	r7, r7, r2, ror #17
	eor	r2, r2, r7, ror #17
	eors	r7, r0
	adds	r7, r2
	eor	r2, r2, r7, ror #31
	eors	r7, r0
	add	r7, r7, r2, ror #24
	eor	r2, r2, r7, ror #16
	eors	r7, r0
	eor	r0, r5, r3
	eor	ip, fp, r9
	eors	r0, r4
	eor	ip, r10
	eor	r0, r0, r0, lsl #16
	eor	ip, ip, ip, lsl #16
	ror	r0, r0, #16
	ror	ip, ip, #16
	eors	r1, r0
	eor	r8, ip
	eor	lr, r0
	eor	r6, ip
	eors	r0, r2
	eor	ip, r7
	eor	r1, fp
	eor	r8, r5
	eor	lr, r9
	eors	r6, r3
	eor	r2, r10, r0
	eor	r7, r4, ip
.L3842:
	pop	{r0}
	str	r6, [r0, #0]
	str	lr, [r0, #4]
	str	r7, [r0, #8]
	str	r2, [r0, #12]
	str	r8, [r0, #16]
	str	r1, [r0, #20]
	str	r5, [r0, #24]
	str	fp, [r0, #28]
	str	r3, [r0, #32]
	str	r9, [r0, #36]
	str	r4, [r0, #40]
	str	r10, [r0, #44]
.L3843:
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	sparkle_384, .-sparkle_384

	.align	2
	.global	sparkle_512
	.thumb
	.thumb_func
	.type	sparkle_512, %function
sparkle_512:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	push	{r1}
	ldr	r3, [r0, #0]
	ldr	r8, [r0, #4]
	ldr	r4, [r0, #8]
	ldr	r9, [r0, #12]
	ldr	r5, [r0, #16]
	ldr	r10, [r0, #20]
	ldr	r6, [r0, #24]
	ldr	fp, [r0, #28]
	ldr	r7, [r0, #32]
	ldr	lr, [r0, #36]
	movw	ip, #20834
	movt	ip, #47073
	eor	r8, ip
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #22656
	movt	ip, #49009
	eor	r8, ip
	eor	r9, r9, #1
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #55894
	movt	ip, #14516
	eor	r8, ip
	eor	r9, r9, #2
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #30520
	movt	ip, #12878
	eor	r8, ip
	eor	r9, r9, #3
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #34283
	movt	ip, #47889
	eor	r8, ip
	eor	r9, r9, #4
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #31575
	movt	ip, #20348
	eor	r8, ip
	eor	r9, r9, #5
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #41416
	movt	ip, #53183
	eor	r8, ip
	eor	r9, r9, #6
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #10557
	movt	ip, #49843
	eor	r8, ip
	eor	r9, r9, #7
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	pop	{r1}
	cmp	r1, #8
	beq	.L512
	movw	ip, #20834
	movt	ip, #47073
	eor	r8, ip
	eor	r9, r9, #8
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #22656
	movt	ip, #49009
	eor	r8, ip
	eor	r9, r9, #9
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #55894
	movt	ip, #14516
	eor	r8, ip
	eor	r9, r9, #10
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
	movw	ip, #30520
	movt	ip, #12878
	eor	r8, ip
	eor	r9, r9, #11
	movw	ip, #20834
	movt	ip, #47073
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	movw	ip, #22656
	movt	ip, #49009
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #55894
	movt	ip, #14516
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #30520
	movt	ip, #12878
	add	r6, r6, fp, ror #31
	eor	fp, fp, r6, ror #24
	eor	r6, ip
	add	r6, r6, fp, ror #17
	eor	fp, fp, r6, ror #17
	eor	r6, ip
	add	r6, fp
	eor	fp, fp, r6, ror #31
	eor	r6, ip
	add	r6, r6, fp, ror #24
	eor	fp, fp, r6, ror #16
	eor	r6, ip
	movw	ip, #34283
	movt	ip, #47889
	add	r7, r7, lr, ror #31
	eor	lr, lr, r7, ror #24
	eor	r7, ip
	add	r7, r7, lr, ror #17
	eor	lr, lr, r7, ror #17
	eor	r7, ip
	add	r7, lr
	eor	lr, lr, r7, ror #31
	eor	r7, ip
	add	r7, r7, lr, ror #24
	eor	lr, lr, r7, ror #16
	eor	r7, ip
	eor	r1, r3, r4
	eor	r2, r8, r9
	eors	r1, r5
	eor	r2, r10
	eors	r1, r6
	eor	r2, fp
	eor	r1, r1, r1, lsl #16
	eor	r2, r2, r2, lsl #16
	ror	r1, r1, #16
	ror	r2, r2, #16
	eor	lr, r1
	eors	r7, r2
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	ldr	r4, [r0, #40]
	ldr	r9, [r0, #44]
	ldr	r5, [r0, #48]
	ldr	r10, [r0, #52]
	ldr	r3, [r0, #56]
	ldr	r8, [r0, #60]
	movw	ip, #31575
	movt	ip, #20348
	add	r4, r4, r9, ror #31
	eor	r9, r9, r4, ror #24
	eor	r4, ip
	add	r4, r4, r9, ror #17
	eor	r9, r9, r4, ror #17
	eor	r4, ip
	add	r4, r9
	eor	r9, r9, r4, ror #31
	eor	r4, ip
	add	r4, r4, r9, ror #24
	eor	r9, r9, r4, ror #16
	eor	r4, ip
	movw	ip, #41416
	movt	ip, #53183
	add	r5, r5, r10, ror #31
	eor	r10, r10, r5, ror #24
	eor	r5, ip
	add	r5, r5, r10, ror #17
	eor	r10, r10, r5, ror #17
	eor	r5, ip
	add	r5, r10
	eor	r10, r10, r5, ror #31
	eor	r5, ip
	add	r5, r5, r10, ror #24
	eor	r10, r10, r5, ror #16
	eor	r5, ip
	movw	ip, #10557
	movt	ip, #49843
	add	r3, r3, r8, ror #31
	eor	r8, r8, r3, ror #24
	eor	r3, ip
	add	r3, r3, r8, ror #17
	eor	r8, r8, r3, ror #17
	eor	r3, ip
	add	r3, r8
	eor	r8, r8, r3, ror #31
	eor	r3, ip
	add	r3, r3, r8, ror #24
	eor	r8, r8, r3, ror #16
	eor	r3, ip
	eor	r9, r1
	eors	r4, r2
	eor	r10, r1
	eors	r5, r2
	eor	r1, r8
	eors	r2, r3
	str	fp, [r0, #60]
	str	r6, [r0, #56]
	ldr	r8, [r0, #4]
	ldr	r3, [r0, #0]
	eor	fp, lr, r8
	eor	r6, r7, r3
	mov	lr, r8
	mov	r7, r3
	ldr	ip, [r0, #12]
	eor	r8, r9, ip
	str	ip, [r0, #44]
	ldr	ip, [r0, #8]
	eor	r3, r4, ip
	str	ip, [r0, #40]
	ldr	ip, [r0, #20]
	eor	r9, r10, ip
	str	ip, [r0, #52]
	ldr	ip, [r0, #16]
	eor	r4, r5, ip
	str	ip, [r0, #48]
	ldr	r10, [r0, #60]
	ldr	r5, [r0, #56]
	eor	r10, r1
	eors	r5, r2
.L512:
	str	r3, [r0, #0]
	str	r8, [r0, #4]
	str	r4, [r0, #8]
	str	r9, [r0, #12]
	str	r5, [r0, #16]
	str	r10, [r0, #20]
	str	r6, [r0, #24]
	str	fp, [r0, #28]
	str	r7, [r0, #32]
	str	lr, [r0, #36]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	sparkle_512, .-sparkle_512

#endif
