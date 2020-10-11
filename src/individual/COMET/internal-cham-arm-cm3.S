#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	cham128_128_encrypt
	.thumb
	.thumb_func
	.type	cham128_128_encrypt, %function
cham128_128_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	push	{r1}
	ldr	r3, [r2, #0]
	ldr	r4, [r2, #4]
	ldr	r5, [r2, #8]
	ldr	r6, [r2, #12]
	ldr	r2, [r0, #0]
	ldr	r7, [r0, #4]
	ldr	r8, [r0, #8]
	ldr	r9, [r0, #12]
	eor	r10, r7, r7, ror #31
	eor	r0, r2, r2, ror #31
	eor	fp, r9, r9, ror #31
	eor	lr, r8, r8, ror #31
	eor	r10, r10, r7, ror #21
	eor	r0, r0, r2, ror #21
	eor	fp, fp, r9, ror #21
	eor	lr, lr, r8, ror #21
	eor	r1, r2, r2, ror #31
	eor	ip, r7, r7, ror #31
	eor	r2, r1, r2, ror #24
	eor	r7, ip, r7, ror #24
	eor	r1, r8, r8, ror #31
	eor	ip, r9, r9, ror #31
	eor	r8, r1, r8, ror #24
	eor	r9, ip, r9, ror #24
	eor	r1, r3, #0
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #1
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #2
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #3
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #4
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #5
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #6
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #7
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #8
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #9
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #10
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #11
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #12
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #13
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #14
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #15
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #16
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #17
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #18
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #19
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #20
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #21
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #22
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #23
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #24
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #25
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #26
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #27
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #28
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #29
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #30
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #31
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #32
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #33
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #34
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #35
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #36
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #37
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #38
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #39
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #40
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #41
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #42
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #43
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #44
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #45
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #46
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #47
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #48
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #49
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #50
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #51
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #52
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #53
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #54
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #55
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #56
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #57
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #58
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #59
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #60
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #61
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #62
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #63
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #64
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #65
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #66
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #67
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #68
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #69
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #70
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #71
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #72
	eor	ip, r2, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #73
	eor	ip, r7, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #74
	eor	ip, r8, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #75
	eor	ip, r9, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	eor	r1, r3, #76
	eor	ip, r10, r4, ror #31
	add	r3, ip, r1
	ror	r3, r3, #24
	eor	r1, r4, #77
	eor	ip, r0, r5, ror #24
	add	r4, ip, r1
	ror	r4, r4, #31
	eor	r1, r5, #78
	eor	ip, fp, r6, ror #31
	add	r5, ip, r1
	ror	r5, r5, #24
	eor	r1, r6, #79
	eor	ip, lr, r3, ror #24
	add	r6, ip, r1
	ror	r6, r6, #31
	pop	{r1}
	str	r3, [r1, #0]
	str	r4, [r1, #4]
	str	r5, [r1, #8]
	str	r6, [r1, #12]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	cham128_128_encrypt, .-cham128_128_encrypt

	.align	2
	.global	cham64_128_encrypt
	.thumb
	.thumb_func
	.type	cham64_128_encrypt, %function
cham64_128_encrypt:
	push	{r4, r5, r6, r7, r8, r9, r10, fp, lr}
	mov	fp, sp
	sub	sp, sp, #24
	str	r1, [fp, #-24]
	ldrh	r3, [r2, #0]
	ldrh	r4, [r2, #2]
	ldrh	r5, [r2, #4]
	ldrh	r6, [r2, #6]
	ldrh	r2, [r0, #0]
	ldrh	r7, [r0, #2]
	ldrh	r8, [r0, #4]
	ldrh	r9, [r0, #6]
	ldrh	r10, [r0, #8]
	ldrh	r1, [r0, #10]
	ldrh	lr, [r0, #12]
	ldrh	r0, [r0, #14]
	eor	ip, r0, r0, lsl #1
	eor	ip, ip, r0, lsr #15
	eor	ip, ip, r0, lsl #11
	eor	ip, ip, r0, lsr #5
	strh	ip, [fp, #-6]
	eor	ip, r0, r0, lsl #1
	eor	ip, ip, r0, lsr #15
	eor	ip, ip, r0, lsl #8
	eor	ip, ip, r0, lsr #8
	strh	ip, [fp, #-20]
	eor	ip, r7, r7, lsl #1
	eor	ip, ip, r7, lsr #15
	eor	r0, ip, r7, lsl #8
	eor	ip, ip, r7, lsl #11
	eor	r0, r0, r7, lsr #8
	eor	ip, ip, r7, lsr #5
	uxth	r7, r0
	strh	ip, [fp, #-18]
	eor	ip, r2, r2, lsl #1
	eor	ip, ip, r2, lsr #15
	eor	r0, ip, r2, lsl #8
	eor	ip, ip, r2, lsl #11
	eor	r0, r0, r2, lsr #8
	eor	ip, ip, r2, lsr #5
	uxth	r2, r0
	strh	ip, [fp, #-16]
	eor	ip, r9, r9, lsl #1
	eor	ip, ip, r9, lsr #15
	eor	r0, ip, r9, lsl #8
	eor	ip, ip, r9, lsl #11
	eor	r0, r0, r9, lsr #8
	eor	ip, ip, r9, lsr #5
	uxth	r9, r0
	strh	ip, [fp, #-14]
	eor	ip, r8, r8, lsl #1
	eor	ip, ip, r8, lsr #15
	eor	r0, ip, r8, lsl #8
	eor	ip, ip, r8, lsl #11
	eor	r0, r0, r8, lsr #8
	eor	ip, ip, r8, lsr #5
	uxth	r8, r0
	strh	ip, [fp, #-12]
	eor	ip, r1, r1, lsl #1
	eor	ip, ip, r1, lsr #15
	eor	r0, ip, r1, lsl #8
	eor	ip, ip, r1, lsl #11
	eor	r0, r0, r1, lsr #8
	eor	ip, ip, r1, lsr #5
	uxth	r1, r0
	strh	ip, [fp, #-10]
	eor	ip, r10, r10, lsl #1
	eor	ip, ip, r10, lsr #15
	eor	r0, ip, r10, lsl #8
	eor	ip, ip, r10, lsl #11
	eor	r0, r0, r10, lsr #8
	eor	ip, ip, r10, lsr #5
	uxth	r10, r0
	strh	ip, [fp, #-8]
	eor	ip, lr, lr, lsl #1
	eor	ip, ip, lr, lsr #15
	eor	r0, ip, lr, lsl #8
	eor	ip, ip, lr, lsl #11
	eor	r0, r0, lr, lsr #8
	eor	ip, ip, lr, lsr #5
	uxth	lr, r0
	strh	ip, [fp, #-4]
	eor	r3, r3, #0
	eor	r0, r2, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #1
	eor	r0, r7, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #2
	eor	r0, r8, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #3
	eor	r0, r9, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #4
	eor	r0, r10, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #5
	eor	r0, r1, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #6
	eor	r0, lr, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #7
	ldrh	ip, [fp, #-20]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #8
	ldrh	ip, [fp, #-18]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #9
	ldrh	ip, [fp, #-16]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #10
	ldrh	ip, [fp, #-14]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #11
	ldrh	ip, [fp, #-12]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #12
	ldrh	ip, [fp, #-10]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #13
	ldrh	ip, [fp, #-8]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #14
	ldrh	ip, [fp, #-6]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #15
	ldrh	ip, [fp, #-4]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #16
	eor	r0, r2, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #17
	eor	r0, r7, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #18
	eor	r0, r8, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #19
	eor	r0, r9, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #20
	eor	r0, r10, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #21
	eor	r0, r1, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #22
	eor	r0, lr, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #23
	ldrh	ip, [fp, #-20]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #24
	ldrh	ip, [fp, #-18]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #25
	ldrh	ip, [fp, #-16]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #26
	ldrh	ip, [fp, #-14]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #27
	ldrh	ip, [fp, #-12]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #28
	ldrh	ip, [fp, #-10]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #29
	ldrh	ip, [fp, #-8]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #30
	ldrh	ip, [fp, #-6]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #31
	ldrh	ip, [fp, #-4]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #32
	eor	r0, r2, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #33
	eor	r0, r7, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #34
	eor	r0, r8, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #35
	eor	r0, r9, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #36
	eor	r0, r10, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #37
	eor	r0, r1, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #38
	eor	r0, lr, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #39
	ldrh	ip, [fp, #-20]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #40
	ldrh	ip, [fp, #-18]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #41
	ldrh	ip, [fp, #-16]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #42
	ldrh	ip, [fp, #-14]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #43
	ldrh	ip, [fp, #-12]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #44
	ldrh	ip, [fp, #-10]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #45
	ldrh	ip, [fp, #-8]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #46
	ldrh	ip, [fp, #-6]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #47
	ldrh	ip, [fp, #-4]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #48
	eor	r0, r2, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #49
	eor	r0, r7, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #50
	eor	r0, r8, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #51
	eor	r0, r9, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #52
	eor	r0, r10, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #53
	eor	r0, r1, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #54
	eor	r0, lr, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #55
	ldrh	ip, [fp, #-20]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #56
	ldrh	ip, [fp, #-18]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #57
	ldrh	ip, [fp, #-16]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #58
	ldrh	ip, [fp, #-14]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #59
	ldrh	ip, [fp, #-12]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #60
	ldrh	ip, [fp, #-10]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #61
	ldrh	ip, [fp, #-8]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #62
	ldrh	ip, [fp, #-6]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #63
	ldrh	ip, [fp, #-4]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #64
	eor	r0, r2, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #65
	eor	r0, r7, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #66
	eor	r0, r8, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #67
	eor	r0, r9, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #68
	eor	r0, r10, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #69
	eor	r0, r1, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #70
	eor	r0, lr, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #71
	ldrh	ip, [fp, #-20]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #72
	ldrh	ip, [fp, #-18]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #73
	ldrh	ip, [fp, #-16]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #74
	ldrh	ip, [fp, #-14]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #75
	ldrh	ip, [fp, #-12]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	eor	r3, r3, #76
	ldrh	ip, [fp, #-10]
	eor	r0, ip, r4, lsl #1
	eor	r0, r0, r4, lsr #15
	add	ip, r3, r0
	uxth	ip, ip
	rev16	r3, ip
	eor	r4, r4, #77
	ldrh	ip, [fp, #-8]
	eor	r0, ip, r5, lsl #8
	eor	r0, r0, r5, lsr #8
	add	ip, r4, r0
	uxth	ip, ip
	lsl	r4, ip, #1
	eor	r4, r4, ip, lsr #15
	uxth	r4, r4
	eor	r5, r5, #78
	ldrh	ip, [fp, #-6]
	eor	r0, ip, r6, lsl #1
	eor	r0, r0, r6, lsr #15
	add	ip, r5, r0
	uxth	ip, ip
	rev16	r5, ip
	eor	r6, r6, #79
	ldrh	ip, [fp, #-4]
	eor	r0, ip, r3, lsl #8
	eor	r0, r0, r3, lsr #8
	add	ip, r6, r0
	uxth	ip, ip
	lsl	r6, ip, #1
	eor	r6, r6, ip, lsr #15
	uxth	r6, r6
	ldr	r1, [fp, #-24]
	mov	sp, fp
	strh	r3, [r1, #0]
	strh	r4, [r1, #2]
	strh	r5, [r1, #4]
	strh	r6, [r1, #6]
	pop	{r4, r5, r6, r7, r8, r9, r10, fp, pc}
	.size	cham64_128_encrypt, .-cham64_128_encrypt

#endif
