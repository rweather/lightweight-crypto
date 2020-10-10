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

#endif
