#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	speck64_128_encrypt
	.thumb
	.thumb_func
	.type	speck64_128_encrypt, %function
speck64_128_encrypt:
	push	{r4, r5}
	ldr	r4, [r2, #0]
	ldr	r3, [r2, #4]
	ldr	r5, [r0, #0]
	ldr	r2, [r0, #4]
	ldr	ip, [r0, #8]
	ldr	r0, [r0, #12]
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #0
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #1
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #2
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #3
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #4
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #5
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #6
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #7
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #8
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #9
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #10
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #11
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #12
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #13
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #14
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #15
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #16
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #17
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #18
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #19
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #20
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #21
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #22
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r0, r5, r0, ror #8
	eor	r0, r0, #23
	eor	r5, r0, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	r2, r5, r2, ror #8
	eor	r2, r2, #24
	eor	r5, r2, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	add	ip, r5, ip, ror #8
	eor	ip, ip, #25
	eor	r5, ip, r5, ror #29
	add	r3, r4, r3, ror #8
	eors	r3, r5
	eor	r4, r3, r4, ror #29
	str	r4, [r1, #0]
	str	r3, [r1, #4]
	pop	{r4, r5}
	bx	lr
	.size	speck64_128_encrypt, .-speck64_128_encrypt

#endif
