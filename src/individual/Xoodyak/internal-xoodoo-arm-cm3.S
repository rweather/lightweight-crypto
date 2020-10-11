#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
	.syntax unified
	.thumb
	.text

	.align	2
	.global	xoodoo_permute
	.thumb
	.thumb_func
	.type	xoodoo_permute, %function
xoodoo_permute:
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
	eor	r0, r4, r8
	eor	ip, r1, r5
	eor	r0, lr
	eor	ip, r9
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r5, r0
	eor	r9, r0
	eor	r0, r2, r6
	eor	r0, r10
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r6, ip
	eor	r10, ip
	eor	ip, r3, r7
	eor	ip, fp
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r7, r0
	eor	fp, r0
	eor	r4, ip
	eor	r8, ip
	eor	lr, ip
	ror	r9, r9, #21
	ror	r10, r10, #21
	ror	fp, fp, #21
	ror	lr, lr, #21
	eor	r1, r1, #88
	bic	r0, r9, r8
	eors	r1, r0
	bic	ip, r1, r9
	eor	r8, ip
	bic	r0, r8, r1
	eor	r9, r0
	bic	ip, r10, r5
	eor	r2, ip
	bic	r0, r2, r10
	eors	r5, r0
	bic	ip, r5, r2
	eor	r10, ip
	bic	r0, fp, r6
	eors	r3, r0
	bic	ip, r3, fp
	eor	r6, ip
	bic	r0, r6, r3
	eor	fp, r0
	bic	ip, lr, r7
	eor	r4, ip
	bic	r0, r4, lr
	eors	r7, r0
	bic	ip, r7, r4
	eor	lr, ip
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r9, r9, #24
	ror	r10, r10, #24
	ror	fp, fp, #24
	ror	lr, lr, #24
	eor	r0, r4, r7
	eor	ip, r1, r8
	eor	r0, r10
	eor	ip, fp
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eor	r8, r0
	eor	fp, r0
	eor	r0, r2, r5
	eor	r0, lr
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r5, ip
	eor	lr, ip
	eor	ip, r3, r6
	eor	ip, r9
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r6, r0
	eor	r9, r0
	eor	r4, ip
	eor	r7, ip
	eor	r10, ip
	ror	fp, fp, #21
	ror	lr, lr, #21
	ror	r9, r9, #21
	ror	r10, r10, #21
	eor	r1, r1, #56
	bic	r0, fp, r7
	eors	r1, r0
	bic	ip, r1, fp
	eor	r7, ip
	bic	r0, r7, r1
	eor	fp, r0
	bic	ip, lr, r8
	eor	r2, ip
	bic	r0, r2, lr
	eor	r8, r0
	bic	ip, r8, r2
	eor	lr, ip
	bic	r0, r9, r5
	eors	r3, r0
	bic	ip, r3, r9
	eor	r5, ip
	bic	r0, r5, r3
	eor	r9, r0
	bic	ip, r10, r6
	eor	r4, ip
	bic	r0, r4, r10
	eors	r6, r0
	bic	ip, r6, r4
	eor	r10, ip
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	fp, fp, #24
	ror	lr, lr, #24
	ror	r9, r9, #24
	ror	r10, r10, #24
	eor	r0, r4, r6
	eor	ip, r1, r7
	eor	r0, lr
	eor	ip, r9
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r7, r0
	eor	r9, r0
	eor	r0, r2, r8
	eor	r0, r10
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r8, ip
	eor	r10, ip
	eor	ip, r3, r5
	eor	ip, fp
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r5, r0
	eor	fp, r0
	eor	r4, ip
	eor	r6, ip
	eor	lr, ip
	ror	r9, r9, #21
	ror	r10, r10, #21
	ror	fp, fp, #21
	ror	lr, lr, #21
	eor	r1, r1, #960
	bic	r0, r9, r6
	eors	r1, r0
	bic	ip, r1, r9
	eor	r6, ip
	bic	r0, r6, r1
	eor	r9, r0
	bic	ip, r10, r7
	eor	r2, ip
	bic	r0, r2, r10
	eors	r7, r0
	bic	ip, r7, r2
	eor	r10, ip
	bic	r0, fp, r8
	eors	r3, r0
	bic	ip, r3, fp
	eor	r8, ip
	bic	r0, r8, r3
	eor	fp, r0
	bic	ip, lr, r5
	eor	r4, ip
	bic	r0, r4, lr
	eors	r5, r0
	bic	ip, r5, r4
	eor	lr, ip
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r9, r9, #24
	ror	r10, r10, #24
	ror	fp, fp, #24
	ror	lr, lr, #24
	eor	r0, r4, r5
	eor	ip, r1, r6
	eor	r0, r10
	eor	ip, fp
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r6, r0
	eor	fp, r0
	eor	r0, r2, r7
	eor	r0, lr
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r7, ip
	eor	lr, ip
	eor	ip, r3, r8
	eor	ip, r9
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eor	r8, r0
	eor	r9, r0
	eor	r4, ip
	eor	r5, ip
	eor	r10, ip
	ror	fp, fp, #21
	ror	lr, lr, #21
	ror	r9, r9, #21
	ror	r10, r10, #21
	eor	r1, r1, #208
	bic	r0, fp, r5
	eors	r1, r0
	bic	ip, r1, fp
	eor	r5, ip
	bic	r0, r5, r1
	eor	fp, r0
	bic	ip, lr, r6
	eor	r2, ip
	bic	r0, r2, lr
	eors	r6, r0
	bic	ip, r6, r2
	eor	lr, ip
	bic	r0, r9, r7
	eors	r3, r0
	bic	ip, r3, r9
	eor	r7, ip
	bic	r0, r7, r3
	eor	r9, r0
	bic	ip, r10, r8
	eor	r4, ip
	bic	r0, r4, r10
	eor	r8, r0
	bic	ip, r8, r4
	eor	r10, ip
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	fp, fp, #24
	ror	lr, lr, #24
	ror	r9, r9, #24
	ror	r10, r10, #24
	eor	r0, r4, r8
	eor	ip, r1, r5
	eor	r0, lr
	eor	ip, r9
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r5, r0
	eor	r9, r0
	eor	r0, r2, r6
	eor	r0, r10
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r6, ip
	eor	r10, ip
	eor	ip, r3, r7
	eor	ip, fp
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r7, r0
	eor	fp, r0
	eor	r4, ip
	eor	r8, ip
	eor	lr, ip
	ror	r9, r9, #21
	ror	r10, r10, #21
	ror	fp, fp, #21
	ror	lr, lr, #21
	eor	r1, r1, #288
	bic	r0, r9, r8
	eors	r1, r0
	bic	ip, r1, r9
	eor	r8, ip
	bic	r0, r8, r1
	eor	r9, r0
	bic	ip, r10, r5
	eor	r2, ip
	bic	r0, r2, r10
	eors	r5, r0
	bic	ip, r5, r2
	eor	r10, ip
	bic	r0, fp, r6
	eors	r3, r0
	bic	ip, r3, fp
	eor	r6, ip
	bic	r0, r6, r3
	eor	fp, r0
	bic	ip, lr, r7
	eor	r4, ip
	bic	r0, r4, lr
	eors	r7, r0
	bic	ip, r7, r4
	eor	lr, ip
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r9, r9, #24
	ror	r10, r10, #24
	ror	fp, fp, #24
	ror	lr, lr, #24
	eor	r0, r4, r7
	eor	ip, r1, r8
	eor	r0, r10
	eor	ip, fp
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eor	r8, r0
	eor	fp, r0
	eor	r0, r2, r5
	eor	r0, lr
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r5, ip
	eor	lr, ip
	eor	ip, r3, r6
	eor	ip, r9
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r6, r0
	eor	r9, r0
	eor	r4, ip
	eor	r7, ip
	eor	r10, ip
	ror	fp, fp, #21
	ror	lr, lr, #21
	ror	r9, r9, #21
	ror	r10, r10, #21
	eor	r1, r1, #20
	bic	r0, fp, r7
	eors	r1, r0
	bic	ip, r1, fp
	eor	r7, ip
	bic	r0, r7, r1
	eor	fp, r0
	bic	ip, lr, r8
	eor	r2, ip
	bic	r0, r2, lr
	eor	r8, r0
	bic	ip, r8, r2
	eor	lr, ip
	bic	r0, r9, r5
	eors	r3, r0
	bic	ip, r3, r9
	eor	r5, ip
	bic	r0, r5, r3
	eor	r9, r0
	bic	ip, r10, r6
	eor	r4, ip
	bic	r0, r4, r10
	eors	r6, r0
	bic	ip, r6, r4
	eor	r10, ip
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	fp, fp, #24
	ror	lr, lr, #24
	ror	r9, r9, #24
	ror	r10, r10, #24
	eor	r0, r4, r6
	eor	ip, r1, r7
	eor	r0, lr
	eor	ip, r9
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r7, r0
	eor	r9, r0
	eor	r0, r2, r8
	eor	r0, r10
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r8, ip
	eor	r10, ip
	eor	ip, r3, r5
	eor	ip, fp
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r5, r0
	eor	fp, r0
	eor	r4, ip
	eor	r6, ip
	eor	lr, ip
	ror	r9, r9, #21
	ror	r10, r10, #21
	ror	fp, fp, #21
	ror	lr, lr, #21
	eor	r1, r1, #96
	bic	r0, r9, r6
	eors	r1, r0
	bic	ip, r1, r9
	eor	r6, ip
	bic	r0, r6, r1
	eor	r9, r0
	bic	ip, r10, r7
	eor	r2, ip
	bic	r0, r2, r10
	eors	r7, r0
	bic	ip, r7, r2
	eor	r10, ip
	bic	r0, fp, r8
	eors	r3, r0
	bic	ip, r3, fp
	eor	r8, ip
	bic	r0, r8, r3
	eor	fp, r0
	bic	ip, lr, r5
	eor	r4, ip
	bic	r0, r4, lr
	eors	r5, r0
	bic	ip, r5, r4
	eor	lr, ip
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r9, r9, #24
	ror	r10, r10, #24
	ror	fp, fp, #24
	ror	lr, lr, #24
	eor	r0, r4, r5
	eor	ip, r1, r6
	eor	r0, r10
	eor	ip, fp
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r6, r0
	eor	fp, r0
	eor	r0, r2, r7
	eor	r0, lr
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r7, ip
	eor	lr, ip
	eor	ip, r3, r8
	eor	ip, r9
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eor	r8, r0
	eor	r9, r0
	eor	r4, ip
	eor	r5, ip
	eor	r10, ip
	ror	fp, fp, #21
	ror	lr, lr, #21
	ror	r9, r9, #21
	ror	r10, r10, #21
	eor	r1, r1, #44
	bic	r0, fp, r5
	eors	r1, r0
	bic	ip, r1, fp
	eor	r5, ip
	bic	r0, r5, r1
	eor	fp, r0
	bic	ip, lr, r6
	eor	r2, ip
	bic	r0, r2, lr
	eors	r6, r0
	bic	ip, r6, r2
	eor	lr, ip
	bic	r0, r9, r7
	eors	r3, r0
	bic	ip, r3, r9
	eor	r7, ip
	bic	r0, r7, r3
	eor	r9, r0
	bic	ip, r10, r8
	eor	r4, ip
	bic	r0, r4, r10
	eor	r8, r0
	bic	ip, r8, r4
	eor	r10, ip
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	fp, fp, #24
	ror	lr, lr, #24
	ror	r9, r9, #24
	ror	r10, r10, #24
	eor	r0, r4, r8
	eor	ip, r1, r5
	eor	r0, lr
	eor	ip, r9
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r5, r0
	eor	r9, r0
	eor	r0, r2, r6
	eor	r0, r10
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r6, ip
	eor	r10, ip
	eor	ip, r3, r7
	eor	ip, fp
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r7, r0
	eor	fp, r0
	eor	r4, ip
	eor	r8, ip
	eor	lr, ip
	ror	r9, r9, #21
	ror	r10, r10, #21
	ror	fp, fp, #21
	ror	lr, lr, #21
	eor	r1, r1, #896
	bic	r0, r9, r8
	eors	r1, r0
	bic	ip, r1, r9
	eor	r8, ip
	bic	r0, r8, r1
	eor	r9, r0
	bic	ip, r10, r5
	eor	r2, ip
	bic	r0, r2, r10
	eors	r5, r0
	bic	ip, r5, r2
	eor	r10, ip
	bic	r0, fp, r6
	eors	r3, r0
	bic	ip, r3, fp
	eor	r6, ip
	bic	r0, r6, r3
	eor	fp, r0
	bic	ip, lr, r7
	eor	r4, ip
	bic	r0, r4, lr
	eors	r7, r0
	bic	ip, r7, r4
	eor	lr, ip
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r9, r9, #24
	ror	r10, r10, #24
	ror	fp, fp, #24
	ror	lr, lr, #24
	eor	r0, r4, r7
	eor	ip, r1, r8
	eor	r0, r10
	eor	ip, fp
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eor	r8, r0
	eor	fp, r0
	eor	r0, r2, r5
	eor	r0, lr
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r5, ip
	eor	lr, ip
	eor	ip, r3, r6
	eor	ip, r9
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r6, r0
	eor	r9, r0
	eor	r4, ip
	eor	r7, ip
	eor	r10, ip
	ror	fp, fp, #21
	ror	lr, lr, #21
	ror	r9, r9, #21
	ror	r10, r10, #21
	eor	r1, r1, #240
	bic	r0, fp, r7
	eors	r1, r0
	bic	ip, r1, fp
	eor	r7, ip
	bic	r0, r7, r1
	eor	fp, r0
	bic	ip, lr, r8
	eor	r2, ip
	bic	r0, r2, lr
	eor	r8, r0
	bic	ip, r8, r2
	eor	lr, ip
	bic	r0, r9, r5
	eors	r3, r0
	bic	ip, r3, r9
	eor	r5, ip
	bic	r0, r5, r3
	eor	r9, r0
	bic	ip, r10, r6
	eor	r4, ip
	bic	r0, r4, r10
	eors	r6, r0
	bic	ip, r6, r4
	eor	r10, ip
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	fp, fp, #24
	ror	lr, lr, #24
	ror	r9, r9, #24
	ror	r10, r10, #24
	eor	r0, r4, r6
	eor	ip, r1, r7
	eor	r0, lr
	eor	ip, r9
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r7, r0
	eor	r9, r0
	eor	r0, r2, r8
	eor	r0, r10
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r8, ip
	eor	r10, ip
	eor	ip, r3, r5
	eor	ip, fp
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eors	r5, r0
	eor	fp, r0
	eor	r4, ip
	eor	r6, ip
	eor	lr, ip
	ror	r9, r9, #21
	ror	r10, r10, #21
	ror	fp, fp, #21
	ror	lr, lr, #21
	eor	r1, r1, #416
	bic	r0, r9, r6
	eors	r1, r0
	bic	ip, r1, r9
	eor	r6, ip
	bic	r0, r6, r1
	eor	r9, r0
	bic	ip, r10, r7
	eor	r2, ip
	bic	r0, r2, r10
	eors	r7, r0
	bic	ip, r7, r2
	eor	r10, ip
	bic	r0, fp, r8
	eors	r3, r0
	bic	ip, r3, fp
	eor	r8, ip
	bic	r0, r8, r3
	eor	fp, r0
	bic	ip, lr, r5
	eor	r4, ip
	bic	r0, r4, lr
	eors	r5, r0
	bic	ip, r5, r4
	eor	lr, ip
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	r5, r5, #31
	ror	r9, r9, #24
	ror	r10, r10, #24
	ror	fp, fp, #24
	ror	lr, lr, #24
	eor	r0, r4, r5
	eor	ip, r1, r6
	eor	r0, r10
	eor	ip, fp
	ror	r0, r0, #18
	ror	ip, ip, #18
	eor	r0, r0, r0, ror #9
	eor	ip, ip, ip, ror #9
	eors	r1, r0
	eors	r6, r0
	eor	fp, r0
	eor	r0, r2, r7
	eor	r0, lr
	ror	r0, r0, #18
	eor	r0, r0, r0, ror #9
	eor	r2, ip
	eor	r7, ip
	eor	lr, ip
	eor	ip, r3, r8
	eor	ip, r9
	ror	ip, ip, #18
	eor	ip, ip, ip, ror #9
	eors	r3, r0
	eor	r8, r0
	eor	r9, r0
	eor	r4, ip
	eor	r5, ip
	eor	r10, ip
	ror	fp, fp, #21
	ror	lr, lr, #21
	ror	r9, r9, #21
	ror	r10, r10, #21
	eor	r1, r1, #18
	bic	r0, fp, r5
	eors	r1, r0
	bic	ip, r1, fp
	eor	r5, ip
	bic	r0, r5, r1
	eor	fp, r0
	bic	ip, lr, r6
	eor	r2, ip
	bic	r0, r2, lr
	eors	r6, r0
	bic	ip, r6, r2
	eor	lr, ip
	bic	r0, r9, r7
	eors	r3, r0
	bic	ip, r3, r9
	eor	r7, ip
	bic	r0, r7, r3
	eor	r9, r0
	bic	ip, r10, r8
	eor	r4, ip
	bic	r0, r4, r10
	eor	r8, r0
	bic	ip, r8, r4
	eor	r10, ip
	ror	r5, r5, #31
	ror	r6, r6, #31
	ror	r7, r7, #31
	ror	r8, r8, #31
	ror	fp, fp, #24
	ror	lr, lr, #24
	ror	r9, r9, #24
	ror	r10, r10, #24
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
	.size	xoodoo_permute, .-xoodoo_permute

#endif
