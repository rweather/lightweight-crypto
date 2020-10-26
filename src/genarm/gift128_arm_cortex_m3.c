/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * This program is used to generate the assembly code version of the
 * GIFT-128 block cipher for ARM Cortex M3 microprocessors.  With minor
 * modifications, this can probably also be used to generate assembly
 * code versions for other Cortex M variants such as M4, M7, M33, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define GIFT128_VARIANT_FULL    0
#define GIFT128_VARIANT_SMALL   1
#define GIFT128_VARIANT_TINY    2

/* Round constants for GIFT-128 in the fixsliced representation */
static uint32_t const GIFT128_RC_fixsliced[40] = {
    0x10000008, 0x80018000, 0x54000002, 0x01010181, 0x8000001f, 0x10888880,
    0x6001e000, 0x51500002, 0x03030180, 0x8000002f, 0x10088880, 0x60016000,
    0x41500002, 0x03030080, 0x80000027, 0x10008880, 0x4001e000, 0x11500002,
    0x03020180, 0x8000002b, 0x10080880, 0x60014000, 0x01400002, 0x02020080,
    0x80000021, 0x10000080, 0x0001c000, 0x51000002, 0x03010180, 0x8000002e,
    0x10088800, 0x60012000, 0x40500002, 0x01030080, 0x80000006, 0x10008808,
    0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};

/* Round constants for GIFT-128 in the bitsliced representation */
static uint8_t const GIFT128_RC[40] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
    0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};

static int variant = GIFT128_VARIANT_FULL;
static int is_nibble_based = 0;
static int is_tweaked = 0;
static int preloaded = 0;
static int label = 1;

static void function_header(const char *prefix, const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.global\t%s_%s\n", prefix, name);
    printf("\t.thumb\n");
    printf("\t.thumb_func\n");
    printf("\t.type\t%s_%s, %%function\n", prefix, name);
    printf("%s_%s:\n", prefix, name);
}

static void function_footer(const char *prefix, const char *name)
{
    printf("\t.size\t%s_%s, .-%s_%s\n", prefix, name, prefix, name);
}

static int is_low_reg(const char *reg)
{
    return reg[0] == 'r' && atoi(reg + 1) < 8;
}

/* Generates a binary operator, preferring thumb instructions if possible */
static void binop(const char *name, const char *reg1, const char *reg2)
{
    if (is_low_reg(reg1) && is_low_reg(reg2))
        printf("\t%ss\t%s, %s\n", name, reg1, reg2);
    else
        printf("\t%s\t%s, %s\n", name, reg1, reg2);
}

/* Determine if a constant can be used as "Operand2" in an instruction */
static int is_op2_constant(uint32_t value)
{
    int shift;
    uint32_t mask;

    /* If the value is less than 256, then it can be used directly */
    if (value < 256U)
        return 1;

    /* If the value has the form 00XY00XY, XY00XY00, or XYXYXYXY, then
     * it can be used as a "modified immediate" in Thumb code */
    if ((value & 0x00FF00FFU) == value && (value >> 16) == (value & 0xFFU))
        return 1;
    if ((value & 0xFF00FF00U) == value && (value >> 16) == (value & 0xFF00U))
        return 1;
    if (((value >> 24) & 0xFF) == (value & 0xFF) &&
             ((value >> 16) & 0xFF) == (value & 0xFF) &&
             ((value >>  8) & 0xFF) == (value & 0xFF))
        return 1;

    /* Check if the value can be expressed as an 8-bit quantity that has
     * been rotated right by a multiple of 4 bits and the top-most bit
     * of the 8 is set to 1 */
    for (shift = 0; shift <= 24; shift += 4) {
        mask = 0xFF000000U >> shift;
        if ((value & mask) != value)
            continue;
        mask = 0x80000000U >> shift;
        if ((value & mask) == mask)
            return 1;
    }

    /* Not usable as a constant in "Operand2" */
    return 0;
}

/* Load an immediate value into a register using the most efficient sequence */
static void loadimm(const char *reg, uint32_t value)
{
    if (is_low_reg(reg) && value < 256U) {
        printf("\tmovs\t%s, #%lu\n", reg, (unsigned long)value);
    } else if (is_op2_constant(value)) {
        printf("\tmov\t%s, #%lu\n", reg, (unsigned long)value);
    } else if (value < 0x10000U) {
        printf("\tmovw\t%s, #%lu\n", reg, (unsigned long)value);
    } else if (is_op2_constant(~value)) {
        printf("\tmvn\t%s, #%lu\n", reg,
               (unsigned long)((~value) & 0xFFFFFFFFUL));
    } else {
        printf("\tmovw\t%s, #%lu\n", reg, (unsigned long)(value & 0xFFFFU));
        printf("\tmovt\t%s, #%lu\n", reg, (unsigned long)(value >> 16));
    }
}

/* List of all registers that we can work with */
typedef struct
{
    const char *s0;
    const char *s1;
    const char *s2;
    const char *s3;
    const char *k0;
    const char *k1;
    const char *k2;
    const char *k3;
    const char *w0;
    const char *w1;
    const char *w2;
    const char *w3;
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;

} reg_names;

/* Rotate the two halves of a 32-bit word right by two rotation amounts */
static void rotate_halves
    (const reg_names *regs, const char *dst, const char *src,
     int rot_high, int rot_low)
{
    /* Generated with "arm-none-eabi-gcc -mcpu=cortex-m3 -mthumb -O3" */
    if (rot_high == 2 && rot_low == 12) {
        printf("\tlsr\t%s, %s, #18\n", regs->t0, src);
        printf("\tlsl\t%s, %s, #18\n", regs->t0, regs->t0);
        printf("\tand\t%s, %s, #%d\n", regs->t1, src, 0x30000);
        printf("\tlsl\t%s, %s, #4\n", regs->t2, src);
        printf("\tlsr\t%s, %s, #2\n", regs->t0, regs->t0);
        printf("\torr\t%s, %s, %s, lsl #14\n", regs->t0, regs->t0, regs->t1);
        printf("\tuxth\t%s, %s\n", regs->t2, regs->t2);
        printf("\torr\t%s, %s, %s\n", regs->t0, regs->t0, regs->t2);
        printf("\tubfx\t%s, %s, #12, #4\n", dst, src);
        printf("\torrs\t%s, %s, %s\n", dst, dst, regs->t0);
    } else if (rot_high == 14 && rot_low == 4) {
        loadimm(regs->t0, 0x3FFF0000);
        printf("\tand\t%s, %s, #%d\n", regs->t1, src, (int)0xC0000000U);
        binop("and", regs->t0, src);
        printf("\tlsl\t%s, %s, #2\n", regs->t0, regs->t0);
        printf("\torr\t%s, %s, %s, lsr #14\n", regs->t0, regs->t0, regs->t1);
        printf("\tubfx\t%s, %s, #4, #12\n", regs->t1, src);
        printf("\tlsl\t%s, %s, #12\n", dst, src);
        binop("orr", regs->t0, regs->t1);
        printf("\tuxth\t%s, %s\n", dst, src);
        binop("orr", dst, regs->t0);
    } else if (rot_high == 4 && rot_low == 8) {
        printf("\tlsr\t%s, %s, #20\n", regs->t0, src);
        printf("\tlsl\t%s, %s, #20\n", regs->t0, regs->t0);
        printf("\tand\t%s, %s, #%d\n", regs->t1, src, 0xF0000);
        printf("\tlsl\t%s, %s, #8\n", regs->t2, src);
        printf("\tlsr\t%s, %s, #4\n", regs->t0, regs->t0);
        printf("\torr\t%s, %s, %s, lsl #12\n", regs->t0, regs->t0, regs->t1);
        printf("\tuxth\t%s, %s\n", regs->t2, regs->t2);
        binop("orr", regs->t0, regs->t2);
        printf("\tubfx\t%s, %s, #8, #8\n", dst, src);
        binop("orr", dst, regs->t0);
    } else {
        fprintf(stderr, "unknown rotation\n");
        exit(1);
    }
}

/* Generate the code for the GIFT-128 S-box */
static void sbox(const reg_names *regs)
{
    /* s1 ^= s0 & s2; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s2);
    binop("eor", regs->s1, regs->t0);

    /* s0 ^= s1 & s3; -- leaves the result in t1 */
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->s1, regs->s3);
    binop("eor", regs->t1, regs->s0);

    /* s2 ^= s0 | s1; */
    printf("\torr\t%s, %s, %s\n", regs->t0, regs->t1, regs->s1);
    binop("eor", regs->s2, regs->t0);

    /* s3 ^= s2; */
    binop("eor", regs->s3, regs->s2);

    /* s1 ^= s3; */
    binop("eor", regs->s1, regs->s3);

    /* s3 ^= 0xFFFFFFFFU; */
    binop("mvn", regs->s3, regs->s3);

    /* s2 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->t1, regs->s1);
    binop("eor", regs->s2, regs->t0);

    /* swap(s0, s3); */
    binop("mov", regs->s0, regs->s3);
    binop("mov", regs->s3, regs->t1);
}

/* Generate the code for the GIFT-128 S-box with no swap at the end */
static void sbox_no_swap(const reg_names *regs)
{
    /* s1 ^= s0 & s2; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s2);
    binop("eor", regs->s1, regs->t0);

    /* s0 ^= s1 & s3; */
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->s1, regs->s3);
    binop("eor", regs->s0, regs->t1);

    /* s2 ^= s0 | s1; */
    printf("\torr\t%s, %s, %s\n", regs->t0, regs->s0, regs->s1);
    binop("eor", regs->s2, regs->t0);

    /* s3 ^= s2; */
    binop("eor", regs->s3, regs->s2);

    /* s1 ^= s3; */
    binop("eor", regs->s1, regs->s3);

    /* s3 ^= 0xFFFFFFFFU; */
    binop("mvn", regs->s3, regs->s3);

    /* s2 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s1);
    binop("eor", regs->s2, regs->t0);
}

/* Generate the code for the inverse of the GIFT-128 S-box */
static void inv_sbox(const reg_names *regs)
{
    /* swap(s0, s3); */
    binop("mov", regs->t1, regs->s0);
    binop("mov", regs->s0, regs->s3);
    binop("mov", regs->s3, regs->t1);

    /* s2 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s1);
    binop("eor", regs->s2, regs->t0);

    /* s3 ^= 0xFFFFFFFFU; */
    binop("mvn", regs->s3, regs->s3);

    /* s1 ^= s3; */
    binop("eor", regs->s1, regs->s3);

    /* s3 ^= s2; */
    binop("eor", regs->s3, regs->s2);

    /* s2 ^= s0 | s1; */
    /* s0 ^= s1 & s3; */
    printf("\torr\t%s, %s, %s\n", regs->t0, regs->s0, regs->s1);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->s1, regs->s3);
    binop("eor", regs->s2, regs->t0);
    binop("eor", regs->s0, regs->t1);

    /* s1 ^= s0 & s2; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s2);
    binop("eor", regs->s1, regs->t0);
}

/* Generate the code for the inverse of the GIFT-128 S-box with no swap */
static void inv_sbox_no_swap(const reg_names *regs)
{
    /* s2 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s1);
    binop("eor", regs->s2, regs->t0);

    /* s3 ^= 0xFFFFFFFFU; */
    binop("mvn", regs->s3, regs->s3);

    /* s1 ^= s3; */
    binop("eor", regs->s1, regs->s3);

    /* s3 ^= s2; */
    binop("eor", regs->s3, regs->s2);

    /* s2 ^= s0 | s1; */
    /* s0 ^= s1 & s3; */
    printf("\torr\t%s, %s, %s\n", regs->t0, regs->s0, regs->s1);
    printf("\tand\t%s, %s, %s\n", regs->t1, regs->s1, regs->s3);
    binop("eor", regs->s2, regs->t0);
    binop("eor", regs->s0, regs->t1);

    /* s1 ^= s0 & s2; */
    printf("\tand\t%s, %s, %s\n", regs->t0, regs->s0, regs->s2);
    binop("eor", regs->s1, regs->t0);
}

/* Perform a bit permutation step */
void bit_permute_step
    (const reg_names *regs, const char *y, uint32_t mask, int shift)
{
    /* t = ((y >> shift) ^ y) & mask */
    printf("\teor\t%s, %s, %s, lsr #%d\n", regs->t0, y, y, shift);
    if (is_op2_constant(mask)) {
        printf("\tand\t%s, %s, #%lu\n",
               regs->t0, regs->t0, (unsigned long)mask);
    } else {
        loadimm(regs->t1, mask);
        printf("\tand\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
    }

    /* y = (y ^ t) ^ (t << shift) */
    printf("\teor\t%s, %s, %s\n", y, y, regs->t0);
    printf("\teor\t%s, %s, %s, lsl #%d\n", y, y, regs->t0, shift);
}

/* Perform a bit permutation step in parallel on 4 state words, which
 * helps with reuse of immediate values that are loaded into registers */
static void bit_permute_step_parallel
    (const reg_names *regs, uint32_t mask, int shift)
{
    /* t = ((y >> shift) ^ y) & mask */
    printf("\teor\t%s, %s, %s, lsr #%d\n",
           regs->t0, regs->s0, regs->s0, shift);
    printf("\teor\t%s, %s, %s, lsr #%d\n",
           regs->t1, regs->s1, regs->s1, shift);
    if (is_op2_constant(mask)) {
        printf("\tand\t%s, %s, #%lu\n",
               regs->t0, regs->t0, (unsigned long)mask);
        printf("\tand\t%s, %s, #%lu\n",
               regs->t1, regs->t1, (unsigned long)mask);
    } else {
        loadimm(regs->t2, mask);
        printf("\tand\t%s, %s, %s\n", regs->t0, regs->t0, regs->t2);
        printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->t2);
    }

    /* y = (y ^ t) ^ (t << shift) */
    printf("\teor\t%s, %s, %s\n", regs->s0, regs->s0, regs->t0);
    printf("\teor\t%s, %s, %s\n", regs->s1, regs->s1, regs->t1);
    printf("\teor\t%s, %s, %s, lsl #%d\n", regs->s0, regs->s0, regs->t0, shift);
    printf("\teor\t%s, %s, %s, lsl #%d\n", regs->s1, regs->s1, regs->t1, shift);

    /* t = ((y >> shift) ^ y) & mask */
    printf("\teor\t%s, %s, %s, lsr #%d\n",
           regs->t0, regs->s2, regs->s2, shift);
    printf("\teor\t%s, %s, %s, lsr #%d\n",
           regs->t1, regs->s3, regs->s3, shift);
    if (is_op2_constant(mask)) {
        printf("\tand\t%s, %s, #%lu\n",
               regs->t0, regs->t0, (unsigned long)mask);
        printf("\tand\t%s, %s, #%lu\n",
               regs->t1, regs->t1, (unsigned long)mask);
    } else {
        printf("\tand\t%s, %s, %s\n", regs->t0, regs->t0, regs->t2);
        printf("\tand\t%s, %s, %s\n", regs->t1, regs->t1, regs->t2);
    }

    /* y = (y ^ t) ^ (t << shift) */
    printf("\teor\t%s, %s, %s\n", regs->s2, regs->s2, regs->t0);
    printf("\teor\t%s, %s, %s\n", regs->s3, regs->s3, regs->t1);
    printf("\teor\t%s, %s, %s, lsl #%d\n", regs->s2, regs->s2, regs->t0, shift);
    printf("\teor\t%s, %s, %s, lsl #%d\n", regs->s3, regs->s3, regs->t1, shift);
}

/* Generate the key initialization function for GIFT-128 */
static void gen_gift128_init(void)
{
    /*
     * r0 holds the pointer to the GIFT-128 key schedule.
     * r1 points to the input key.
     *
     * r2, r3, and ip can be used as temporaries without saving.
     */
    reg_names regs = { .s0 = 0 };
    regs.k0 = "r2";
    regs.k1 = "r3";
    regs.k2 = "r4";
    regs.k3 = "r5";

    /* Quick version for tiny as we can avoid saving registers on the stack.
     * We mirror the fix-sliced word order of 3, 1, 2, 0. */
    if (variant == GIFT128_VARIANT_TINY) {
        regs.k2 = regs.k0;
        regs.k3 = regs.k1;
        if (is_nibble_based) {
            printf("\tldr\t%s, [r1, #0]\n",  regs.k0);
            printf("\tldr\t%s, [r1, #8]\n",  regs.k1);
            printf("\tstr\t%s, [r0, #0]\n",  regs.k0);
            printf("\tstr\t%s, [r0, #4]\n",  regs.k1);
            printf("\tldr\t%s, [r1, #4]\n",  regs.k2);
            printf("\tldr\t%s, [r1, #12]\n", regs.k3);
            printf("\tstr\t%s, [r0, #8]\n",  regs.k2);
            printf("\tstr\t%s, [r0, #12]\n", regs.k3);
        } else {
            printf("\tldr\t%s, [r1, #12]\n", regs.k0);
            printf("\tldr\t%s, [r1, #4]\n",  regs.k1);
            printf("\trev\t%s, %s\n", regs.k0, regs.k0);
            printf("\trev\t%s, %s\n", regs.k1, regs.k1);
            printf("\tstr\t%s, [r0, #0]\n",  regs.k0);
            printf("\tstr\t%s, [r0, #4]\n",  regs.k1);
            printf("\tldr\t%s, [r1, #8]\n",  regs.k2);
            printf("\tldr\t%s, [r1, #0]\n",  regs.k3);
            printf("\trev\t%s, %s\n", regs.k2, regs.k2);
            printf("\trev\t%s, %s\n", regs.k3, regs.k3);
            printf("\tstr\t%s, [r0, #8]\n",  regs.k2);
            printf("\tstr\t%s, [r0, #12]\n", regs.k3);
        }
        printf("\tbx\tlr\n");
        return;
    }

    /* Save registers on entry to the function */
    printf("\tpush\t{r4, r5}\n");

    /* Load the key words into registers and byte-swap if necessary */
    if (is_nibble_based) {
        printf("\tldr\t%s, [r1, #12]\n", regs.k0);
        printf("\tldr\t%s, [r1, #8]\n",  regs.k1);
        printf("\tldr\t%s, [r1, #4]\n",  regs.k2);
        printf("\tldr\t%s, [r1, #0]\n",  regs.k3);
    } else {
        printf("\tldr\t%s, [r1, #0]\n",  regs.k0);
        printf("\tldr\t%s, [r1, #4]\n",  regs.k1);
        printf("\tldr\t%s, [r1, #8]\n",  regs.k2);
        printf("\tldr\t%s, [r1, #12]\n", regs.k3);
        printf("\trev\t%s, %s\n", regs.k0, regs.k0);
        printf("\trev\t%s, %s\n", regs.k1, regs.k1);
        printf("\trev\t%s, %s\n", regs.k2, regs.k2);
        printf("\trev\t%s, %s\n", regs.k3, regs.k3);
    }

    /* Set the regular key with k0 and k3 pre-swapped for the round function */
    printf("\tstr\t%s, [r0, #12]\n", regs.k0);
    printf("\tstr\t%s, [r0, #4]\n",  regs.k1);
    printf("\tstr\t%s, [r0, #8]\n",  regs.k2);
    printf("\tstr\t%s, [r0, #0]\n",  regs.k3);

    /* Pre-compute the keys for rounds 3..10 and permute into fixsliced form */
    // TODO

    /* Derive the fixsliced keys for the remaining rounds 11..40 */
    if (variant == GIFT128_VARIANT_FULL) {
        // TODO
    }

    /* Pop the saved registers and return */
    printf("\tpop\t{r4, r5}\n");
    printf("\tbx\tlr\n");
}

/* Loads the input state for an encryption or decryption operation */
static void load_state(const reg_names *regs)
{
    reg_names regs2 = *regs;
    if (is_nibble_based) {
        /* Swap s0/s1/s2/s3 and t0/t1/t2/t3 to avoid a move later */
        regs2.s0 = regs->t0;
        regs2.s1 = regs->t1;
        regs2.s2 = regs->t2;
        regs2.s3 = regs->t3;
        regs2.t0 = regs->s0;
        regs2.t1 = regs->s1;
        regs2.t2 = regs->s2;
        regs2.t3 = regs->s3;

        /* Load in little-endian byte order */
        printf("\tldr\t%s, [r2, #12]\n", regs2.s0);
        printf("\tldr\t%s, [r2, #8]\n",  regs2.s1);
        printf("\tldr\t%s, [r2, #4]\n",  regs2.s2);
        printf("\tldr\t%s, [r2, #0]\n",  regs2.s3);

        /* Rearrange the nibbles to spread the nibble bits to separate bytes */
        bit_permute_step_parallel(&regs2, 0x0a0a0a0a, 3);
        bit_permute_step_parallel(&regs2, 0x00cc00cc, 6);
        bit_permute_step_parallel(&regs2, 0x0000f0f0, 12);
        bit_permute_step_parallel(&regs2, 0x0000ff00, 8);

        /* Move the bytes into separate words */
        printf("\tbfi\t%s, %s, #24, #8\n", regs2.t0, regs2.s0);
        printf("\tbfi\t%s, %s, #16, #8\n", regs2.t0, regs2.s1);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs2.t0, regs2.s2);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs2.t0, regs2.s3);
        printf("\tlsr\t%s, %s, #8\n", regs2.s0, regs2.s0);
        printf("\tlsr\t%s, %s, #8\n", regs2.s1, regs2.s1);
        printf("\tlsr\t%s, %s, #8\n", regs2.s2, regs2.s2);
        printf("\tlsr\t%s, %s, #8\n", regs2.s3, regs2.s3);
        printf("\tbfi\t%s, %s, #24, #8\n", regs2.t1, regs2.s0);
        printf("\tbfi\t%s, %s, #16, #8\n", regs2.t1, regs2.s1);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs2.t1, regs2.s2);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs2.t1, regs2.s3);
        printf("\tlsr\t%s, %s, #8\n", regs2.s0, regs2.s0);
        printf("\tlsr\t%s, %s, #8\n", regs2.s1, regs2.s1);
        printf("\tlsr\t%s, %s, #8\n", regs2.s2, regs2.s2);
        printf("\tlsr\t%s, %s, #8\n", regs2.s3, regs2.s3);
        printf("\tbfi\t%s, %s, #24, #8\n", regs2.t2, regs2.s0);
        printf("\tbfi\t%s, %s, #16, #8\n", regs2.t2, regs2.s1);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs2.t2, regs2.s2);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs2.t2, regs2.s3);
        printf("\tlsr\t%s, %s, #8\n", regs2.s0, regs2.s0);
        printf("\tlsr\t%s, %s, #8\n", regs2.s1, regs2.s1);
        printf("\tlsr\t%s, %s, #8\n", regs2.s2, regs2.s2);
        printf("\tlsr\t%s, %s, #8\n", regs2.s3, regs2.s3);
        printf("\tbfi\t%s, %s, #24, #8\n", regs2.t3, regs2.s0);
        printf("\tbfi\t%s, %s, #16, #8\n", regs2.t3, regs2.s1);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs2.t3, regs2.s2);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs2.t3, regs2.s3);

        /* Result is now in t0/t1/t2/t3 which due to the register swap
         * above means that the result is in the caller's s0/s1/s2/s3 */
    } else if (preloaded) {
        /* Already preloaded in little-endian byte order */
        printf("\tldr\t%s, [r2, #0]\n",  regs->s0);
        printf("\tldr\t%s, [r2, #4]\n",  regs->s1);
        printf("\tldr\t%s, [r2, #8]\n",  regs->s2);
        printf("\tldr\t%s, [r2, #12]\n", regs->s3);
    } else {
        /* Load in big-endian byte order */
        printf("\tldr\t%s, [r2, #0]\n",  regs->s0);
        printf("\tldr\t%s, [r2, #4]\n",  regs->s1);
        printf("\tldr\t%s, [r2, #8]\n",  regs->s2);
        printf("\tldr\t%s, [r2, #12]\n", regs->s3);
        printf("\trev\t%s, %s\n", regs->s0, regs->s0);
        printf("\trev\t%s, %s\n", regs->s1, regs->s1);
        printf("\trev\t%s, %s\n", regs->s2, regs->s2);
        printf("\trev\t%s, %s\n", regs->s3, regs->s3);
    }
}

/* Stores the output state for an encryption or decryption operation */
static void store_state(const reg_names *regs)
{
    reg_names regs2 = *regs;
    if (is_nibble_based) {
        /* Rearrange the bytes */
        printf("\tbfi\t%s, %s, #24, #8\n", regs->t3, regs->s3);
        printf("\tbfi\t%s, %s, #16, #8\n", regs->t3, regs->s2);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs->t3, regs->s1);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs->t3, regs->s0);
        printf("\tlsr\t%s, %s, #8\n", regs->s3, regs->s3);
        printf("\tlsr\t%s, %s, #8\n", regs->s2, regs->s2);
        printf("\tlsr\t%s, %s, #8\n", regs->s1, regs->s1);
        printf("\tlsr\t%s, %s, #8\n", regs->s0, regs->s0);
        printf("\tbfi\t%s, %s, #24, #8\n", regs->t2, regs->s3);
        printf("\tbfi\t%s, %s, #16, #8\n", regs->t2, regs->s2);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs->t2, regs->s1);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs->t2, regs->s0);
        printf("\tlsr\t%s, %s, #8\n", regs->s3, regs->s3);
        printf("\tlsr\t%s, %s, #8\n", regs->s2, regs->s2);
        printf("\tlsr\t%s, %s, #8\n", regs->s1, regs->s1);
        printf("\tlsr\t%s, %s, #8\n", regs->s0, regs->s0);
        printf("\tbfi\t%s, %s, #24, #8\n", regs->t1, regs->s3);
        printf("\tbfi\t%s, %s, #16, #8\n", regs->t1, regs->s2);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs->t1, regs->s1);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs->t1, regs->s0);
        printf("\tlsr\t%s, %s, #8\n", regs->s3, regs->s3);
        printf("\tlsr\t%s, %s, #8\n", regs->s2, regs->s2);
        printf("\tlsr\t%s, %s, #8\n", regs->s1, regs->s1);
        printf("\tlsr\t%s, %s, #8\n", regs->s0, regs->s0);
        printf("\tbfi\t%s, %s, #24, #8\n", regs->t0, regs->s3);
        printf("\tbfi\t%s, %s, #16, #8\n", regs->t0, regs->s2);
        printf("\tbfi\t%s, %s, #8, #8\n",  regs->t0, regs->s1);
        printf("\tbfi\t%s, %s, #0, #8\n",  regs->t0, regs->s0);

        /* Rearrange to collect the nibble bits from separate bytes */
        regs2.s0 = regs->t0;
        regs2.s1 = regs->t1;
        regs2.s2 = regs->t2;
        regs2.s3 = regs->t3;
        regs2.t0 = regs->s0;
        regs2.t1 = regs->s1;
        regs2.t2 = regs->s2;
        regs2.t3 = regs->s3;
        bit_permute_step_parallel(&regs2, 0x00aa00aa, 7);
        bit_permute_step_parallel(&regs2, 0x0000cccc, 14);
        bit_permute_step_parallel(&regs2, 0x00f000f0, 4);
        bit_permute_step_parallel(&regs2, 0x0000ff00, 8);

        /* Store in little-endian byte order */
        printf("\tstr\t%s, [r1, #12]\n", regs2.s0);
        printf("\tstr\t%s, [r1, #8]\n",  regs2.s1);
        printf("\tstr\t%s, [r1, #4]\n",  regs2.s2);
        printf("\tstr\t%s, [r1, #0]\n",  regs2.s3);
    } else if (preloaded) {
        /* Store preloaded words in little-endian byte order */
        printf("\tstr\t%s, [r1, #0]\n",  regs->s0);
        printf("\tstr\t%s, [r1, #4]\n",  regs->s1);
        printf("\tstr\t%s, [r1, #8]\n",  regs->s2);
        printf("\tstr\t%s, [r1, #12]\n", regs->s3);
    } else {
        /* Store in big-endian byte order */
        printf("\trev\t%s, %s\n", regs->s0, regs->s0);
        printf("\trev\t%s, %s\n", regs->s1, regs->s1);
        printf("\trev\t%s, %s\n", regs->s2, regs->s2);
        printf("\trev\t%s, %s\n", regs->s3, regs->s3);
        printf("\tstr\t%s, [r1, #0]\n",  regs->s0);
        printf("\tstr\t%s, [r1, #4]\n",  regs->s1);
        printf("\tstr\t%s, [r1, #8]\n",  regs->s2);
        printf("\tstr\t%s, [r1, #12]\n", regs->s3);
    }
}

/* Generate the tiny bitsliced encryption function for GIFT-128
 * with the key schedule expanded on the fly */
static void gen_gift128_encrypt_tiny(void)
{
    /*
     * r0 holds the pointer to the GIFT-128 key or key schedule.
     * r1 points to the output buffer.
     * r2 points to the input buffer.
     * r3 is the tweak value.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs = { .s0 = 0 };
    int top_label;
    int round, rounds;
    const char *temp;
    regs.s0 = "r4";
    regs.s1 = "r5";
    regs.s2 = "r6";
    regs.s3 = "r2";
    regs.w0 = "r7";
    regs.w1 = "r8";
    regs.w2 = "r9";
    regs.w3 = "r10";
    regs.t0 = "r0";
    regs.t1 = "r3";
    regs.t2 = "ip";
    regs.t3 = "fp";

    /* Save the callee-saved registers we will be using */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Save r3 on the stack if we are doing tweaked encryption */
    if (is_tweaked)
        printf("\tpush\t{r3}\n");

    /* Load the key schedule */
    printf("\tldr\t%s, [r0, #12]\n", regs.w0);
    printf("\tldr\t%s, [r0, #4]\n",  regs.w1);
    printf("\tldr\t%s, [r0, #8]\n",  regs.w2);
    printf("\tldr\t%s, [r0, #0]\n",  regs.w3);

    /* Load the input state */
    load_state(&regs);

    /* Perform all 40 encryption rounds, 4 or 5 at a time */
    top_label = label++;
    loadimm("lr", 40);
    printf("\tadr\t%s, rconst%s\n", regs.t3, is_tweaked ? "2" : "");
    printf(".L%d:\n", top_label);
    rounds = is_tweaked ? 5 : 4;
    for (round = 0; round < rounds; ++round) {
        /* Apply the S-box with an implicit swap of s0 and s3 */
        if (round < 4) {
            sbox_no_swap(&regs);
            temp = regs.s0;
            regs.s0 = regs.s3;
            regs.s3 = temp;
        } else {
            /* For tweaked encryption, the 5th round does a real swap */
            sbox(&regs);
        }

        /* Apply the 128-bit permutation */
        bit_permute_step_parallel(&regs, 0x0a0a0a0a, 3);
        bit_permute_step_parallel(&regs, 0x00cc00cc, 6);
        bit_permute_step_parallel(&regs, 0x0000f0f0, 12);
        bit_permute_step_parallel(&regs, 0x000000ff, 24);
        printf("\tror\t%s, %s, #24\n", regs.s0, regs.s0);
        printf("\tror\t%s, %s, #16\n", regs.s1, regs.s1);
        printf("\tror\t%s, %s, #8\n", regs.s2, regs.s2);

        /* XOR the round key and round constant with the state */
        printf("\tldr\t%s, [%s], #4\n", regs.t0, regs.t3);
        binop("eor", regs.s2, regs.w1);
        binop("eor", regs.s1, regs.w3);
        binop("eor", regs.s3, regs.t0);

        /* Rotate the key schedule implicitly */
        if (round < 4) {
            temp = regs.w3;
            regs.w3 = regs.w2;
            regs.w2 = regs.w1;
            regs.w1 = regs.w0;
            regs.w0 = temp;
            rotate_halves(&regs, regs.w0, regs.w0, 2, 12);
        } else {
            /* For tweaked encryption, the 5th round does a real rotate */
            printf("\tmov\t%s, %s\n", regs.t2, regs.w3);
            printf("\tmov\t%s, %s\n", regs.w3, regs.w2);
            printf("\tmov\t%s, %s\n", regs.w2, regs.w1);
            printf("\tmov\t%s, %s\n", regs.w1, regs.w0);
            printf("\tmov\t%s, %s\n", regs.w0, regs.t2);
            rotate_halves(&regs, regs.w0, regs.w0, 2, 12);
        }
    }
    if (is_tweaked) {
        /* We need to XOR in the tweak every 5 rounds except for the last.
         * The tweak value is on the top of the stack. */
        int bottom_label = label++;
        printf("\tpop\t{r3}\n");
        printf("\tsubs\tlr, lr, #%d\n", rounds);
        printf("\tbeq\t.L%d\n", bottom_label);
        binop("eor", regs.s0, "r3");
        printf("\tpush\t{r3}\n");
        printf("\tb\t.L%d\n", top_label);
        printf(".L%d:\n", bottom_label);
    } else {
        printf("\tsubs\tlr, lr, #%d\n", rounds);
        printf("\tbne\t.L%d\n", top_label);
    }

    /* Store the final state to the output buffer */
    store_state(&regs);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generate the tiny bitsliced decryption function for GIFT-128
 * with the key schedule expanded on the fly */
static void gen_gift128_decrypt_tiny(void)
{
    /*
     * r0 holds the pointer to the GIFT-128 key or key schedule.
     * r1 points to the output buffer.
     * r2 points to the input buffer.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs = { .s0 = 0 };
    int top_label;
    int round, rounds;
    const char *temp;
    regs.s0 = "r4";
    regs.s1 = "r5";
    regs.s2 = "r6";
    regs.s3 = "r2";
    regs.w0 = "r7";
    regs.w1 = "r8";
    regs.w2 = "r9";
    regs.w3 = "r10";
    regs.t0 = "r0";
    regs.t1 = "r3";
    regs.t2 = "ip";
    regs.t3 = "fp";

    /* Save the callee-saved registers we will be using */
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Save r3 on the stack if we are doing tweaked encryption */
    if (is_tweaked)
        printf("\tpush\t{r3}\n");

    /* Load the key schedule */
    printf("\tldr\t%s, [r0, #12]\n", regs.w0);
    printf("\tldr\t%s, [r0, #4]\n",  regs.w1);
    printf("\tldr\t%s, [r0, #8]\n",  regs.w2);
    printf("\tldr\t%s, [r0, #0]\n",  regs.w3);

    /* Load the input state */
    load_state(&regs);

    /* Forward the key schedule to the end */
    rotate_halves(&regs, regs.w0, regs.w0, 4, 8);
    rotate_halves(&regs, regs.w1, regs.w1, 4, 8);
    rotate_halves(&regs, regs.w2, regs.w2, 4, 8);
    rotate_halves(&regs, regs.w3, regs.w3, 4, 8);

    /* Perform all 40 decryption rounds, 4 or 5 at a time */
    top_label = label++;
    loadimm("lr", 40);
    printf("\tadr\t%s, rconst%s\n", regs.t3, is_tweaked ? "2" : "");
    printf("\tadd\t%s, %s, #160\n", regs.t3, regs.t3);
    printf(".L%d:\n", top_label);
    rounds = is_tweaked ? 5 : 4;
    for (round = 0; round < rounds; ++round) {
        /* Rotate the key schedule backwards */
        if (round < 4) {
            temp = regs.w0;
            regs.w0 = regs.w1;
            regs.w1 = regs.w2;
            regs.w2 = regs.w3;
            regs.w3 = temp;
            rotate_halves(&regs, regs.w3, regs.w3, 14, 4);
        } else {
            /* For tweaked decryption, the 5th round does a real rotate */
            printf("\tmov\t%s, %s\n", regs.t2, regs.w0);
            printf("\tmov\t%s, %s\n", regs.w0, regs.w1);
            printf("\tmov\t%s, %s\n", regs.w1, regs.w2);
            printf("\tmov\t%s, %s\n", regs.w2, regs.w3);
            printf("\tmov\t%s, %s\n", regs.w3, regs.t2);
            rotate_halves(&regs, regs.w3, regs.w3, 14, 4);
        }

        /* XOR the round key and round constant with the state */
        printf("\tldr\t%s, [%s, #-4]!\n", regs.t0, regs.t3);
        binop("eor", regs.s2, regs.w1);
        binop("eor", regs.s1, regs.w3);
        binop("eor", regs.s3, regs.t0);

        /* Apply the inverse of the 128-bit permutation */
        printf("\tror\t%s, %s, #8\n", regs.s0, regs.s0);
        printf("\tror\t%s, %s, #16\n", regs.s1, regs.s1);
        printf("\tror\t%s, %s, #24\n", regs.s2, regs.s2);
        bit_permute_step_parallel(&regs, 0x00550055, 9);
        bit_permute_step_parallel(&regs, 0x00003333, 18);
        bit_permute_step_parallel(&regs, 0x000f000f, 12);
        bit_permute_step_parallel(&regs, 0x000000ff, 24);

        /* Apply the inverse of the S-box with an implicit swap of s0 and s3 */
        if (round < 4) {
            temp = regs.s0;
            regs.s0 = regs.s3;
            regs.s3 = temp;
            inv_sbox_no_swap(&regs);
        } else {
            /* For tweaked decryption, the 5th round does a real swap */
            inv_sbox(&regs);
        }
    }
    if (is_tweaked) {
        /* We need to XOR in the tweak every 5 rounds except for the last.
         * The tweak value is on the top of the stack. */
        int bottom_label = label++;
        printf("\tpop\t{r3}\n");
        printf("\tsubs\tlr, lr, #%d\n", rounds);
        printf("\tbeq\t.L%d\n", bottom_label);
        binop("eor", regs.s0, "r3");
        printf("\tpush\t{r3}\n");
        printf("\tb\t.L%d\n", top_label);
        printf(".L%d:\n", bottom_label);
    } else {
        printf("\tsubs\tlr, lr, #%d\n", rounds);
        printf("\tbne\t.L%d\n", top_label);
    }

    /* Store the final state to the output buffer */
    store_state(&regs);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

static void gen_rc(const char *name)
{
    int index;
    printf("\n\t.align\t4\n");
    printf("\t.type\t%s, %%object\n", name);
    printf("%s:\n", name);
    if (1) { // FIXME: variant == GIFT128_VARIANT_TINY) {
        for (index = 0; index < 40; ++index)
            printf("\t.word\t0x%08lx\n", 0x80000000UL | GIFT128_RC[index]);
    } else {
        for (index = 0; index < 40; ++index)
            printf("\t.word\t0x%08lx\n", (unsigned long)(GIFT128_RC_fixsliced[index]));
    }
    printf("\t.size\t%s, .-%s\n", name, name);

}

int main(int argc, char *argv[])
{
    const char *variant_name;
    const char *order_name;

    /* Determine which variant to generate */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s (full|small|tiny) (bitsliced|nibble)\n",
                argv[0]);
        return 1;
    }
    if (!strcmp(argv[1], "full")) {
        variant = GIFT128_VARIANT_FULL;
        variant_name = "GIFT128_VARIANT_FULL";
    } else if (!strcmp(argv[1], "small")) {
        variant = GIFT128_VARIANT_SMALL;
        variant_name = "GIFT128_VARIANT_SMALL";
    } else {
        variant = GIFT128_VARIANT_TINY;
        variant_name = "GIFT128_VARIANT_TINY";
    }
    if (!strcmp(argv[2], "nibble")) {
        is_nibble_based = 1;
        order_name = "gift128n";
    } else {
        is_nibble_based = 0;
        order_name = "gift128b";
    }

    /* Output the file header */
    printf("#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7\n");
    printf("#include \"internal-gift128-config.h\"\n");
    printf("#if GIFT128_VARIANT == %s\n", variant_name);
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the round constant table */
    gen_rc("rconst");

    /* Output the GIFT-128 key setup function */
    function_header(order_name, "init");
    gen_gift128_init();
    function_footer(order_name, "init");

    /* Output the primary GIFT-128 encryption function */
    function_header(order_name, "encrypt");
    gen_gift128_encrypt_tiny();
    function_footer(order_name, "encrypt");

    /* Output the preloaded GIFT-128 encryption function */
    if (!is_nibble_based) {
        function_header(order_name, "encrypt_preloaded");
        preloaded = 1;
        gen_gift128_encrypt_tiny();
        preloaded = 0;
        function_footer(order_name, "encrypt_preloaded");
    }

    /* Output the primary GIFT-128 decryption function */
    function_header(order_name, "decrypt");
    gen_gift128_decrypt_tiny();
    function_footer(order_name, "decrypt");

    /* Output the tweaked encryption and decryption functions in nibble mode */
    if (is_nibble_based) {
        order_name = "gift128t";
        is_tweaked = 1;
        /* Due to the size of the preceding code, we need another copy of
         * the round constant table because it is now too far away in the
         * text segment to reference directly. */
        gen_rc("rconst2");
        function_header(order_name, "encrypt");
        gen_gift128_encrypt_tiny();
        function_footer(order_name, "encrypt");
        function_header(order_name, "decrypt");
        gen_gift128_decrypt_tiny();
        function_footer(order_name, "decrypt");
        is_tweaked = 0;
    }

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    printf("#endif\n");
    return 0;
}
