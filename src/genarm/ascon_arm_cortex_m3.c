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
 * ASCON permutation for ARM Cortex M3 microprocessors.  With minor
 * modifications, this can probably also be used to generate assembly
 * code versions for other Cortex M variants such as M4, M7, M33, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void function_header(const char *name)
{
    printf("\n\t.align\t2\n");
    printf("\t.global\t%s\n", name);
    printf("\t.thumb\n");
    printf("\t.thumb_func\n");
    printf("\t.type\t%s, %%function\n", name);
    printf("%s:\n", name);
}

static void function_footer(const char *name)
{
    printf("\tbx\tlr\n");
    printf("\t.size\t%s, .-%s\n", name, name);
}

static void function_footer_no_lr(const char *name)
{
    printf("\t.size\t%s, .-%s\n", name, name);
}

/* List of all registers that we can work with */
typedef struct
{
    const char *x0_e;
    const char *x1_e;
    const char *x2_e;
    const char *x3_e;
    const char *x4_e;
    const char *x0_o;
    const char *x1_o;
    const char *x2_o;
    const char *x3_o;
    const char *x4_o;
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;

} reg_names;

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

/* Generates a "bic" instruction: dest = src1 & ~src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    if (!strcmp(dest, src1) && is_low_reg(src1) && is_low_reg(src2))
        printf("\tbics\t%s, %s\n", src1, src2);
    else
        printf("\tbic\t%s, %s, %s\n", dest, src1, src2);
}

/* Applies the S-box to five 64-bit words of the state */
static void gen_sbox(const reg_names *regs)
{
    binop("eor", regs->x0_e, regs->x4_e);       /* x0_e ^= x4_e; */
    binop("eor", regs->x0_o, regs->x4_o);       /* x0_o ^= x4_o; */
    binop("eor", regs->x4_e, regs->x3_e);       /* x4_e ^= x3_e; */
    binop("eor", regs->x4_o, regs->x3_o);       /* x4_o ^= x3_o; */
    binop("eor", regs->x2_e, regs->x1_e);       /* x2_e ^= x1_e; */
    binop("eor", regs->x2_o, regs->x1_o);       /* x2_o ^= x1_o; */
    bic(regs->t0, regs->x1_e, regs->x0_e);      /* t0 = (~x0_e) & x_e1; */
    bic(regs->t2, regs->x2_e, regs->x1_e);      /* x0_e ^= (~x1_e) & x2_e; */
    bic(regs->t3, regs->x3_e, regs->x2_e);      /* x1_e ^= (~x2_e) & x3_e; */
    binop("eor", regs->x1_e, regs->t3);
    bic(regs->t3, regs->x0_e, regs->x4_e);      /* x3_e ^= (~x4_e) & t1; */
    binop("eor", regs->x0_e, regs->t2);
    bic(regs->t2, regs->x4_e, regs->x3_e);      /* x2_e ^= (~x3_e) & x4_e; */
    binop("eor", regs->x2_e, regs->t2);
    binop("eor", regs->x3_e, regs->t3);
    binop("eor", regs->x4_e, regs->t0);         /* x4_e ^= t0_e; */
    bic(regs->t0, regs->x1_o, regs->x0_o);      /* t0 = (~x0_o) & x_o1; */
    bic(regs->t2, regs->x2_o, regs->x1_o);      /* x0_o ^= (~x1_o) & x2_o; */
    bic(regs->t3, regs->x3_o, regs->x2_o);      /* x1_o ^= (~x2_o) & x3_o; */
    binop("eor", regs->x1_o, regs->t3);
    bic(regs->t3, regs->x0_o, regs->x4_o);      /* x3_o ^= (~x4_o) & t1; */
    binop("eor", regs->x0_o, regs->t2);
    bic(regs->t2, regs->x4_o, regs->x3_o);      /* x2_o ^= (~x3_o) & x4_o; */
    binop("eor", regs->x2_o, regs->t2);
    binop("eor", regs->x3_o, regs->t3);
    binop("eor", regs->x4_o, regs->t0);         /* x4_o ^= t0_o; */
    binop("eor", regs->x1_e, regs->x0_e);       /* x1_e ^= x0_e; */
    binop("eor", regs->x1_o, regs->x0_o);       /* x1_o ^= x0_o; */
    binop("eor", regs->x0_e, regs->x4_e);       /* x0_e ^= x4_e; */
    binop("eor", regs->x0_o, regs->x4_o);       /* x0_o ^= x4_o; */
    binop("eor", regs->x3_e, regs->x2_e);       /* x3_e ^= x2_e; */
    binop("eor", regs->x3_o, regs->x2_o);       /* x3_o ^= x2_o; */
    binop("mvn", regs->x2_e, regs->x2_e);       /* x2_e = ~x2_e; */
    binop("mvn", regs->x2_o, regs->x2_o);       /* x2_o = ~x2_o; */
}

static void linear_xor
    (const char *xl, const char *xh, const char *t0, const char *t1, int shift)
{
    if (shift < 32) {
        printf("\teor\t%s, %s, %s, lsr #%d\n", xl, xl, t0, shift);
        printf("\teor\t%s, %s, %s, lsr #%d\n", xh, xh, t1, shift);
        printf("\teor\t%s, %s, %s, lsl #%d\n", xl, xl, t1, 32 - shift);
        printf("\teor\t%s, %s, %s, lsl #%d\n", xh, xh, t0, 32 - shift);
    } else {
        shift -= 32;
        printf("\teor\t%s, %s, %s, lsr #%d\n", xl, xl, t1, shift);
        printf("\teor\t%s, %s, %s, lsr #%d\n", xh, xh, t0, shift);
        printf("\teor\t%s, %s, %s, lsl #%d\n", xl, xl, t0, 32 - shift);
        printf("\teor\t%s, %s, %s, lsl #%d\n", xh, xh, t1, 32 - shift);
    }
}

/* Perform a non-sliced linear diffusion step */
static void linear
    (const reg_names *regs, const char *xl, const char *xh,
     int shift1, int shift2)
{
    binop("mov", regs->t0, xl);
    binop("mov", regs->t1, xh);
    linear_xor(xl, xh, regs->t0, regs->t1, shift1);
    linear_xor(xl, xh, regs->t0, regs->t1, shift2);
}

/* Generate the code for a single ASCON round */
static void gen_round(const reg_names *regs, int round)
{
    /* Apply the round constant to x2 */
    printf("\teor\t%s, %s, #%d\n", regs->x2_e, regs->x2_e,
           ((0x0F - round) << 4) | round);

    /* Apply the S-box to the even and odd halves of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    linear(regs, regs->x0_e, regs->x0_o, 19, 28);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    linear(regs, regs->x1_e, regs->x1_o, 61, 39);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    linear(regs, regs->x2_e, regs->x2_o, 1, 6);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    linear(regs, regs->x3_e, regs->x3_o, 10, 17);

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    linear(regs, regs->x4_e, regs->x4_o, 7, 41);
}

/* Generate the code for a single sliced ASCON round */
static void gen_round_sliced(const reg_names *regs, int round)
{
    /* Round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };

    /* Apply the round constants to x2_e and x2_o */
    printf("\teor\t%s, %s, #%d\n", regs->x2_e, regs->x2_e, RC[round * 2]);
    printf("\teor\t%s, %s, #%d\n", regs->x2_o, regs->x2_o, RC[round * 2 + 1]);

    /* Apply the S-box to the even and odd halves of the state */
    gen_sbox(regs);

    /* Linear diffusion layer */

    /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
    // t0 = x0_e ^ rightRotate4(x0_o);
    // t1 = x0_o ^ rightRotate5(x0_e);
    // x0_e ^= rightRotate9(t1);
    // x0_o ^= rightRotate10(t0);
    printf("\teor\t%s, %s, %s, ror #4\n", regs->t0, regs->x0_e, regs->x0_o);
    printf("\teor\t%s, %s, %s, ror #5\n", regs->t1, regs->x0_o, regs->x0_e);
    printf("\teor\t%s, %s, %s, ror #10\n", regs->x0_o, regs->x0_o, regs->t0);
    printf("\teor\t%s, %s, %s, ror #9\n", regs->x0_e, regs->x0_e, regs->t1);

    /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
    // t0 = x1_e ^ rightRotate11(x1_e);
    // t1 = x1_o ^ rightRotate11(x1_o);
    // x1_e ^= rightRotate19(t1);
    // x1_o ^= rightRotate20(t0);
    printf("\teor\t%s, %s, %s, ror #11\n", regs->t0, regs->x1_e, regs->x1_e);
    printf("\teor\t%s, %s, %s, ror #11\n", regs->t1, regs->x1_o, regs->x1_o);
    printf("\teor\t%s, %s, %s, ror #20\n", regs->x1_o, regs->x1_o, regs->t0);
    printf("\teor\t%s, %s, %s, ror #19\n", regs->x1_e, regs->x1_e, regs->t1);

    /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
    // t0 = x2_e ^ rightRotate2(x2_o);
    // t1 = x2_o ^ rightRotate3(x2_e);
    // x2_e ^= t1;
    // x2_o ^= rightRotate1(t0);
    printf("\teor\t%s, %s, %s, ror #2\n", regs->t0, regs->x2_e, regs->x2_o);
    printf("\teor\t%s, %s, %s, ror #3\n", regs->t1, regs->x2_o, regs->x2_e);
    printf("\teor\t%s, %s, %s, ror #1\n", regs->x2_o, regs->x2_o, regs->t0);
    binop("eor", regs->x2_e, regs->t1);

    /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
    // t0 = x3_e ^ rightRotate3(x3_o);
    // t1 = x3_o ^ rightRotate4(x3_e);
    // x3_e ^= rightRotate5(t0);
    // x3_o ^= rightRotate5(t1);
    printf("\teor\t%s, %s, %s, ror #3\n", regs->t0, regs->x3_e, regs->x3_o);
    printf("\teor\t%s, %s, %s, ror #4\n", regs->t1, regs->x3_o, regs->x3_e);
    printf("\teor\t%s, %s, %s, ror #5\n", regs->x3_e, regs->x3_e, regs->t0);
    printf("\teor\t%s, %s, %s, ror #5\n", regs->x3_o, regs->x3_o, regs->t1);

    /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
    // t0 = x4_e ^ rightRotate17(x4_e);
    // t1 = x4_o ^ rightRotate17(x4_o);
    // x4_e ^= rightRotate3(t1);
    // x4_o ^= rightRotate4(t0);
    printf("\teor\t%s, %s, %s, ror #17\n", regs->t0, regs->x4_e, regs->x4_e);
    printf("\teor\t%s, %s, %s, ror #17\n", regs->t1, regs->x4_o, regs->x4_o);
    printf("\teor\t%s, %s, %s, ror #4\n", regs->x4_o, regs->x4_o, regs->t0);
    printf("\teor\t%s, %s, %s, ror #3\n", regs->x4_e, regs->x4_e, regs->t1);
}

/* Swap the bytes in a word */
static void swap(const char *reg)
{
    printf("\trev\t%s, %s\n", reg, reg);
}

/* Generate the body of the ASCON permutation function */
static void gen_permute(int is_sliced)
{
    /*
     * r0 holds the pointer to the ASCON state on entry and exit.
     *
     * r1 is the "first round" parameter on entry, which will normally be
     * one of the values 0, 4, or 6.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs;
    int round;
    const char *prefix = is_sliced ? "L" : "LP";
    regs.x0_e = "r2";
    regs.x1_e = "r3";
    regs.x2_e = "r4";
    regs.x3_e = "r5";
    regs.x4_e = "r6";
    regs.x0_o = "r7";
    regs.x1_o = "r8";
    regs.x2_o = "r9";
    regs.x3_o = "r10";
    regs.x4_o = "fp";
    regs.t0 = "r0";
    regs.t1 = "r1";
    regs.t2 = "ip";
    regs.t3 = "lr";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load all words of the state into registers */
    if (is_sliced) {
        printf("\tldr\t%s, [r0, #%d]\n", regs.x0_e, 0);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x0_o, 4);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x1_e, 8);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x1_o, 12);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x2_e, 16);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x2_o, 20);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x3_e, 24);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x3_o, 28);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x4_e, 32);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x4_o, 36);
    } else {
        printf("\tldr\t%s, [r0, #%d]\n", regs.x0_o, 0);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x0_e, 4);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x1_o, 8);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x1_e, 12);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x2_o, 16);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x2_e, 20);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x3_o, 24);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x3_e, 28);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x4_o, 32);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x4_e, 36);
        swap(regs.x0_o); swap(regs.x0_e);
        swap(regs.x1_o); swap(regs.x1_e);
        swap(regs.x2_o); swap(regs.x2_e);
        swap(regs.x3_o); swap(regs.x3_e);
        swap(regs.x4_o); swap(regs.x4_e);
    }
    printf("\tpush\t{r0}\n"); /* Free up r0 for use as an extra temporary */

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    printf("\tcmp\tr1, #6\n");
    printf("\tbeq\t.%s6\n", prefix);
    printf("\tcmp\tr1, #0\n");
    printf("\tbeq\t.%s0\n", prefix);
    printf("\tcmp\tr1, #4\n");
    printf("\tbeq\t.%s4\n", prefix);
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf("\tcmp\tr1, #%d\n", round);
        printf("\tbeq\t.%s%d\n", prefix, round);
    }
    printf("\tb\t.%s12\n", prefix);

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".%s%d:\n", prefix, round);
        if (is_sliced)
            gen_round_sliced(&regs, round);
        else
            gen_round(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".%s12:\n", prefix);
    printf("\tpop\t{r0}\n");
    if (is_sliced) {
        printf("\tstr\t%s, [r0, #%d]\n", regs.x0_e, 0);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x0_o, 4);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x1_e, 8);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x1_o, 12);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x2_e, 16);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x2_o, 20);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x3_e, 24);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x3_o, 28);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x4_e, 32);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x4_o, 36);
    } else {
        swap(regs.x0_o); swap(regs.x0_e);
        swap(regs.x1_o); swap(regs.x1_e);
        swap(regs.x2_o); swap(regs.x2_e);
        swap(regs.x3_o); swap(regs.x3_e);
        swap(regs.x4_o); swap(regs.x4_e);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x0_o, 0);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x0_e, 4);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x1_o, 8);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x1_e, 12);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x2_o, 16);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x2_e, 20);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x3_o, 24);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x3_e, 28);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x4_o, 32);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x4_e, 36);
    }
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Do two bit_permute_step() operations in parallel to improve scheduling */
static void bit_permute_step_two
    (const char *y1, const char *y2, const char *t1, const char *t2,
     const char *t3, unsigned long mask, int shift)
{
    /* t = ((y >> (shift)) ^ y) & (mask);
     * y = (y ^ t) ^ (t << (shift)); */
    if (t3)
        printf("\tmovw\t%s, #%lu\n", t3, mask);
    printf("\teor\t%s, %s, %s, lsr #%d\n", t1, y1, y1, shift);
    printf("\teor\t%s, %s, %s, lsr #%d\n", t2, y2, y2, shift);
    if (t3) {
        binop("and", t1, t3);
        binop("and", t2, t3);
    } else {
        printf("\tand\t%s, %s, #%lu\n", t1, t1, mask);
        printf("\tand\t%s, %s, #%lu\n", t2, t2, mask);
    }
    binop("eor", y1, t1);
    binop("eor", y2, t2);
    printf("\teor\t%s, %s, %s, lsl #%d\n", y1, y1, t1, shift);
    printf("\teor\t%s, %s, %s, lsl #%d\n", y2, y2, t2, shift);
}

/* Output the function to convert to sliced form */
static void gen_to_sliced(void)
{
    /*
     * r0 holds the pointer to the ASCON state to be rearranged.
     * r1, r2, r3, and ip can be used as scratch registers without saving.
     */
    const char *state = "r0";
    const char *high = "r1";
    const char *low = "r2";
    const char *temp1 = "r3";
    const char *temp2 = "ip";
    int index;
    for (index = 0; index < 40; index += 8) {
        /* load high and low from the state */
        printf("\tldr\t%s, [%s, #%d]\n", high, state, index);
        printf("\tldr\t%s, [%s, #%d]\n", low, state, index + 4);

        /* ascon_separate(high) and ascon_separate(low) */
        bit_permute_step_two(high, low, temp1, temp2, 0, 0x22222222, 1);
        bit_permute_step_two(high, low, temp1, temp2, 0, 0x0c0c0c0c, 2);
        bit_permute_step_two(high, low, temp1, temp2, 0, 0x000f000f, 12);
        bit_permute_step_two(high, low, temp1, temp2, 0, 0x000000ff, 24);

        /* rearrange and store back */
        printf("\tuxth\t%s, %s\n", temp1, low);
        printf("\torr\t%s, %s, %s, lsl #16\n", temp1, temp1, high);
        printf("\tlsrs\t%s, %s, #16\n", high, high);
        printf("\tstr\t%s, [%s, #%d]\n", temp1, state, index);
        printf("\tlsls\t%s, %s, #16\n", temp2, high);
        printf("\torr\t%s, %s, %s, lsr #%d\n", temp2, temp2, low, 16);
        printf("\tstr\t%s, [%s, #%d]\n", temp2, state, index + 4);
    }
}

/* Output the function to convert from sliced form */
static void gen_from_sliced(void)
{
    /*
     * r0 holds the pointer to the ASCON state to be rearranged.
     * r1, r2, r3, and ip can be used as scratch registers without saving.
     */
    const char *state = "r0";
    const char *high = "r1";
    const char *low = "r2";
    const char *temp1 = "r3";
    const char *temp2 = "ip";
    const char *temp3 = "r4";
    int index;
    printf("\tpush\t{%s}\n", temp3);
    for (index = 0; index < 40; index += 8) {
        /* load high and low from the state */
        printf("\tldr\t%s, [%s, #%d]\n", high, state, index);
        printf("\tldr\t%s, [%s, #%d]\n", low, state, index + 4);

        /* rearrange the half words */
        printf("\tlsrs\t%s, %s, #16\n", temp1, low);
        printf("\tlsls\t%s, %s, #16\n", temp1, temp1);
        printf("\tuxth\t%s, %s\n", temp2, high);
        printf("\torr\t%s, %s, %s, lsr #16\n", high, temp1, high);
        printf("\torr\t%s, %s, %s, lsl #16\n", low, temp2, low);

        /* ascon_combine(high) and ascon_combine(low) */
        bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000aaaa, 15);
        bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000cccc, 14);
        bit_permute_step_two(high, low, temp1, temp2, temp3, 0x0000f0f0, 12);
        bit_permute_step_two(high, low, temp1, temp2, 0,     0x000000ff, 24);
        printf("\tstr\t%s, [%s, #%d]\n", high, state, index);
        printf("\tstr\t%s, [%s, #%d]\n", low, state, index + 4);
    }
    printf("\tpop\t{%s}\n", temp3);
}

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7\n");
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the regular version of the permutation function */
    function_header("ascon_permute");
    gen_permute(0);
    function_footer_no_lr("ascon_permute");

    /* Output the sliced version of the permutation function */
    function_header("ascon_permute_sliced");
    gen_permute(1);
    function_footer_no_lr("ascon_permute_sliced");

    /* Output the function to convert to sliced form */
    function_header("ascon_to_sliced");
    gen_to_sliced();
    function_footer("ascon_to_sliced");

    /* Output the function to convert from sliced form */
    function_header("ascon_from_sliced");
    gen_from_sliced();
    function_footer("ascon_from_sliced");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
