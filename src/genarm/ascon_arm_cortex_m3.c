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

typedef struct
{
    const char *x0;
    const char *x1;
    const char *x2;
    const char *x3;
    const char *x4;
    const char *t0;
    const char *t1;
    const char *t2;

} sbox_reg_names;

/* Applies the S-box to 5 words of the state */
static void gen_sbox(const sbox_reg_names *regs)
{
    /* S-box with only 3 temporary registers, not the usual 5 */
    binop("eor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("eor", regs->x4, regs->x3);       /* x4 ^= x3; */
    binop("eor", regs->x2, regs->x1);       /* x2 ^= x1; */
    binop("mov", regs->t1, regs->x0);       /* t1 = x0; */
    binop("mvn", regs->t0, regs->x0);       /* t0 = (~x0) & x1; */
    binop("and", regs->t0, regs->x1);
    binop("mvn", regs->t2, regs->x1);       /* x0 ^= (~x1) & x2; */
    binop("and", regs->t2, regs->x2);
    binop("eor", regs->x0, regs->t2);
    binop("mvn", regs->t2, regs->x2);       /* x1 ^= (~x2) & x3; */
    binop("and", regs->t2, regs->x3);
    binop("eor", regs->x1, regs->t2);
    binop("mvn", regs->t2, regs->x3);       /* x2 ^= (~x3) & x4; */
    binop("and", regs->t2, regs->x4);
    binop("eor", regs->x2, regs->t2);
    binop("mvn", regs->t2, regs->x4);       /* x3 ^= (~x4) & t1; */
    binop("and", regs->t2, regs->t1);
    binop("eor", regs->x3, regs->t2);
    binop("eor", regs->x4, regs->t0);       /* x4 ^= t0; */
    binop("eor", regs->x1, regs->x0);       /* x1 ^= x0; */
    binop("eor", regs->x0, regs->x4);       /* x0 ^= x4; */
    binop("eor", regs->x3, regs->x2);       /* x3 ^= x2; */
    binop("mvn", regs->x2, regs->x2);       /* x2 = ~x2; */
}

/* Generate the code for a single ASCON round */
static void gen_round(const reg_names *regs, int round)
{
    /* Round constants for all rounds */
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    sbox_reg_names sbox_regs;

    /* Apply the round constants to x2_e and x2_o */
    printf("\teor\t%s, %s, #%d\n", regs->x2_e, regs->x2_e, RC[round * 2]);
    printf("\teor\t%s, %s, #%d\n", regs->x2_o, regs->x2_o, RC[round * 2 + 1]);

    /* Apply the S-box to the even and odd halves of the state */
    sbox_regs.x0 = regs->x0_e;
    sbox_regs.x1 = regs->x1_e;
    sbox_regs.x2 = regs->x2_e;
    sbox_regs.x3 = regs->x3_e;
    sbox_regs.x4 = regs->x4_e;
    sbox_regs.t0 = regs->t0;
    sbox_regs.t1 = regs->t1;
    sbox_regs.t2 = regs->t2;
    gen_sbox(&sbox_regs);
    sbox_regs.x0 = regs->x0_o;
    sbox_regs.x1 = regs->x1_o;
    sbox_regs.x2 = regs->x2_o;
    sbox_regs.x3 = regs->x3_o;
    sbox_regs.x4 = regs->x4_o;
    gen_sbox(&sbox_regs);

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

/* Generate the body of the ascon_permute_sliced() function */
static void gen_permute(void)
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
     */
    reg_names regs;
    int round;
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
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp}\n");

    /* Load all words of the state into registers */
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
    printf("\tpush\t{r0}\n"); /* Free up r0 for use as an extra temporary */

    /* Determine which round is first and jump ahead.  Most of the time,
     * we will be seeing "first round" set to 6, 0, or 4 so we handle
     * those cases first.  But we can do any number of rounds.   If the
     * "first round" value is 12 or higher, then we will do nothing. */
    printf("\tcmp\tr1, #6\n");
    printf("\tbeq\t.L6\n");
    printf("\tcmp\tr1, #0\n");
    printf("\tbeq\t.L0\n");
    printf("\tcmp\tr1, #4\n");
    printf("\tbeq\t.L4\n");
    for (round = 11; round > 0; --round) {
        if (round == 0 || round == 4 || round == 6)
            continue;
        printf("\tcmp\tr1, #%d\n", round);
        printf("\tbeq\t.L%d\n", round);
    }
    printf("\tb\t.L12\n");

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        printf(".L%d:\n", round);
        gen_round(&regs, round);
    }

    /* Store the words back to the state and exit */
    printf(".L12:\n");
    printf("\tpop\t{r0}\n");
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
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp}\n");
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

    /* Output the sliced version of the permutation function */
    function_header("ascon_permute_sliced");
    gen_permute();
    function_footer("ascon_permute_sliced");

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
