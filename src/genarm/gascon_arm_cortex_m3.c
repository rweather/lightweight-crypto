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
 * GASCON permutation for ARM Cortex M3 microprocessors.  With minor
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

/* Rotate a 32-bit source and write to a destination */
static void rotate(const char *dest, const char *src, int shift)
{
    if (shift != 0)
        printf("\tmov\t%s, %s, ror #%d\n", dest, src, shift);
    else
        binop("mov", dest, src);
}

/* Rotate a 32-bit word and XOR it with itself */
static void rotate_xor(const char *reg, int shift)
{
    printf("\teor\t%s, %s, %s, ror #%d\n", reg, reg, reg, shift);
}

/* Performs two interleaved rotations on a 64-bit register pair and
 * XOR's the results with the register pair */
static void intRightRotate
    (const reg_names *regs, const char *xe, const char *xo,
     int shift1, int shift2)
{
    /* One of the shifts will be even and the other odd.  Odd shifts
     * involve a word swap.  Make sure that "shift2" is the even one. */
    if (shift2 & 1) {
        int temp = shift1;
        shift1 = shift2;
        shift2 = temp;
    }

    /* Compute "x ^= (x >>> shift1) ^ (x >>> shift2)" */
    if (shift1 == 1) {
        binop("mov", regs->t0, xo);
        rotate(regs->t1, xe, 1);
    } else {
        rotate(regs->t0, xo, shift1 / 2);
        rotate(regs->t1, xe, ((shift1 / 2) + 1) % 32);
    }
    rotate_xor(xe, shift2 / 2);
    rotate_xor(xo, shift2 / 2);
    binop("eor", xe, regs->t0);
    binop("eor", xo, regs->t1);
}

/* Generate the code for a single GASCON round */
static void gen_round(const reg_names *regs, int round)
{
    int RC;
    sbox_reg_names sbox_regs;

    /* Apply the round constant to x2_e */
    RC = ((0x0F - round) << 4) | round;
    printf("\teor\t%s, %s, #%d\n", regs->x2_e, regs->x2_e, RC);

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

    /* x0 ^= intRightRotate19_64(x0) ^ intRightRotate28_64(x0); */
    intRightRotate(regs, regs->x0_e, regs->x0_o, 19, 28);

    /* x1 ^= intRightRotate61_64(x1) ^ intRightRotate38_64(x1); */
    intRightRotate(regs, regs->x1_e, regs->x1_o, 61, 38);

    /* x2 ^= intRightRotate1_64(x2)  ^ intRightRotate6_64(x2); */
    intRightRotate(regs, regs->x2_e, regs->x2_o, 1, 6);

    /* x3 ^= intRightRotate10_64(x3) ^ intRightRotate17_64(x3); */
    intRightRotate(regs, regs->x3_e, regs->x3_o, 10, 17);

    /* x4 ^= intRightRotate7_64(x4)  ^ intRightRotate40_64(x4); */
    intRightRotate(regs, regs->x4_e, regs->x4_o, 7, 40);
}

/* Generate the body of the gascon_permute() function */
static void gen_permute(void)
{
    /*
     * r0 holds the pointer to the GASCON state on entry and exit.
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

int main(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    /* Output the file header */
    printf("#if defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7\n");
    printf("\t.syntax unified\n");
    printf("\t.thumb\n");
    printf("\t.text\n");

    /* Output the GASCON permutation function */
    function_header("gascon_permute");
    gen_permute();
    function_footer("gascon_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
