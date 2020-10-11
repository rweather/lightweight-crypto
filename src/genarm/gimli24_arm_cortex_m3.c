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
 * GIMLI24 permutation for ARM Cortex M3 microprocessors.  With minor
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
    printf("\t.size\t%s, .-%s\n", name, name);
}

/* List of all registers that we can work with */
typedef struct
{
    const char *s0;
    const char *s1;
    const char *s2;
    const char *s3;
    const char *s4;
    const char *s5;
    const char *s6;
    const char *s7;
    const char *s8;
    const char *s9;
    const char *s10;
    const char *s11;
    const char *x;
    const char *y;

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

/* Evaluate the GIMLI24 SP-box */
static void gen_gimli24_sp
    (const char *x, const char *y, const char *s0,
     const char *s4, const char *s8)
{
    /* x = leftRotate24(s0); */
    printf("\tror\t%s, %s, #8\n", x, s0);

    /* y = leftRotate9(s4); */
    printf("\tror\t%s, %s, #23\n", y, s4);

    /* s4 = y ^ x ^ ((x | s8) << 1); */
    printf("\torr\t%s, %s, %s\n", s4, x, s8);
    printf("\teor\t%s, %s, %s, lsl #1\n", s4, y, s4);
    binop("eor", s4, x);

    /* s0 = s8 ^ y ^ ((x & y) << 3); */
    printf("\tand\t%s, %s, %s\n", s0, x, y);
    printf("\teor\t%s, %s, %s, lsl #3\n", s0, y, s0);
    binop("eor", s0, s8);

    /* s8 = x ^ (s8 << 1) ^ ((y & s8) << 2); */
    printf("\tand\t%s, %s, %s\n", y, y, s8);
    printf("\teor\t%s, %s, %s, lsl #1\n", s8, x, s8);
    printf("\teor\t%s, %s, %s, lsl #2\n", s8, s8, y);
}

/* Generate the body of the gascon_permute() function */
static void gen_permute(void)
{
    /*
     * r0 holds the pointer to the GIMLI24 state on entry.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    const char *t0;
    const char *t1;
    unsigned long RC;
    int round;
    regs.s0 = "r1";
    regs.s1 = "r2";
    regs.s2 = "r3";
    regs.s3 = "r4";
    regs.s4 = "r5";
    regs.s5 = "r6";
    regs.s6 = "r7";
    regs.s7 = "r8";
    regs.s8 = "r9";
    regs.s9 = "r10";
    regs.s10 = "fp";
    regs.s11 = "lr";
    regs.x = "ip";
    regs.y = "r0";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load all words of the state into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s4, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s5, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s6, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s7, 28);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s8, 32);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s9, 36);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s10, 40);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s11, 44);
    printf("\tpush\t{r0}\n"); /* Free up r0 for use as an extra temporary */

    /* Perform all rounds 4 at a time */
    for (round = 24; round > 0; round -= 4) {
        /* Round 0: SP-box, small swap, add round constant */
        #define GIMLI24_SP(a, b, c) \
            gen_gimli24_sp(regs.x, regs.y, regs.a, regs.b, regs.c)
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);
        t0 = regs.s0;
        t1 = regs.s2;
        RC = 0x9e377900UL ^ round;
        printf("\tmovw\t%s, #%lu\n", regs.y, RC & 0x0000FFFFUL);
        printf("\tmovt\t%s, #%lu\n", regs.y, RC >> 16);
        binop("eor", regs.s1, regs.y);
        regs.s0 = regs.s1;
        regs.s1 = t0;
        regs.s2 = regs.s3;
        regs.s3 = t1;

        /* Round 1: SP-box only */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);

        /* Round 2: SP-box, big swap */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);
        t0 = regs.s0;
        t1 = regs.s1;
        regs.s0 = regs.s2;
        regs.s1 = regs.s3;
        regs.s2 = t0;
        regs.s3 = t1;

        /* Round 3: SP-box only */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);
    }

    /* Store the words back to the state and exit */
    printf("\tpop\t{r0}\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s4, 16);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s5, 20);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s6, 24);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s7, 28);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s8, 32);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s9, 36);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s10, 40);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s11, 44);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
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

    /* Output the GIMLI24 permutation function */
    function_header("gimli24_permute");
    gen_permute();
    function_footer("gimli24_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
