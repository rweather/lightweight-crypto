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
 * TinyJAMBU permutation for ARM Cortex M3 microprocessors.  With minor
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
    const char *k0;
    const char *k1;
    const char *k2;
    const char *k3;
    const char *k4;
    const char *k5;
    const char *t0;
    const char *t1;

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

/* Perform 32 steps of the TinyJAMBU permutation */
static void tinyjambu_steps_32
    (const reg_names *regs, const char *s0, const char *s1,
     const char *s2, const char *s3, const char *kreg, int offset)
{
    /*
     * t1 = (s1 >> 15) | (s2 << 17);
     * t2 = (s2 >> 6)  | (s3 << 26);
     * t3 = (s2 >> 21) | (s3 << 11);
     * t4 = (s2 >> 27) | (s3 << 5);
     * s0 ^= t1 ^ (~(t2 & t3)) ^ t4 ^ kreg;
     */

    /* s0 ^= t1 ^ t4 */
    printf("\teor\t%s, %s, %s, lsr #15\n", s0, s0, s1);
    printf("\teor\t%s, %s, %s, lsl #17\n", s0, s0, s2);
    printf("\teor\t%s, %s, %s, lsr #27\n", s0, s0, s2);
    printf("\teor\t%s, %s, %s, lsl #5\n",  s0, s0, s3);

    /* s0 ^= ~(t2 & t3) */
    printf("\tlsr\t%s, %s, #6\n", regs->t0, s2);
    printf("\tlsr\t%s, %s, #21\n", regs->t1, s2);
    printf("\teor\t%s, %s, %s, lsl #26\n", regs->t0, regs->t0, s3);
    printf("\teor\t%s, %s, %s, lsl #11\n", regs->t1, regs->t1, s3);
    binop("and", regs->t0, regs->t1);
    binop("mvn", regs->t0, regs->t0);
    binop("eor", s0, regs->t0);

    /* XOR the key word from a register or memory offset */
    if (kreg) {
        binop("eor", s0, kreg);
    } else {
        printf("\tldr\t%s, [r1, #%d]\n", regs->t0, offset);
        binop("eor", s0, regs->t0);
    }
}

/*
 * r0 holds the pointer to the TinyJAMBU state on entry and exit.
 * r1 points to the key words on entry.
 * r2 is the number of rounds to perform (* 128 for the number of steps).
 *
 * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
 * but the value of ip may not survive across a branch instruction.
 *
 * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
 *
 * lr can be used as a temporary as long as it is saved on the stack.
 */

/* Generate the body of the TinyJAMBU-128 permutation function */
static void gen_tinyjambu_128(void)
{
    reg_names regs;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.k0 = "r7";
    regs.k1 = "r8";
    regs.k2 = "r9";
    regs.k3 = "r10";
    regs.k4 = 0;
    regs.k5 = 0;
    regs.t0 = "r1";
    regs.t1 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10}\n");

    /* Load all words of the state and the key into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k0, 0);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k1, 4);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k2, 8);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k3, 12);

    /* Top of the round loop */
    printf(".L128:\n");

    /* Perform 128 steps for this round */
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k0, 0);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k1, 4);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k2, 8);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k3, 12);

    /* Bottom of the round loop */
    printf("\tsubs\tr2, r2, #1\n");
    printf("\tbne\t.L128\n");

    /* Store the words back to the state and exit */
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10}\n");
    printf("\tbx\tlr\n");
}

/* Generate the body of the TinyJAMBU-192 permutation function */
static void gen_tinyjambu_192(void)
{
    reg_names regs;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.k0 = "r7";
    regs.k1 = "r8";
    regs.k2 = "r9";
    regs.k3 = "r10";
    regs.k4 = "fp";
    regs.k5 = "lr";
    regs.t0 = "r1";
    regs.t1 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load all words of the state and the key into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k0, 0);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k1, 4);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k2, 8);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k3, 12);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k4, 16);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k5, 20);

    /* Top of the round loop */
    printf(".L1921:\n");

    /* Unroll the loop 3 times to help with key word alignment */
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k0, 0);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k1, 4);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k2, 8);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k3, 12);
    printf("\tsubs\tr2, r2, #1\n");
    printf("\tbeq\t.L1922\n");  /* Early exit if the rounds are done */
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k4, 16);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k5, 20);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k0, 0);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k1, 4);
    printf("\tsubs\tr2, r2, #1\n");
    printf("\tbeq\t.L1922\n");  /* Early exit if the rounds are done */
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k2, 8);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k3, 12);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k4, 16);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k5, 20);

    /* Bottom of the round loop */
    printf("\tsubs\tr2, r2, #1\n");
    printf("\tbne\t.L1921\n");

    /* Store the words back to the state and exit */
    printf(".L1922:\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generate the body of the TinyJAMBU-256 permutation function */
static void gen_tinyjambu_256(void)
{
    reg_names regs;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.k0 = "r8";
    regs.k1 = "r9";
    regs.k2 = "r10";
    regs.k3 = "fp";
    regs.k4 = "lr";
    regs.k5 = 0;
    regs.t0 = "r7";
    regs.t1 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load all words of the state and most of the key into registers.
     * The last 3 key words need to be loaded on demand. */
    printf("\tldr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s3, 12);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k0, 0);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k1, 4);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k2, 8);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k3, 12);
    printf("\tldr\t%s, [r1, #%d]\n", regs.k4, 16);

    /* Top of the round loop */
    printf(".L2561:\n");

    /* Unroll the loop 2 times to help with key word alignment */
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k0, 0);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, regs.k1, 4);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, regs.k2, 8);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, regs.k3, 12);
    printf("\tsubs\tr2, r2, #1\n");
    printf("\tbeq\t.L2562\n");  /* Early exit if the rounds are done */
    tinyjambu_steps_32(&regs, regs.s0, regs.s1, regs.s2, regs.s3, regs.k4, 16);
    tinyjambu_steps_32(&regs, regs.s1, regs.s2, regs.s3, regs.s0, 0, 20);
    tinyjambu_steps_32(&regs, regs.s2, regs.s3, regs.s0, regs.s1, 0, 24);
    tinyjambu_steps_32(&regs, regs.s3, regs.s0, regs.s1, regs.s2, 0, 28);

    /* Bottom of the round loop */
    printf("\tsubs\tr2, r2, #1\n");
    printf("\tbne\t.L2561\n");

    /* Store the words back to the state and exit */
    printf(".L2562:\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.s3, 12);
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

    /* Output the TinyJAMBU-128 permutation function */
    function_header("tiny_jambu_permutation_128");
    gen_tinyjambu_128();
    function_footer("tiny_jambu_permutation_128");

    /* Output the TinyJAMBU-192 permutation function */
    function_header("tiny_jambu_permutation_192");
    gen_tinyjambu_192();
    function_footer("tiny_jambu_permutation_192");

    /* Output the TinyJAMBU-256 permutation function */
    function_header("tiny_jambu_permutation_256");
    gen_tinyjambu_256();
    function_footer("tiny_jambu_permutation_256");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
