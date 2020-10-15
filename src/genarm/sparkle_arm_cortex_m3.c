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
 * SPARKLE permutation for ARM Cortex M3 microprocessors.  With minor
 * modifications, this can probably also be used to generate assembly
 * code versions for other Cortex M variants such as M4, M7, M33, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* The 8 basic round constants from the specification */
#define RC_0 0xB7E15162
#define RC_1 0xBF715880
#define RC_2 0x38B4DA56
#define RC_3 0x324E7738
#define RC_4 0xBB1185EB
#define RC_5 0x4F7C7B57
#define RC_6 0xCFBFA1C8
#define RC_7 0xC2B3293D

/* Round constants for all SPARKLE steps; maximum of 12 for SPARKLE-512 */
static uint32_t const sparkle_rc[12] = {
    RC_0, RC_1, RC_2, RC_3, RC_4, RC_5, RC_6, RC_7,
    RC_0, RC_1, RC_2, RC_3
};

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
    const char *x0;
    const char *x1;
    const char *x2;
    const char *x3;
    const char *x4;
    const char *x5;
    const char *x6;
    const char *x7;
    const char *y0;
    const char *y1;
    const char *y2;
    const char *y3;
    const char *y4;
    const char *y5;
    const char *y6;
    const char *y7;
    const char *tx;
    const char *ty;
    const char *tz;

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

/* Add the round constants for a step */
static void add_round_constants(const reg_names *regs, int step)
{
    unsigned long rc;

    /* y0 ^= sparkle_rc[step]; */
    rc = sparkle_rc[step];
    printf("\tmovw\t%s, #%lu\n", regs->tz, rc & 0x0000FFFFUL);
    printf("\tmovt\t%s, #%lu\n", regs->tz, rc >> 16);
    binop("eor", regs->y0, regs->tz);

    /* y1 ^= step; */
    if (step != 0)
        printf("\teor\t%s, %s, #%d\n", regs->y1, regs->y1, step);
}

/* Perform the Alzette block cipher encryption operation */
static void alzette
    (const reg_names *regs, const char *x, const char *y, unsigned long k)
{
    /* Load the constant key value into a register */
    if (k) {
        printf("\tmovw\t%s, #%lu\n", regs->tz, k & 0x0000FFFFUL);
        printf("\tmovt\t%s, #%lu\n", regs->tz, k >> 16);
    }

    /* x += leftRotate1(y); */
    printf("\tadd\t%s, %s, %s, ror #31\n", x, x, y);

    /* y ^= leftRotate8(x); */
    printf("\teor\t%s, %s, %s, ror #24\n", y, y, x);

    /* x ^= k; */
    binop("eor", x, regs->tz);

    /* x += leftRotate15(y); */
    printf("\tadd\t%s, %s, %s, ror #17\n", x, x, y);

    /* y ^= leftRotate15(x); */
    printf("\teor\t%s, %s, %s, ror #17\n", y, y, x);

    /* x ^= k; */
    binop("eor", x, regs->tz);

    /* x += y; */
    binop("add", x, y);

    /* y ^= leftRotate1(x); */
    printf("\teor\t%s, %s, %s, ror #31\n", y, y, x);

    /* x ^= k; */
    binop("eor", x, regs->tz);

    /* x += leftRotate8(y); */
    printf("\tadd\t%s, %s, %s, ror #24\n", x, x, y);

    /* y ^= leftRotate16(x); */
    printf("\teor\t%s, %s, %s, ror #16\n", y, y, x);

    /* x ^= k; */
    binop("eor", x, regs->tz);
}

/* Generate the body of the SPARKLE-256 permutation function */
static void gen_sparkle_256(void)
{
    /*
     * r0 holds the pointer to the Xoodoo state on entry and exit.
     *
     * r1 holds the number of steps to perform on entry (7 or 10).
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    const char *roty;
    const char *rotx;
    int step;
    regs.x0 = "r3";
    regs.x1 = "r4";
    regs.x2 = "r5";
    regs.x3 = "r6";
    regs.x4 = 0;
    regs.x5 = 0;
    regs.x6 = 0;
    regs.x7 = 0;
    regs.y0 = "r7";
    regs.y1 = "r8";
    regs.y2 = "r9";
    regs.y3 = "r10";
    regs.y4 = 0;
    regs.y5 = 0;
    regs.y6 = 0;
    regs.y7 = 0;
    regs.tx = "r2";
    regs.ty = "ip";
    regs.tz = regs.tx;
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10}\n");

    /* Load all words of the state into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.x0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y0, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x1, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y1, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x2, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y2, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x3, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y3, 28);

    /* Unroll the steps, maximum of 10 */
    for (step = 0; step < 10; ++step) {
        /* Add round constants */
        add_round_constants(&regs, step);

        /* ARXbox layer.  One of the round constants was already
         * loaded above.  By rearranging the order of Alzette calls,
         * we can sometimes avoid double-loading the value. */
        switch (step) {
        case 0: case 8:
            alzette(&regs, regs.x0, regs.y0, 0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            break;
        case 1: case 9:
            alzette(&regs, regs.x1, regs.y1, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            break;
        case 2:
            alzette(&regs, regs.x2, regs.y2, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            break;
        case 3:
            alzette(&regs, regs.x3, regs.y3, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            break;
        default:
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            break;
        }

        /* Linear layer */
        /* tx = x0 ^ x1; */
        /* ty = y0 ^ y1; */
        /* tx = leftRotate16(tx ^ (tx << 16)); */
        /* ty = leftRotate16(ty ^ (ty << 16)); */
        printf("\teor\t%s, %s, %s\n", regs.tx, regs.x0, regs.x1);
        printf("\teor\t%s, %s, %s\n", regs.ty, regs.y0, regs.y1);
        printf("\teor\t%s, %s, %s, lsl #16\n", regs.tx, regs.tx, regs.tx);
        printf("\teor\t%s, %s, %s, lsl #16\n", regs.ty, regs.ty, regs.ty);
        printf("\tror\t%s, %s, #16\n", regs.tx, regs.tx);
        printf("\tror\t%s, %s, #16\n", regs.ty, regs.ty);
        /* y2 ^= tx; */
        /* x2 ^= ty; */
        binop("eor", regs.y2, regs.tx);
        binop("eor", regs.x2, regs.ty);
        /* tx ^= y3; */
        /* ty ^= x3; */
        binop("eor", regs.tx, regs.y3);
        binop("eor", regs.ty, regs.x3);
        /* Rotate the state virtually */
        /* y3 = y1; -- result in original y1 */
        /* x3 = x1; -- result in original x1 */
        roty = regs.y3;
        rotx = regs.x3;
        regs.y3 = regs.y1;
        regs.x3 = regs.x1;
        /* y1 = y2 ^ y0; -- result in original y2 */
        /* x1 = x2 ^ x0; -- result in original x2 */
        binop("eor", regs.y2, regs.y0);
        binop("eor", regs.x2, regs.x0);
        regs.y1 = regs.y2;
        regs.x1 = regs.x2;
        /* y2 = y0; -- result in original y0 */
        /* x2 = x0; -- result in original x0 */
        regs.y2 = regs.y0;
        regs.x2 = regs.x0;
        /* y0 = tx ^ y3; -- result in original y3 */
        /* x0 = ty ^ x3; -- result in original x3 */
        printf("\teor\t%s, %s, %s\n", roty, regs.y3, regs.tx);
        printf("\teor\t%s, %s, %s\n", rotx, regs.x3, regs.ty);
        regs.y0 = roty;
        regs.x0 = rotx;

        /* Check for early bail out after step 7.  The rotation order
         * will be different from the final order so we need to save
         * the final state words here before jumping to the end. */
        if ((step + 1) == 7) {
            printf("\tcmp\tr1, #7\n");
            printf("\tbne\t.L2561\n");
            printf("\tstr\t%s, [r0, #%d]\n", regs.x0, 0);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y0, 4);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x1, 8);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y1, 12);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x2, 16);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y2, 20);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x3, 24);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y3, 28);
            printf("\tb\t.L2563\n");
            printf(".L2561:\n");
        }
    }

    /* Store the words back to the state and exit */
    printf(".L2562:\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y0, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y1, 12);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, 16);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y2, 20);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, 24);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y3, 28);
    printf(".L2563:\n");
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10}\n");
    printf("\tbx\tlr\n");
}

/* Generate the body of the SPARKLE-384 permutation function */
static void gen_sparkle_384(void)
{
    /*
     * r0 holds the pointer to the Xoodoo state on entry and exit.
     *
     * r1 holds the number of steps to perform on entry (7 or 11).
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    const char *roty;
    const char *rotx;
    int step;
    regs.x0 = "r3";
    regs.x1 = "r4";
    regs.x2 = "r5";
    regs.x3 = "r6";
    regs.x4 = "r7";
    regs.x5 = "r8";
    regs.x6 = 0;
    regs.x7 = 0;
    regs.y0 = "r9";
    regs.y1 = "r10";
    regs.y2 = "fp";
    regs.y3 = "lr";
    regs.y4 = "r2";
    regs.y5 = "r1";
    regs.y6 = 0;
    regs.y7 = 0;
    regs.tx = "r0";
    regs.ty = "ip";
    regs.tz = regs.tx;
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Save r0 and r1 on the stack - we need them for temporaries */
    printf("\tpush\t{r0}\n");
    printf("\tpush\t{r1}\n");

    /* Load all words of the state into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.x0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y0, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x1, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y1, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x2, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y2, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x3, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y3, 28);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x4, 32);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y4, 36);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x5, 40);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y5, 44);

    /* Unroll the steps, maximum of 11 */
    for (step = 0; step < 11; ++step) {
        /* Add round constants */
        add_round_constants(&regs, step);

        /* ARXbox layer.  One of the round constants was already
         * loaded above.  By rearranging the order of Alzette calls,
         * we can sometimes avoid double-loading the value. */
        switch (step) {
        case 0: case 8:
            alzette(&regs, regs.x0, regs.y0, 0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            alzette(&regs, regs.x5, regs.y5, RC_5);
            break;
        case 1: case 9:
            alzette(&regs, regs.x1, regs.y1, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            alzette(&regs, regs.x5, regs.y5, RC_5);
            break;
        case 2: case 10:
            alzette(&regs, regs.x2, regs.y2, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            alzette(&regs, regs.x5, regs.y5, RC_5);
            break;
        case 3:
            alzette(&regs, regs.x3, regs.y3, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            alzette(&regs, regs.x5, regs.y5, RC_5);
            break;
        case 4:
            alzette(&regs, regs.x4, regs.y4, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x5, regs.y5, RC_5);
            break;
        case 5:
            alzette(&regs, regs.x5, regs.y5, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            break;
        default:
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            alzette(&regs, regs.x5, regs.y5, RC_5);
            break;
        }

        /* Linear layer */
        /* tx = x0 ^ x1 ^ x2; */
        /* ty = y0 ^ y1 ^ y2; */
        /* tx = leftRotate16(tx ^ (tx << 16)); */
        /* ty = leftRotate16(ty ^ (ty << 16)); */
        printf("\teor\t%s, %s, %s\n", regs.tx, regs.x0, regs.x1);
        printf("\teor\t%s, %s, %s\n", regs.ty, regs.y0, regs.y1);
        binop("eor", regs.tx, regs.x2);
        binop("eor", regs.ty, regs.y2);
        printf("\teor\t%s, %s, %s, lsl #16\n", regs.tx, regs.tx, regs.tx);
        printf("\teor\t%s, %s, %s, lsl #16\n", regs.ty, regs.ty, regs.ty);
        printf("\tror\t%s, %s, #16\n", regs.tx, regs.tx);
        printf("\tror\t%s, %s, #16\n", regs.ty, regs.ty);
        /* y3 ^= tx; */
        /* y4 ^= tx; */
        /* x3 ^= ty; */
        /* x4 ^= ty; */
        binop("eor", regs.y3, regs.tx);
        binop("eor", regs.x3, regs.ty);
        binop("eor", regs.y4, regs.tx);
        binop("eor", regs.x4, regs.ty);
        /* tx ^= y5; */
        /* ty ^= x5; */
        binop("eor", regs.tx, regs.y5);
        binop("eor", regs.ty, regs.x5);
        /* Rotate the state virtually */
        /* y5 = y2; -- result in original y2 */
        /* x5 = x2; -- result in original x2 */
        roty = regs.y5;
        rotx = regs.x5;
        regs.y5 = regs.y2;
        regs.x5 = regs.x2;
        /* y2 = y3 ^ y0; -- result in original y3 */
        /* x2 = x3 ^ x0; -- result in original x3 */
        binop("eor", regs.y3, regs.y0);
        binop("eor", regs.x3, regs.x0);
        regs.y2 = regs.y3;
        regs.x2 = regs.x3;
        /* y3 = y0; -- result in original y0 */
        /* x3 = x0; -- result in original x0 */
        regs.y3 = regs.y0;
        regs.x3 = regs.x0;
        /* y0 = y4 ^ y1; -- result in original y4 */
        /* x0 = x4 ^ x1; -- result in original x4 */
        binop("eor", regs.y4, regs.y1);
        binop("eor", regs.x4, regs.x1);
        regs.y0 = regs.y4;
        regs.x0 = regs.x4;
        /* y4 = y1; -- result in original y1 */
        /* x4 = x1; -- result in original x1 */
        regs.y4 = regs.y1;
        regs.x4 = regs.x1;
        /* y1 = tx ^ y5; -- result in original y5 */
        /* x1 = ty ^ x5; -- result in original x5 */
        printf("\teor\t%s, %s, %s\n", roty, regs.y5, regs.tx);
        printf("\teor\t%s, %s, %s\n", rotx, regs.x5, regs.ty);
        regs.y1 = roty;
        regs.x1 = rotx;

        /* Check for early bail out after step 7.  The rotation order
         * will be different from the final order so we need to save
         * the final state words here before jumping to the end. */
        if ((step + 1) == 7) {
            printf("\tpop\t{r0}\n"); /* Pop the step counter (originally r1) */
            printf("\tcmp\tr0, #7\n");
            printf("\tbne\t.L3841\n");
            printf("\tpop\t{r0}\n"); /* Pop the state pointer */
            printf("\tstr\t%s, [r0, #%d]\n", regs.x0, 0);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y0, 4);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x1, 8);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y1, 12);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x2, 16);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y2, 20);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x3, 24);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y3, 28);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x4, 32);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y4, 36);
            printf("\tstr\t%s, [r0, #%d]\n", regs.x5, 40);
            printf("\tstr\t%s, [r0, #%d]\n", regs.y5, 44);
            printf("\tb\t.L3843\n");
            printf(".L3841:\n");
        }
    }

    /* Store the words back to the state and exit */
    printf(".L3842:\n");
    printf("\tpop\t{r0}\n"); /* Pop the state pointer */
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y0, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y1, 12);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, 16);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y2, 20);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, 24);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y3, 28);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x4, 32);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y4, 36);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x5, 40);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y5, 44);
    printf(".L3843:\n");
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, fp, pc}\n");
}

/* Generate the body of the SPARKLE-512 permutation function */
static void gen_sparkle_512(void)
{
    /*
     * r0 holds the pointer to the Xoodoo state on entry and exit.
     *
     * r1 holds the number of steps to perform on entry (8 or 12).
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    int step;
    regs.x0 = "r3";
    regs.x1 = "r4";
    regs.x2 = "r5";
    regs.x3 = "r6";
    regs.x4 = "r7";
    regs.x5 = regs.x1; /* Aliases for convenience */
    regs.x6 = regs.x2;
    regs.x7 = regs.x0;
    regs.y0 = "r8";
    regs.y1 = "r9";
    regs.y2 = "r10";
    regs.y3 = "fp";
    regs.y4 = "lr";
    regs.y5 = regs.y1; /* Aliases for convenience */
    regs.y6 = regs.y2;
    regs.y7 = regs.y0;
    regs.tx = "r1";
    regs.ty = "r2";
    regs.tz = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Save r1 on the stack - we need it for temporaries */
    printf("\tpush\t{r1}\n");

    /* Load the first five rows into registers.  The remaining 3 will
     * be left in the state buffer.  We spill out some of the registers
     * to the state buffer when we need to process the remaining 3. */
    printf("\tldr\t%s, [r0, #%d]\n", regs.x0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y0, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x1, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y1, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x2, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y2, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x3, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y3, 28);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x4, 32);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y4, 36);
    /*
    printf("\tldr\t%s, [r0, #%d]\n", regs.x5, 40);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y5, 44);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x6, 48);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y6, 52);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x7, 56);
    printf("\tldr\t%s, [r0, #%d]\n", regs.y7, 60);
    */

    /* Unroll the steps, maximum of 12 */
    for (step = 0; step < 12; ++step) {
        /* Add round constants */
        add_round_constants(&regs, step);

        /* ARXbox layer for the first 5 rows.  ARXbox operations on the
         * remaining 3 rows are delayed until we need the values below */
        switch (step) {
        case 0: case 8:
            alzette(&regs, regs.x0, regs.y0, 0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            break;
        case 1: case 9:
            alzette(&regs, regs.x1, regs.y1, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            break;
        case 2: case 10:
            alzette(&regs, regs.x2, regs.y2, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            break;
        case 3:
            alzette(&regs, regs.x3, regs.y3, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            break;
        case 4:
            alzette(&regs, regs.x4, regs.y4, 0);
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            break;
        default:
            alzette(&regs, regs.x0, regs.y0, RC_0);
            alzette(&regs, regs.x1, regs.y1, RC_1);
            alzette(&regs, regs.x2, regs.y2, RC_2);
            alzette(&regs, regs.x3, regs.y3, RC_3);
            alzette(&regs, regs.x4, regs.y4, RC_4);
            break;
        }

        /* Linear layer */
        /* tx = x0 ^ x1 ^ x2 ^ x3; */
        /* ty = y0 ^ y1 ^ y2 ^ y3; */
        /* tx = leftRotate16(tx ^ (tx << 16)); */
        /* ty = leftRotate16(ty ^ (ty << 16)); */
        printf("\teor\t%s, %s, %s\n", regs.tx, regs.x0, regs.x1);
        printf("\teor\t%s, %s, %s\n", regs.ty, regs.y0, regs.y1);
        binop("eor", regs.tx, regs.x2);
        binop("eor", regs.ty, regs.y2);
        binop("eor", regs.tx, regs.x3);
        binop("eor", regs.ty, regs.y3);
        printf("\teor\t%s, %s, %s, lsl #16\n", regs.tx, regs.tx, regs.tx);
        printf("\teor\t%s, %s, %s, lsl #16\n", regs.ty, regs.ty, regs.ty);
        printf("\tror\t%s, %s, #16\n", regs.tx, regs.tx);
        printf("\tror\t%s, %s, #16\n", regs.ty, regs.ty);
        /* y4 ^= tx; */
        /* x4 ^= ty; */
        binop("eor", regs.y4, regs.tx);
        binop("eor", regs.x4, regs.ty);

        /* Spill rows 0, 1, and 2 and load rows 5, 6, and 7 */
        printf("\tstr\t%s, [r0, #%d]\n", regs.x0, 0);
        printf("\tstr\t%s, [r0, #%d]\n", regs.y0, 4);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x1, 8);
        printf("\tstr\t%s, [r0, #%d]\n", regs.y1, 12);
        printf("\tstr\t%s, [r0, #%d]\n", regs.x2, 16);
        printf("\tstr\t%s, [r0, #%d]\n", regs.y2, 20);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x5, 40);
        printf("\tldr\t%s, [r0, #%d]\n", regs.y5, 44);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x6, 48);
        printf("\tldr\t%s, [r0, #%d]\n", regs.y6, 52);
        printf("\tldr\t%s, [r0, #%d]\n", regs.x7, 56);
        printf("\tldr\t%s, [r0, #%d]\n", regs.y7, 60);

        /* Apply Alzette to the remaining rows */
        alzette(&regs, regs.x5, regs.y5, RC_5);
        alzette(&regs, regs.x6, regs.y6, RC_6);
        alzette(&regs, regs.x7, regs.y7, RC_7);

        /* Continue with the linear layer */
        /* y5 ^= tx; */
        /* x5 ^= ty; */
        binop("eor", regs.y5, regs.tx);
        binop("eor", regs.x5, regs.ty);
        /* y6 ^= tx; */
        /* x6 ^= ty; */
        binop("eor", regs.y6, regs.tx);
        binop("eor", regs.x6, regs.ty);
        /* tx ^= y7; */
        /* ty ^= x7; */
        binop("eor", regs.tx, regs.y7);
        binop("eor", regs.ty, regs.x7);
        /* y7 = y3; */
        /* x7 = x3; */
        printf("\tstr\t%s, [r0, #%d]\n", regs.y3, 60); /* y7 */
        printf("\tstr\t%s, [r0, #%d]\n", regs.x3, 56); /* x7 */
        /* y3 = y4 ^ y0; */
        /* x3 = x4 ^ x0; */
        printf("\tldr\t%s, [r0, #%d]\n", regs.y0, 4); /* y0 */
        printf("\tldr\t%s, [r0, #%d]\n", regs.x0, 0); /* x0 */
        printf("\teor\t%s, %s, %s\n", regs.y3, regs.y4, regs.y0);
        printf("\teor\t%s, %s, %s\n", regs.x3, regs.x4, regs.x0);
        /* y4 = y0; */
        /* x4 = x0; */
        printf("\tmov\t%s, %s\n", regs.y4, regs.y0);
        printf("\tmov\t%s, %s\n", regs.x4, regs.x0);
        /* y0 = y5 ^ y1; */
        /* x0 = x5 ^ x1; */
        /* y5 = y1; */
        /* x5 = x1; */
        printf("\tldr\t%s, [r0, #%d]\n", regs.tz, 12); /* y1 */
        printf("\teor\t%s, %s, %s\n", regs.y0, regs.y5, regs.tz);
        printf("\tstr\t%s, [r0, #%d]\n", regs.tz, 44); /* y5 */
        printf("\tldr\t%s, [r0, #%d]\n", regs.tz, 8);  /* x1 */
        printf("\teor\t%s, %s, %s\n", regs.x0, regs.x5, regs.tz);
        printf("\tstr\t%s, [r0, #%d]\n", regs.tz, 40); /* x5 */
        /* y1 = y6 ^ y2; */
        /* x1 = x6 ^ x2; */
        /* y6 = y2; */
        /* x6 = x2; */
        printf("\tldr\t%s, [r0, #%d]\n", regs.tz, 20); /* y2 */
        printf("\teor\t%s, %s, %s\n", regs.y1, regs.y6, regs.tz);
        printf("\tstr\t%s, [r0, #%d]\n", regs.tz, 52); /* y6 */
        printf("\tldr\t%s, [r0, #%d]\n", regs.tz, 16); /* x2 */
        printf("\teor\t%s, %s, %s\n", regs.x1, regs.x6, regs.tz);
        printf("\tstr\t%s, [r0, #%d]\n", regs.tz, 48); /* x6 */
        /* y2 = tx ^ y7; */
        /* x2 = ty ^ x7; */
        printf("\tldr\t%s, [r0, #%d]\n", regs.y2, 60); /* y7 */
        printf("\tldr\t%s, [r0, #%d]\n", regs.x2, 56); /* x7 */
        binop("eor", regs.y2, regs.tx);
        binop("eor", regs.x2, regs.ty);

        /* Check for early bail out after step 8 */
        if ((step + 1) == 8) {
            printf("\tpop\t{r1}\n"); /* Pop the step counter */
            printf("\tcmp\tr1, #8\n");
            printf("\tbeq\t.L512\n");
        }
    }

    /* Store the words back to the state and exit.  The bottom
     * three rows of the state have already been spilled. */
    printf(".L512:\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.x0, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y0, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x1, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y1, 12);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x2, 16);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y2, 20);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x3, 24);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y3, 28);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x4, 32);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y4, 36);
    /*
    printf("\tstr\t%s, [r0, #%d]\n", regs.x5, 40);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y5, 44);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x6, 48);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y6, 52);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x7, 56);
    printf("\tstr\t%s, [r0, #%d]\n", regs.y7, 60);
    */
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

    /* Output the SPARKLE-256 permutation function */
    function_header("sparkle_256");
    gen_sparkle_256();
    function_footer("sparkle_256");

    /* Output the SPARKLE-384 permutation function */
    function_header("sparkle_384");
    gen_sparkle_384();
    function_footer("sparkle_384");

    /* Output the SPARKLE-512 permutation function */
    function_header("sparkle_512");
    gen_sparkle_512();
    function_footer("sparkle_512");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
