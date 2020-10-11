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
 * Xoodoo permutation for ARM Cortex M3 microprocessors.  With minor
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
    const char *x00;
    const char *x01;
    const char *x02;
    const char *x03;
    const char *x10;
    const char *x11;
    const char *x12;
    const char *x13;
    const char *x20;
    const char *x21;
    const char *x22;
    const char *x23;
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

/* Generates a "bic" instruction: dest = src1 & ~src2 */
static void bic(const char *dest, const char *src1, const char *src2)
{
    if (!strcmp(dest, src1) && is_low_reg(src1) && is_low_reg(src2))
        printf("\tbics\t%s, %s\n", src1, src2);
    else
        printf("\tbic\t%s, %s, %s\n", dest, src1, src2);
}

/* Generate the body of the Xoodoo permutation function */
static void gen_xoodoo_permute(void)
{
    static unsigned const rc[12] = {
        0x0058, 0x0038, 0x03C0, 0x00D0, 0x0120, 0x0014,
        0x0060, 0x002C, 0x0380, 0x00F0, 0x01A0, 0x0012
    };

    /*
     * r0 holds the pointer to the Xoodoo state on entry and exit.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, fp, and lr must be callee-saved.
     */
    reg_names regs;
    const char *temp1;
    const char *temp2;
    int round;
    regs.x00 = "r1";
    regs.x01 = "r2";
    regs.x02 = "r3";
    regs.x03 = "r4";
    regs.x10 = "r5";
    regs.x11 = "r6";
    regs.x12 = "r7";
    regs.x13 = "r8";
    regs.x20 = "r9";
    regs.x21 = "r10";
    regs.x22 = "fp";
    regs.x23 = "lr";
    regs.t1 = "r0";
    regs.t2 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Load all words of the state into registers */
    printf("\tldr\t%s, [r0, #%d]\n", regs.x00, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x01, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x02, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x03, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x10, 16);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x11, 20);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x12, 24);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x13, 28);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x20, 32);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x21, 36);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x22, 40);
    printf("\tldr\t%s, [r0, #%d]\n", regs.x23, 44);
    printf("\tpush\t{r0}\n"); /* Free up r0 for use as an extra temporary */

    /* Unroll the rounds */
    for (round = 0; round < 12; ++round) {
        /* Step theta: Mix column parity */
        /* t1 = x03 ^ x13 ^ x23; */
        /* t2 = x00 ^ x10 ^ x20; */
        printf("\teor\t%s, %s, %s\n", regs.t1, regs.x03, regs.x13);
        printf("\teor\t%s, %s, %s\n", regs.t2, regs.x00, regs.x10);
        binop("eor", regs.t1, regs.x23);
        binop("eor", regs.t2, regs.x20);
        /* t1 = leftRotate5(t1) ^ leftRotate14(t1); */
        /* t2 = leftRotate5(t2) ^ leftRotate14(t2); */
        printf("\tror\t%s, %s, #18\n", regs.t1, regs.t1);
        printf("\tror\t%s, %s, #18\n", regs.t2, regs.t2);
        printf("\teor\t%s, %s, %s, ror #9\n", regs.t1, regs.t1, regs.t1);
        printf("\teor\t%s, %s, %s, ror #9\n", regs.t2, regs.t2, regs.t2);
        /* x00 ^= t1; */
        /* x10 ^= t1; */
        /* x20 ^= t1; */
        binop("eor", regs.x00, regs.t1);
        binop("eor", regs.x10, regs.t1);
        binop("eor", regs.x20, regs.t1);
        /* t1 = x01 ^ x11 ^ x21; */
        printf("\teor\t%s, %s, %s\n", regs.t1, regs.x01, regs.x11);
        binop("eor", regs.t1, regs.x21);
        /* t1 = leftRotate5(t1) ^ leftRotate14(t1); */
        printf("\tror\t%s, %s, #18\n", regs.t1, regs.t1);
        printf("\teor\t%s, %s, %s, ror #9\n", regs.t1, regs.t1, regs.t1);
        /* x01 ^= t2; */
        /* x11 ^= t2; */
        /* x21 ^= t2; */
        binop("eor", regs.x01, regs.t2);
        binop("eor", regs.x11, regs.t2);
        binop("eor", regs.x21, regs.t2);
        /* t2 = x02 ^ x12 ^ x22; */
        printf("\teor\t%s, %s, %s\n", regs.t2, regs.x02, regs.x12);
        binop("eor", regs.t2, regs.x22);
        /* t2 = leftRotate5(t2) ^ leftRotate14(t2); */
        printf("\tror\t%s, %s, #18\n", regs.t2, regs.t2);
        printf("\teor\t%s, %s, %s, ror #9\n", regs.t2, regs.t2, regs.t2);
        /* x02 ^= t1; */
        /* x12 ^= t1; */
        /* x22 ^= t1; */
        binop("eor", regs.x02, regs.t1);
        binop("eor", regs.x12, regs.t1);
        binop("eor", regs.x22, regs.t1);
        /* x03 ^= t2; */
        /* x13 ^= t2; */
        /* x23 ^= t2; */
        binop("eor", regs.x03, regs.t2);
        binop("eor", regs.x13, regs.t2);
        binop("eor", regs.x23, regs.t2);

        /* Step rho-west: Plane shift */
        /* t1 = x13; */
        /* x13 = x12; */
        /* x12 = x11; */
        /* x11 = x10; */
        /* x10 = t1; */
        temp1 = regs.x13;
        regs.x13 = regs.x12;
        regs.x12 = regs.x11;
        regs.x11 = regs.x10;
        regs.x10 = temp1;
        /* x20 = leftRotate11(x20); */
        /* x21 = leftRotate11(x21); */
        /* x22 = leftRotate11(x22); */
        /* x23 = leftRotate11(x23); */
        printf("\tror\t%s, %s, #21\n", regs.x20, regs.x20);
        printf("\tror\t%s, %s, #21\n", regs.x21, regs.x21);
        printf("\tror\t%s, %s, #21\n", regs.x22, regs.x22);
        printf("\tror\t%s, %s, #21\n", regs.x23, regs.x23);

        /* Step iota: Add the round constant to the state */
        /* x00 ^= rc[round]; */
        printf("\teor\t%s, %s, #%d\n", regs.x00, regs.x00, rc[round]);

        /* Step chi: Non-linear layer */
        /* x00 ^= (~x10) & x20; */
        bic(regs.t1, regs.x20, regs.x10);
        binop("eor", regs.x00, regs.t1);
        /* x10 ^= (~x20) & x00; */
        bic(regs.t2, regs.x00, regs.x20);
        binop("eor", regs.x10, regs.t2);
        /* x20 ^= (~x00) & x10; */
        bic(regs.t1, regs.x10, regs.x00);
        binop("eor", regs.x20, regs.t1);
        /* x01 ^= (~x11) & x21; */
        bic(regs.t2, regs.x21, regs.x11);
        binop("eor", regs.x01, regs.t2);
        /* x11 ^= (~x21) & x01; */
        bic(regs.t1, regs.x01, regs.x21);
        binop("eor", regs.x11, regs.t1);
        /* x21 ^= (~x01) & x11; */
        bic(regs.t2, regs.x11, regs.x01);
        binop("eor", regs.x21, regs.t2);
        /* x02 ^= (~x12) & x22; */
        bic(regs.t1, regs.x22, regs.x12);
        binop("eor", regs.x02, regs.t1);
        /* x12 ^= (~x22) & x02; */
        bic(regs.t2, regs.x02, regs.x22);
        binop("eor", regs.x12, regs.t2);
        /* x22 ^= (~x02) & x12; */
        bic(regs.t1, regs.x12, regs.x02);
        binop("eor", regs.x22, regs.t1);
        /* x03 ^= (~x13) & x23; */
        bic(regs.t2, regs.x23, regs.x13);
        binop("eor", regs.x03, regs.t2);
        /* x13 ^= (~x23) & x03; */
        bic(regs.t1, regs.x03, regs.x23);
        binop("eor", regs.x13, regs.t1);
        /* x23 ^= (~x03) & x13; */
        bic(regs.t2, regs.x13, regs.x03);
        binop("eor", regs.x23, regs.t2);

        /* Step rho-east: Plane shift */
        /* x10 = leftRotate1(x10); */
        /* x11 = leftRotate1(x11); */
        /* x12 = leftRotate1(x12); */
        /* x13 = leftRotate1(x13); */
        printf("\tror\t%s, %s, #31\n", regs.x10, regs.x10);
        printf("\tror\t%s, %s, #31\n", regs.x11, regs.x11);
        printf("\tror\t%s, %s, #31\n", regs.x12, regs.x12);
        printf("\tror\t%s, %s, #31\n", regs.x13, regs.x13);
        /* t1 = leftRotate8(x22); */
        /* t2 = leftRotate8(x23); */
        /* x22 = leftRotate8(x20); */
        /* x23 = leftRotate8(x21); */
        /* x20 = t1; */
        /* x21 = t2; */
        printf("\tror\t%s, %s, #24\n", regs.x20, regs.x20);
        printf("\tror\t%s, %s, #24\n", regs.x21, regs.x21);
        printf("\tror\t%s, %s, #24\n", regs.x22, regs.x22);
        printf("\tror\t%s, %s, #24\n", regs.x23, regs.x23);
        temp1 = regs.x22;
        temp2 = regs.x23;
        regs.x22 = regs.x20;
        regs.x23 = regs.x21;
        regs.x20 = temp1;
        regs.x21 = temp2;
    }

    /* Store the words back to the state and exit */
    printf("\tpop\t{r0}\n");
    printf("\tstr\t%s, [r0, #%d]\n", regs.x00, 0);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x01, 4);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x02, 8);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x03, 12);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x10, 16);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x11, 20);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x12, 24);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x13, 28);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x20, 32);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x21, 36);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x22, 40);
    printf("\tstr\t%s, [r0, #%d]\n", regs.x23, 44);
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

    /* Output the Xoodoo permutation function */
    function_header("xoodoo_permute");
    gen_xoodoo_permute();
    function_footer("xoodoo_permute");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
