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
 * CHAM block cipher for ARM Cortex M3 microprocessors.  With minor
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
    const char *x0;
    const char *x1;
    const char *x2;
    const char *x3;
    const char *k0;
    const char *k1;
    const char *k2;
    const char *k3;
    const char *k4;
    const char *k5;
    const char *k6;
    const char *k7;
    const char *t0;
    const char *t1;

} reg_names;

/*
 * r0 holds the pointer to the CHAM key.
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

/* Generate the body of the CHAM-128 block cipher encrypt function */
static void gen_encrypt_cham128(void)
{
    reg_names regs;
    int round;
    regs.x0 = "r3";
    regs.x1 = "r4";
    regs.x2 = "r5";
    regs.x3 = "r6";
    regs.k0 = "r2";
    regs.k1 = "r7";
    regs.k2 = "r8";
    regs.k3 = "r9";
    regs.k4 = "r10";
    regs.k5 = "r0";
    regs.k6 = "fp";
    regs.k7 = "lr";
    regs.t0 = "r1";
    regs.t1 = "ip";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, fp, lr}\n");

    /* Save r1 on the stack because we need it for temporaries */
    printf("\tpush\t{r1}\n");

    /* Load all words of the state and the key into registers */
    printf("\tldr\t%s, [r2, #%d]\n", regs.x0, 0);
    printf("\tldr\t%s, [r2, #%d]\n", regs.x1, 4);
    printf("\tldr\t%s, [r2, #%d]\n", regs.x2, 8);
    printf("\tldr\t%s, [r2, #%d]\n", regs.x3, 12);
    printf("\tldr\t%s, [r0, #%d]\n", regs.k0, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.k1, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.k2, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.k3, 12);

    /* Generate the key schedule:
     *
     * k[4] = k[1] ^ leftRotate1(k[1]) ^ leftRotate11(k[1]);
     * k[5] = k[0] ^ leftRotate1(k[0]) ^ leftRotate11(k[0]);
     * k[6] = k[3] ^ leftRotate1(k[3]) ^ leftRotate11(k[3]);
     * k[7] = k[2] ^ leftRotate1(k[2]) ^ leftRotate11(k[2]);
     * k[0] ^= leftRotate1(k[0]) ^ leftRotate8(k[0]);
     * k[1] ^= leftRotate1(k[1]) ^ leftRotate8(k[1]);
     * k[2] ^= leftRotate1(k[2]) ^ leftRotate8(k[2]);
     * k[3] ^= leftRotate1(k[3]) ^ leftRotate8(k[3]);
     */
    printf("\teor\t%s, %s, %s, ror #31\n", regs.k4, regs.k1, regs.k1);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.k5, regs.k0, regs.k0);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.k6, regs.k3, regs.k3);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.k7, regs.k2, regs.k2);
    printf("\teor\t%s, %s, %s, ror #21\n", regs.k4, regs.k4, regs.k1);
    printf("\teor\t%s, %s, %s, ror #21\n", regs.k5, regs.k5, regs.k0);
    printf("\teor\t%s, %s, %s, ror #21\n", regs.k6, regs.k6, regs.k3);
    printf("\teor\t%s, %s, %s, ror #21\n", regs.k7, regs.k7, regs.k2);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.t0, regs.k0, regs.k0);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.t1, regs.k1, regs.k1);
    printf("\teor\t%s, %s, %s, ror #24\n", regs.k0, regs.t0, regs.k0);
    printf("\teor\t%s, %s, %s, ror #24\n", regs.k1, regs.t1, regs.k1);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.t0, regs.k2, regs.k2);
    printf("\teor\t%s, %s, %s, ror #31\n", regs.t1, regs.k3, regs.k3);
    printf("\teor\t%s, %s, %s, ror #24\n", regs.k2, regs.t0, regs.k2);
    printf("\teor\t%s, %s, %s, ror #24\n", regs.k3, regs.t1, regs.k3);

    /* Unroll all 80 rounds, 8 at a time */
    for (round = 0; round < 80; round += 8) {
        /* x0 = leftRotate8((x0 ^ round)       + (leftRotate1(x1) ^ k[0])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x0, round);
        printf("\teor\t%s, %s, %s, ror #31\n", regs.t1, regs.k0, regs.x1);
        printf("\tadd\t%s, %s, %s\n", regs.x0, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #24\n", regs.x0, regs.x0);

        /* x1 = leftRotate1((x1 ^ (round + 1)) + (leftRotate8(x2) ^ k[1])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x1, round + 1);
        printf("\teor\t%s, %s, %s, ror #24\n", regs.t1, regs.k1, regs.x2);
        printf("\tadd\t%s, %s, %s\n", regs.x1, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #31\n", regs.x1, regs.x1);

        /* x2 = leftRotate8((x2 ^ (round + 2)) + (leftRotate1(x3) ^ k[2])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x2, round + 2);
        printf("\teor\t%s, %s, %s, ror #31\n", regs.t1, regs.k2, regs.x3);
        printf("\tadd\t%s, %s, %s\n", regs.x2, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #24\n", regs.x2, regs.x2);

        /* x3 = leftRotate1((x3 ^ (round + 3)) + (leftRotate8(x0) ^ k[3])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x3, round + 3);
        printf("\teor\t%s, %s, %s, ror #24\n", regs.t1, regs.k3, regs.x0);
        printf("\tadd\t%s, %s, %s\n", regs.x3, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #31\n", regs.x3, regs.x3);

        /* x0 = leftRotate8((x0 ^ (round + 4)) + (leftRotate1(x1) ^ k[4])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x0, round + 4);
        printf("\teor\t%s, %s, %s, ror #31\n", regs.t1, regs.k4, regs.x1);
        printf("\tadd\t%s, %s, %s\n", regs.x0, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #24\n", regs.x0, regs.x0);

        /* x1 = leftRotate1((x1 ^ (round + 5)) + (leftRotate8(x2) ^ k[5])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x1, round + 5);
        printf("\teor\t%s, %s, %s, ror #24\n", regs.t1, regs.k5, regs.x2);
        printf("\tadd\t%s, %s, %s\n", regs.x1, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #31\n", regs.x1, regs.x1);

        /* x2 = leftRotate8((x2 ^ (round + 6)) + (leftRotate1(x3) ^ k[6])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x2, round + 6);
        printf("\teor\t%s, %s, %s, ror #31\n", regs.t1, regs.k6, regs.x3);
        printf("\tadd\t%s, %s, %s\n", regs.x2, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #24\n", regs.x2, regs.x2);

        /* x3 = leftRotate1((x3 ^ (round + 7)) + (leftRotate8(x0) ^ k[7])); */
        printf("\teor\t%s, %s, #%d\n", regs.t0, regs.x3, round + 7);
        printf("\teor\t%s, %s, %s, ror #24\n", regs.t1, regs.k7, regs.x0);
        printf("\tadd\t%s, %s, %s\n", regs.x3, regs.t1, regs.t0);
        printf("\tror\t%s, %s, #31\n", regs.x3, regs.x3);
    }

    /* Store the words back to the state and exit */
    printf("\tpop\t{r1}\n");
    printf("\tstr\t%s, [r1, #%d]\n", regs.x0, 0);
    printf("\tstr\t%s, [r1, #%d]\n", regs.x1, 4);
    printf("\tstr\t%s, [r1, #%d]\n", regs.x2, 8);
    printf("\tstr\t%s, [r1, #%d]\n", regs.x3, 12);
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

    /* Output the CHAM-128 encryption function */
    function_header("cham128_128_encrypt");
    gen_encrypt_cham128();
    function_footer("cham128_128_encrypt");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
