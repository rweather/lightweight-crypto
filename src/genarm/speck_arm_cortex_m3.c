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
 * SPECK block cipher for ARM Cortex M3 microprocessors.  With minor
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
    const char *x;
    const char *y;
    const char *s;
    const char *l0;
    const char *l1;
    const char *l2;

} reg_names;

/*
 * r0 holds the pointer to the SPECK key.
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

/* Generate the body of the SPECK-64 block cipher encrypt function */
static void gen_encrypt_speck64(void)
{
    reg_names regs;
    int round;
    regs.x = "r3";
    regs.y = "r4";
    regs.s = "r5";
    regs.l0 = "r2";
    regs.l1 = "ip";
    regs.l2 = "r0";
    printf("\tpush\t{r4, r5}\n");

    /* Load all words of the state and the key into registers */
    printf("\tldr\t%s, [r2, #%d]\n", regs.y, 0);
    printf("\tldr\t%s, [r2, #%d]\n", regs.x, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.s, 0);
    printf("\tldr\t%s, [r0, #%d]\n", regs.l0, 4);
    printf("\tldr\t%s, [r0, #%d]\n", regs.l1, 8);
    printf("\tldr\t%s, [r0, #%d]\n", regs.l2, 12);

    /* Perform all 27 encryption rounds 3 at a time */
    for (round = 0; round < 27; round += 3) {
        /*
         * Each round:
         *
         * x = (rightRotate8(x) + y) ^ s;
         * y = leftRotate3(y) ^ x;
         * l = (s + rightRotate8(l)) ^ round;
         * s = leftRotate3(s) ^ l;
         */

        /* Round 0 */
        printf("\tadd\t%s, %s, %s, ror #8\n", regs.x, regs.y, regs.x);
        printf("\teors\t%s, %s\n", regs.x, regs.s);
        printf("\teor\t%s, %s, %s, ror #29\n", regs.y, regs.x, regs.y);
        printf("\tadd\t%s, %s, %s, ror #8\n", regs.l0, regs.s, regs.l0);
        printf("\teor\t%s, %s, #%d\n", regs.l0, regs.l0, round);
        printf("\teor\t%s, %s, %s, ror #29\n", regs.s, regs.l0, regs.s);

        /* Round 1 */
        printf("\tadd\t%s, %s, %s, ror #8\n", regs.x, regs.y, regs.x);
        printf("\teors\t%s, %s\n", regs.x, regs.s);
        printf("\teor\t%s, %s, %s, ror #29\n", regs.y, regs.x, regs.y);
        printf("\tadd\t%s, %s, %s, ror #8\n", regs.l1, regs.s, regs.l1);
        printf("\teor\t%s, %s, #%d\n", regs.l1, regs.l1, round + 1);
        printf("\teor\t%s, %s, %s, ror #29\n", regs.s, regs.l1, regs.s);

        /* Round 2 */
        printf("\tadd\t%s, %s, %s, ror #8\n", regs.x, regs.y, regs.x);
        printf("\teors\t%s, %s\n", regs.x, regs.s);
        printf("\teor\t%s, %s, %s, ror #29\n", regs.y, regs.x, regs.y);
        if ((round + 3) < 27) {
            /* No need to calculate next key schedule word on the last round */
            printf("\tadd\t%s, %s, %s, ror #8\n", regs.l2, regs.s, regs.l2);
            printf("\teor\t%s, %s, #%d\n", regs.l2, regs.l2, round + 2);
            printf("\teor\t%s, %s, %s, ror #29\n", regs.s, regs.l2, regs.s);
        }
    }

    /* Store the words back to the state and exit */
    printf("\tstr\t%s, [r1, #%d]\n", regs.y, 0);
    printf("\tstr\t%s, [r1, #%d]\n", regs.x, 4);
    printf("\tpop\t{r4, r5}\n");
    printf("\tbx\tlr\n");
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
    function_header("speck64_128_encrypt");
    gen_encrypt_speck64();
    function_footer("speck64_128_encrypt");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
