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
 * Pyjamask block cipher for ARM Cortex M3 microprocessors.  With minor
 * modifications, this can probably also be used to generate assembly
 * code versions for other Cortex M variants such as M4, M7, M33, etc.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define PYJAMASK_ROUNDS 14

static int label = 1;
static int alt_multiply = 0;

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
    const char *t0;
    const char *t1;
    const char *t2;
    const char *t3;
    const char *tc;

} reg_names;

/* Performs a circulant binary matrix multiplication */
static void pyjamask_matrix_multiply
    (const reg_names *regs, uint32_t x, const char *y, int move)
{
    int bit;
    if (!alt_multiply) {
        /* Traditional multiplication with first parameter constant */
        printf("\tmovw\t%s, #%d\n", regs->t2, (int)(x & 0xFFFFU));
        printf("\tmovt\t%s, #%d\n", regs->t2, (int)((x >> 16) & 0xFFFFU));
        for (bit = 31; bit >= 0; bit -= 2) {
            /* result ^= x & -((y >> bit) & 1); */
            /* x = rightRotate1(x); */
            printf("\tsbfx\t%s, %s, #%d, #1\n", regs->t0, y, bit);
            printf("\tsbfx\t%s, %s, #%d, #1\n", regs->t1, y, bit - 1);
            if (bit == 31) {
                printf("\tand\t%s, %s, %s\n", regs->t3, regs->t0, regs->t2);
                printf("\tand\t%s, %s, %s, ror #1\n",
                       regs->t1, regs->t1, regs->t2);
                binop("eor", regs->t3, regs->t1);
            } else {
                printf("\tand\t%s, %s, %s, ror #%d\n",
                       regs->t0, regs->t0, regs->t2, 31 - bit);
                printf("\tand\t%s, %s, %s, ror #%d\n",
                       regs->t1, regs->t1, regs->t2, 31 - (bit - 1));
                binop("eor", regs->t3, regs->t0);
                binop("eor", regs->t3, regs->t1);
            }
        }
        if (move)
            binop("mov", y, regs->t3);
    } else {
        /* Faster version with the second parameter constant.  We only
         * need to do a rotate and XOR for each 1 bit in the constant */
        int t0_set = 0;
        int t1_set = 0;
        int t2_set = 0;
        int t3_set = 0;
        int phase = 0;
        for (bit = 31; bit >= 0; --bit) {
            if (!(x & (1 << bit)))
                continue;
            switch (phase) {
            case 0:
                if (t0_set) {
                    printf("\teor\t%s, %s, %s, ror #%d\n",
                           regs->t0, regs->t0, y, 31 - bit);
                } else {
                    printf("\tror\t%s, %s, #%d\n", regs->t0, y, 31 - bit);
                    t0_set = 1;
                }
                phase = 1;
                break;
            case 1:
                if (t1_set) {
                    printf("\teor\t%s, %s, %s, ror #%d\n",
                           regs->t1, regs->t1, y, 31 - bit);
                } else {
                    printf("\tror\t%s, %s, #%d\n", regs->t1, y, 31 - bit);
                    t1_set = 1;
                }
                phase = 2;
                break;
            case 2:
                if (t2_set) {
                    printf("\teor\t%s, %s, %s, ror #%d\n",
                           regs->t2, regs->t2, y, 31 - bit);
                } else {
                    printf("\tror\t%s, %s, #%d\n", regs->t2, y, 31 - bit);
                    t2_set = 1;
                }
                phase = 3;
                break;
            default:
                if (t3_set) {
                    printf("\teor\t%s, %s, %s, ror #%d\n",
                           regs->t3, regs->t3, y, 31 - bit);
                } else {
                    printf("\tror\t%s, %s, #%d\n", regs->t3, y, 31 - bit);
                    t3_set = 1;
                }
                phase = 0;
                break;
            }
        }
        if (move) {
            printf("\teor\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
            printf("\teor\t%s, %s, %s\n", y, regs->t2, regs->t3);
            binop("eor", y, regs->t0);
        } else {
            printf("\teor\t%s, %s, %s\n", regs->t0, regs->t0, regs->t1);
            printf("\teor\t%s, %s, %s\n", regs->t3, regs->t2, regs->t3);
            binop("eor", regs->t3, regs->t0);
        }
    }
}

/* Generate the body of the Pyjamask setup function */
static void gen_setup_pyjamask(int block_bits)
{
    /*
     * r0 holds the pointer to the output Pyjamask-128 key schedule.
     * r1 points to the input key.
     *
     * r0, r1, r2, r3, and ip can be used as scratch registers without saving,
     * but the value of ip may not survive across a branch instruction.
     *
     * r4, r5, r6, r7, r8, r9, r10, and fp must be callee-saved.
     *
     * lr can be used as a temporary as long as it is saved on the stack.
     */
    reg_names regs;
    int top_label;
    regs.k0 = "r2";
    regs.k1 = "r3";
    regs.k2 = "r4";
    regs.k3 = "r5";
    regs.t0 = "r1";
    regs.t1 = "r6";
    regs.t2 = "r7";
    regs.t3 = "ip";
    regs.tc = "r8";
    regs.s0 = "r9";
    regs.s1 = "r10";
    regs.s2 = "lr";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9, r10, lr}\n");

    /* Load all words of the key into registers and byte-swap */
    printf("\tldr\t%s, [r1]\n",      regs.k0);
    printf("\tldr\t%s, [r1, #4]\n",  regs.k1);
    printf("\tldr\t%s, [r1, #8]\n",  regs.k2);
    printf("\tldr\t%s, [r1, #12]\n", regs.k3);
    printf("\trev\t%s, %s\n", regs.k0, regs.k0);
    printf("\trev\t%s, %s\n", regs.k1, regs.k1);
    printf("\trev\t%s, %s\n", regs.k2, regs.k2);
    printf("\trev\t%s, %s\n", regs.k3, regs.k3);

    /* The first round key is the same as the key itself */
    printf("\tstr\t%s, [r0], #4\n", regs.k0);
    printf("\tstr\t%s, [r0], #4\n", regs.k1);
    printf("\tstr\t%s, [r0], #4\n", regs.k2);
    if (block_bits == 128)
        printf("\tstr\t%s, [r0], #4\n", regs.k3);

    /* We need some immediate values in registers for round constants below */
    /* s0 = 0x00006a00U; */
    /* s1 = 0x003f0000U; */
    /* s2 = 0x24000000U; */
    printf("\tmovw\t%s, #%d\n", regs.s0, 0x6a00);
    printf("\tmovw\t%s, #%d\n", regs.s1, 0);
    printf("\tmovt\t%s, #%d\n", regs.s1, 0x003f);
    printf("\tmovw\t%s, #%d\n", regs.s2, 0);
    printf("\tmovt\t%s, #%d\n", regs.s2, 0x2400);

    /* Derive the round keys for all of the other rounds */
    top_label = label++;
    printf("\tmov\t%s, #128\n", regs.tc); /* 0x80 */
    printf(".L%d:\n", top_label);

    /* Mix the columns */
    /* temp = k0 ^ k1 ^ k2 ^ k3; */
    /* k0 ^= temp; */
    /* k1 ^= temp; */
    /* k2 ^= temp; */
    /* k3 ^= temp; */
    printf("\teor\t%s, %s, %s\n", regs.t0, regs.k0, regs.k1);
    printf("\teor\t%s, %s, %s\n", regs.t1, regs.k2, regs.k3);
    binop("eor", regs.t0, regs.t1);
    binop("eor", regs.k0, regs.t0);
    binop("eor", regs.k1, regs.t0);
    binop("eor", regs.k2, regs.t0);
    binop("eor", regs.k3, regs.t0);

    /* Mix the rows and add the round constants */
    /* k0 = pyjamask_matrix_multiply(0xb881b9caU, k0) ^ 0x00000080U ^ round; */
    /* k1 = rightRotate8(k1)  ^ 0x00006a00U; */
    /* k2 = rightRotate15(k2) ^ 0x003f0000U; */
    /* k3 = rightRotate18(k3) ^ 0x24000000U; */
    pyjamask_matrix_multiply(&regs, 0xb881b9caU, regs.k0, 0);
    printf("\teor\t%s, %s, %s, ror #8\n", regs.k1, regs.s0, regs.k1);
    printf("\teor\t%s, %s, %s\n", regs.k0, regs.t3, regs.tc);
    printf("\teor\t%s, %s, %s, ror #15\n", regs.k2, regs.s1, regs.k2);
    printf("\teor\t%s, %s, %s, ror #18\n", regs.k3, regs.s2, regs.k3);

    /* Write the round key to the schedule */
    printf("\tstr\t%s, [r0], #4\n", regs.k0);
    printf("\tstr\t%s, [r0], #4\n", regs.k1);
    printf("\tstr\t%s, [r0], #4\n", regs.k2);
    if (block_bits == 128)
        printf("\tstr\t%s, [r0], #4\n", regs.k3);

    /* Bottom of the round loop */
    printf("\tadd\t%s, %s, #1\n", regs.tc, regs.tc);
    printf("\tcmp\t%s, #%d\n", regs.tc, 0x80 + PYJAMASK_ROUNDS);
    printf("\tbne\t.L%d\n", top_label);

    /* Clean up and exit */
    printf("\tpop\t{r4, r5, r6, r7, r8, r9, r10, pc}\n");
}

/* Generate the body of the Pyjamask-128 block cipher encrypt function */
static void gen_encrypt_pyjamask128(void)
{
    /*
     * r0 holds the pointer to the Pyjamask-128 key schedule.
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
    reg_names regs;
    int top_label;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.t0 = "r2";
    regs.t1 = "r7";
    regs.t2 = "r8";
    regs.t3 = "ip";
    regs.tc = "r9";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9}\n");

    /* Load all words of the state into registers and byte-swap */
    printf("\tldr\t%s, [r2]\n",      regs.s0);
    printf("\tldr\t%s, [r2, #4]\n",  regs.s1);
    printf("\tldr\t%s, [r2, #8]\n",  regs.s2);
    printf("\tldr\t%s, [r2, #12]\n", regs.s3);
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);
    printf("\trev\t%s, %s\n", regs.s3, regs.s3);

    /* Perform all rounds */
    top_label = label++;
    printf("\tmov\t%s, #%d\n", regs.tc, PYJAMASK_ROUNDS);
    printf(".L%d:\n", top_label);

    /* Add the round key to the state */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    /* s3 ^= rk[3]; */
    printf("\tldr\t%s, [r0], #4\n", regs.t0);
    printf("\tldr\t%s, [r0], #4\n", regs.t1);
    printf("\tldr\t%s, [r0], #4\n", regs.t2);
    printf("\tldr\t%s, [r0], #4\n", regs.t3);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s3, regs.t3);

    /* Apply the 128-bit Pyjamask sbox */
    /* s0 ^= s3; */
    binop("eor", regs.s0, regs.s3);
    /* s3 ^= s0 & s1; */
    /* s0 ^= s1 & s2; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s0, regs.s1);
    printf("\tand\t%s, %s, %s\n", regs.t1, regs.s1, regs.s2);
    binop("eor", regs.s3, regs.t0);
    binop("eor", regs.s0, regs.t1);
    /* s1 ^= s2 & s3; */
    /* s2 ^= s0 & s3; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s2, regs.s3);
    printf("\tand\t%s, %s, %s\n", regs.t1, regs.s0, regs.s3);
    binop("eor", regs.s1, regs.t0);
    binop("eor", regs.s2, regs.t1);
    /* s2 ^= s1; */
    /* s1 ^= s0; */
    /* s3 = ~s3; */
    /* swap(s2, s3); */
    printf("\teor\t%s, %s, %s\n", regs.t0, regs.s2, regs.s1);
    binop("eor", regs.s1, regs.s0);
    binop("mvn", regs.s2, regs.s3);
    binop("mov", regs.s3, regs.t0);

    /* Mix the rows of the state */
    pyjamask_matrix_multiply(&regs, 0xa3861085U, regs.s0, 1);
    pyjamask_matrix_multiply(&regs, 0x63417021U, regs.s1, 1);
    pyjamask_matrix_multiply(&regs, 0x692cf280U, regs.s2, 1);
    pyjamask_matrix_multiply(&regs, 0x48a54813U, regs.s3, 1);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.tc, regs.tc);
    printf("\tbne\t.L%d\n", top_label);

    /* Mix in the key one last time */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    /* s3 ^= rk[3]; */
    printf("\tldr\t%s, [r0]\n",      regs.t0);
    printf("\tldr\t%s, [r0, #4]\n",  regs.t1);
    printf("\tldr\t%s, [r0, #8]\n",  regs.t2);
    printf("\tldr\t%s, [r0, #12]\n", regs.t3);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s3, regs.t3);

    /* Store the words back to the state and exit */
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);
    printf("\trev\t%s, %s\n", regs.s3, regs.s3);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9}\n");
    printf("\tbx\tlr\n");
}

/* Generate the body of the Pyjamask-128 block cipher decrypt function */
static void gen_decrypt_pyjamask128(void)
{
    /*
     * r0 holds the pointer to the Pyjamask-128 key schedule.
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
    reg_names regs;
    int top_label;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.s3 = "r6";
    regs.t0 = "r2";
    regs.t1 = "r7";
    regs.t2 = "r8";
    regs.t3 = "ip";
    regs.tc = "r9";
    printf("\tpush\t{r4, r5, r6, r7, r8, r9}\n");

    /* Advance to the end of the key schedule */
    printf("\tadd\tr0, r0, #%d\n", 16 * PYJAMASK_ROUNDS);

    /* Load all words of the state into registers and byte-swap */
    printf("\tldr\t%s, [r2]\n",      regs.s0);
    printf("\tldr\t%s, [r2, #4]\n",  regs.s1);
    printf("\tldr\t%s, [r2, #8]\n",  regs.s2);
    printf("\tldr\t%s, [r2, #12]\n", regs.s3);
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);
    printf("\trev\t%s, %s\n", regs.s3, regs.s3);

    /* Mix in the last round key */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    /* s3 ^= rk[3]; */
    printf("\tldr\t%s, [r0]\n",      regs.t0);
    printf("\tldr\t%s, [r0, #4]\n",  regs.t1);
    printf("\tldr\t%s, [r0, #8]\n",  regs.t2);
    printf("\tldr\t%s, [r0, #12]\n", regs.t3);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s3, regs.t3);

    /* Perform all rounds */
    top_label = label++;
    printf("\tmov\t%s, #%d\n", regs.tc, PYJAMASK_ROUNDS);
    printf(".L%d:\n", top_label);

    /* Inverse mix of the rows in the state */
    pyjamask_matrix_multiply(&regs, 0x2037a121U, regs.s0, 1);
    pyjamask_matrix_multiply(&regs, 0x108ff2a0U, regs.s1, 1);
    pyjamask_matrix_multiply(&regs, 0x9054d8c0U, regs.s2, 1);
    pyjamask_matrix_multiply(&regs, 0x3354b117U, regs.s3, 0);

    /* Apply the inverse of the 128-bit Pyjamask sbox */
    /* swap(s2, s3); */
    /* s3 = ~s3; */
    binop("mvn", regs.s3, regs.s2);
    binop("mov", regs.s2, regs.t3);
    /* s1 ^= s0; */
    binop("eor", regs.s1, regs.s0);
    /* s2 ^= s1; */
    binop("eor", regs.s2, regs.s1);
    /* s2 ^= s0 & s3; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s0, regs.s3);
    binop("eor", regs.s2, regs.t0);
    /* s1 ^= s2 & s3; */
    printf("\tand\t%s, %s, %s\n", regs.t1, regs.s2, regs.s3);
    binop("eor", regs.s1, regs.t1);
    /* s0 ^= s1 & s2; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s1, regs.s2);
    binop("eor", regs.s0, regs.t0);
    /* s3 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs.t1, regs.s0, regs.s1);
    binop("eor", regs.s3, regs.t1);
    /* s0 ^= s3; */
    binop("eor", regs.s0, regs.s3);

    /* Add the round key to the state */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    /* s3 ^= rk[3]; */
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t3);
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t2);
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t1);
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t0);
    binop("eor", regs.s3, regs.t3);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s0, regs.t0);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.tc, regs.tc);
    printf("\tbne\t.L%d\n", top_label);

    /* Store the words back to the state and exit */
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);
    printf("\trev\t%s, %s\n", regs.s3, regs.s3);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s2, 8);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s3, 12);
    printf("\tpop\t{r4, r5, r6, r7, r8, r9}\n");
    printf("\tbx\tlr\n");
}

/* Generate the body of the Pyjamask-96 block cipher encrypt function */
static void gen_encrypt_pyjamask96(void)
{
    /*
     * r0 holds the pointer to the Pyjamask-96 key schedule.
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
    reg_names regs;
    int top_label;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.t0 = "r2";
    regs.t1 = "r6";
    regs.t2 = "r7";
    regs.t3 = "ip";
    regs.tc = "r8";
    printf("\tpush\t{r4, r5, r6, r7, r8}\n");

    /* Load all words of the state into registers and byte-swap */
    printf("\tldr\t%s, [r2]\n",      regs.s0);
    printf("\tldr\t%s, [r2, #4]\n",  regs.s1);
    printf("\tldr\t%s, [r2, #8]\n",  regs.s2);
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);

    /* Perform all rounds */
    top_label = label++;
    printf("\tmov\t%s, #%d\n", regs.tc, PYJAMASK_ROUNDS);
    printf(".L%d:\n", top_label);

    /* Add the round key to the state */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    printf("\tldr\t%s, [r0], #4\n", regs.t0);
    printf("\tldr\t%s, [r0], #4\n", regs.t1);
    printf("\tldr\t%s, [r0], #4\n", regs.t2);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);

    /* Apply the 96-bit Pyjamask sbox */
    /* s0 ^= s1; */
    binop("eor", regs.s0, regs.s1);
    /* s1 ^= s2; */
    binop("eor", regs.s1, regs.s2);
    /* s2 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s0, regs.s1);
    binop("eor", regs.s2, regs.t0);
    /* s0 ^= s1 & s2; */
    printf("\tand\t%s, %s, %s\n", regs.t1, regs.s1, regs.s2);
    binop("eor", regs.s0, regs.t1);
    /* s1 ^= s0 & s2; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s0, regs.s2);
    binop("eor", regs.s1, regs.t0);
    /* s2 ^= s0; */
    binop("eor", regs.s2, regs.s0);
    /* s1 ^= s0; */
    binop("eor", regs.s1, regs.s0);
    /* s0 ^= s1; */
    binop("eor", regs.s0, regs.s1);
    /* s2 = ~s2; */
    binop("mvn", regs.s2, regs.s2);

    /* Mix the rows of the state */
    pyjamask_matrix_multiply(&regs, 0xa3861085U, regs.s0, 1);
    pyjamask_matrix_multiply(&regs, 0x63417021U, regs.s1, 1);
    pyjamask_matrix_multiply(&regs, 0x692cf280U, regs.s2, 1);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.tc, regs.tc);
    printf("\tbne\t.L%d\n", top_label);

    /* Mix in the key one last time */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    printf("\tldr\t%s, [r0]\n",      regs.t0);
    printf("\tldr\t%s, [r0, #4]\n",  regs.t1);
    printf("\tldr\t%s, [r0, #8]\n",  regs.t2);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);

    /* Store the words back to the state and exit */
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s2, 8);
    printf("\tpop\t{r4, r5, r6, r7, r8}\n");
    printf("\tbx\tlr\n");
}

/* Generate the body of the Pyjamask-96 block cipher decrypt function */
static void gen_decrypt_pyjamask96(void)
{
    /*
     * r0 holds the pointer to the Pyjamask-96 key schedule.
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
    reg_names regs;
    int top_label;
    regs.s0 = "r3";
    regs.s1 = "r4";
    regs.s2 = "r5";
    regs.t0 = "r2";
    regs.t1 = "r6";
    regs.t2 = "r7";
    regs.t3 = "ip";
    regs.tc = "r8";
    printf("\tpush\t{r4, r5, r6, r7, r8}\n");

    /* Advance to the end of the key schedule */
    printf("\tadd\tr0, r0, #%d\n", 12 * PYJAMASK_ROUNDS);

    /* Load all words of the state into registers and byte-swap */
    printf("\tldr\t%s, [r2]\n",      regs.s0);
    printf("\tldr\t%s, [r2, #4]\n",  regs.s1);
    printf("\tldr\t%s, [r2, #8]\n",  regs.s2);
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);

    /* Mix in the last round key */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    printf("\tldr\t%s, [r0]\n",      regs.t0);
    printf("\tldr\t%s, [r0, #4]\n",  regs.t1);
    printf("\tldr\t%s, [r0, #8]\n",  regs.t2);
    binop("eor", regs.s0, regs.t0);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s2, regs.t2);

    /* Perform all rounds */
    top_label = label++;
    printf("\tmov\t%s, #%d\n", regs.tc, PYJAMASK_ROUNDS);
    printf(".L%d:\n", top_label);

    /* Inverse mix of the rows in the state */
    pyjamask_matrix_multiply(&regs, 0x2037a121U, regs.s0, 1);
    pyjamask_matrix_multiply(&regs, 0x108ff2a0U, regs.s1, 1);
    pyjamask_matrix_multiply(&regs, 0x9054d8c0U, regs.s2, 0);

    /* Apply the inverse of the 96-bit Pyjamask sbox */
    /* s2 = ~s2; */
    binop("mvn", regs.s2, regs.t3);
    /* s0 ^= s1; */
    binop("eor", regs.s0, regs.s1);
    /* s1 ^= s0; */
    binop("eor", regs.s1, regs.s0);
    /* s2 ^= s0; */
    binop("eor", regs.s2, regs.s0);
    /* s1 ^= s0 & s2; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s0, regs.s2);
    binop("eor", regs.s1, regs.t0);
    /* s0 ^= s1 & s2; */
    printf("\tand\t%s, %s, %s\n", regs.t1, regs.s1, regs.s2);
    binop("eor", regs.s0, regs.t1);
    /* s2 ^= s0 & s1; */
    printf("\tand\t%s, %s, %s\n", regs.t0, regs.s0, regs.s1);
    binop("eor", regs.s2, regs.t0);
    /* s1 ^= s2; */
    binop("eor", regs.s1, regs.s2);
    /* s0 ^= s1; */
    binop("eor", regs.s0, regs.s1);

    /* Add the round key to the state */
    /* s0 ^= rk[0]; */
    /* s1 ^= rk[1]; */
    /* s2 ^= rk[2]; */
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t2);
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t1);
    printf("\tldr\t%s, [r0, #-4]!\n", regs.t0);
    binop("eor", regs.s2, regs.t2);
    binop("eor", regs.s1, regs.t1);
    binop("eor", regs.s0, regs.t0);

    /* Bottom of the round loop */
    printf("\tsubs\t%s, %s, #1\n", regs.tc, regs.tc);
    printf("\tbne\t.L%d\n", top_label);

    /* Store the words back to the state and exit */
    printf("\trev\t%s, %s\n", regs.s0, regs.s0);
    printf("\trev\t%s, %s\n", regs.s1, regs.s1);
    printf("\trev\t%s, %s\n", regs.s2, regs.s2);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s0, 0);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s1, 4);
    printf("\tstr\t%s, [r1, #%d]\n", regs.s2, 8);
    printf("\tpop\t{r4, r5, r6, r7, r8}\n");
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

    /* Output the Pyjamask key setup functions */
    function_header("pyjamask_128_setup_key");
    gen_setup_pyjamask(128);
    function_footer("pyjamask_128_setup_key");
    function_header("pyjamask_96_setup_key");
    gen_setup_pyjamask(96);
    function_footer("pyjamask_96_setup_key");

    /* Output the Pyjamask-128 encryption and decryption functions */
    function_header("pyjamask_128_encrypt");
    gen_encrypt_pyjamask128();
    function_footer("pyjamask_128_encrypt");
    function_header("pyjamask_128_decrypt");
    gen_decrypt_pyjamask128();
    function_footer("pyjamask_128_decrypt");

    /* Output the Pyjamask-96 encryption and decryption functions */
    function_header("pyjamask_96_encrypt");
    gen_encrypt_pyjamask96();
    function_footer("pyjamask_96_encrypt");
    function_header("pyjamask_96_decrypt");
    gen_decrypt_pyjamask96();
    function_footer("pyjamask_96_decrypt");

    /* Output the file footer */
    printf("\n");
    printf("#endif\n");
    return 0;
}
