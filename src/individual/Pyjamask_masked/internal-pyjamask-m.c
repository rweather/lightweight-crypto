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

#include "internal-pyjamask-m.h"

/* Macros for specific matrix values */
#define pyjamask_matrix_multiply_b881b9ca(y) \
    do { \
        uint32_t result; \
        result  = (y); \
        result ^= rightRotate2((y)); \
        result ^= rightRotate3((y)); \
        result ^= rightRotate4((y)); \
        result ^= rightRotate8((y)); \
        result ^= rightRotate15((y)); \
        result ^= rightRotate16((y)); \
        result ^= rightRotate18((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate20((y)); \
        result ^= rightRotate23((y)); \
        result ^= rightRotate24((y)); \
        result ^= rightRotate25((y)); \
        result ^= rightRotate28((y)); \
        result ^= rightRotate30((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_a3861085(y) \
    do { \
        uint32_t result; \
        result  = (y); \
        result ^= rightRotate2((y)); \
        result ^= rightRotate6((y)); \
        result ^= rightRotate7((y)); \
        result ^= rightRotate8((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate14((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate24((y)); \
        result ^= rightRotate29((y)); \
        result ^= rightRotate31((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_63417021(y) \
    do { \
        uint32_t result; \
        result  = rightRotate1((y)); \
        result ^= rightRotate2((y)); \
        result ^= rightRotate6((y)); \
        result ^= rightRotate7((y)); \
        result ^= rightRotate9((y)); \
        result ^= rightRotate15((y)); \
        result ^= rightRotate17((y)); \
        result ^= rightRotate18((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate26((y)); \
        result ^= rightRotate31((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_692cf280(y) \
    do { \
        uint32_t result; \
        result  = rightRotate1((y)); \
        result ^= rightRotate2((y)); \
        result ^= rightRotate4((y)); \
        result ^= rightRotate7((y)); \
        result ^= rightRotate10((y)); \
        result ^= rightRotate12((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate16((y)); \
        result ^= rightRotate17((y)); \
        result ^= rightRotate18((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate22((y)); \
        result ^= rightRotate24((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_48a54813(y) \
    do { \
        uint32_t result; \
        result  = rightRotate1((y)); \
        result ^= rightRotate4((y)); \
        result ^= rightRotate8((y)); \
        result ^= rightRotate10((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate15((y)); \
        result ^= rightRotate17((y)); \
        result ^= rightRotate20((y)); \
        result ^= rightRotate27((y)); \
        result ^= rightRotate30((y)); \
        result ^= rightRotate31((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_2037a121(y) \
    do { \
        uint32_t result; \
        result  = rightRotate2((y)); \
        result ^= rightRotate10((y)); \
        result ^= rightRotate11((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate14((y)); \
        result ^= rightRotate15((y)); \
        result ^= rightRotate16((y)); \
        result ^= rightRotate18((y)); \
        result ^= rightRotate23((y)); \
        result ^= rightRotate26((y)); \
        result ^= rightRotate31((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_108ff2a0(y) \
    do { \
        uint32_t result; \
        result  = rightRotate3((y)); \
        result ^= rightRotate8((y)); \
        result ^= rightRotate12((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate14((y)); \
        result ^= rightRotate15((y)); \
        result ^= rightRotate16((y)); \
        result ^= rightRotate17((y)); \
        result ^= rightRotate18((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate22((y)); \
        result ^= rightRotate24((y)); \
        result ^= rightRotate26((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_9054d8c0(y) \
    do { \
        uint32_t result; \
        result  = (y); \
        result ^= rightRotate3((y)); \
        result ^= rightRotate9((y)); \
        result ^= rightRotate11((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate16((y)); \
        result ^= rightRotate17((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate20((y)); \
        result ^= rightRotate24((y)); \
        result ^= rightRotate25((y)); \
        (y) = result; \
    } while (0)
#define pyjamask_matrix_multiply_3354b117(y) \
    do { \
        uint32_t result; \
        result  = rightRotate2((y)); \
        result ^= rightRotate3((y)); \
        result ^= rightRotate6((y)); \
        result ^= rightRotate7((y)); \
        result ^= rightRotate9((y)); \
        result ^= rightRotate11((y)); \
        result ^= rightRotate13((y)); \
        result ^= rightRotate16((y)); \
        result ^= rightRotate18((y)); \
        result ^= rightRotate19((y)); \
        result ^= rightRotate23((y)); \
        result ^= rightRotate27((y)); \
        result ^= rightRotate29((y)); \
        result ^= rightRotate30((y)); \
        result ^= rightRotate31((y)); \
        (y) = result; \
    } while (0)

/* Define masked multiply operations based on the number of shares */
#if AEAD_MASKING_SHARES == 2
#define pyjamask_matrix_multiply_masked_define(x) \
static void pyjamask_matrix_multiply_masked_##x(mask_uint32_t *y) \
{ \
    pyjamask_matrix_multiply_##x(y->a); \
    pyjamask_matrix_multiply_##x(y->b); \
}
#elif AEAD_MASKING_SHARES == 3
#define pyjamask_matrix_multiply_masked_define(x) \
static void pyjamask_matrix_multiply_masked_##x(mask_uint32_t *y) \
{ \
    pyjamask_matrix_multiply_##x(y->a); \
    pyjamask_matrix_multiply_##x(y->b); \
    pyjamask_matrix_multiply_##x(y->c); \
}
#elif AEAD_MASKING_SHARES == 4
#define pyjamask_matrix_multiply_masked_define(x) \
static void pyjamask_matrix_multiply_masked_##x(mask_uint32_t *y) \
{ \
    pyjamask_matrix_multiply_##x(y->a); \
    pyjamask_matrix_multiply_##x(y->b); \
    pyjamask_matrix_multiply_##x(y->c); \
    pyjamask_matrix_multiply_##x(y->d); \
}
#elif AEAD_MASKING_SHARES == 5
#define pyjamask_matrix_multiply_masked_define(x) \
static void pyjamask_matrix_multiply_masked_##x(mask_uint32_t *y) \
{ \
    pyjamask_matrix_multiply_##x(y->a); \
    pyjamask_matrix_multiply_##x(y->b); \
    pyjamask_matrix_multiply_##x(y->c); \
    pyjamask_matrix_multiply_##x(y->d); \
    pyjamask_matrix_multiply_##x(y->e); \
}
#elif AEAD_MASKING_SHARES == 6
#define pyjamask_matrix_multiply_masked_define(x) \
static void pyjamask_matrix_multiply_masked_##x(mask_uint32_t *y) \
{ \
    pyjamask_matrix_multiply_##x(y->a); \
    pyjamask_matrix_multiply_##x(y->b); \
    pyjamask_matrix_multiply_##x(y->c); \
    pyjamask_matrix_multiply_##x(y->d); \
    pyjamask_matrix_multiply_##x(y->e); \
    pyjamask_matrix_multiply_##x(y->f); \
}
#else
#error "Unknown number of shares"
#endif
pyjamask_matrix_multiply_masked_define(b881b9ca)
pyjamask_matrix_multiply_masked_define(a3861085)
pyjamask_matrix_multiply_masked_define(63417021)
pyjamask_matrix_multiply_masked_define(692cf280)
pyjamask_matrix_multiply_masked_define(48a54813)
pyjamask_matrix_multiply_masked_define(2037a121)
pyjamask_matrix_multiply_masked_define(108ff2a0)
pyjamask_matrix_multiply_masked_define(9054d8c0)
pyjamask_matrix_multiply_masked_define(3354b117)

void pyjamask_masked_128_setup_key
    (pyjamask_masked_128_key_schedule_t *ks, const unsigned char *key)
{
    mask_uint32_t *rk = ks->k;
    mask_uint32_t k0, k1, k2, k3;
    mask_uint32_t temp;
    uint8_t round;

    /* Make sure that the system random number generator is initialized */
    aead_random_init();

    /* Load the words of the key and mask them */
    mask_input(k0, be_load_word32(key));
    mask_input(k1, be_load_word32(key + 4));
    mask_input(k2, be_load_word32(key + 8));
    mask_input(k3, be_load_word32(key + 12));

    /* The first round key is the same as the key itself */
    rk[0] = k0;
    rk[1] = k1;
    rk[2] = k2;
    rk[3] = k3;
    rk += 4;

    /* Derive the round keys for all of the other rounds */
    for (round = 0; round < PYJAMASK_MASKED_ROUNDS; ++round, rk += 4) {
        /* Mix the columns */
        temp = k0;
        mask_xor(temp, k1);
        mask_xor(temp, k2);
        mask_xor(temp, k3);
        mask_xor(k0, temp);
        mask_xor(k1, temp);
        mask_xor(k2, temp);
        mask_xor(k3, temp);

        /* Mix the rows and add the round constants.  Note that the Pyjamask
         * specification says that k1/k2/k3 should be rotated left by 8, 15,
         * and 18 bits.  But the reference code actually rotates the words
         * right.  And the test vectors in the specification match up with
         * right rotations, not left.  We match the reference code here */
        pyjamask_matrix_multiply_masked_b881b9ca(&k0);
        mask_xor_const(k0, 0x00000080U ^ round);
        mask_ror(k1, k1, 8);
        mask_xor_const(k1, 0x00006a00U);
        mask_ror(k2, k2, 15);
        mask_xor_const(k2, 0x003f0000U);
        mask_ror(k3, k3, 18);
        mask_xor_const(k3, 0x24000000U);

        /* Write the round key to the schedule */
        rk[0] = k0;
        rk[1] = k1;
        rk[2] = k2;
        rk[3] = k3;
    }
}

void pyjamask_masked_96_setup_key
    (pyjamask_masked_96_key_schedule_t *ks, const unsigned char *key)
{
    mask_uint32_t *rk = ks->k;
    mask_uint32_t k0, k1, k2, k3;
    mask_uint32_t temp;
    uint8_t round;

    /* Make sure that the system random number generator is initialized */
    aead_random_init();

    /* Load the words of the key */
    mask_input(k0, be_load_word32(key));
    mask_input(k1, be_load_word32(key + 4));
    mask_input(k2, be_load_word32(key + 8));
    mask_input(k3, be_load_word32(key + 12));

    /* The first round key is the same as the key itself */
    rk[0] = k0;
    rk[1] = k1;
    rk[2] = k2;
    rk += 3;

    /* Derive the round keys for all of the other rounds */
    for (round = 0; round < PYJAMASK_MASKED_ROUNDS; ++round, rk += 3) {
        /* Mix the columns */
        temp = k0;
        mask_xor(temp, k1);
        mask_xor(temp, k2);
        mask_xor(temp, k3);
        mask_xor(k0, temp);
        mask_xor(k1, temp);
        mask_xor(k2, temp);
        mask_xor(k3, temp);

        /* Mix the rows and add the round constants.  Note that the Pyjamask
         * specification says that k1/k2/k3 should be rotated left by 8, 15,
         * and 18 bits.  But the reference code actually rotates the words
         * right.  And the test vectors in the specification match up with
         * right rotations, not left.  We match the reference code here */
        pyjamask_matrix_multiply_masked_b881b9ca(&k0);
        mask_xor_const(k0, 0x00000080U ^ round);
        mask_ror(k1, k1, 8);
        mask_xor_const(k1, 0x00006a00U);
        mask_ror(k2, k2, 15);
        mask_xor_const(k2, 0x003f0000U);
        mask_ror(k3, k3, 18);
        mask_xor_const(k3, 0x24000000U);

        /* Write the round key to the schedule */
        rk[0] = k0;
        rk[1] = k1;
        rk[2] = k2;
    }
}

void pyjamask_masked_128_encrypt
    (const pyjamask_masked_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const mask_uint32_t *rk = ks->k;
    mask_uint32_t s0, s1, s2, s3;
    uint32_t temp;
    uint8_t round;

    /* Load the plaintext from the input buffer */
    mask_input(s0, be_load_word32(input));
    mask_input(s1, be_load_word32(input + 4));
    mask_input(s2, be_load_word32(input + 8));
    mask_input(s3, be_load_word32(input + 12));

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_MASKED_ROUNDS; ++round, rk += 4) {
        /* Add the round key to the state */
        mask_xor(s0, rk[0]);
        mask_xor(s1, rk[1]);
        mask_xor(s2, rk[2]);
        mask_xor(s3, rk[3]);

        /* Apply the 128-bit Pyjamask sbox */
        mask_xor(s0, s3);
        mask_and(s3, s0, s1);
        mask_and(s0, s1, s2);
        mask_and(s1, s2, s3);
        mask_and(s2, s0, s3);
        mask_xor(s2, s1);
        mask_xor(s1, s0);
        mask_not(s3);
        mask_swap(s2, s3);

        /* Mix the rows of the state */
        pyjamask_matrix_multiply_masked_a3861085(&s0);
        pyjamask_matrix_multiply_masked_63417021(&s1);
        pyjamask_matrix_multiply_masked_692cf280(&s2);
        pyjamask_matrix_multiply_masked_48a54813(&s3);
    }

    /* Mix in the key one last time */
    mask_xor(s0, rk[0]);
    mask_xor(s1, rk[1]);
    mask_xor(s2, rk[2]);
    mask_xor(s3, rk[3]);

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      mask_output(s0));
    be_store_word32(output + 4,  mask_output(s1));
    be_store_word32(output + 8,  mask_output(s2));
    be_store_word32(output + 12, mask_output(s3));
}

void pyjamask_masked_128_decrypt
    (const pyjamask_masked_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const mask_uint32_t *rk = ks->k + 4 * PYJAMASK_MASKED_ROUNDS;
    mask_uint32_t s0, s1, s2, s3;
    uint32_t temp;
    uint8_t round;

    /* Load the ciphertext from the input buffer */
    mask_input(s0, be_load_word32(input));
    mask_input(s1, be_load_word32(input + 4));
    mask_input(s2, be_load_word32(input + 8));
    mask_input(s3, be_load_word32(input + 12));

    /* Mix in the last round key */
    mask_xor(s0, rk[0]);
    mask_xor(s1, rk[1]);
    mask_xor(s2, rk[2]);
    mask_xor(s3, rk[3]);
    rk -= 4;

    /* Perform all decryption rounds */
    for (round = 0; round < PYJAMASK_MASKED_ROUNDS; ++round, rk -= 4) {
        /* Inverse mix of the rows in the state */
        pyjamask_matrix_multiply_masked_2037a121(&s0);
        pyjamask_matrix_multiply_masked_108ff2a0(&s1);
        pyjamask_matrix_multiply_masked_9054d8c0(&s2);
        pyjamask_matrix_multiply_masked_3354b117(&s3);

        /* Apply the inverse of the 128-bit Pyjamask sbox */
        mask_swap(s2, s3);
        mask_not(s3);
        mask_xor(s1, s0);
        mask_xor(s2, s1);
        mask_and(s2, s0, s3);
        mask_and(s1, s2, s3);
        mask_and(s0, s1, s2);
        mask_and(s3, s0, s1);
        mask_xor(s0, s3);

        /* Add the round key to the state */
        mask_xor(s0, rk[0]);
        mask_xor(s1, rk[1]);
        mask_xor(s2, rk[2]);
        mask_xor(s3, rk[3]);
    }

    /* Write the plaintext to the output buffer */
    be_store_word32(output,      mask_output(s0));
    be_store_word32(output + 4,  mask_output(s1));
    be_store_word32(output + 8,  mask_output(s2));
    be_store_word32(output + 12, mask_output(s3));
}

void pyjamask_masked_96_encrypt
    (const pyjamask_masked_96_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const mask_uint32_t *rk = ks->k;
    mask_uint32_t s0, s1, s2;
    uint32_t temp;
    uint8_t round;

    /* Load the plaintext from the input buffer */
    mask_input(s0, be_load_word32(input));
    mask_input(s1, be_load_word32(input + 4));
    mask_input(s2, be_load_word32(input + 8));

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_MASKED_ROUNDS; ++round, rk += 3) {
        /* Add the round key to the state */
        mask_xor(s0, rk[0]);
        mask_xor(s1, rk[1]);
        mask_xor(s2, rk[2]);

        /* Apply the 96-bit Pyjamask sbox */
        mask_xor(s0, s1);
        mask_xor(s1, s2);
        mask_and(s2, s0, s1);
        mask_and(s0, s1, s2);
        mask_and(s1, s0, s2);
        mask_xor(s2, s0);
        mask_not(s2);
        mask_xor(s1, s0);
        mask_xor(s0, s1);

        /* Mix the rows of the state */
        pyjamask_matrix_multiply_masked_a3861085(&s0);
        pyjamask_matrix_multiply_masked_63417021(&s1);
        pyjamask_matrix_multiply_masked_692cf280(&s2);
    }

    /* Mix in the key one last time */
    mask_xor(s0, rk[0]);
    mask_xor(s1, rk[1]);
    mask_xor(s2, rk[2]);

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      mask_output(s0));
    be_store_word32(output + 4,  mask_output(s1));
    be_store_word32(output + 8,  mask_output(s2));
}

void pyjamask_masked_96_decrypt
    (const pyjamask_masked_96_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const mask_uint32_t *rk = ks->k + 3 * PYJAMASK_MASKED_ROUNDS;
    mask_uint32_t s0, s1, s2;
    uint32_t temp;
    uint8_t round;

    /* Load the plaintext from the input buffer */
    mask_input(s0, be_load_word32(input));
    mask_input(s1, be_load_word32(input + 4));
    mask_input(s2, be_load_word32(input + 8));

    /* Mix in the last round key */
    mask_xor(s0, rk[0]);
    mask_xor(s1, rk[1]);
    mask_xor(s2, rk[2]);
    rk -= 3;

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_MASKED_ROUNDS; ++round, rk -= 3) {
        /* Inverse mix of the rows in the state */
        pyjamask_matrix_multiply_masked_2037a121(&s0);
        pyjamask_matrix_multiply_masked_108ff2a0(&s1);
        pyjamask_matrix_multiply_masked_9054d8c0(&s2);

        /* Apply the inverse of the 96-bit Pyjamask sbox */
        mask_xor(s0, s1);
        mask_xor(s1, s0);
        mask_not(s2);
        mask_xor(s2, s0);
        mask_and(s1, s0, s2);
        mask_and(s0, s1, s2);
        mask_and(s2, s0, s1);
        mask_xor(s1, s2);
        mask_xor(s0, s1);

        /* Add the round key to the state */
        mask_xor(s0, rk[0]);
        mask_xor(s1, rk[1]);
        mask_xor(s2, rk[2]);
    }

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      mask_output(s0));
    be_store_word32(output + 4,  mask_output(s1));
    be_store_word32(output + 8,  mask_output(s2));
}
