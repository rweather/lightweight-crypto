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

/* Single step in the binary matrix multiplication */
#define STEP(y, bit) \
    mask = rightRotate1(mask); \
    result ^= mask & -(((y) >> (bit)) & 1)

/**
 * \brief Performs a circulant binary matrix multiplication.
 *
 * \param x The matrix.
 * \param y The vector to multiply with the matrix.  Also the result.
 */
#define pyjamask_matrix_multiply(x, y) \
    do { \
        uint32_t mask = (x); \
        uint32_t result; \
        result = mask & -(((y) >> 31) & 1); \
        STEP((y), 30); STEP((y), 29); STEP((y), 28); STEP((y), 27); \
        STEP((y), 26); STEP((y), 25); STEP((y), 24); STEP((y), 23); \
        STEP((y), 22); STEP((y), 21); STEP((y), 20); STEP((y), 19); \
        STEP((y), 18); STEP((y), 17); STEP((y), 16); STEP((y), 15); \
        STEP((y), 14); STEP((y), 13); STEP((y), 12); STEP((y), 11); \
        STEP((y), 10); STEP((y), 9); STEP((y), 8); STEP((y), 7); \
        STEP((y), 6); STEP((y), 5); STEP((y), 4); STEP((y), 3); \
        STEP((y), 2); STEP((y), 1); STEP((y), 0); \
        (y) = result; \
    } while (0)

/**
 * \brief Performs a circulant binary matrix multiplication on a masked vector.
 *
 * \param y Points to the masked vector to multiply with the matrix.
 * \param x The matrix.
 */
static void pyjamask_matrix_multiply_masked(mask_uint32_t *y, uint32_t x)
{
    pyjamask_matrix_multiply(x, y->a);
    pyjamask_matrix_multiply(x, y->b);
#if AEAD_MASKING_SHARES >= 3
    pyjamask_matrix_multiply(x, y->c);
#endif
#if AEAD_MASKING_SHARES >= 4
    pyjamask_matrix_multiply(x, y->d);
#endif
#if AEAD_MASKING_SHARES >= 5
    pyjamask_matrix_multiply(x, y->e);
#endif
#if AEAD_MASKING_SHARES >= 6
    pyjamask_matrix_multiply(x, y->f);
#endif
#if AEAD_MASKING_SHARES > 6
    #error "Unknown number of shares"
#endif
}

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
        pyjamask_matrix_multiply_masked(&k0, 0xb881b9caU);
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
        pyjamask_matrix_multiply_masked(&k0, 0xb881b9caU);
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
        pyjamask_matrix_multiply_masked(&s0, 0xa3861085U);
        pyjamask_matrix_multiply_masked(&s1, 0x63417021U);
        pyjamask_matrix_multiply_masked(&s2, 0x692cf280U);
        pyjamask_matrix_multiply_masked(&s3, 0x48a54813U);
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
        pyjamask_matrix_multiply_masked(&s0, 0x2037a121U);
        pyjamask_matrix_multiply_masked(&s1, 0x108ff2a0U);
        pyjamask_matrix_multiply_masked(&s2, 0x9054d8c0U);
        pyjamask_matrix_multiply_masked(&s3, 0x3354b117U);

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
        pyjamask_matrix_multiply_masked(&s0, 0xa3861085U);
        pyjamask_matrix_multiply_masked(&s1, 0x63417021U);
        pyjamask_matrix_multiply_masked(&s2, 0x692cf280U);
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
        pyjamask_matrix_multiply_masked(&s0, 0x2037a121U);
        pyjamask_matrix_multiply_masked(&s1, 0x108ff2a0U);
        pyjamask_matrix_multiply_masked(&s2, 0x9054d8c0U);

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
