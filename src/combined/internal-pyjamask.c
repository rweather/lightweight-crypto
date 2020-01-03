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

#include "internal-pyjamask.h"
#include "internal-util.h"

/**
 * \brief Performs a circulant binary matrix multiplication.
 *
 * \param x The matrix.
 * \param y The vector to multiply with the matrix.
 *
 * \return The vector result of multiplying x by y.
 */
STATIC_INLINE uint32_t pyjamask_matrix_multiply(uint32_t x, uint32_t y)
{
    uint32_t result = 0;
    int bit;
    for (bit = 31; bit >= 0; --bit) {
#if defined(ESP32)
        /* This version has slightly better performance on ESP32 */
        y = leftRotate1(y);
        result ^= x & -(y & 1);
        x = rightRotate1(x);
#else
        result ^= x & -((y >> bit) & 1);
        x = rightRotate1(x);
#endif
    }
    return result;
}

void pyjamask_setup_key(pyjamask_key_schedule_t *ks, const unsigned char *key)
{
    uint32_t *rk = ks->k;
    uint32_t k0, k1, k2, k3;
    uint32_t temp;
    uint8_t round;

    /* Load the words of the key */
    k0 = be_load_word32(key);
    k1 = be_load_word32(key + 4);
    k2 = be_load_word32(key + 8);
    k3 = be_load_word32(key + 12);

    /* The first round key is the same as the key itself */
    rk[0] = k0;
    rk[1] = k1;
    rk[2] = k2;
    rk[3] = k3;
    rk += 4;

    /* Derive the round keys for all of the other rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 4) {
        /* Mix the columns */
        temp = k0 ^ k1 ^ k2 ^ k3;
        k0 ^= temp;
        k1 ^= temp;
        k2 ^= temp;
        k3 ^= temp;

        /* Mix the rows and add the round constants.  Note that the Pyjamask
         * specification says that k1/k2/k3 should be rotated left by 8, 15,
         * and 18 bits.  But the reference code actually rotates the words
         * right.  And the test vectors in the specification match up with
         * right rotations, not left.  We match the reference code here */
        k0 = pyjamask_matrix_multiply(0xb881b9caU, k0) ^ 0x00000080U ^ round;
        k1 = rightRotate8(k1)  ^ 0x00006a00U;
        k2 = rightRotate15(k2) ^ 0x003f0000U;
        k3 = rightRotate18(k3) ^ 0x24000000U;

        /* Write the round key to the schedule */
        rk[0] = k0;
        rk[1] = k1;
        rk[2] = k2;
        rk[3] = k3;
    }
}

void pyjamask_128_encrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k;
    uint32_t s0, s1, s2, s3;
    uint8_t round;

    /* Load the plaintext from the input buffer */
    s0 = be_load_word32(input);
    s1 = be_load_word32(input + 4);
    s2 = be_load_word32(input + 8);
    s3 = be_load_word32(input + 12);

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 4) {
        /* Add the round key to the state */
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
        s3 ^= rk[3];

        /* Apply the 128-bit Pyjamask sbox */
        s0 ^= s3;
        s3 ^= s0 & s1;
        s0 ^= s1 & s2;
        s1 ^= s2 & s3;
        s2 ^= s0 & s3;
        s2 ^= s1;
        s1 ^= s0;
        s3 = ~s3;
        s2 ^= s3;
        s3 ^= s2;
        s2 ^= s3;

        /* Mix the rows of the state */
        s0 = pyjamask_matrix_multiply(0xa3861085U, s0);
        s1 = pyjamask_matrix_multiply(0x63417021U, s1);
        s2 = pyjamask_matrix_multiply(0x692cf280U, s2);
        s3 = pyjamask_matrix_multiply(0x48a54813U, s3);
    }

    /* Mix in the key one last time */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
}

void pyjamask_128_decrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k + 4 * PYJAMASK_ROUNDS;
    uint32_t s0, s1, s2, s3;
    uint8_t round;

    /* Load the ciphertext from the input buffer */
    s0 = be_load_word32(input);
    s1 = be_load_word32(input + 4);
    s2 = be_load_word32(input + 8);
    s3 = be_load_word32(input + 12);

    /* Mix in the last round key */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];
    rk -= 4;

    /* Perform all decryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk -= 4) {
        /* Inverse mix of the rows in the state */
        s0 = pyjamask_matrix_multiply(0x2037a121U, s0);
        s1 = pyjamask_matrix_multiply(0x108ff2a0U, s1);
        s2 = pyjamask_matrix_multiply(0x9054d8c0U, s2);
        s3 = pyjamask_matrix_multiply(0x3354b117U, s3);

        /* Apply the inverse of the 128-bit Pyjamask sbox */
        s2 ^= s3;
        s3 ^= s2;
        s2 ^= s3;
        s3 = ~s3;
        s1 ^= s0;
        s2 ^= s1;
        s2 ^= s0 & s3;
        s1 ^= s2 & s3;
        s0 ^= s1 & s2;
        s3 ^= s0 & s1;
        s0 ^= s3;

        /* Add the round key to the state */
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
        s3 ^= rk[3];
    }

    /* Write the plaintext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
}

void pyjamask_96_encrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k;
    uint32_t s0, s1, s2;
    uint8_t round;

    /* Load the plaintext from the input buffer */
    s0 = be_load_word32(input);
    s1 = be_load_word32(input + 4);
    s2 = be_load_word32(input + 8);

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 4) {
        /* Add the round key to the state */
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];

        /* Apply the 96-bit Pyjamask sbox */
        s0 ^= s1;
        s1 ^= s2;
        s2 ^= s0 & s1;
        s0 ^= s1 & s2;
        s1 ^= s0 & s2;
        s2 ^= s0;
        s0 ^= s1;
        s2 = ~s2;
        s0 ^= s1;
        s1 ^= s0;
        s0 ^= s1;

        /* Mix the rows of the state */
        s0 = pyjamask_matrix_multiply(0xa3861085U, s0);
        s1 = pyjamask_matrix_multiply(0x63417021U, s1);
        s2 = pyjamask_matrix_multiply(0x692cf280U, s2);
    }

    /* Mix in the key one last time */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
}

void pyjamask_96_decrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k + 4 * PYJAMASK_ROUNDS;
    uint32_t s0, s1, s2;
    uint8_t round;

    /* Load the plaintext from the input buffer */
    s0 = be_load_word32(input);
    s1 = be_load_word32(input + 4);
    s2 = be_load_word32(input + 8);

    /* Mix in the last round key */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    rk -= 4;

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk -= 4) {
        /* Inverse mix of the rows in the state */
        s0 = pyjamask_matrix_multiply(0x2037a121U, s0);
        s1 = pyjamask_matrix_multiply(0x108ff2a0U, s1);
        s2 = pyjamask_matrix_multiply(0x9054d8c0U, s2);

        /* Apply the inverse of the 96-bit Pyjamask sbox */
        s0 ^= s1;
        s1 ^= s0;
        s0 ^= s1;
        s2 = ~s2;
        s0 ^= s1;
        s2 ^= s0;
        s1 ^= s0 & s2;
        s0 ^= s1 & s2;
        s2 ^= s0 & s1;
        s1 ^= s2;
        s0 ^= s1;

        /* Add the round key to the state */
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
    }

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
}
