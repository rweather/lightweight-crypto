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
#include "internal-masking.h"

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

static void pyjamask_masked_setup_internal(uint32_t *rk, int round_constants)
{
    uint32_t k0, k1, k2, k3;
    uint32_t temp;
    uint8_t round;

    /* The first round key is the same as the key itself */
    k0 = rk[0];
    k1 = rk[1];
    k2 = rk[2];
    k3 = rk[3];
    rk += 16;

    /* Derive the round keys for all of the other rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 16) {
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
        k0 = pyjamask_matrix_multiply(0xb881b9caU, k0);
        k1 = rightRotate8(k1);
        k2 = rightRotate15(k2);
        k3 = rightRotate18(k3);
        if (round_constants) {
            k0 ^= 0x00000080U ^ round;
            k1 ^= 0x00006a00U;
            k2 ^= 0x003f0000U;
            k3 ^= 0x24000000U;
        }

        /* Write the round key to the schedule */
        rk[0] = k0;
        rk[1] = k1;
        rk[2] = k2;
        rk[3] = k3;
    }
}

void pyjamask_masked_setup_key
    (pyjamask_masked_key_schedule_t *ks, const unsigned char *key)
{
    uint32_t k0, k1, k2, k3;
    uint8_t order;

    /* Make sure that the system random number generator is initialized */
    aead_masking_init();

    /* Generate the random masking keys */
    aead_masking_generate
        (ks->k + 4, (PYJAMASK_MASKING_ORDER - 1) * 4 * sizeof(uint32_t));

    /* Mask the primary key by XOR'ing it against all the random keys */
    k0 = be_load_word32(key);
    k1 = be_load_word32(key + 4);
    k2 = be_load_word32(key + 8);
    k3 = be_load_word32(key + 12);
    for (order = 1; order < PYJAMASK_MASKING_ORDER; ++order) {
        k0 ^= ks->k[order * 4];
        k1 ^= ks->k[order * 4 + 1];
        k2 ^= ks->k[order * 4 + 2];
        k3 ^= ks->k[order * 4 + 3];
    }
    ks->k[0] = k0;
    ks->k[1] = k1;
    ks->k[2] = k2;
    ks->k[3] = k3;

    /* Generate the key schedules for all masked keys */
    for (order = 0; order < PYJAMASK_MASKING_ORDER; ++order) {
        pyjamask_masked_setup_internal(ks->k + order * 4, order == 0);
    }
}

#if PYJAMASK_MASKING_ORDER != 4
/* We make some assumptions in the functions below that the order is 4 */
#error "Masking needs to be updated for order change"
#endif

/* Inner step for pyjamask_masked_and_xor() to mix two sets of words */
#define pyjamask_mix_words(x2, x1, x0, y2, y1, y0) \
    do { \
        temp = aead_masking_generate_32(); \
        (x2) ^= temp; \
        temp ^= ((y0) & (x1)); \
        (y2) = ((y2) ^ temp) ^ ((y1) & (x0)); \
    } while (0)

/**
 * \brief Perform a 32-bit masked AND-XOR operation.
 *
 * \param s2 Reference to the main state's s2 word.
 * \param s0 Reference to the main state's s0 word.
 * \param s1 Reference to the main state's s1 word.
 * \param i2 Index into the masked states of the s2 word.
 * \param i0 Index into the masked states of the s0 word.
 * \param i1 Index into the masked states of the s1 word.
 *
 * The effect of this function is "s2 ^= (s0 & s1)" across all masking levels.
 */
#define pyjamask_masked_and_xor(s2, s0, s1, i2, i0, i1) \
    do { \
        (s2) ^= (s0) & (s1); \
        pyjamask_mix_words(s2, s1, s0, m[0][i2], m[0][i1], m[0][i0]); \
        pyjamask_mix_words(s2, s1, s0, m[1][i2], m[1][i1], m[1][i0]); \
        pyjamask_mix_words(s2, s1, s0, m[2][i2], m[2][i1], m[2][i0]); \
        m[0][i2] ^= m[0][i0] & m[0][i1]; \
        pyjamask_mix_words(m[0][i2], m[0][i1], m[0][i0], \
                           m[1][i2], m[1][i1], m[1][i0]); \
        pyjamask_mix_words(m[0][i2], m[0][i1], m[0][i0], \
                           m[2][i2], m[2][i1], m[2][i0]); \
        m[1][i2] ^= m[1][i0] & m[1][i1]; \
        pyjamask_mix_words(m[1][i2], m[1][i1], m[1][i0], \
                           m[2][i2], m[2][i1], m[2][i0]); \
        m[2][i2] ^= m[2][i0] & m[2][i1]; \
    } while (0)

void pyjamask_masked_128_encrypt
    (const pyjamask_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k;
    uint32_t s0, s1, s2, s3, temp;
    uint32_t m[PYJAMASK_MASKING_ORDER - 1][4];
    uint8_t order, round;

    /* Generate random masking plaintexts */
    aead_masking_generate(m, sizeof(m));

    /* Load the plaintext from the input buffer and mask it */
    s0 = be_load_word32(input)      ^ m[0][0] ^ m[1][0] ^ m[2][0];
    s1 = be_load_word32(input + 4)  ^ m[0][1] ^ m[1][1] ^ m[2][1];
    s2 = be_load_word32(input + 8)  ^ m[0][2] ^ m[1][2] ^ m[2][2];
    s3 = be_load_word32(input + 12) ^ m[0][3] ^ m[1][3] ^ m[2][3];

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 4) {
        /* Add the round key to the state */
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
        s3 ^= rk[3];
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            rk += 4;
            m[order][0] ^= rk[0];
            m[order][1] ^= rk[1];
            m[order][2] ^= rk[2];
            m[order][3] ^= rk[3];
        }

        /* Apply the 128-bit Pyjamask sbox in masked mode */
        s0 ^= s3;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][0] ^= m[order][3];
        }
        pyjamask_masked_and_xor(s3, s0, s1, 3, 0, 1);
        pyjamask_masked_and_xor(s0, s1, s2, 0, 1, 2);
        pyjamask_masked_and_xor(s1, s2, s3, 1, 2, 3);
        pyjamask_masked_and_xor(s2, s0, s3, 2, 0, 3);
        s2 ^= s1;
        s1 ^= s0;
        s2 ^= s3;
        s3 ^= s2;
        s2 ^= s3;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][2] ^= m[order][1];
            m[order][1] ^= m[order][0];
            m[order][2] ^= m[order][3];
            m[order][3] ^= m[order][2];
            m[order][2] ^= m[order][3];
        }
        s2 = ~s2;

        /* Mix the rows of the state */
        s0 = pyjamask_matrix_multiply(0xa3861085U, s0);
        s1 = pyjamask_matrix_multiply(0x63417021U, s1);
        s2 = pyjamask_matrix_multiply(0x692cf280U, s2);
        s3 = pyjamask_matrix_multiply(0x48a54813U, s3);
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][0] = pyjamask_matrix_multiply(0xa3861085U, m[order][0]);
            m[order][1] = pyjamask_matrix_multiply(0x63417021U, m[order][1]);
            m[order][2] = pyjamask_matrix_multiply(0x692cf280U, m[order][2]);
            m[order][3] = pyjamask_matrix_multiply(0x48a54813U, m[order][3]);
        }
    }

    /* Mix in the key one last time */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];
    for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
        rk += 4;
        m[order][0] ^= rk[0];
        m[order][1] ^= rk[1];
        m[order][2] ^= rk[2];
        m[order][3] ^= rk[3];
    }

    /* Unmask the output state */
    s0 ^= m[0][0] ^ m[1][0] ^ m[2][0];
    s1 ^= m[0][1] ^ m[1][1] ^ m[2][1];
    s2 ^= m[0][2] ^ m[1][2] ^ m[2][2];
    s3 ^= m[0][3] ^ m[1][3] ^ m[2][3];

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
}

void pyjamask_masked_128_decrypt
    (const pyjamask_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk =
        ks->k + PYJAMASK_MASKING_ORDER * (PYJAMASK_ROUNDS + 1) * 4;
    uint32_t s0, s1, s2, s3, temp;
    uint32_t m[PYJAMASK_MASKING_ORDER - 1][4];
    uint8_t round;
    int order;

    /* Generate random masking plaintexts */
    aead_masking_generate(m, sizeof(m));

    /* Load the ciphertext from the input buffer and mask it */
    s0 = be_load_word32(input)      ^ m[0][0] ^ m[1][0] ^ m[2][0];
    s1 = be_load_word32(input + 4)  ^ m[0][1] ^ m[1][1] ^ m[2][1];
    s2 = be_load_word32(input + 8)  ^ m[0][2] ^ m[1][2] ^ m[2][2];
    s3 = be_load_word32(input + 12) ^ m[0][3] ^ m[1][3] ^ m[2][3];

    /* Mix in the last round key */
    for (order = PYJAMASK_MASKING_ORDER - 2; order >= 0; --order) {
        rk -= 4;
        m[order][0] ^= rk[0];
        m[order][1] ^= rk[1];
        m[order][2] ^= rk[2];
        m[order][3] ^= rk[3];
    }
    rk -= 4;
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    s3 ^= rk[3];

    /* Perform all decryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round) {
        /* Inverse mix of the rows in the state */
        s0 = pyjamask_matrix_multiply(0x2037a121U, s0);
        s1 = pyjamask_matrix_multiply(0x108ff2a0U, s1);
        s2 = pyjamask_matrix_multiply(0x9054d8c0U, s2);
        s3 = pyjamask_matrix_multiply(0x3354b117U, s3);
        for (order = PYJAMASK_MASKING_ORDER - 2; order >= 0; --order) {
            m[order][0] = pyjamask_matrix_multiply(0x2037a121U, m[order][0]);
            m[order][1] = pyjamask_matrix_multiply(0x108ff2a0U, m[order][1]);
            m[order][2] = pyjamask_matrix_multiply(0x9054d8c0U, m[order][2]);
            m[order][3] = pyjamask_matrix_multiply(0x3354b117U, m[order][3]);
        }

        /* Apply the inverse of the 128-bit Pyjamask sbox in masked mode */
        s2 = ~s2;
        s2 ^= s3;
        s3 ^= s2;
        s2 ^= s3;
        s1 ^= s0;
        s2 ^= s1;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][2] ^= m[order][3];
            m[order][3] ^= m[order][2];
            m[order][2] ^= m[order][3];
            m[order][1] ^= m[order][0];
            m[order][2] ^= m[order][1];
        }
        pyjamask_masked_and_xor(s2, s0, s3, 2, 0, 3);
        pyjamask_masked_and_xor(s1, s2, s3, 1, 2, 3);
        pyjamask_masked_and_xor(s0, s1, s2, 0, 1, 2);
        pyjamask_masked_and_xor(s3, s0, s1, 3, 0, 1);
        s0 ^= s3;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][0] ^= m[order][3];
        }

        /* Add the round key to the state */
        for (order = PYJAMASK_MASKING_ORDER - 2; order >= 0; --order) {
            rk -= 4;
            m[order][0] ^= rk[0];
            m[order][1] ^= rk[1];
            m[order][2] ^= rk[2];
            m[order][3] ^= rk[3];
        }
        rk -= 4;
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
        s3 ^= rk[3];
    }

    /* Unmask the output state */
    s0 ^= m[0][0] ^ m[1][0] ^ m[2][0];
    s1 ^= m[0][1] ^ m[1][1] ^ m[2][1];
    s2 ^= m[0][2] ^ m[1][2] ^ m[2][2];
    s3 ^= m[0][3] ^ m[1][3] ^ m[2][3];

    /* Write the plaintext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
}

void pyjamask_masked_96_encrypt
    (const pyjamask_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k;
    uint32_t s0, s1, s2, temp;
    uint32_t m[PYJAMASK_MASKING_ORDER - 1][3];
    uint8_t order, round;

    /* Generate random masking plaintexts */
    aead_masking_generate(m, sizeof(m));

    /* Load the plaintext from the input buffer and mask it */
    s0 = be_load_word32(input)      ^ m[0][0] ^ m[1][0] ^ m[2][0];
    s1 = be_load_word32(input + 4)  ^ m[0][1] ^ m[1][1] ^ m[2][1];
    s2 = be_load_word32(input + 8)  ^ m[0][2] ^ m[1][2] ^ m[2][2];

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 4) {
        /* Add the round key to the state */
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            rk += 4;
            m[order][0] ^= rk[0];
            m[order][1] ^= rk[1];
            m[order][2] ^= rk[2];
        }

        /* Apply the 96-bit Pyjamask sbox in masked mode */
        s0 ^= s1;
        s1 ^= s2;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][0] ^= m[order][1];
            m[order][1] ^= m[order][2];
        }
        pyjamask_masked_and_xor(s2, s0, s1, 2, 0, 1);
        pyjamask_masked_and_xor(s0, s1, s2, 0, 1, 2);
        pyjamask_masked_and_xor(s1, s0, s2, 1, 0, 2);
        s2 ^= s0;
        s1 ^= s0;
        s0 ^= s1;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][2] ^= m[order][0];
            m[order][1] ^= m[order][0];
            m[order][0] ^= m[order][1];
        }
        s2 = ~s2;

        /* Mix the rows of the state */
        s0 = pyjamask_matrix_multiply(0xa3861085U, s0);
        s1 = pyjamask_matrix_multiply(0x63417021U, s1);
        s2 = pyjamask_matrix_multiply(0x692cf280U, s2);
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][0] = pyjamask_matrix_multiply(0xa3861085U, m[order][0]);
            m[order][1] = pyjamask_matrix_multiply(0x63417021U, m[order][1]);
            m[order][2] = pyjamask_matrix_multiply(0x692cf280U, m[order][2]);
        }
    }

    /* Mix in the key one last time */
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];
    for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
        rk += 4;
        m[order][0] ^= rk[0];
        m[order][1] ^= rk[1];
        m[order][2] ^= rk[2];
    }

    /* Unmask the output state */
    s0 ^= m[0][0] ^ m[1][0] ^ m[2][0];
    s1 ^= m[0][1] ^ m[1][1] ^ m[2][1];
    s2 ^= m[0][2] ^ m[1][2] ^ m[2][2];

    /* Write the ciphertext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
}

void pyjamask_masked_96_decrypt
    (const pyjamask_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk =
        ks->k + PYJAMASK_MASKING_ORDER * (PYJAMASK_ROUNDS + 1) * 4;
    uint32_t s0, s1, s2, temp;
    uint32_t m[PYJAMASK_MASKING_ORDER - 1][3];
    uint8_t round;
    int order;

    /* Generate random masking plaintexts */
    aead_masking_generate(m, sizeof(m));

    /* Load the ciphertext from the input buffer and mask it */
    s0 = be_load_word32(input)      ^ m[0][0] ^ m[1][0] ^ m[2][0];
    s1 = be_load_word32(input + 4)  ^ m[0][1] ^ m[1][1] ^ m[2][1];
    s2 = be_load_word32(input + 8)  ^ m[0][2] ^ m[1][2] ^ m[2][2];

    /* Mix in the last round key */
    for (order = PYJAMASK_MASKING_ORDER - 2; order >= 0; --order) {
        rk -= 4;
        m[order][0] ^= rk[0];
        m[order][1] ^= rk[1];
        m[order][2] ^= rk[2];
    }
    rk -= 4;
    s0 ^= rk[0];
    s1 ^= rk[1];
    s2 ^= rk[2];

    /* Perform all decryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round) {
        /* Inverse mix of the rows in the state */
        s0 = pyjamask_matrix_multiply(0x2037a121U, s0);
        s1 = pyjamask_matrix_multiply(0x108ff2a0U, s1);
        s2 = pyjamask_matrix_multiply(0x9054d8c0U, s2);
        for (order = PYJAMASK_MASKING_ORDER - 2; order >= 0; --order) {
            m[order][0] = pyjamask_matrix_multiply(0x2037a121U, m[order][0]);
            m[order][1] = pyjamask_matrix_multiply(0x108ff2a0U, m[order][1]);
            m[order][2] = pyjamask_matrix_multiply(0x9054d8c0U, m[order][2]);
        }

        /* Apply the inverse of the 96-bit Pyjamask sbox in masked mode */
        s2 = ~s2;
        s0 ^= s1;
        s1 ^= s0;
        s2 ^= s0;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][0] ^= m[order][1];
            m[order][1] ^= m[order][0];
            m[order][2] ^= m[order][0];
        }
        pyjamask_masked_and_xor(s1, s0, s2, 1, 0, 2);
        pyjamask_masked_and_xor(s0, s1, s2, 0, 1, 2);
        pyjamask_masked_and_xor(s2, s0, s1, 2, 0, 1);
        s1 ^= s2;
        s0 ^= s1;
        for (order = 0; order < (PYJAMASK_MASKING_ORDER - 1); ++order) {
            m[order][1] ^= m[order][2];
            m[order][0] ^= m[order][1];
        }

        /* Add the round key to the state */
        for (order = PYJAMASK_MASKING_ORDER - 2; order >= 0; --order) {
            rk -= 4;
            m[order][0] ^= rk[0];
            m[order][1] ^= rk[1];
            m[order][2] ^= rk[2];
        }
        rk -= 4;
        s0 ^= rk[0];
        s1 ^= rk[1];
        s2 ^= rk[2];
    }

    /* Unmask the output state */
    s0 ^= m[0][0] ^ m[1][0] ^ m[2][0];
    s1 ^= m[0][1] ^ m[1][1] ^ m[2][1];
    s2 ^= m[0][2] ^ m[1][2] ^ m[2][2];

    /* Write the plaintext to the output buffer */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
}
