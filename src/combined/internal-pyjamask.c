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

/* Determine which versions should be accelerated with assembly code */
#if defined(__AVR__)
#define PYJAMASK_128_ASM 1
#define PYJAMASK_96_ASM 1
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define PYJAMASK_128_ASM 1
#define PYJAMASK_96_ASM 1
#else
#define PYJAMASK_128_ASM 0
#define PYJAMASK_96_ASM 0
#endif

#if !PYJAMASK_128_ASM || !PYJAMASK_96_ASM

/* Define this to 1 to reverse the order of parameters for the circulant
 * matrix multiplications.  Define to 0 for the original order.
 *
 * Reversing the parameters results in a signficiant speed improvement.
 * But it is unclear as to whether the resulting algorithm will have
 * the same resistance to power analysis as the original parameter order.
 */
#define PYJAMASK_REVERSED_MATRIX 1

#if PYJAMASK_REVERSED_MATRIX

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

#else /* !PYJAMASK_REVERSED_MATRIX */

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

/* Macros for specific matrix values */
#define pyjamask_matrix_multiply_b881b9ca(y) \
    pyjamask_matrix_multiply(0xb881b9caU, (y))
#define pyjamask_matrix_multiply_a3861085(y) \
    pyjamask_matrix_multiply(0xa3861085U, (y))
#define pyjamask_matrix_multiply_63417021(y) \
    pyjamask_matrix_multiply(0x63417021U, (y))
#define pyjamask_matrix_multiply_692cf280(y) \
    pyjamask_matrix_multiply(0x692cf280U, (y))
#define pyjamask_matrix_multiply_48a54813(y) \
    pyjamask_matrix_multiply(0x48a54813U, (y))
#define pyjamask_matrix_multiply_2037a121(y) \
    pyjamask_matrix_multiply(0x2037a121U, (y))
#define pyjamask_matrix_multiply_108ff2a0(y) \
    pyjamask_matrix_multiply(0x108ff2a0U, (y))
#define pyjamask_matrix_multiply_9054d8c0(y) \
    pyjamask_matrix_multiply(0x9054d8c0U, (y))
#define pyjamask_matrix_multiply_3354b117(y) \
    pyjamask_matrix_multiply(0x3354b117U, (y))

#endif /* !PYJAMASK_REVERSED_MATRIX */

#endif

#if !PYJAMASK_128_ASM

void pyjamask_128_setup_key
    (pyjamask_128_key_schedule_t *ks, const unsigned char *key)
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
        pyjamask_matrix_multiply_b881b9ca(k0);
        k0 ^= 0x00000080U ^ round;
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
    (const pyjamask_128_key_schedule_t *ks, unsigned char *output,
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
        pyjamask_matrix_multiply_a3861085(s0);
        pyjamask_matrix_multiply_63417021(s1);
        pyjamask_matrix_multiply_692cf280(s2);
        pyjamask_matrix_multiply_48a54813(s3);
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
    (const pyjamask_128_key_schedule_t *ks, unsigned char *output,
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
        pyjamask_matrix_multiply_2037a121(s0);
        pyjamask_matrix_multiply_108ff2a0(s1);
        pyjamask_matrix_multiply_9054d8c0(s2);
        pyjamask_matrix_multiply_3354b117(s3);

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

#endif

#if !PYJAMASK_96_ASM

void pyjamask_96_setup_key
    (pyjamask_96_key_schedule_t *ks, const unsigned char *key)
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
    rk += 3;

    /* Derive the round keys for all of the other rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 3) {
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
        pyjamask_matrix_multiply_b881b9ca(k0);
        k0 ^= 0x00000080U ^ round;
        k1 = rightRotate8(k1)  ^ 0x00006a00U;
        k2 = rightRotate15(k2) ^ 0x003f0000U;
        k3 = rightRotate18(k3) ^ 0x24000000U;

        /* Write the round key to the schedule */
        rk[0] = k0;
        rk[1] = k1;
        rk[2] = k2;
    }
}

void pyjamask_96_encrypt
    (const pyjamask_96_key_schedule_t *ks, unsigned char *output,
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
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk += 3) {
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
        s2 = ~s2;
        s1 ^= s0;
        s0 ^= s1;

        /* Mix the rows of the state */
        pyjamask_matrix_multiply_a3861085(s0);
        pyjamask_matrix_multiply_63417021(s1);
        pyjamask_matrix_multiply_692cf280(s2);
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
    (const pyjamask_96_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    const uint32_t *rk = ks->k + 3 * PYJAMASK_ROUNDS;
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
    rk -= 3;

    /* Perform all encryption rounds */
    for (round = 0; round < PYJAMASK_ROUNDS; ++round, rk -= 3) {
        /* Inverse mix of the rows in the state */
        pyjamask_matrix_multiply_2037a121(s0);
        pyjamask_matrix_multiply_108ff2a0(s1);
        pyjamask_matrix_multiply_9054d8c0(s2);

        /* Apply the inverse of the 96-bit Pyjamask sbox */
        s0 ^= s1;
        s1 ^= s0;
        s2 = ~s2;
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

#endif
