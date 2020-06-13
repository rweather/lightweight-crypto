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

#include "internal-photon256.h"
#include "internal-util.h"

#if !defined(__AVR__)

/**
 * \brief Number of rounds in the PHOTON-256 permutation in bit-sliced form.
 */
#define PHOTON256_ROUNDS 12

/* Round constants for PHOTON-256 */
static uint32_t const photon256_rc[PHOTON256_ROUNDS] = {
    0x96d2f0e1, 0xb4f0d2c3, 0xf0b49687, 0x692d0f1e,
    0x5a1e3c2d, 0x3c785a4b, 0xe1a58796, 0x4b0f2d3c,
    0x1e5a7869, 0xa5e1c3d2, 0xd296b4a5, 0x2d694b5a
};

/**
 * \brief Evaluates the PHOTON-256 S-box in bit-sliced form.
 *
 * \param x0 Slice with bit 0 of all nibbles.
 * \param x1 Slice with bit 1 of all nibbles.
 * \param x2 Slice with bit 2 of all nibbles.
 * \param x3 Slice with bit 3 of all nibbles.
 *
 * This bit-sliced S-box implementation is based on the AVR version
 * "add_avr8_bitslice_asm" from the PHOTON-Beetle reference code.
 */
#define photon256_sbox(x0, x1, x2, x3) \
    do { \
        x1 ^= x2; \
        x3 ^= (x2 & x1); \
        t1 = x3; \
        x3 = (x3 & x1) ^ x2; \
        t2 = x3; \
        x3 ^= x0; \
        x3 = ~(x3); \
        x2 = x3; \
        t2 |= x0; \
        x0 ^= t1; \
        x1 ^= x0; \
        x2 |= x1; \
        x2 ^= t1; \
        x1 ^= t2; \
        x3 ^= x1; \
    } while (0)

/**
 * \brief Performs a field multiplication on the 8 nibbles in a row.
 *
 * \param a Field constant to multiply by.
 * \param x Bit-sliced form of the row, with bits 0..3 of each nibble
 * in bytes 0..3 of the word.
 *
 * \return a * x packed into the bytes of a word.
 */
static uint32_t photon256_field_multiply(uint8_t a, uint32_t x)
{
    /* For each 4-bit nibble we need to do this:
     *
     *      result = 0;
     *      for (bit = 0; bit < 4; ++ bit) {
     *          if ((a & (1 << bit)) != 0)
     *              result ^= x;
     *          if ((x & 0x08) != 0) {
     *              x = (x << 1) ^ 3;
     *          } else {
     *              x = (x << 1);
     *          }
     *      }
     *
     * We don't need to worry about constant time for "a" because it is a
     * known constant that isn't data-dependent.  But we do need to worry
     * about constant time for "x" as it is data.
     */
    uint32_t result = 0;
    uint32_t t;
    #define PARALLEL_CONDITIONAL_ADD(bit) \
        do { \
            if ((a) & (1 << (bit))) \
                result ^= x; \
        } while (0)
    #define PARALELL_ROTATE() \
        do { \
            t = x >> 24; \
            x = (x << 8) ^ t ^ (t << 8); \
        } while (0)
    PARALLEL_CONDITIONAL_ADD(0);
    PARALELL_ROTATE();
    PARALLEL_CONDITIONAL_ADD(1);
    PARALELL_ROTATE();
    PARALLEL_CONDITIONAL_ADD(2);
    PARALELL_ROTATE();
    PARALLEL_CONDITIONAL_ADD(3);
    return result;
}

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/**
 * \brief Converts a PHOTON-256 state into bit-sliced form.
 *
 * \param out Points to the converted output.
 * \param in Points to the PHOTON-256 state to convert.
 */
static void photon256_to_sliced
    (uint32_t out[PHOTON256_STATE_SIZE / 4],
     const unsigned char in[PHOTON256_STATE_SIZE])
{
    /* We first scatter bits 0..3 of the nibbles to bytes 0..3 of the words.
     * Then we rearrange the bytes to group all bits N into word N.
     *
     * Permutation generated with "http://programming.sirrida.de/calcperm.php".
     *
     * P = [0 8 16 24 1 9 17 25 2 10 18 26 3 11 19 27
     *      4 12 20 28 5 13 21 29 6 14 22 30 7 15 23 31]
     */
    uint32_t t0, t1, t2, t3;
    #define TO_BITSLICED_PERM(x) \
        do { \
            bit_permute_step(x, 0x0a0a0a0a, 3); \
            bit_permute_step(x, 0x00cc00cc, 6); \
            bit_permute_step(x, 0x0000f0f0, 12); \
            bit_permute_step(x, 0x0000ff00, 8); \
        } while (0)
    #define FROM_BITSLICED_PERM(x) \
        do { \
            bit_permute_step(x, 0x00aa00aa, 7); \
            bit_permute_step(x, 0x0000cccc, 14); \
            bit_permute_step(x, 0x00f000f0, 4); \
            bit_permute_step(x, 0x0000ff00, 8); \
        } while (0)
    t0 = le_load_word32(in);
    t1 = le_load_word32(in + 4);
    t2 = le_load_word32(in + 8);
    t3 = le_load_word32(in + 12);
    TO_BITSLICED_PERM(t0);
    TO_BITSLICED_PERM(t1);
    TO_BITSLICED_PERM(t2);
    TO_BITSLICED_PERM(t3);
    out[0] = (t0 & 0x000000FFU) | ((t1 << 8) & 0x0000FF00U) |
             ((t2 << 16) & 0x00FF0000U) | ((t3 << 24) & 0xFF000000U);
    out[1] = ((t0 >> 8) & 0x000000FFU) | (t1 & 0x0000FF00U) |
             ((t2 << 8) & 0x00FF0000U) | ((t3 << 16) & 0xFF000000U);
    out[2] = ((t0 >> 16) & 0x000000FFU) | ((t1 >> 8) & 0x0000FF00U) |
             (t2 & 0x00FF0000U) | ((t3 << 8) & 0xFF000000U);
    out[3] = ((t0 >> 24) & 0x000000FFU) | ((t1 >> 16) & 0x0000FF00U) |
             ((t2 >> 8) & 0x00FF0000U) | (t3 & 0xFF000000U);
    t0 = le_load_word32(in + 16);
    t1 = le_load_word32(in + 20);
    t2 = le_load_word32(in + 24);
    t3 = le_load_word32(in + 28);
    TO_BITSLICED_PERM(t0);
    TO_BITSLICED_PERM(t1);
    TO_BITSLICED_PERM(t2);
    TO_BITSLICED_PERM(t3);
    out[4] = (t0 & 0x000000FFU) | ((t1 << 8) & 0x0000FF00U) |
             ((t2 << 16) & 0x00FF0000U) | ((t3 << 24) & 0xFF000000U);
    out[5] = ((t0 >> 8) & 0x000000FFU) | (t1 & 0x0000FF00U) |
             ((t2 << 8) & 0x00FF0000U) | ((t3 << 16) & 0xFF000000U);
    out[6] = ((t0 >> 16) & 0x000000FFU) | ((t1 >> 8) & 0x0000FF00U) |
             (t2 & 0x00FF0000U) | ((t3 << 8) & 0xFF000000U);
    out[7] = ((t0 >> 24) & 0x000000FFU) | ((t1 >> 16) & 0x0000FF00U) |
             ((t2 >> 8) & 0x00FF0000U) | (t3 & 0xFF000000U);
}

/**
 * \brief Converts a PHOTON-256 state from bit-sliced form.
 *
 * \param out Points to the converted output.
 * \param in Points to the PHOTON-256 state to convert.
 */
static void photon256_from_sliced
    (unsigned char out[PHOTON256_STATE_SIZE],
     const unsigned char in[PHOTON256_STATE_SIZE])
{
    /* Do the reverse of photon256_to_sliced() */
    uint32_t x0, x1, x2, x3;
    x0 =  ((uint32_t)(in[0])) |
         (((uint32_t)(in[4]))  << 8) |
         (((uint32_t)(in[8]))  << 16) |
         (((uint32_t)(in[12])) << 24);
    x1 =  ((uint32_t)(in[1])) |
         (((uint32_t)(in[5]))  << 8) |
         (((uint32_t)(in[9]))  << 16) |
         (((uint32_t)(in[13])) << 24);
    x2 =  ((uint32_t)(in[2])) |
         (((uint32_t)(in[6]))  << 8) |
         (((uint32_t)(in[10])) << 16) |
         (((uint32_t)(in[14])) << 24);
    x3 =  ((uint32_t)(in[3])) |
         (((uint32_t)(in[7]))  << 8) |
         (((uint32_t)(in[11])) << 16) |
         (((uint32_t)(in[15])) << 24);
    FROM_BITSLICED_PERM(x0);
    FROM_BITSLICED_PERM(x1);
    FROM_BITSLICED_PERM(x2);
    FROM_BITSLICED_PERM(x3);
    le_store_word32(out,      x0);
    le_store_word32(out + 4,  x1);
    le_store_word32(out + 8,  x2);
    le_store_word32(out + 12, x3);
    x0 =  ((uint32_t)(in[16])) |
         (((uint32_t)(in[20])) << 8) |
         (((uint32_t)(in[24])) << 16) |
         (((uint32_t)(in[28])) << 24);
    x1 =  ((uint32_t)(in[17])) |
         (((uint32_t)(in[21])) << 8) |
         (((uint32_t)(in[25])) << 16) |
         (((uint32_t)(in[29])) << 24);
    x2 =  ((uint32_t)(in[18])) |
         (((uint32_t)(in[22])) << 8) |
         (((uint32_t)(in[26])) << 16) |
         (((uint32_t)(in[30])) << 24);
    x3 =  ((uint32_t)(in[19])) |
         (((uint32_t)(in[23])) << 8) |
         (((uint32_t)(in[27])) << 16) |
         (((uint32_t)(in[31])) << 24);
    FROM_BITSLICED_PERM(x0);
    FROM_BITSLICED_PERM(x1);
    FROM_BITSLICED_PERM(x2);
    FROM_BITSLICED_PERM(x3);
    le_store_word32(out + 16, x0);
    le_store_word32(out + 20, x1);
    le_store_word32(out + 24, x2);
    le_store_word32(out + 28, x3);
}

#if defined(LW_UTIL_LITTLE_ENDIAN)
/* Index the bit-sliced state bytes in little-endian byte order */
#define READ_ROW0() \
     (((uint32_t)(S.bytes[0])) | \
     (((uint32_t)(S.bytes[4]))  << 8)  | \
     (((uint32_t)(S.bytes[8]))  << 16) | \
     (((uint32_t)(S.bytes[12])) << 24))
#define READ_ROW1() \
     (((uint32_t)(S.bytes[1])) | \
     (((uint32_t)(S.bytes[5]))  << 8)  | \
     (((uint32_t)(S.bytes[9]))  << 16) | \
     (((uint32_t)(S.bytes[13])) << 24))
#define READ_ROW2() \
     (((uint32_t)(S.bytes[2])) | \
     (((uint32_t)(S.bytes[6]))  << 8)  | \
     (((uint32_t)(S.bytes[10])) << 16) | \
     (((uint32_t)(S.bytes[14])) << 24))
#define READ_ROW3() \
     (((uint32_t)(S.bytes[3])) | \
     (((uint32_t)(S.bytes[7]))  << 8)  | \
     (((uint32_t)(S.bytes[11])) << 16) | \
     (((uint32_t)(S.bytes[15])) << 24))
#define READ_ROW4() \
     (((uint32_t)(S.bytes[16])) | \
     (((uint32_t)(S.bytes[20])) << 8)  | \
     (((uint32_t)(S.bytes[24])) << 16) | \
     (((uint32_t)(S.bytes[28])) << 24))
#define READ_ROW5() \
     (((uint32_t)(S.bytes[17])) | \
     (((uint32_t)(S.bytes[21])) << 8)  | \
     (((uint32_t)(S.bytes[25])) << 16) | \
     (((uint32_t)(S.bytes[29])) << 24))
#define READ_ROW6() \
     (((uint32_t)(S.bytes[18])) | \
     (((uint32_t)(S.bytes[22])) << 8)  | \
     (((uint32_t)(S.bytes[26])) << 16) | \
     (((uint32_t)(S.bytes[30])) << 24))
#define READ_ROW7() \
     (((uint32_t)(S.bytes[19])) | \
     (((uint32_t)(S.bytes[23])) << 8)  | \
     (((uint32_t)(S.bytes[27])) << 16) | \
     (((uint32_t)(S.bytes[31])) << 24))
#define WRITE_ROW(row, value) \
    do { \
        if ((row) < 4) { \
            S.bytes[(row)]      = (uint8_t)(value); \
            S.bytes[(row) + 4]  = (uint8_t)((value) >> 8); \
            S.bytes[(row) + 8]  = (uint8_t)((value) >> 16); \
            S.bytes[(row) + 12] = (uint8_t)((value) >> 24); \
        } else { \
            S.bytes[(row) + 12] = (uint8_t)(value); \
            S.bytes[(row) + 16] = (uint8_t)((value) >> 8); \
            S.bytes[(row) + 20] = (uint8_t)((value) >> 16); \
            S.bytes[(row) + 24] = (uint8_t)((value) >> 24); \
        } \
    } while (0)
#else
/* Index the bit-sliced state bytes in big-endian byte order */
#define READ_ROW0() \
     (((uint32_t)(S.bytes[3])) | \
     (((uint32_t)(S.bytes[7]))  << 8)  | \
     (((uint32_t)(S.bytes[11])) << 16) | \
     (((uint32_t)(S.bytes[15])) << 24))
#define READ_ROW1() \
     (((uint32_t)(S.bytes[2])) | \
     (((uint32_t)(S.bytes[6]))  << 8)  | \
     (((uint32_t)(S.bytes[10])) << 16) | \
     (((uint32_t)(S.bytes[14])) << 24))
#define READ_ROW2() \
     (((uint32_t)(S.bytes[1])) | \
     (((uint32_t)(S.bytes[5]))  << 8)  | \
     (((uint32_t)(S.bytes[9]))  << 16) | \
     (((uint32_t)(S.bytes[13])) << 24))
#define READ_ROW3() \
     (((uint32_t)(S.bytes[0])) | \
     (((uint32_t)(S.bytes[4]))  << 8)  | \
     (((uint32_t)(S.bytes[8]))  << 16) | \
     (((uint32_t)(S.bytes[12])) << 24))
#define READ_ROW4() \
     (((uint32_t)(S.bytes[19])) | \
     (((uint32_t)(S.bytes[23])) << 8)  | \
     (((uint32_t)(S.bytes[27])) << 16) | \
     (((uint32_t)(S.bytes[31])) << 24))
#define READ_ROW5() \
     (((uint32_t)(S.bytes[18])) | \
     (((uint32_t)(S.bytes[22])) << 8)  | \
     (((uint32_t)(S.bytes[26])) << 16) | \
     (((uint32_t)(S.bytes[30])) << 24))
#define READ_ROW6() \
     (((uint32_t)(S.bytes[17])) | \
     (((uint32_t)(S.bytes[21])) << 8)  | \
     (((uint32_t)(S.bytes[25])) << 16) | \
     (((uint32_t)(S.bytes[29])) << 24))
#define READ_ROW7() \
     (((uint32_t)(S.bytes[16])) | \
     (((uint32_t)(S.bytes[20])) << 8)  | \
     (((uint32_t)(S.bytes[24])) << 16) | \
     (((uint32_t)(S.bytes[28])) << 24))
#define WRITE_ROW(row, value) \
    do { \
        if ((row) < 4) { \
            S.bytes[3  - (row)] = (uint8_t)(value); \
            S.bytes[7  - (row)] = (uint8_t)((value) >> 8); \
            S.bytes[11 - (row)] = (uint8_t)((value) >> 16); \
            S.bytes[15 - (row)] = (uint8_t)((value) >> 24); \
        } else { \
            S.bytes[20 - (row)] = (uint8_t)(value); \
            S.bytes[24 - (row)] = (uint8_t)((value) >> 8); \
            S.bytes[28 - (row)] = (uint8_t)((value) >> 16); \
            S.bytes[32 - (row)] = (uint8_t)((value) >> 24); \
        } \
    } while (0)
#endif

void photon256_permute(unsigned char state[PHOTON256_STATE_SIZE])
{
    union {
        uint32_t words[PHOTON256_STATE_SIZE / 4];
        uint8_t bytes[PHOTON256_STATE_SIZE];
    } S;
    uint32_t t0, t1, t2, t3, t4, t5, t6, t7, t8;
    uint8_t round;

    /* Convert the state into bit-sliced form */
    photon256_to_sliced(S.words, state);

    /* Perform all 12 permutation rounds */
    for (round = 0; round < PHOTON256_ROUNDS; ++round) {
        /* Add the constants for this round */
        t0 = photon256_rc[round];
        S.words[0] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[1] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[2] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[3] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[4] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[5] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[6] ^= t0 & 0x01010101U;
        t0 >>= 1;
        S.words[7] ^= t0 & 0x01010101U;

        /* Apply the sbox to all nibbles in the state */
        photon256_sbox(S.words[0], S.words[1], S.words[2], S.words[3]);
        photon256_sbox(S.words[4], S.words[5], S.words[6], S.words[7]);

        /* Rotate all rows left by the row number.
         *
         * We do this by applying permutations to the top and bottom words
         * to rearrange the bits into the rotated form.  Permutations
         * generated with "http://programming.sirrida.de/calcperm.php".
         *
         * P_top = [0 1 2 3 4 5 6 7 15 8 9 10 11 12 13 14 22 23
         *          16 17 18 19 20 21 29 30 31 24 25 26 27 28]
         * P_bot = [4 5 6 7 0 1 2 3 11 12 13 14 15 8 9 10 18 19
         *          20 21 22 23 16 17 25 26 27 28 29 30 31 24
         */
        #define TOP_ROTATE_PERM(x) \
            do { \
                t1 = (x); \
                bit_permute_step(t1, 0x07030100, 4); \
                bit_permute_step(t1, 0x22331100, 2); \
                bit_permute_step(t1, 0x55005500, 1); \
                (x) = t1; \
            } while (0)
        #define BOTTOM_ROTATE_PERM(x) \
            do { \
                t1 = (x); \
                bit_permute_step(t1, 0x080c0e0f, 4); \
                bit_permute_step(t1, 0x22331100, 2); \
                bit_permute_step(t1, 0x55005500, 1); \
                (x) = t1; \
            } while (0)
        TOP_ROTATE_PERM(S.words[0]);
        TOP_ROTATE_PERM(S.words[1]);
        TOP_ROTATE_PERM(S.words[2]);
        TOP_ROTATE_PERM(S.words[3]);
        BOTTOM_ROTATE_PERM(S.words[4]);
        BOTTOM_ROTATE_PERM(S.words[5]);
        BOTTOM_ROTATE_PERM(S.words[6]);
        BOTTOM_ROTATE_PERM(S.words[7]);

        /* Mix the columns */
        #define MUL(a, x) (photon256_field_multiply((a), (x)))
        t0 = READ_ROW0();
        t1 = READ_ROW1();
        t2 = READ_ROW2();
        t3 = READ_ROW3();
        t4 = READ_ROW4();
        t5 = READ_ROW5();
        t6 = READ_ROW6();
        t7 = READ_ROW7();
        t8 = MUL(0x02, t0) ^ MUL(0x04, t1) ^ MUL(0x02, t2) ^ MUL(0x0b, t3) ^
             MUL(0x02, t4) ^ MUL(0x08, t5) ^ MUL(0x05, t6) ^ MUL(0x06, t7);
        WRITE_ROW(0, t8);
        t8 = MUL(0x0c, t0) ^ MUL(0x09, t1) ^ MUL(0x08, t2) ^ MUL(0x0d, t3) ^
             MUL(0x07, t4) ^ MUL(0x07, t5) ^ MUL(0x05, t6) ^ MUL(0x02, t7);
        WRITE_ROW(1, t8);
        t8 = MUL(0x04, t0) ^ MUL(0x04, t1) ^ MUL(0x0d, t2) ^ MUL(0x0d, t3) ^
             MUL(0x09, t4) ^ MUL(0x04, t5) ^ MUL(0x0d, t6) ^ MUL(0x09, t7);
        WRITE_ROW(2, t8);
        t8 = MUL(0x01, t0) ^ MUL(0x06, t1) ^ MUL(0x05, t2) ^ MUL(0x01, t3) ^
             MUL(0x0c, t4) ^ MUL(0x0d, t5) ^ MUL(0x0f, t6) ^ MUL(0x0e, t7);
        WRITE_ROW(3, t8);
        t8 = MUL(0x0f, t0) ^ MUL(0x0c, t1) ^ MUL(0x09, t2) ^ MUL(0x0d, t3) ^
             MUL(0x0e, t4) ^ MUL(0x05, t5) ^ MUL(0x0e, t6) ^ MUL(0x0d, t7);
        WRITE_ROW(4, t8);
        t8 = MUL(0x09, t0) ^ MUL(0x0e, t1) ^ MUL(0x05, t2) ^ MUL(0x0f, t3) ^
             MUL(0x04, t4) ^ MUL(0x0c, t5) ^ MUL(0x09, t6) ^ MUL(0x06, t7);
        WRITE_ROW(5, t8);
        t8 = MUL(0x0c, t0) ^ MUL(0x02, t1) ^ MUL(0x02, t2) ^ MUL(0x0a, t3) ^
             MUL(0x03, t4) ^ MUL(0x01, t5) ^ MUL(0x01, t6) ^ MUL(0x0e, t7);
        WRITE_ROW(6, t8);
        t8 = MUL(0x0f, t0) ^ MUL(0x01, t1) ^ MUL(0x0d, t2) ^ MUL(0x0a, t3) ^
             MUL(0x05, t4) ^ MUL(0x0a, t5) ^ MUL(0x02, t6) ^ MUL(0x03, t7);
        WRITE_ROW(7, t8);
    }

    /* Convert back from bit-sliced form to regular form */
    photon256_from_sliced(state, S.bytes);
}

#endif /* !__AVR__ */
