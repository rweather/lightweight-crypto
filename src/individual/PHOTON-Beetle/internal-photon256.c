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

/**
 * \brief Number of rounds in the PHOTON-256 permutation.
 */
#define PHOTON256_ROUNDS 12

/**
 * \brief PHOTON-256 S-box implemented as a lookup table.
 *
 * Warning: This isn't constant-cache!
 */
static unsigned char const photon256_sbox_table[256] = {
    0xcc, 0xc5, 0xc6, 0xcb, 0xc9, 0xc0, 0xca, 0xcd,
    0xc3, 0xce, 0xcf, 0xc8, 0xc4, 0xc7, 0xc1, 0xc2,
    0x5c, 0x55, 0x56, 0x5b, 0x59, 0x50, 0x5a, 0x5d,
    0x53, 0x5e, 0x5f, 0x58, 0x54, 0x57, 0x51, 0x52,
    0x6c, 0x65, 0x66, 0x6b, 0x69, 0x60, 0x6a, 0x6d,
    0x63, 0x6e, 0x6f, 0x68, 0x64, 0x67, 0x61, 0x62,
    0xbc, 0xb5, 0xb6, 0xbb, 0xb9, 0xb0, 0xba, 0xbd,
    0xb3, 0xbe, 0xbf, 0xb8, 0xb4, 0xb7, 0xb1, 0xb2,
    0x9c, 0x95, 0x96, 0x9b, 0x99, 0x90, 0x9a, 0x9d,
    0x93, 0x9e, 0x9f, 0x98, 0x94, 0x97, 0x91, 0x92,
    0x0c, 0x05, 0x06, 0x0b, 0x09, 0x00, 0x0a, 0x0d,
    0x03, 0x0e, 0x0f, 0x08, 0x04, 0x07, 0x01, 0x02,
    0xac, 0xa5, 0xa6, 0xab, 0xa9, 0xa0, 0xaa, 0xad,
    0xa3, 0xae, 0xaf, 0xa8, 0xa4, 0xa7, 0xa1, 0xa2,
    0xdc, 0xd5, 0xd6, 0xdb, 0xd9, 0xd0, 0xda, 0xdd,
    0xd3, 0xde, 0xdf, 0xd8, 0xd4, 0xd7, 0xd1, 0xd2,
    0x3c, 0x35, 0x36, 0x3b, 0x39, 0x30, 0x3a, 0x3d,
    0x33, 0x3e, 0x3f, 0x38, 0x34, 0x37, 0x31, 0x32,
    0xec, 0xe5, 0xe6, 0xeb, 0xe9, 0xe0, 0xea, 0xed,
    0xe3, 0xee, 0xef, 0xe8, 0xe4, 0xe7, 0xe1, 0xe2,
    0xfc, 0xf5, 0xf6, 0xfb, 0xf9, 0xf0, 0xfa, 0xfd,
    0xf3, 0xfe, 0xff, 0xf8, 0xf4, 0xf7, 0xf1, 0xf2,
    0x8c, 0x85, 0x86, 0x8b, 0x89, 0x80, 0x8a, 0x8d,
    0x83, 0x8e, 0x8f, 0x88, 0x84, 0x87, 0x81, 0x82,
    0x4c, 0x45, 0x46, 0x4b, 0x49, 0x40, 0x4a, 0x4d,
    0x43, 0x4e, 0x4f, 0x48, 0x44, 0x47, 0x41, 0x42,
    0x7c, 0x75, 0x76, 0x7b, 0x79, 0x70, 0x7a, 0x7d,
    0x73, 0x7e, 0x7f, 0x78, 0x74, 0x77, 0x71, 0x72,
    0x1c, 0x15, 0x16, 0x1b, 0x19, 0x10, 0x1a, 0x1d,
    0x13, 0x1e, 0x1f, 0x18, 0x14, 0x17, 0x11, 0x12,
    0x2c, 0x25, 0x26, 0x2b, 0x29, 0x20, 0x2a, 0x2d,
    0x23, 0x2e, 0x2f, 0x28, 0x24, 0x27, 0x21, 0x22
};

/* Round constants for PHOTON-256 */
static unsigned char const photon256_rc[PHOTON256_ROUNDS * 8] = {
    0x01, 0x00, 0x02, 0x06, 0x0e, 0x0f, 0x0d, 0x09, /* Round 1 */
    0x03, 0x02, 0x00, 0x04, 0x0c, 0x0d, 0x0f, 0x0b, /* Round 2 */
    0x07, 0x06, 0x04, 0x00, 0x08, 0x09, 0x0b, 0x0f, /* Round 3 */
    0x0e, 0x0f, 0x0d, 0x09, 0x01, 0x00, 0x02, 0x06, /* Round 4 */
    0x0d, 0x0c, 0x0e, 0x0a, 0x02, 0x03, 0x01, 0x05, /* Round 5 */
    0x0b, 0x0a, 0x08, 0x0c, 0x04, 0x05, 0x07, 0x03, /* Round 6 */
    0x06, 0x07, 0x05, 0x01, 0x09, 0x08, 0x0a, 0x0e, /* Round 7 */
    0x0c, 0x0d, 0x0f, 0x0b, 0x03, 0x02, 0x00, 0x04, /* Round 8 */
    0x09, 0x08, 0x0a, 0x0e, 0x06, 0x07, 0x05, 0x01, /* Round 9 */
    0x02, 0x03, 0x01, 0x05, 0x0d, 0x0c, 0x0e, 0x0a, /* Round 10 */
    0x05, 0x04, 0x06, 0x02, 0x0a, 0x0b, 0x09, 0x0d, /* Round 11 */
    0x0a, 0x0b, 0x09, 0x0d, 0x05, 0x04, 0x06, 0x02  /* Round 12 */
};

/**
 * \brief Applies the PHOTON-256 S-box to all nibbles in a 32-bit word.
 *
 * \param x The word to apply the S-box to.
 * \param y The output of the S-box.
 *
 * Warning: This function does not have constant-cache behaviour!
 */
STATIC_INLINE uint32_t photon256_sbox(uint32_t x)
{
    uint32_t y;
    y = photon256_sbox_table[x & 0xFFU];
    y |= ((uint32_t)(photon256_sbox_table[(x >> 8)  & 0xFFU])) << 8;
    y |= ((uint32_t)(photon256_sbox_table[(x >> 16) & 0xFFU])) << 16;
    y |= ((uint32_t)(photon256_sbox_table[(x >> 24) & 0xFFU])) << 24;
    return y;
}

/**
 * \brief Performs a field multiplication on the 8 nibbles in a word.
 *
 * \param x 8 nibbles of first values for the multiplication.
 * \param y 8 nibbles of second values for the multiplication.
 *
 * \return x * y expressed as a set of 8 nibble results.
 */
static uint32_t photon256_field_multiply(uint32_t x, uint32_t y)
{
    /* For each 4-bit nibble we need to do this:
     *
     *      result = 0;
     *      for (bit = 0; bit < 4; ++ bit) {
     *          if ((y & (1 << bit)) != 0)
     *              result ^= x;
     *          if ((x & 0x08) != 0) {
     *              x = (x << 1) ^ 3;
     *          } else {
     *              x = (x << 1);
     *          }
     *      }
     *
     * Obviously we need to do this in constant time without conditionals,
     * and it needs to be done on 8 nibbles in parallel.
     */
    uint32_t result = 0;
    uint32_t mask;
    #define PARALLEL_CONDITIONAL_ADD() \
        do { \
            mask = (y & 0x11111111U); \
            mask |= (mask << 1); \
            mask |= (mask << 2); \
            result ^= x & mask; \
        } while (0)
    #define PARALELL_ROTATE() \
        do { \
            x = ((x << 1) & 0xEEEEEEEEU) ^ \
                ((x >> 3) & 0x11111111U) ^ \
                ((x >> 2) & 0x22222222U); \
            y >>= 1; \
        } while (0)
    PARALLEL_CONDITIONAL_ADD();
    PARALELL_ROTATE();
    PARALLEL_CONDITIONAL_ADD();
    PARALELL_ROTATE();
    PARALLEL_CONDITIONAL_ADD();
    PARALELL_ROTATE();
    PARALLEL_CONDITIONAL_ADD();
    return result;
}

void photon256_permute(unsigned char state[PHOTON256_STATE_SIZE])
{
    const unsigned char *rc = photon256_rc;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t t0, t1, t2, t3, t4, t5, t6;
    uint8_t round;

    /* Load the state into local variables */
    x0 = le_load_word32(state);
    x1 = le_load_word32(state + 4);
    x2 = le_load_word32(state + 8);
    x3 = le_load_word32(state + 12);
    x4 = le_load_word32(state + 16);
    x5 = le_load_word32(state + 20);
    x6 = le_load_word32(state + 24);
    x7 = le_load_word32(state + 28);

    /* Perform all 12 permutation rounds */
    for (round = 0; round < PHOTON256_ROUNDS; ++round, rc += 8) {
        /* Add the round constants for this round */
        x0 ^= rc[0]; x1 ^= rc[1]; x2 ^= rc[2]; x3 ^= rc[3];
        x4 ^= rc[4]; x5 ^= rc[5]; x6 ^= rc[6]; x7 ^= rc[7];

        /* Apply the sbox to all nibbles in the state */
        x0 = photon256_sbox(x0);
        x1 = photon256_sbox(x1);
        x2 = photon256_sbox(x2);
        x3 = photon256_sbox(x3);
        x4 = photon256_sbox(x4);
        x5 = photon256_sbox(x5);
        x6 = photon256_sbox(x6);
        x7 = photon256_sbox(x7);

        /* Rotate all rows left by the row number (no rotate for row 0).
         * Note: The left rotation on the nibbles turns into a right rotation
         * on the words because the left-most nibble is in the low bits */
        x1 = rightRotate4(x1);
        x2 = rightRotate8(x2);
        x3 = rightRotate12(x3);
        x4 = rightRotate16(x4);
        x5 = rightRotate20(x5);
        x6 = rightRotate24(x6);
        x7 = rightRotate28(x7);

        /* Mix the columns */
        #define MUL(x, y) (photon256_field_multiply((x), (y)))
        t0 = MUL(0x22222222, x0) ^ MUL(0x44444444, x1) ^ MUL(0x22222222, x2) ^
             MUL(0xbbbbbbbb, x3) ^ MUL(0x22222222, x4) ^ MUL(0x88888888, x5) ^
             MUL(0x55555555, x6) ^ MUL(0x66666666, x7);
        t1 = MUL(0xcccccccc, x0) ^ MUL(0x99999999, x1) ^ MUL(0x88888888, x2) ^
             MUL(0xdddddddd, x3) ^ MUL(0x77777777, x4) ^ MUL(0x77777777, x5) ^
             MUL(0x55555555, x6) ^ MUL(0x22222222, x7);
        t2 = MUL(0x44444444, x0) ^ MUL(0x44444444, x1) ^ MUL(0xdddddddd, x2) ^
             MUL(0xdddddddd, x3) ^ MUL(0x99999999, x4) ^ MUL(0x44444444, x5) ^
             MUL(0xdddddddd, x6) ^ MUL(0x99999999, x7);
        t3 = MUL(0x11111111, x0) ^ MUL(0x66666666, x1) ^ MUL(0x55555555, x2) ^
             MUL(0x11111111, x3) ^ MUL(0xcccccccc, x4) ^ MUL(0xdddddddd, x5) ^
             MUL(0xffffffff, x6) ^ MUL(0xeeeeeeee, x7);
        t4 = MUL(0xffffffff, x0) ^ MUL(0xcccccccc, x1) ^ MUL(0x99999999, x2) ^
             MUL(0xdddddddd, x3) ^ MUL(0xeeeeeeee, x4) ^ MUL(0x55555555, x5) ^
             MUL(0xeeeeeeee, x6) ^ MUL(0xdddddddd, x7);
        t5 = MUL(0x99999999, x0) ^ MUL(0xeeeeeeee, x1) ^ MUL(0x55555555, x2) ^
             MUL(0xffffffff, x3) ^ MUL(0x44444444, x4) ^ MUL(0xcccccccc, x5) ^
             MUL(0x99999999, x6) ^ MUL(0x66666666, x7);
        t6 = MUL(0xcccccccc, x0) ^ MUL(0x22222222, x1) ^ MUL(0x22222222, x2) ^
             MUL(0xaaaaaaaa, x3) ^ MUL(0x33333333, x4) ^ MUL(0x11111111, x5) ^
             MUL(0x11111111, x6) ^ MUL(0xeeeeeeee, x7);
        x7 = MUL(0xffffffff, x0) ^ MUL(0x11111111, x1) ^ MUL(0xdddddddd, x2) ^
             MUL(0xaaaaaaaa, x3) ^ MUL(0x55555555, x4) ^ MUL(0xaaaaaaaa, x5) ^
             MUL(0x22222222, x6) ^ MUL(0x33333333, x7);
        x0 = t0; x1 = t1; x2 = t2; x3 = t3;
        x4 = t4; x5 = t5; x6 = t6;
    }

    /* Store the local variables back to the state */
    le_store_word32(state,      x0);
    le_store_word32(state  + 4, x1);
    le_store_word32(state  + 8, x2);
    le_store_word32(state + 12, x3);
    le_store_word32(state + 16, x4);
    le_store_word32(state + 20, x5);
    le_store_word32(state + 24, x6);
    le_store_word32(state + 28, x7);
}
