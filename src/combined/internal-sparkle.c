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

#include "internal-sparkle.h"

#if !defined(__AVR__)

/* The 8 basic round constants from the specification */
#define RC_0 0xB7E15162
#define RC_1 0xBF715880
#define RC_2 0x38B4DA56
#define RC_3 0x324E7738
#define RC_4 0xBB1185EB
#define RC_5 0x4F7C7B57
#define RC_6 0xCFBFA1C8
#define RC_7 0xC2B3293D

/* Round constants for all SPARKLE steps; maximum of 12 for SPARKLE-512 */
static uint32_t const sparkle_rc[12] = {
    RC_0, RC_1, RC_2, RC_3, RC_4, RC_5, RC_6, RC_7,
    RC_0, RC_1, RC_2, RC_3
};

/**
 * \brief Alzette block cipher that implements the ARXbox layer of the
 * SPARKLE permutation.
 *
 * \param x Left half of the 64-bit block.
 * \param y Right half of the 64-bit block.
 * \param k 32-bit round key.
 */
#define alzette(x, y, k) \
    do { \
        (x) += leftRotate1((y)); \
        (y) ^= leftRotate8((x)); \
        (x) ^= (k); \
        (x) += leftRotate15((y)); \
        (y) ^= leftRotate15((x)); \
        (x) ^= (k); \
        (x) += (y); \
        (y) ^= leftRotate1((x)); \
        (x) ^= (k); \
        (x) += leftRotate8((y)); \
        (y) ^= leftRotate16((x)); \
        (x) ^= (k); \
    } while (0)

void sparkle_256(uint32_t s[SPARKLE_256_STATE_SIZE], unsigned steps)
{
    uint32_t x0, x1, x2, x3;
    uint32_t y0, y1, y2, y3;
    uint32_t tx, ty;
    unsigned step;

    /* Load the SPARKLE-256 state up into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = s[0];
    y0 = s[1];
    x1 = s[2];
    y1 = s[3];
    x2 = s[4];
    y2 = s[5];
    x3 = s[6];
    y3 = s[7];
#else
    x0 = le_load_word32((const uint8_t *)&(s[0]));
    y0 = le_load_word32((const uint8_t *)&(s[1]));
    x1 = le_load_word32((const uint8_t *)&(s[2]));
    y1 = le_load_word32((const uint8_t *)&(s[3]));
    x2 = le_load_word32((const uint8_t *)&(s[4]));
    y2 = le_load_word32((const uint8_t *)&(s[5]));
    x3 = le_load_word32((const uint8_t *)&(s[6]));
    y3 = le_load_word32((const uint8_t *)&(s[7]));
#endif

    /* Perform all requested steps */
    for (step = 0; step < steps; ++step) {
        /* Add round constants */
        y0 ^= sparkle_rc[step];
        y1 ^= step;

        /* ARXbox layer */
        alzette(x0, y0, RC_0);
        alzette(x1, y1, RC_1);
        alzette(x2, y2, RC_2);
        alzette(x3, y3, RC_3);

        /* Linear layer */
        tx = x0 ^ x1;
        ty = y0 ^ y1;
        tx = leftRotate16(tx ^ (tx << 16));
        ty = leftRotate16(ty ^ (ty << 16));
        y2 ^= tx;
        tx ^= y3;
        y3 = y1;
        y1 = y2 ^ y0;
        y2 = y0;
        y0 = tx ^ y3;
        x2 ^= ty;
        ty ^= x3;
        x3 = x1;
        x1 = x2 ^ x0;
        x2 = x0;
        x0 = ty ^ x3;
    }

    /* Write the local variables back to the SPARKLE-256 state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s[0] = x0;
    s[1] = y0;
    s[2] = x1;
    s[3] = y1;
    s[4] = x2;
    s[5] = y2;
    s[6] = x3;
    s[7] = y3;
#else
    le_store_word32((uint8_t *)&(s[0]), x0);
    le_store_word32((uint8_t *)&(s[1]), y0);
    le_store_word32((uint8_t *)&(s[2]), x1);
    le_store_word32((uint8_t *)&(s[3]), y1);
    le_store_word32((uint8_t *)&(s[4]), x2);
    le_store_word32((uint8_t *)&(s[5]), y2);
    le_store_word32((uint8_t *)&(s[6]), x3);
    le_store_word32((uint8_t *)&(s[7]), y3);
#endif
}

void sparkle_384(uint32_t s[SPARKLE_384_STATE_SIZE], unsigned steps)
{
    uint32_t x0, x1, x2, x3, x4, x5;
    uint32_t y0, y1, y2, y3, y4, y5;
    uint32_t tx, ty;
    unsigned step;

    /* Load the SPARKLE-384 state up into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = s[0];
    y0 = s[1];
    x1 = s[2];
    y1 = s[3];
    x2 = s[4];
    y2 = s[5];
    x3 = s[6];
    y3 = s[7];
    x4 = s[8];
    y4 = s[9];
    x5 = s[10];
    y5 = s[11];
#else
    x0 = le_load_word32((const uint8_t *)&(s[0]));
    y0 = le_load_word32((const uint8_t *)&(s[1]));
    x1 = le_load_word32((const uint8_t *)&(s[2]));
    y1 = le_load_word32((const uint8_t *)&(s[3]));
    x2 = le_load_word32((const uint8_t *)&(s[4]));
    y2 = le_load_word32((const uint8_t *)&(s[5]));
    x3 = le_load_word32((const uint8_t *)&(s[6]));
    y3 = le_load_word32((const uint8_t *)&(s[7]));
    x4 = le_load_word32((const uint8_t *)&(s[8]));
    y4 = le_load_word32((const uint8_t *)&(s[9]));
    x5 = le_load_word32((const uint8_t *)&(s[10]));
    y5 = le_load_word32((const uint8_t *)&(s[11]));
#endif

    /* Perform all requested steps */
    for (step = 0; step < steps; ++step) {
        /* Add round constants */
        y0 ^= sparkle_rc[step];
        y1 ^= step;

        /* ARXbox layer */
        alzette(x0, y0, RC_0);
        alzette(x1, y1, RC_1);
        alzette(x2, y2, RC_2);
        alzette(x3, y3, RC_3);
        alzette(x4, y4, RC_4);
        alzette(x5, y5, RC_5);

        /* Linear layer */
        tx = x0 ^ x1 ^ x2;
        ty = y0 ^ y1 ^ y2;
        tx = leftRotate16(tx ^ (tx << 16));
        ty = leftRotate16(ty ^ (ty << 16));
        y3 ^= tx;
        y4 ^= tx;
        tx ^= y5;
        y5 = y2;
        y2 = y3 ^ y0;
        y3 = y0;
        y0 = y4 ^ y1;
        y4 = y1;
        y1 = tx ^ y5;
        x3 ^= ty;
        x4 ^= ty;
        ty ^= x5;
        x5 = x2;
        x2 = x3 ^ x0;
        x3 = x0;
        x0 = x4 ^ x1;
        x4 = x1;
        x1 = ty ^ x5;
    }

    /* Write the local variables back to the SPARKLE-384 state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s[0]  = x0;
    s[1]  = y0;
    s[2]  = x1;
    s[3]  = y1;
    s[4]  = x2;
    s[5]  = y2;
    s[6]  = x3;
    s[7]  = y3;
    s[8]  = x4;
    s[9]  = y4;
    s[10] = x5;
    s[11] = y5;
#else
    le_store_word32((uint8_t *)&(s[0]),  x0);
    le_store_word32((uint8_t *)&(s[1]),  y0);
    le_store_word32((uint8_t *)&(s[2]),  x1);
    le_store_word32((uint8_t *)&(s[3]),  y1);
    le_store_word32((uint8_t *)&(s[4]),  x2);
    le_store_word32((uint8_t *)&(s[5]),  y2);
    le_store_word32((uint8_t *)&(s[6]),  x3);
    le_store_word32((uint8_t *)&(s[7]),  y3);
    le_store_word32((uint8_t *)&(s[8]),  x4);
    le_store_word32((uint8_t *)&(s[9]),  y4);
    le_store_word32((uint8_t *)&(s[10]), x5);
    le_store_word32((uint8_t *)&(s[11]), y5);
#endif
}

void sparkle_512(uint32_t s[SPARKLE_512_STATE_SIZE], unsigned steps)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t y0, y1, y2, y3, y4, y5, y6, y7;
    uint32_t tx, ty;
    unsigned step;

    /* Load the SPARKLE-512 state up into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = s[0];
    y0 = s[1];
    x1 = s[2];
    y1 = s[3];
    x2 = s[4];
    y2 = s[5];
    x3 = s[6];
    y3 = s[7];
    x4 = s[8];
    y4 = s[9];
    x5 = s[10];
    y5 = s[11];
    x6 = s[12];
    y6 = s[13];
    x7 = s[14];
    y7 = s[15];
#else
    x0 = le_load_word32((const uint8_t *)&(s[0]));
    y0 = le_load_word32((const uint8_t *)&(s[1]));
    x1 = le_load_word32((const uint8_t *)&(s[2]));
    y1 = le_load_word32((const uint8_t *)&(s[3]));
    x2 = le_load_word32((const uint8_t *)&(s[4]));
    y2 = le_load_word32((const uint8_t *)&(s[5]));
    x3 = le_load_word32((const uint8_t *)&(s[6]));
    y3 = le_load_word32((const uint8_t *)&(s[7]));
    x4 = le_load_word32((const uint8_t *)&(s[8]));
    y4 = le_load_word32((const uint8_t *)&(s[9]));
    x5 = le_load_word32((const uint8_t *)&(s[10]));
    y5 = le_load_word32((const uint8_t *)&(s[11]));
    x6 = le_load_word32((const uint8_t *)&(s[12]));
    y6 = le_load_word32((const uint8_t *)&(s[13]));
    x7 = le_load_word32((const uint8_t *)&(s[14]));
    y7 = le_load_word32((const uint8_t *)&(s[15]));
#endif

    /* Perform all requested steps */
    for (step = 0; step < steps; ++step) {
        /* Add round constants */
        y0 ^= sparkle_rc[step];
        y1 ^= step;

        /* ARXbox layer */
        alzette(x0, y0, RC_0);
        alzette(x1, y1, RC_1);
        alzette(x2, y2, RC_2);
        alzette(x3, y3, RC_3);
        alzette(x4, y4, RC_4);
        alzette(x5, y5, RC_5);
        alzette(x6, y6, RC_6);
        alzette(x7, y7, RC_7);

        /* Linear layer */
        tx = x0 ^ x1 ^ x2 ^ x3;
        ty = y0 ^ y1 ^ y2 ^ y3;
        tx = leftRotate16(tx ^ (tx << 16));
        ty = leftRotate16(ty ^ (ty << 16));
        y4 ^= tx;
        y5 ^= tx;
        y6 ^= tx;
        tx ^= y7;
        y7 = y3;
        y3 = y4 ^ y0;
        y4 = y0;
        y0 = y5 ^ y1;
        y5 = y1;
        y1 = y6 ^ y2;
        y6 = y2;
        y2 = tx ^ y7;
        x4 ^= ty;
        x5 ^= ty;
        x6 ^= ty;
        ty ^= x7;
        x7 = x3;
        x3 = x4 ^ x0;
        x4 = x0;
        x0 = x5 ^ x1;
        x5 = x1;
        x1 = x6 ^ x2;
        x6 = x2;
        x2 = ty ^ x7;
    }

    /* Write the local variables back to the SPARKLE-512 state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s[0]  = x0;
    s[1]  = y0;
    s[2]  = x1;
    s[3]  = y1;
    s[4]  = x2;
    s[5]  = y2;
    s[6]  = x3;
    s[7]  = y3;
    s[8]  = x4;
    s[9]  = y4;
    s[10] = x5;
    s[11] = y5;
    s[12] = x6;
    s[13] = y6;
    s[14] = x7;
    s[15] = y7;
#else
    le_store_word32((uint8_t *)&(s[0]),  x0);
    le_store_word32((uint8_t *)&(s[1]),  y0);
    le_store_word32((uint8_t *)&(s[2]),  x1);
    le_store_word32((uint8_t *)&(s[3]),  y1);
    le_store_word32((uint8_t *)&(s[4]),  x2);
    le_store_word32((uint8_t *)&(s[5]),  y2);
    le_store_word32((uint8_t *)&(s[6]),  x3);
    le_store_word32((uint8_t *)&(s[7]),  y3);
    le_store_word32((uint8_t *)&(s[8]),  x4);
    le_store_word32((uint8_t *)&(s[9]),  y4);
    le_store_word32((uint8_t *)&(s[10]), x5);
    le_store_word32((uint8_t *)&(s[11]), y5);
    le_store_word32((uint8_t *)&(s[12]), x6);
    le_store_word32((uint8_t *)&(s[13]), y6);
    le_store_word32((uint8_t *)&(s[14]), x7);
    le_store_word32((uint8_t *)&(s[15]), y7);
#endif
}

#endif
