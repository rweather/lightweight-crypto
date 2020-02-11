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

#include "internal-gimli24.h"

/* Apply the SP-box to a specific column in the state array */
#define GIMLI24_SP(col) \
    do { \
        x = leftRotate24(state[(col)]); \
        y = leftRotate9(state[(col) + 4]); \
        z = state[(col) + 8]; \
        state[(col) + 8] = x ^ (z << 1) ^ ((y & z) << 2); \
        state[(col) + 4] = y ^ x ^ ((x | z) << 1); \
        state[(col)] = z ^ y ^ ((x & y) << 3); \
    } while (0)

void gimli24_permute(uint32_t state[12])
{
    uint32_t x, y, z;
    unsigned round;

    /* Convert state from little-endian if the platform is not little-endian */
#if !defined(LW_UTIL_LITTLE_ENDIAN)
    for (round = 0; round < 12; ++round)
        state[round] = le_load_word32((const unsigned char *)(&(state[round])));
#endif

    /* Unroll and perform the rounds 4 at a time */
    for (round = 24; round > 0; round -= 4) {
        /* Round 0: SP-box, small swap, add round constant */
        GIMLI24_SP(0);
        GIMLI24_SP(1);
        GIMLI24_SP(2);
        GIMLI24_SP(3);
        x = state[0];
        y = state[2];
        state[0] = state[1] ^ 0x9e377900U ^ round;
        state[1] = x;
        state[2] = state[3];
        state[3] = y;

        /* Round 1: SP-box only */
        GIMLI24_SP(0);
        GIMLI24_SP(1);
        GIMLI24_SP(2);
        GIMLI24_SP(3);

        /* Round 2: SP-box, big swap */
        GIMLI24_SP(0);
        GIMLI24_SP(1);
        GIMLI24_SP(2);
        GIMLI24_SP(3);
        x = state[0];
        y = state[1];
        state[0] = state[2];
        state[1] = state[3];
        state[2] = x;
        state[3] = y;

        /* Round 3: SP-box only */
        GIMLI24_SP(0);
        GIMLI24_SP(1);
        GIMLI24_SP(2);
        GIMLI24_SP(3);
    }

    /* Convert state to little-endian if the platform is not little-endian */
#if !defined(LW_UTIL_LITTLE_ENDIAN)
    for (round = 0; round < 12; ++round)
        le_store_word32(((unsigned char *)(&(state[round]))), state[round]);
#endif
}
