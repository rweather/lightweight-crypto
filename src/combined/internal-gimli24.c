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
#define GIMLI24_SP(s0, s4, s8) \
    do { \
        x = leftRotate24(s0); \
        y = leftRotate9(s4); \
        s4 = y ^ x ^ ((x | s8) << 1); \
        s0 = s8 ^ y ^ ((x & y) << 3); \
        s8 = x ^ (s8 << 1) ^ ((y & s8) << 2); \
    } while (0)

void gimli24_permute(uint32_t state[12])
{
    uint32_t s0, s1, s2, s3, s4,  s5;
    uint32_t s6, s7, s8, s9, s10, s11;
    uint32_t x, y;
    unsigned round;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s0  = state[0];
    s1  = state[1];
    s2  = state[2];
    s3  = state[3];
    s4  = state[4];
    s5  = state[5];
    s6  = state[6];
    s7  = state[7];
    s8  = state[8];
    s9  = state[9];
    s10 = state[10];
    s11 = state[11];
#else
    s0  = le_load_word32((const unsigned char *)(&(state[0])));
    s1  = le_load_word32((const unsigned char *)(&(state[1])));
    s2  = le_load_word32((const unsigned char *)(&(state[2])));
    s3  = le_load_word32((const unsigned char *)(&(state[3])));
    s4  = le_load_word32((const unsigned char *)(&(state[4])));
    s5  = le_load_word32((const unsigned char *)(&(state[5])));
    s6  = le_load_word32((const unsigned char *)(&(state[6])));
    s7  = le_load_word32((const unsigned char *)(&(state[7])));
    s8  = le_load_word32((const unsigned char *)(&(state[8])));
    s9  = le_load_word32((const unsigned char *)(&(state[9])));
    s10 = le_load_word32((const unsigned char *)(&(state[10])));
    s11 = le_load_word32((const unsigned char *)(&(state[11])));
#endif

    /* Unroll and perform the rounds 4 at a time */
    for (round = 24; round > 0; round -= 4) {
        /* Round 0: SP-box, small swap, add round constant */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);
        x = s0;
        y = s2;
        s0 = s1 ^ 0x9e377900U ^ round;
        s1 = x;
        s2 = s3;
        s3 = y;

        /* Round 1: SP-box only */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);

        /* Round 2: SP-box, big swap */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);
        x = s0;
        y = s1;
        s0 = s2;
        s1 = s3;
        s2 = x;
        s3 = y;

        /* Round 3: SP-box only */
        GIMLI24_SP(s0, s4, s8);
        GIMLI24_SP(s1, s5, s9);
        GIMLI24_SP(s2, s6, s10);
        GIMLI24_SP(s3, s7, s11);
    }

    /* Convert state to little-endian if the platform is not little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state[0]  = s0;
    state[1]  = s1;
    state[2]  = s2;
    state[3]  = s3;
    state[4]  = s4;
    state[5]  = s5;
    state[6]  = s6;
    state[7]  = s7;
    state[8]  = s8;
    state[9]  = s9;
    state[10] = s10;
    state[11] = s11;
#else
    le_store_word32(((unsigned char *)(&(state[0]))),  s0);
    le_store_word32(((unsigned char *)(&(state[1]))),  s1);
    le_store_word32(((unsigned char *)(&(state[2]))),  s2);
    le_store_word32(((unsigned char *)(&(state[3]))),  s3);
    le_store_word32(((unsigned char *)(&(state[4]))),  s4);
    le_store_word32(((unsigned char *)(&(state[5]))),  s5);
    le_store_word32(((unsigned char *)(&(state[6]))),  s6);
    le_store_word32(((unsigned char *)(&(state[7]))),  s7);
    le_store_word32(((unsigned char *)(&(state[8]))),  s8);
    le_store_word32(((unsigned char *)(&(state[9]))),  s9);
    le_store_word32(((unsigned char *)(&(state[10]))), s10);
    le_store_word32(((unsigned char *)(&(state[11]))), s11);
#endif
}
