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

#include "internal-gascon.h"

#if !defined(__AVR__)

/* Right rotations in bit-interleaved format */
#define intRightRotateEven(x,bits) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate(_x0, (bits)); \
        _x1 = rightRotate(_x1, (bits)); \
        _x0 | (((uint64_t)_x1) << 32); \
    }))
#define intRightRotateOdd(x,bits) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate(_x0, ((bits) + 1) % 32); \
        _x1 = rightRotate(_x1, (bits)); \
        _x1 | (((uint64_t)_x0) << 32); \
    }))
#define intRightRotate1_64(x) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate1(_x0); \
        _x1 | (((uint64_t)_x0) << 32); \
    }))
#define intRightRotate2_64(x)  (intRightRotateEven((x), 1))
#define intRightRotate3_64(x)  (intRightRotateOdd((x), 1))
#define intRightRotate4_64(x)  (intRightRotateEven((x), 2))
#define intRightRotate5_64(x)  (intRightRotateOdd((x), 2))
#define intRightRotate6_64(x)  (intRightRotateEven((x), 3))
#define intRightRotate7_64(x)  (intRightRotateOdd((x), 3))
#define intRightRotate8_64(x)  (intRightRotateEven((x), 4))
#define intRightRotate9_64(x)  (intRightRotateOdd((x), 4))
#define intRightRotate10_64(x) (intRightRotateEven((x), 5))
#define intRightRotate11_64(x) (intRightRotateOdd((x), 5))
#define intRightRotate12_64(x) (intRightRotateEven((x), 6))
#define intRightRotate13_64(x) (intRightRotateOdd((x), 6))
#define intRightRotate14_64(x) (intRightRotateEven((x), 7))
#define intRightRotate15_64(x) (intRightRotateOdd((x), 7))
#define intRightRotate16_64(x) (intRightRotateEven((x), 8))
#define intRightRotate17_64(x) (intRightRotateOdd((x), 8))
#define intRightRotate18_64(x) (intRightRotateEven((x), 9))
#define intRightRotate19_64(x) (intRightRotateOdd((x), 9))
#define intRightRotate20_64(x) (intRightRotateEven((x), 10))
#define intRightRotate21_64(x) (intRightRotateOdd((x), 10))
#define intRightRotate22_64(x) (intRightRotateEven((x), 11))
#define intRightRotate23_64(x) (intRightRotateOdd((x), 11))
#define intRightRotate24_64(x) (intRightRotateEven((x), 12))
#define intRightRotate25_64(x) (intRightRotateOdd((x), 12))
#define intRightRotate26_64(x) (intRightRotateEven((x), 13))
#define intRightRotate27_64(x) (intRightRotateOdd((x), 13))
#define intRightRotate28_64(x) (intRightRotateEven((x), 14))
#define intRightRotate29_64(x) (intRightRotateOdd((x), 14))
#define intRightRotate30_64(x) (intRightRotateEven((x), 15))
#define intRightRotate31_64(x) (intRightRotateOdd((x), 15))
#define intRightRotate32_64(x) (intRightRotateEven((x), 16))
#define intRightRotate33_64(x) (intRightRotateOdd((x), 16))
#define intRightRotate34_64(x) (intRightRotateEven((x), 17))
#define intRightRotate35_64(x) (intRightRotateOdd((x), 17))
#define intRightRotate36_64(x) (intRightRotateEven((x), 18))
#define intRightRotate37_64(x) (intRightRotateOdd((x), 18))
#define intRightRotate38_64(x) (intRightRotateEven((x), 19))
#define intRightRotate39_64(x) (intRightRotateOdd((x), 19))
#define intRightRotate40_64(x) (intRightRotateEven((x), 20))
#define intRightRotate41_64(x) (intRightRotateOdd((x), 20))
#define intRightRotate42_64(x) (intRightRotateEven((x), 21))
#define intRightRotate43_64(x) (intRightRotateOdd((x), 21))
#define intRightRotate44_64(x) (intRightRotateEven((x), 22))
#define intRightRotate45_64(x) (intRightRotateOdd((x), 22))
#define intRightRotate46_64(x) (intRightRotateEven((x), 23))
#define intRightRotate47_64(x) (intRightRotateOdd((x), 23))
#define intRightRotate48_64(x) (intRightRotateEven((x), 24))
#define intRightRotate49_64(x) (intRightRotateOdd((x), 24))
#define intRightRotate50_64(x) (intRightRotateEven((x), 25))
#define intRightRotate51_64(x) (intRightRotateOdd((x), 25))
#define intRightRotate52_64(x) (intRightRotateEven((x), 26))
#define intRightRotate53_64(x) (intRightRotateOdd((x), 26))
#define intRightRotate54_64(x) (intRightRotateEven((x), 27))
#define intRightRotate55_64(x) (intRightRotateOdd((x), 27))
#define intRightRotate56_64(x) (intRightRotateEven((x), 28))
#define intRightRotate57_64(x) (intRightRotateOdd((x), 28))
#define intRightRotate58_64(x) (intRightRotateEven((x), 29))
#define intRightRotate59_64(x) (intRightRotateOdd((x), 29))
#define intRightRotate60_64(x) (intRightRotateEven((x), 30))
#define intRightRotate61_64(x) (intRightRotateOdd((x), 30))
#define intRightRotate62_64(x) (intRightRotateEven((x), 31))
#define intRightRotate63_64(x) (intRightRotateOdd((x), 31))

#define gascon128_core_round(x0,x1,x2,x3,x4,round) do { \
    uint64_t t0, t1, t2, t3, t4; \
    x2 ^= ((0x0F - round) << 4) | round; \
    x0 ^= x4; x2 ^= x1; x4 ^= x3; t0 = (~x0) & x1; t1 = (~x1) & x2; \
    t2 = (~x2) & x3; t3 = (~x3) & x4; t4 = (~x4) & x0; x0 ^= t1; \
    x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0; x1 ^= x0; x3 ^= x2; \
    x0 ^= x4; x2 = ~x2; \
    x0 ^= intRightRotate19_64(x0) ^ intRightRotate28_64(x0); \
    x1 ^= intRightRotate61_64(x1) ^ intRightRotate38_64(x1); \
    x2 ^= intRightRotate1_64(x2)  ^ intRightRotate6_64(x2); \
    x3 ^= intRightRotate10_64(x3) ^ intRightRotate17_64(x3); \
    x4 ^= intRightRotate7_64(x4)  ^ intRightRotate40_64(x4); \
    } while(0)

void gascon_permute(gascon_state_t *state, uint8_t first_round)
{
#if defined(LW_UTIL_BIG_ENDIAN)
    uint64_t x0 = le_load_word64(state->B);
    uint64_t x1 = le_load_word64(state->B + 8);
    uint64_t x2 = le_load_word64(state->B + 16);
    uint64_t x3 = le_load_word64(state->B + 24);
    uint64_t x4 = le_load_word64(state->B + 32);
#else
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];
#endif
    while (first_round < 12) {
        gascon128_core_round(x0,x1,x2,x3,x4, first_round);
        /* Move onto the next round */
        ++first_round;
    }
#if defined(LW_UTIL_BIG_ENDIAN)
    le_store_word64(state->B,      x0);
    le_store_word64(state->B +  8, x1);
    le_store_word64(state->B + 16, x2);
    le_store_word64(state->B + 24, x3);
    le_store_word64(state->B + 32, x4);
#else
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
#endif
}

#endif /* !__AVR__ */
