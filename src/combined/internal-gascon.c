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

/* Right rotations in bit-interleaved format */
#define intRightRotateEven(yl,yh,xl,xh, bits) \
    (__extension__ ({ \
        yl = rightRotate(xl, (bits)); \
        yh = rightRotate(xh, (bits)); \
    }))
#define intRightRotateOdd(yl,yh,xl,xh, bits) \
    (__extension__ ({ \
        yl = rightRotate(xh, (bits)); \
        yh = rightRotate(xl, ((bits) + 1) % 32); \
    }))
#define intRightRotate1_64(yl,yh,xl,xh) \
    (__extension__ ({ \
        yl = xh; \
        yh = rightRotate1(xl); \
    }))
#define intRightRotate2_64(yl,yh,xl,xh)  (intRightRotateEven(yl,yh,xl,xh, 1))
#define intRightRotate3_64(yl,yh,xl,xh)  (intRightRotateOdd(yl,yh,xl,xh, 1))
#define intRightRotate4_64(yl,yh,xl,xh)  (intRightRotateEven(yl,yh,xl,xh, 2))
#define intRightRotate5_64(yl,yh,xl,xh)  (intRightRotateOdd(yl,yh,xl,xh, 2))
#define intRightRotate6_64(yl,yh,xl,xh)  (intRightRotateEven(yl,yh,xl,xh, 3))
#define intRightRotate7_64(yl,yh,xl,xh)  (intRightRotateOdd(yl,yh,xl,xh, 3))
#define intRightRotate8_64(yl,yh,xl,xh)  (intRightRotateEven(yl,yh,xl,xh, 4))
#define intRightRotate9_64(yl,yh,xl,xh)  (intRightRotateOdd(yl,yh,xl,xh, 4))
#define intRightRotate10_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 5))
#define intRightRotate11_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 5))
#define intRightRotate12_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 6))
#define intRightRotate13_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 6))
#define intRightRotate14_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 7))
#define intRightRotate15_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 7))
#define intRightRotate16_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 8))
#define intRightRotate17_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 8))
#define intRightRotate18_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 9))
#define intRightRotate19_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 9))
#define intRightRotate20_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 10))
#define intRightRotate21_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 10))
#define intRightRotate22_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 11))
#define intRightRotate23_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 11))
#define intRightRotate24_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 12))
#define intRightRotate25_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 12))
#define intRightRotate26_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 13))
#define intRightRotate27_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 13))
#define intRightRotate28_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 14))
#define intRightRotate29_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 14))
#define intRightRotate30_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 15))
#define intRightRotate31_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 15))
#define intRightRotate32_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 16))
#define intRightRotate33_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 16))
#define intRightRotate34_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 17))
#define intRightRotate35_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 17))
#define intRightRotate36_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 18))
#define intRightRotate37_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 18))
#define intRightRotate38_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 19))
#define intRightRotate39_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 19))
#define intRightRotate40_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 20))
#define intRightRotate41_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 20))
#define intRightRotate42_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 21))
#define intRightRotate43_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 21))
#define intRightRotate44_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 22))
#define intRightRotate45_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 22))
#define intRightRotate46_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 23))
#define intRightRotate47_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 23))
#define intRightRotate48_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 24))
#define intRightRotate49_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 24))
#define intRightRotate50_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 25))
#define intRightRotate51_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 25))
#define intRightRotate52_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 26))
#define intRightRotate53_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 26))
#define intRightRotate54_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 27))
#define intRightRotate55_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 27))
#define intRightRotate56_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 28))
#define intRightRotate57_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 28))
#define intRightRotate58_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 29))
#define intRightRotate59_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 29))
#define intRightRotate60_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 30))
#define intRightRotate61_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 30))
#define intRightRotate62_64(yl,yh,xl,xh) (intRightRotateEven(yl,yh,xl,xh, 31))
#define intRightRotate63_64(yl,yh,xl,xh) (intRightRotateOdd(yl,yh,xl,xh, 31))

void gascon_permute(gascon_state_t *state, uint8_t first_round)
{
    uint32_t t0, t1, t2, t3, t4;
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint32_t x0_l = state->W[0];
    uint32_t x0_h = state->W[1];
    uint32_t x1_l = state->W[2];
    uint32_t x1_h = state->W[3];
    uint32_t x2_l = state->W[4];
    uint32_t x2_h = state->W[5];
    uint32_t x3_l = state->W[6];
    uint32_t x3_h = state->W[7];
    uint32_t x4_l = state->W[8];
    uint32_t x4_h = state->W[9];
#else
    uint32_t x0_l = le_load_word32(state->B);
    uint32_t x0_h = le_load_word32(state->B + 4);
    uint32_t x1_l = le_load_word32(state->B + 8);
    uint32_t x1_h = le_load_word32(state->B + 12);
    uint32_t x2_l = le_load_word32(state->B + 16);
    uint32_t x2_h = le_load_word32(state->B + 20);
    uint32_t x3_l = le_load_word32(state->B + 24);
    uint32_t x3_h = le_load_word32(state->B + 28);
    uint32_t x4_l = le_load_word32(state->B + 32);
    uint32_t x4_h = le_load_word32(state->B + 36);
#endif
    while (first_round < 12) {
        /* Add the round constant to the middle of the state */
        x2_l ^= ((0x0F - first_round) << 4) | first_round;

        /* Substitution layer */
        #define gascon_sbox(x0, x1, x2, x3, x4) \
            do { \
                x0 ^= x4; x2 ^= x1; x4 ^= x3; t0 = (~x0) & x1; t1 = (~x1) & x2; \
                t2 = (~x2) & x3; t3 = (~x3) & x4; t4 = (~x4) & x0; x0 ^= t1; \
                x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0; x1 ^= x0; x3 ^= x2; \
                x0 ^= x4; x2 = ~x2; \
            } while (0)
        gascon_sbox(x0_l, x1_l, x2_l, x3_l, x4_l);
        gascon_sbox(x0_h, x1_h, x2_h, x3_h, x4_h);

        /* Linear diffusion layer */
        /* x0 ^= intRightRotate19_64(x0) ^ intRightRotate28_64(x0); */
        intRightRotate19_64(t0, t1, x0_l, x0_h);
        intRightRotate28_64(t2, t3, x0_l, x0_h);
        x0_l ^= t0 ^ t2;
        x0_h ^= t1 ^ t3;
        /* x1 ^= intRightRotate61_64(x1) ^ intRightRotate38_64(x1); */
        intRightRotate61_64(t0, t1, x1_l, x1_h);
        intRightRotate38_64(t2, t3, x1_l, x1_h);
        x1_l ^= t0 ^ t2;
        x1_h ^= t1 ^ t3;
        /* x2 ^= intRightRotate1_64(x2)  ^ intRightRotate6_64(x2); */
        intRightRotate1_64(t0, t1, x2_l, x2_h);
        intRightRotate6_64(t2, t3, x2_l, x2_h);
        x2_l ^= t0 ^ t2;
        x2_h ^= t1 ^ t3;
        /* x3 ^= intRightRotate10_64(x3) ^ intRightRotate17_64(x3); */
        intRightRotate10_64(t0, t1, x3_l, x3_h);
        intRightRotate17_64(t2, t3, x3_l, x3_h);
        x3_l ^= t0 ^ t2;
        x3_h ^= t1 ^ t3;
        /* x4 ^= intRightRotate7_64(x4)  ^ intRightRotate40_64(x4); */
        intRightRotate7_64(t0, t1, x4_l, x4_h);
        intRightRotate40_64(t2, t3, x4_l, x4_h);
        x4_l ^= t0 ^ t2;
        x4_h ^= t1 ^ t3;

        /* Move onto the next round */
        ++first_round;
    }
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = x0_l;
    state->W[1] = x0_h;
    state->W[2] = x1_l;
    state->W[3] = x1_h;
    state->W[4] = x2_l;
    state->W[5] = x2_h;
    state->W[6] = x3_l;
    state->W[7] = x3_h;
    state->W[8] = x4_l;
    state->W[9] = x4_h;
#else
    le_store_word32(state->B,      x0_l);
    le_store_word32(state->B +  4, x0_h);
    le_store_word32(state->B +  8, x1_l);
    le_store_word32(state->B + 12, x1_h);
    le_store_word32(state->B + 16, x2_l);
    le_store_word32(state->B + 20, x2_h);
    le_store_word32(state->B + 24, x3_l);
    le_store_word32(state->B + 28, x3_h);
    le_store_word32(state->B + 32, x4_l);
    le_store_word32(state->B + 36, x4_h);
#endif
}
