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

#include "internal-xoodoo.h"

#if !defined(__AVR__)

void xoodoo_permute(xoodoo_state_t *state)
{
    static uint16_t const rc[XOODOO_ROUNDS] = {
        0x0058, 0x0038, 0x03C0, 0x00D0, 0x0120, 0x0014,
        0x0060, 0x002C, 0x0380, 0x00F0, 0x01A0, 0x0012
    };
    uint8_t round;
    uint32_t x00, x01, x02, x03;
    uint32_t x10, x11, x12, x13;
    uint32_t x20, x21, x22, x23;
    uint32_t t1, t2;

    /* Load the state and convert from little-endian byte order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x00 = state->S[0][0];
    x01 = state->S[0][1];
    x02 = state->S[0][2];
    x03 = state->S[0][3];
    x10 = state->S[1][0];
    x11 = state->S[1][1];
    x12 = state->S[1][2];
    x13 = state->S[1][3];
    x20 = state->S[2][0];
    x21 = state->S[2][1];
    x22 = state->S[2][2];
    x23 = state->S[2][3];
#else
    x00 = le_load_word32(state->B);
    x01 = le_load_word32(state->B + 4);
    x02 = le_load_word32(state->B + 8);
    x03 = le_load_word32(state->B + 12);
    x10 = le_load_word32(state->B + 16);
    x11 = le_load_word32(state->B + 20);
    x12 = le_load_word32(state->B + 24);
    x13 = le_load_word32(state->B + 28);
    x20 = le_load_word32(state->B + 32);
    x21 = le_load_word32(state->B + 36);
    x22 = le_load_word32(state->B + 40);
    x23 = le_load_word32(state->B + 44);
#endif

    /* Perform all permutation rounds */
    for (round = 0; round < XOODOO_ROUNDS; ++round) {
        /* Optimization ideas from the Xoodoo implementation here:
         * https://github.com/XKCP/XKCP/tree/master/lib/low/Xoodoo/Optimized */

        /* Step theta: Mix column parity */
        t1 = x03 ^ x13 ^ x23;
        t2 = x00 ^ x10 ^ x20;
        t1 = leftRotate5(t1) ^ leftRotate14(t1);
        t2 = leftRotate5(t2) ^ leftRotate14(t2);
        x00 ^= t1;
        x10 ^= t1;
        x20 ^= t1;
        t1 = x01 ^ x11 ^ x21;
        t1 = leftRotate5(t1) ^ leftRotate14(t1);
        x01 ^= t2;
        x11 ^= t2;
        x21 ^= t2;
        t2 = x02 ^ x12 ^ x22;
        t2 = leftRotate5(t2) ^ leftRotate14(t2);
        x02 ^= t1;
        x12 ^= t1;
        x22 ^= t1;
        x03 ^= t2;
        x13 ^= t2;
        x23 ^= t2;

        /* Step rho-west: Plane shift */
        t1 = x13;
        x13 = x12;
        x12 = x11;
        x11 = x10;
        x10 = t1;
        x20 = leftRotate11(x20);
        x21 = leftRotate11(x21);
        x22 = leftRotate11(x22);
        x23 = leftRotate11(x23);

        /* Step iota: Add the round constant to the state */
        x00 ^= rc[round];

        /* Step chi: Non-linear layer */
        x00 ^= (~x10) & x20;
        x10 ^= (~x20) & x00;
        x20 ^= (~x00) & x10;
        x01 ^= (~x11) & x21;
        x11 ^= (~x21) & x01;
        x21 ^= (~x01) & x11;
        x02 ^= (~x12) & x22;
        x12 ^= (~x22) & x02;
        x22 ^= (~x02) & x12;
        x03 ^= (~x13) & x23;
        x13 ^= (~x23) & x03;
        x23 ^= (~x03) & x13;

        /* Step rho-east: Plane shift */
        x10 = leftRotate1(x10);
        x11 = leftRotate1(x11);
        x12 = leftRotate1(x12);
        x13 = leftRotate1(x13);
        t1 = leftRotate8(x22);
        t2 = leftRotate8(x23);
        x22 = leftRotate8(x20);
        x23 = leftRotate8(x21);
        x20 = t1;
        x21 = t2;
    }

    /* Convert back into little-endian and store to the output state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->S[0][0] = x00;
    state->S[0][1] = x01;
    state->S[0][2] = x02;
    state->S[0][3] = x03;
    state->S[1][0] = x10;
    state->S[1][1] = x11;
    state->S[1][2] = x12;
    state->S[1][3] = x13;
    state->S[2][0] = x20;
    state->S[2][1] = x21;
    state->S[2][2] = x22;
    state->S[2][3] = x23;
#else
    le_store_word32(state->B,      x00);
    le_store_word32(state->B +  4, x01);
    le_store_word32(state->B +  8, x02);
    le_store_word32(state->B + 12, x03);
    le_store_word32(state->B + 16, x10);
    le_store_word32(state->B + 20, x11);
    le_store_word32(state->B + 24, x12);
    le_store_word32(state->B + 28, x13);
    le_store_word32(state->B + 32, x20);
    le_store_word32(state->B + 36, x21);
    le_store_word32(state->B + 40, x22);
    le_store_word32(state->B + 44, x23);
#endif
}

#endif /* !__AVR__ */
