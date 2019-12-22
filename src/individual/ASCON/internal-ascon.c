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

#include "internal-ascon.h"

void ascon_permute(ascon_state_t *state, uint8_t first_round)
{
    uint64_t t0, t1, t2, t3, t4;
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t x0 = be_load_word64(state->B);
    uint64_t x1 = be_load_word64(state->B + 8);
    uint64_t x2 = be_load_word64(state->B + 16);
    uint64_t x3 = be_load_word64(state->B + 24);
    uint64_t x4 = be_load_word64(state->B + 32);
#else
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];
#endif
    while (first_round < 12) {
        /* Add the round constant to the state */
        x2 ^= ((0x0F - first_round) << 4) | first_round;

        /* Substitution layer - apply the s-box using bit-slicing
         * according to the algorithm recommended in the specification */
        x0 ^= x4;   x4 ^= x3;   x2 ^= x1;
        t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4;
        t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0;
        x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0;
        x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2;

        /* Linear diffusion layer */
        x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0);
        x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1);
        x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2);
        x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3);
        x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4);

        /* Move onto the next round */
        ++first_round;
    }
#if defined(LW_UTIL_LITTLE_ENDIAN)
    be_store_word64(state->B,      x0);
    be_store_word64(state->B +  8, x1);
    be_store_word64(state->B + 16, x2);
    be_store_word64(state->B + 24, x3);
    be_store_word64(state->B + 32, x4);
#else
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
#endif
}
