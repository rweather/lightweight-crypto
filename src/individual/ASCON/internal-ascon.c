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

/* Determine which versions should be accelerated with assembly code */
#if defined(__AVR__)
#define ASCON_ASM_REGULAR 1
#define ASCON_ASM_SLICED 0
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define ASCON_ASM_REGULAR 1
#define ASCON_ASM_SLICED 1
#else
#define ASCON_ASM_REGULAR 0
#define ASCON_ASM_SLICED 0
#endif

#if !ASCON_ASM_REGULAR

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

#endif /* !ASCON_ASM_REGULAR */

#if ASCON_SLICED && !ASCON_ASM_SLICED

void ascon_to_sliced(ascon_state_t *state)
{
    int index;
    uint32_t high, low;
    for (index = 0; index < 10; index += 2) {
        high = be_load_word32(state->B + index * 4);
        low  = be_load_word32(state->B + index * 4 + 4);
        ascon_separate(high);
        ascon_separate(low);
        state->W[index] = (high << 16) | (low & 0x0000FFFFU);
        state->W[index + 1] = (high & 0xFFFF0000U) | (low >> 16);
    }
}

void ascon_from_sliced(ascon_state_t *state)
{
    int index;
    uint32_t high, low;
    for (index = 0; index < 10; index += 2) {
        high = (state->W[index] >> 16) | (state->W[index + 1] & 0xFFFF0000U);
        low  = (state->W[index] & 0x0000FFFFU) | (state->W[index + 1] << 16);
        ascon_combine(high);
        ascon_combine(low);
        be_store_word32(state->B + index * 4,     high);
        be_store_word32(state->B + index * 4 + 4, low);
    }
}

void ascon_permute_sliced(ascon_state_t *state, uint8_t first_round)
{
    static const unsigned char RC[12 * 2] = {
        12, 12, 9, 12, 12, 9, 9, 9, 6, 12, 3, 12,
        6, 9, 3, 9, 12, 6, 9, 6, 12, 3, 9, 3
    };
    const unsigned char *rc = RC + first_round * 2;
    uint32_t t0, t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t x0_e = state->W[0];
    uint32_t x0_o = state->W[1];
    uint32_t x1_e = state->W[2];
    uint32_t x1_o = state->W[3];
    uint32_t x2_e = state->W[4];
    uint32_t x2_o = state->W[5];
    uint32_t x3_e = state->W[6];
    uint32_t x3_o = state->W[7];
    uint32_t x4_e = state->W[8];
    uint32_t x4_o = state->W[9];

    /* Perform all permutation rounds */
    while (first_round < 12) {
        /* Add the round constants for this round to the state */
        x2_e ^= rc[0];
        x2_o ^= rc[1];
        rc += 2;

        /* Substitution layer */
        #define ascon_sbox(x0, x1, x2, x3, x4) \
            do { \
                x0 ^= x4;   x4 ^= x3;   x2 ^= x1; \
                t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4; \
                t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0; \
                x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0; \
                x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2; \
            } while (0)
        ascon_sbox(x0_e, x1_e, x2_e, x3_e, x4_e);
        ascon_sbox(x0_o, x1_o, x2_o, x3_o, x4_o);

        /* Linear diffusion layer */
        /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
        t0 = x0_e ^ rightRotate4(x0_o);
        t1 = x0_o ^ rightRotate5(x0_e);
        x0_e ^= rightRotate9(t1);
        x0_o ^= rightRotate10(t0);
        /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
        t0 = x1_e ^ rightRotate11(x1_e);
        t1 = x1_o ^ rightRotate11(x1_o);
        x1_e ^= rightRotate19(t1);
        x1_o ^= rightRotate20(t0);
        /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
        t0 = x2_e ^ rightRotate2(x2_o);
        t1 = x2_o ^ rightRotate3(x2_e);
        x2_e ^= t1;
        x2_o ^= rightRotate1(t0);
        /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
        t0 = x3_e ^ rightRotate3(x3_o);
        t1 = x3_o ^ rightRotate4(x3_e);
        x3_e ^= rightRotate5(t0);
        x3_o ^= rightRotate5(t1);
        /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
        t0 = x4_e ^ rightRotate17(x4_e);
        t1 = x4_o ^ rightRotate17(x4_o);
        x4_e ^= rightRotate3(t1);
        x4_o ^= rightRotate4(t0);

        /* Move onto the next round */
        ++first_round;
    }

    /* Write the local variables back to the state */
    state->W[0] = x0_e;
    state->W[1] = x0_o;
    state->W[2] = x1_e;
    state->W[3] = x1_o;
    state->W[4] = x2_e;
    state->W[5] = x2_o;
    state->W[6] = x3_e;
    state->W[7] = x3_o;
    state->W[8] = x4_e;
    state->W[9] = x4_o;
}

#endif /* ASCON_SLICED */
