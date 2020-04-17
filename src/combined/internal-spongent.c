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

#include "internal-spongent.h"

#if !defined(__AVR__)

/**
 * \brief Applies the Spongent-pi S-box in parallel to the 8 nibbles
 * of a 32-bit word.
 *
 * \param x3 The input values to the parallel S-boxes.
 *
 * \return The output values from the parallel S-boxes.
 *
 * Based on the bit-sliced S-box implementation from here:
 * https://github.com/DadaIsCrazy/usuba/blob/master/data/sboxes/spongent.ua
 *
 * Note that spongent.ua numbers bits from highest to lowest, so x0 is the
 * high bit of each nibble and x3 is the low bit.
 */
static uint32_t spongent_sbox(uint32_t x3)
{
    uint32_t q0, q1, q2, q3, t0, t1, t2, t3;
    uint32_t x2 = (x3 >> 1);
    uint32_t x1 = (x2 >> 1);
    uint32_t x0 = (x1 >> 1);
    q0 = x0 ^ x2;
    q1 = x1 ^ x2;
    t0 = q0 & q1;
    q2 = ~(x0 ^ x1 ^ x3 ^ t0);
    t1 = q2 & ~x0;
    q3 = x1 ^ t1;
    t2 = q3 & (q3 ^ x2 ^ x3 ^ t0);
    t3 = (x2 ^ t0) & ~(x1 ^ t0);
    q0 = x1 ^ x2 ^ x3 ^ t2;
    q1 = x0 ^ x2 ^ x3 ^ t0 ^ t1;
    q2 = x0 ^ x1 ^ x2 ^ t1;
    q3 = x0 ^ x3 ^ t0 ^ t3;
    return ((q0 << 3) & 0x88888888U) | ((q1 << 2) & 0x44444444U) |
           ((q2 << 1) & 0x22222222U) |  (q3       & 0x11111111U);
}

void spongent160_permute(spongent160_state_t *state)
{
    static uint8_t const RC[] = {
        /* Round constants for Spongent-pi[160] */
        0x75, 0xae, 0x6a, 0x56, 0x54, 0x2a, 0x29, 0x94,
        0x53, 0xca, 0x27, 0xe4, 0x4f, 0xf2, 0x1f, 0xf8,
        0x3e, 0x7c, 0x7d, 0xbe, 0x7a, 0x5e, 0x74, 0x2e,
        0x68, 0x16, 0x50, 0x0a, 0x21, 0x84, 0x43, 0xc2,
        0x07, 0xe0, 0x0e, 0x70, 0x1c, 0x38, 0x38, 0x1c,
        0x71, 0x8e, 0x62, 0x46, 0x44, 0x22, 0x09, 0x90,
        0x12, 0x48, 0x24, 0x24, 0x49, 0x92, 0x13, 0xc8,
        0x26, 0x64, 0x4d, 0xb2, 0x1b, 0xd8, 0x36, 0x6c,
        0x6d, 0xb6, 0x5a, 0x5a, 0x35, 0xac, 0x6b, 0xd6,
        0x56, 0x6a, 0x2d, 0xb4, 0x5b, 0xda, 0x37, 0xec,
        0x6f, 0xf6, 0x5e, 0x7a, 0x3d, 0xbc, 0x7b, 0xde,
        0x76, 0x6e, 0x6c, 0x36, 0x58, 0x1a, 0x31, 0x8c,
        0x63, 0xc6, 0x46, 0x62, 0x0d, 0xb0, 0x1a, 0x58,
        0x34, 0x2c, 0x69, 0x96, 0x52, 0x4a, 0x25, 0xa4,
        0x4b, 0xd2, 0x17, 0xe8, 0x2e, 0x74, 0x5d, 0xba,
        0x3b, 0xdc, 0x77, 0xee, 0x6e, 0x76, 0x5c, 0x3a,
        0x39, 0x9c, 0x73, 0xce, 0x66, 0x66, 0x4c, 0x32,
        0x19, 0x98, 0x32, 0x4c, 0x65, 0xa6, 0x4a, 0x52,
        0x15, 0xa8, 0x2a, 0x54, 0x55, 0xaa, 0x2b, 0xd4,
        0x57, 0xea, 0x2f, 0xf4, 0x5f, 0xfa, 0x3f, 0xfc
    };
    const uint8_t *rc = RC;
    uint32_t x0, x1, x2, x3, x4;
    uint32_t t0, t1, t2, t3, t4;
    uint8_t round;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = state->W[0];
    x1 = state->W[1];
    x2 = state->W[2];
    x3 = state->W[3];
    x4 = state->W[4];
#else
    x0 = le_load_word32(state->B);
    x1 = le_load_word32(state->B + 4);
    x2 = le_load_word32(state->B + 8);
    x3 = le_load_word32(state->B + 12);
    x4 = le_load_word32(state->B + 16);
#endif

    /* Perform the 80 rounds of Spongent-pi[160] */
    for (round = 0; round < 80; ++round, rc += 2) {
        /* Add the round constant to front and back of the state */
        x0 ^= rc[0];
        x4 ^= ((uint32_t)(rc[1])) << 24;

        /* Apply the S-box to all 4-bit groups in the state */
        t0 = spongent_sbox(x0);
        t1 = spongent_sbox(x1);
        t2 = spongent_sbox(x2);
        t3 = spongent_sbox(x3);
        t4 = spongent_sbox(x4);

        /* Permute the bits of the state.  Bit i is moved to (40 * i) % 159
         * for all bits except the last which is left where it is.
         * BCP = bit copy, BUP = move bit up, BDN = move bit down */
        #define BCP(x, bit) ((x) & (((uint32_t)1) << (bit)))
        #define BUP(x, from, to) \
            (((x) << ((to) - (from))) & (((uint32_t)1) << (to)))
        #define BDN(x, from, to) \
            (((x) >> ((from) - (to))) & (((uint32_t)1) << (to)))
        x0 = BCP(t0,  0)     ^ BDN(t0,  4,  1) ^ BDN(t0,  8,  2) ^
             BDN(t0, 12,  3) ^ BDN(t0, 16,  4) ^ BDN(t0, 20,  5) ^
             BDN(t0, 24,  6) ^ BDN(t0, 28,  7) ^ BUP(t1,  0,  8) ^
             BUP(t1,  4,  9) ^ BUP(t1,  8, 10) ^ BDN(t1, 12, 11) ^
             BDN(t1, 16, 12) ^ BDN(t1, 20, 13) ^ BDN(t1, 24, 14) ^
             BDN(t1, 28, 15) ^ BUP(t2,  0, 16) ^ BUP(t2,  4, 17) ^
             BUP(t2,  8, 18) ^ BUP(t2, 12, 19) ^ BUP(t2, 16, 20) ^
             BUP(t2, 20, 21) ^ BDN(t2, 24, 22) ^ BDN(t2, 28, 23) ^
             BUP(t3,  0, 24) ^ BUP(t3,  4, 25) ^ BUP(t3,  8, 26) ^
             BUP(t3, 12, 27) ^ BUP(t3, 16, 28) ^ BUP(t3, 20, 29) ^
             BUP(t3, 24, 30) ^ BUP(t3, 28, 31);
        x1 = BUP(t0,  1,  8) ^ BUP(t0,  5,  9) ^ BUP(t0,  9, 10) ^
             BDN(t0, 13, 11) ^ BDN(t0, 17, 12) ^ BDN(t0, 21, 13) ^
             BDN(t0, 25, 14) ^ BDN(t0, 29, 15) ^ BUP(t1,  1, 16) ^
             BUP(t1,  5, 17) ^ BUP(t1,  9, 18) ^ BUP(t1, 13, 19) ^
             BUP(t1, 17, 20) ^ BCP(t1, 21)     ^ BDN(t1, 25, 22) ^
             BDN(t1, 29, 23) ^ BUP(t2,  1, 24) ^ BUP(t2,  5, 25) ^
             BUP(t2,  9, 26) ^ BUP(t2, 13, 27) ^ BUP(t2, 17, 28) ^
             BUP(t2, 21, 29) ^ BUP(t2, 25, 30) ^ BUP(t2, 29, 31) ^
             BCP(t4,  0)     ^ BDN(t4,  4,  1) ^ BDN(t4,  8,  2) ^
             BDN(t4, 12,  3) ^ BDN(t4, 16,  4) ^ BDN(t4, 20,  5) ^
             BDN(t4, 24,  6) ^ BDN(t4, 28,  7);
        x2 = BUP(t0,  2, 16) ^ BUP(t0,  6, 17) ^ BUP(t0, 10, 18) ^
             BUP(t0, 14, 19) ^ BUP(t0, 18, 20) ^ BDN(t0, 22, 21) ^
             BDN(t0, 26, 22) ^ BDN(t0, 30, 23) ^ BUP(t1,  2, 24) ^
             BUP(t1,  6, 25) ^ BUP(t1, 10, 26) ^ BUP(t1, 14, 27) ^
             BUP(t1, 18, 28) ^ BUP(t1, 22, 29) ^ BUP(t1, 26, 30) ^
             BUP(t1, 30, 31) ^ BDN(t3,  1,  0) ^ BDN(t3,  5,  1) ^
             BDN(t3,  9,  2) ^ BDN(t3, 13,  3) ^ BDN(t3, 17,  4) ^
             BDN(t3, 21,  5) ^ BDN(t3, 25,  6) ^ BDN(t3, 29,  7) ^
             BUP(t4,  1,  8) ^ BUP(t4,  5,  9) ^ BUP(t4,  9, 10) ^
             BDN(t4, 13, 11) ^ BDN(t4, 17, 12) ^ BDN(t4, 21, 13) ^
             BDN(t4, 25, 14) ^ BDN(t4, 29, 15);
        x3 = BUP(t0,  3, 24) ^ BUP(t0,  7, 25) ^ BUP(t0, 11, 26) ^
             BUP(t0, 15, 27) ^ BUP(t0, 19, 28) ^ BUP(t0, 23, 29) ^
             BUP(t0, 27, 30) ^ BCP(t0, 31)     ^ BDN(t2,  2,  0) ^
             BDN(t2,  6,  1) ^ BDN(t2, 10,  2) ^ BDN(t2, 14,  3) ^
             BDN(t2, 18,  4) ^ BDN(t2, 22,  5) ^ BDN(t2, 26,  6) ^
             BDN(t2, 30,  7) ^ BUP(t3,  2,  8) ^ BUP(t3,  6,  9) ^
             BCP(t3, 10)     ^ BDN(t3, 14, 11) ^ BDN(t3, 18, 12) ^
             BDN(t3, 22, 13) ^ BDN(t3, 26, 14) ^ BDN(t3, 30, 15) ^
             BUP(t4,  2, 16) ^ BUP(t4,  6, 17) ^ BUP(t4, 10, 18) ^
             BUP(t4, 14, 19) ^ BUP(t4, 18, 20) ^ BDN(t4, 22, 21) ^
             BDN(t4, 26, 22) ^ BDN(t4, 30, 23);
        x4 = BDN(t1,  3,  0) ^ BDN(t1,  7,  1) ^ BDN(t1, 11,  2) ^
             BDN(t1, 15,  3) ^ BDN(t1, 19,  4) ^ BDN(t1, 23,  5) ^
             BDN(t1, 27,  6) ^ BDN(t1, 31,  7) ^ BUP(t2,  3,  8) ^
             BUP(t2,  7,  9) ^ BDN(t2, 11, 10) ^ BDN(t2, 15, 11) ^
             BDN(t2, 19, 12) ^ BDN(t2, 23, 13) ^ BDN(t2, 27, 14) ^
             BDN(t2, 31, 15) ^ BUP(t3,  3, 16) ^ BUP(t3,  7, 17) ^
             BUP(t3, 11, 18) ^ BUP(t3, 15, 19) ^ BUP(t3, 19, 20) ^
             BDN(t3, 23, 21) ^ BDN(t3, 27, 22) ^ BDN(t3, 31, 23) ^
             BUP(t4,  3, 24) ^ BUP(t4,  7, 25) ^ BUP(t4, 11, 26) ^
             BUP(t4, 15, 27) ^ BUP(t4, 19, 28) ^ BUP(t4, 23, 29) ^
             BUP(t4, 27, 30) ^ BCP(t4, 31);
    }

    /* Store the local variables back to the state in little-endian order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = x0;
    state->W[1] = x1;
    state->W[2] = x2;
    state->W[3] = x3;
    state->W[4] = x4;
#else
    le_store_word32(state->B,      x0);
    le_store_word32(state->B +  4, x1);
    le_store_word32(state->B +  8, x2);
    le_store_word32(state->B + 12, x3);
    le_store_word32(state->B + 16, x4);
#endif
}

void spongent176_permute(spongent176_state_t *state)
{
    static uint8_t const RC[] = {
        /* Round constants for Spongent-pi[176] */
        0x45, 0xa2, 0x0b, 0xd0, 0x16, 0x68, 0x2c, 0x34,
        0x59, 0x9a, 0x33, 0xcc, 0x67, 0xe6, 0x4e, 0x72,
        0x1d, 0xb8, 0x3a, 0x5c, 0x75, 0xae, 0x6a, 0x56,
        0x54, 0x2a, 0x29, 0x94, 0x53, 0xca, 0x27, 0xe4,
        0x4f, 0xf2, 0x1f, 0xf8, 0x3e, 0x7c, 0x7d, 0xbe,
        0x7a, 0x5e, 0x74, 0x2e, 0x68, 0x16, 0x50, 0x0a,
        0x21, 0x84, 0x43, 0xc2, 0x07, 0xe0, 0x0e, 0x70,
        0x1c, 0x38, 0x38, 0x1c, 0x71, 0x8e, 0x62, 0x46,
        0x44, 0x22, 0x09, 0x90, 0x12, 0x48, 0x24, 0x24,
        0x49, 0x92, 0x13, 0xc8, 0x26, 0x64, 0x4d, 0xb2,
        0x1b, 0xd8, 0x36, 0x6c, 0x6d, 0xb6, 0x5a, 0x5a,
        0x35, 0xac, 0x6b, 0xd6, 0x56, 0x6a, 0x2d, 0xb4,
        0x5b, 0xda, 0x37, 0xec, 0x6f, 0xf6, 0x5e, 0x7a,
        0x3d, 0xbc, 0x7b, 0xde, 0x76, 0x6e, 0x6c, 0x36,
        0x58, 0x1a, 0x31, 0x8c, 0x63, 0xc6, 0x46, 0x62,
        0x0d, 0xb0, 0x1a, 0x58, 0x34, 0x2c, 0x69, 0x96,
        0x52, 0x4a, 0x25, 0xa4, 0x4b, 0xd2, 0x17, 0xe8,
        0x2e, 0x74, 0x5d, 0xba, 0x3b, 0xdc, 0x77, 0xee,
        0x6e, 0x76, 0x5c, 0x3a, 0x39, 0x9c, 0x73, 0xce,
        0x66, 0x66, 0x4c, 0x32, 0x19, 0x98, 0x32, 0x4c,
        0x65, 0xa6, 0x4a, 0x52, 0x15, 0xa8, 0x2a, 0x54,
        0x55, 0xaa, 0x2b, 0xd4, 0x57, 0xea, 0x2f, 0xf4,
        0x5f, 0xfa, 0x3f, 0xfc
    };
    const uint8_t *rc = RC;
    uint32_t x0, x1, x2, x3, x4, x5;
    uint32_t t0, t1, t2, t3, t4, t5;
    uint8_t round;

    /* Load the state into local variables and convert from little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = state->W[0];
    x1 = state->W[1];
    x2 = state->W[2];
    x3 = state->W[3];
    x4 = state->W[4];
    x5 = state->W[5];
#else
    x0 = le_load_word32(state->B);
    x1 = le_load_word32(state->B + 4);
    x2 = le_load_word32(state->B + 8);
    x3 = le_load_word32(state->B + 12);
    x4 = le_load_word32(state->B + 16);
    x5 = le_load_word16(state->B + 20); /* Last word is only 16 bits */
#endif

    /* Perform the 90 rounds of Spongent-pi[176] */
    for (round = 0; round < 90; ++round, rc += 2) {
        /* Add the round constant to front and back of the state */
        x0 ^= rc[0];
        x5 ^= ((uint32_t)(rc[1])) << 8;

        /* Apply the S-box to all 4-bit groups in the state */
        t0 = spongent_sbox(x0);
        t1 = spongent_sbox(x1);
        t2 = spongent_sbox(x2);
        t3 = spongent_sbox(x3);
        t4 = spongent_sbox(x4);
        t5 = spongent_sbox(x5);

        /* Permute the bits of the state.  Bit i is moved to (44 * i) % 175
         * for all bits except the last which is left where it is.
         * BCP = bit copy, BUP = move bit up, BDN = move bit down */
        x0 = BCP(t0,  0)     ^ BDN(t0,  4,  1) ^ BDN(t0,  8,  2) ^
             BDN(t0, 12,  3) ^ BDN(t0, 16,  4) ^ BDN(t0, 20,  5) ^
             BDN(t0, 24,  6) ^ BDN(t0, 28,  7) ^ BUP(t1,  0,  8) ^
             BUP(t1,  4,  9) ^ BUP(t1,  8, 10) ^ BDN(t1, 12, 11) ^
             BDN(t1, 16, 12) ^ BDN(t1, 20, 13) ^ BDN(t1, 24, 14) ^
             BDN(t1, 28, 15) ^ BUP(t2,  0, 16) ^ BUP(t2,  4, 17) ^
             BUP(t2,  8, 18) ^ BUP(t2, 12, 19) ^ BUP(t2, 16, 20) ^
             BUP(t2, 20, 21) ^ BDN(t2, 24, 22) ^ BDN(t2, 28, 23) ^
             BUP(t3,  0, 24) ^ BUP(t3,  4, 25) ^ BUP(t3,  8, 26) ^
             BUP(t3, 12, 27) ^ BUP(t3, 16, 28) ^ BUP(t3, 20, 29) ^
             BUP(t3, 24, 30) ^ BUP(t3, 28, 31);
        x1 = BUP(t0,  1, 12) ^ BUP(t0,  5, 13) ^ BUP(t0,  9, 14) ^
             BUP(t0, 13, 15) ^ BDN(t0, 17, 16) ^ BDN(t0, 21, 17) ^
             BDN(t0, 25, 18) ^ BDN(t0, 29, 19) ^ BUP(t1,  1, 20) ^
             BUP(t1,  5, 21) ^ BUP(t1,  9, 22) ^ BUP(t1, 13, 23) ^
             BUP(t1, 17, 24) ^ BUP(t1, 21, 25) ^ BUP(t1, 25, 26) ^
             BDN(t1, 29, 27) ^ BUP(t2,  1, 28) ^ BUP(t2,  5, 29) ^
             BUP(t2,  9, 30) ^ BUP(t2, 13, 31) ^ BCP(t4,  0)     ^
             BDN(t4,  4,  1) ^ BDN(t4,  8,  2) ^ BDN(t4, 12,  3) ^
             BDN(t4, 16,  4) ^ BDN(t4, 20,  5) ^ BDN(t4, 24,  6) ^
             BDN(t4, 28,  7) ^ BUP(t5,  0,  8) ^ BUP(t5,  4,  9) ^
             BUP(t5,  8, 10) ^ BDN(t5, 12, 11);
        x2 = BUP(t0,  2, 24) ^ BUP(t0,  6, 25) ^ BUP(t0, 10, 26) ^
             BUP(t0, 14, 27) ^ BUP(t0, 18, 28) ^ BUP(t0, 22, 29) ^
             BUP(t0, 26, 30) ^ BUP(t0, 30, 31) ^ BDN(t2, 17,  0) ^
             BDN(t2, 21,  1) ^ BDN(t2, 25,  2) ^ BDN(t2, 29,  3) ^
             BUP(t3,  1,  4) ^ BCP(t3,  5)     ^ BDN(t3,  9,  6) ^
             BDN(t3, 13,  7) ^ BDN(t3, 17,  8) ^ BDN(t3, 21,  9) ^
             BDN(t3, 25, 10) ^ BDN(t3, 29, 11) ^ BUP(t4,  1, 12) ^
             BUP(t4,  5, 13) ^ BUP(t4,  9, 14) ^ BUP(t4, 13, 15) ^
             BDN(t4, 17, 16) ^ BDN(t4, 21, 17) ^ BDN(t4, 25, 18) ^
             BDN(t4, 29, 19) ^ BUP(t5,  1, 20) ^ BUP(t5,  5, 21) ^
             BUP(t5,  9, 22) ^ BUP(t5, 13, 23);
        x3 = BDN(t1,  2,  0) ^ BDN(t1,  6,  1) ^ BDN(t1, 10,  2) ^
             BDN(t1, 14,  3) ^ BDN(t1, 18,  4) ^ BDN(t1, 22,  5) ^
             BDN(t1, 26,  6) ^ BDN(t1, 30,  7) ^ BUP(t2,  2,  8) ^
             BUP(t2,  6,  9) ^ BCP(t2, 10)     ^ BDN(t2, 14, 11) ^
             BDN(t2, 18, 12) ^ BDN(t2, 22, 13) ^ BDN(t2, 26, 14) ^
             BDN(t2, 30, 15) ^ BUP(t3,  2, 16) ^ BUP(t3,  6, 17) ^
             BUP(t3, 10, 18) ^ BUP(t3, 14, 19) ^ BUP(t3, 18, 20) ^
             BDN(t3, 22, 21) ^ BDN(t3, 26, 22) ^ BDN(t3, 30, 23) ^
             BUP(t4,  2, 24) ^ BUP(t4,  6, 25) ^ BUP(t4, 10, 26) ^
             BUP(t4, 14, 27) ^ BUP(t4, 18, 28) ^ BUP(t4, 22, 29) ^
             BUP(t4, 26, 30) ^ BUP(t4, 30, 31);
        x4 = BUP(t0,  3,  4) ^ BDN(t0,  7,  5) ^ BDN(t0, 11,  6) ^
             BDN(t0, 15,  7) ^ BDN(t0, 19,  8) ^ BDN(t0, 23,  9) ^
             BDN(t0, 27, 10) ^ BDN(t0, 31, 11) ^ BUP(t1,  3, 12) ^
             BUP(t1,  7, 13) ^ BUP(t1, 11, 14) ^ BCP(t1, 15)     ^
             BDN(t1, 19, 16) ^ BDN(t1, 23, 17) ^ BDN(t1, 27, 18) ^
             BDN(t1, 31, 19) ^ BUP(t2,  3, 20) ^ BUP(t2,  7, 21) ^
             BUP(t2, 11, 22) ^ BUP(t2, 15, 23) ^ BUP(t2, 19, 24) ^
             BUP(t2, 23, 25) ^ BDN(t2, 27, 26) ^ BDN(t2, 31, 27) ^
             BUP(t3,  3, 28) ^ BUP(t3,  7, 29) ^ BUP(t3, 11, 30) ^
             BUP(t3, 15, 31) ^ BDN(t5,  2,  0) ^ BDN(t5,  6,  1) ^
             BDN(t5, 10,  2) ^ BDN(t5, 14,  3);
        x5 = BDN(t3, 19,  0) ^ BDN(t3, 23,  1) ^ BDN(t3, 27,  2) ^
             BDN(t3, 31,  3) ^ BUP(t4,  3,  4) ^ BDN(t4,  7,  5) ^
             BDN(t4, 11,  6) ^ BDN(t4, 15,  7) ^ BDN(t4, 19,  8) ^
             BDN(t4, 23,  9) ^ BDN(t4, 27, 10) ^ BDN(t4, 31, 11) ^
             BUP(t5,  3, 12) ^ BUP(t5,  7, 13) ^ BUP(t5, 11, 14) ^
             BCP(t5, 15);
    }

    /* Store the local variables back to the state in little-endian order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0] = x0;
    state->W[1] = x1;
    state->W[2] = x2;
    state->W[3] = x3;
    state->W[4] = x4;
    state->W[5] = x5;
#else
    le_store_word32(state->B,      x0);
    le_store_word32(state->B +  4, x1);
    le_store_word32(state->B +  8, x2);
    le_store_word32(state->B + 12, x3);
    le_store_word32(state->B + 16, x4);
    le_store_word16(state->B + 20, x5); /* Last word is only 16 bits */
#endif
}

#endif /* !__AVR__ */
