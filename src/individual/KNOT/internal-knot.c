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

#include "internal-knot.h"

/* Round constants for the KNOT-256, KNOT-384, and KNOT-512 permutations */
static uint8_t const rc6[52] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06, 0x0c, 0x18, 0x31, 0x22,
    0x05, 0x0a, 0x14, 0x29, 0x13, 0x27, 0x0f, 0x1e, 0x3d, 0x3a, 0x34, 0x28,
    0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32, 0x24, 0x09, 0x12, 0x25, 0x0b,
    0x16, 0x2d, 0x1b, 0x37, 0x2e, 0x1d, 0x3b, 0x36, 0x2c, 0x19, 0x33, 0x26,
    0x0d, 0x1a, 0x35, 0x2a
};
static uint8_t const rc7[104] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06, 0x0c, 0x18, 0x30,
    0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47, 0x0f, 0x1e, 0x3c,
    0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16, 0x2c, 0x59, 0x33,
    0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53, 0x27, 0x4f, 0x1f,
    0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07, 0x0e, 0x1c, 0x38,
    0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26, 0x4d, 0x1b, 0x36,
    0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37, 0x6f, 0x5e, 0x3d, 0x7b,
    0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d, 0x1a, 0x34, 0x69, 0x52, 0x25,
    0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e, 0x5c
};
static uint8_t const rc8[140] = {
    0x01, 0x02, 0x04, 0x08, 0x11, 0x23, 0x47, 0x8e, 0x1c, 0x38, 0x71, 0xe2,
    0xc4, 0x89, 0x12, 0x25, 0x4b, 0x97, 0x2e, 0x5c, 0xb8, 0x70, 0xe0, 0xc0,
    0x81, 0x03, 0x06, 0x0c, 0x19, 0x32, 0x64, 0xc9, 0x92, 0x24, 0x49, 0x93,
    0x26, 0x4d, 0x9b, 0x37, 0x6e, 0xdc, 0xb9, 0x72, 0xe4, 0xc8, 0x90, 0x20,
    0x41, 0x82, 0x05, 0x0a, 0x15, 0x2b, 0x56, 0xad, 0x5b, 0xb6, 0x6d, 0xda,
    0xb5, 0x6b, 0xd6, 0xac, 0x59, 0xb2, 0x65, 0xcb, 0x96, 0x2c, 0x58, 0xb0,
    0x61, 0xc3, 0x87, 0x0f, 0x1f, 0x3e, 0x7d, 0xfb, 0xf6, 0xed, 0xdb, 0xb7,
    0x6f, 0xde, 0xbd, 0x7a, 0xf5, 0xeb, 0xd7, 0xae, 0x5d, 0xba, 0x74, 0xe8,
    0xd1, 0xa2, 0x44, 0x88, 0x10, 0x21, 0x43, 0x86, 0x0d, 0x1b, 0x36, 0x6c,
    0xd8, 0xb1, 0x63, 0xc7, 0x8f, 0x1e, 0x3c, 0x79, 0xf3, 0xe7, 0xce, 0x9c,
    0x39, 0x73, 0xe6, 0xcc, 0x98, 0x31, 0x62, 0xc5, 0x8b, 0x16, 0x2d, 0x5a,
    0xb4, 0x69, 0xd2, 0xa4, 0x48, 0x91, 0x22, 0x45
};

/* Applies the KNOT S-box to four 64-bit words in bit-sliced mode */
#define knot_sbox64(a0, a1, a2, a3, b1, b2, b3) \
    do { \
        uint64_t t1, t3, t6; \
        t1 = ~(a0); \
        t3 = (a2) ^ ((a1) & t1); \
        (b3) = (a3) ^ t3; \
        t6 = (a3) ^ t1; \
        (b2) = ((a1) | (a2)) ^ t6; \
        t1 = (a1) ^ (a3); \
        (a0) = t1 ^ (t3 & t6); \
        (b1) = t3 ^ ((b2) & t1); \
    } while (0)

/* Applies the KNOT S-box to four 32-bit words in bit-sliced mode */
#define knot_sbox32(a0, a1, a2, a3, b1, b2, b3) \
    do { \
        uint32_t t1, t3, t6; \
        t1 = ~(a0); \
        t3 = (a2) ^ ((a1) & t1); \
        (b3) = (a3) ^ t3; \
        t6 = (a3) ^ t1; \
        (b2) = ((a1) | (a2)) ^ t6; \
        t1 = (a1) ^ (a3); \
        (a0) = t1 ^ (t3 & t6); \
        (b1) = t3 ^ ((b2) & t1); \
    } while (0)

static void knot256_permute
    (knot256_state_t *state, const uint8_t *rc, uint8_t rounds)
{
    uint64_t b1, b2, b3;

    /* Load the input state into local variables; each row is 64 bits */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
#else
    uint64_t x0 = le_load_word64(state->B);
    uint64_t x1 = le_load_word64(state->B + 8);
    uint64_t x2 = le_load_word64(state->B + 16);
    uint64_t x3 = le_load_word64(state->B + 24);
#endif

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds) {
        /* Add the next round constant to the state */
        x0 ^= *rc++;

        /* Substitution layer */
        knot_sbox64(x0, x1, x2, x3, b1, b2, b3);

        /* Linear diffusion layer */
        x1 = leftRotate1_64(b1);
        x2 = leftRotate8_64(b2);
        x3 = leftRotate25_64(b3);
    }

    /* Store the local variables to the output state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
#else
    le_store_word64(state->B,      x0);
    le_store_word64(state->B +  8, x1);
    le_store_word64(state->B + 16, x2);
    le_store_word64(state->B + 24, x3);
#endif
}

void knot256_permute_6(knot256_state_t *state, uint8_t rounds)
{
    knot256_permute(state, rc6, rounds);
}

void knot256_permute_7(knot256_state_t *state, uint8_t rounds)
{
    knot256_permute(state, rc7, rounds);
}

void knot384_permute_7(knot384_state_t *state, uint8_t rounds)
{
    const uint8_t *rc = rc7;
    uint64_t b2, b4, b6;
    uint32_t b3, b5, b7;

    /* Load the input state into local variables; each row is 96 bits */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t x0 = state->S[0];
    uint32_t x1 = state->W[2];
    uint64_t x2 = state->W[3] | (((uint64_t)(state->W[4])) << 32);
    uint32_t x3 = state->W[5];
    uint64_t x4 = state->S[3];
    uint32_t x5 = state->W[8];
    uint64_t x6 = state->W[9] | (((uint64_t)(state->W[10])) << 32);
    uint32_t x7 = state->W[11];
#else
    uint64_t x0 = le_load_word64(state->B);
    uint32_t x1 = le_load_word32(state->B + 8);
    uint64_t x2 = le_load_word64(state->B + 12);
    uint32_t x3 = le_load_word32(state->B + 20);
    uint64_t x4 = le_load_word64(state->B + 24);
    uint32_t x5 = le_load_word32(state->B + 32);
    uint64_t x6 = le_load_word64(state->B + 36);
    uint32_t x7 = le_load_word32(state->B + 44);
#endif

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds) {
        /* Add the next round constant to the state */
        x0 ^= *rc++;

        /* Substitution layer */
        knot_sbox64(x0, x2, x4, x6, b2, b4, b6);
        knot_sbox32(x1, x3, x5, x7, b3, b5, b7);

        /* Linear diffusion layer */
        #define leftRotateShort_96(a0, a1, b0, b1, bits) \
            do { \
                (a0) = ((b0) << (bits)) | ((b1) >> (32 - (bits))); \
                (a1) = ((b1) << (bits)) | ((b0) >> (64 - (bits))); \
            } while (0)
        #define leftRotateLong_96(a0, a1, b0, b1, bits) \
            do { \
                (a0) = ((b0) << (bits)) | \
                       (((uint64_t)(b1)) << ((bits) - 32)) | \
                       ((b0) >> (96 - (bits))); \
                (a1) = (uint32_t)(((b0) << ((bits) - 32)) >> 32); \
            } while (0)
        leftRotateShort_96(x2, x3, b2, b3, 1);
        leftRotateShort_96(x4, x5, b4, b5, 8);
        leftRotateLong_96(x6, x7, b6, b7, 55);
    }

    /* Store the local variables to the output state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->S[0]  = x0;
    state->W[2]  = x1;
    state->W[3]  = (uint32_t)x2;
    state->W[4]  = (uint32_t)(x2 >> 32);
    state->W[5]  = x3;
    state->S[3]  = x4;
    state->W[8]  = x5;
    state->W[9]  = (uint32_t)x6;
    state->W[10] = (uint32_t)(x6 >> 32);
    state->W[11] = x7;
#else
    le_store_word64(state->B,      x0);
    le_store_word32(state->B +  8, x1);
    le_store_word64(state->B + 12, x2);
    le_store_word32(state->B + 20, x3);
    le_store_word64(state->B + 24, x4);
    le_store_word32(state->B + 32, x5);
    le_store_word64(state->B + 36, x6);
    le_store_word32(state->B + 44, x7);
#endif
}

static void knot512_permute
    (knot512_state_t *state, const uint8_t *rc, uint8_t rounds)
{
    uint64_t b2, b3, b4, b5, b6, b7;

    /* Load the input state into local variables; each row is 128 bits */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];
    uint64_t x5 = state->S[5];
    uint64_t x6 = state->S[6];
    uint64_t x7 = state->S[7];
#else
    uint64_t x0 = le_load_word64(state->B);
    uint64_t x1 = le_load_word64(state->B + 8);
    uint64_t x2 = le_load_word64(state->B + 16);
    uint64_t x3 = le_load_word64(state->B + 24);
    uint64_t x4 = le_load_word64(state->B + 32);
    uint64_t x5 = le_load_word64(state->B + 40);
    uint64_t x6 = le_load_word64(state->B + 48);
    uint64_t x7 = le_load_word64(state->B + 56);
#endif

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds) {
        /* Add the next round constant to the state */
        x0 ^= *rc++;

        /* Substitution layer */
        knot_sbox64(x0, x2, x4, x6, b2, b4, b6);
        knot_sbox64(x1, x3, x5, x7, b3, b5, b7);

        /* Linear diffusion layer */
        #define leftRotate_128(a0, a1, b0, b1, bits) \
            do { \
                (a0) = ((b0) << (bits)) | ((b1) >> (64 - (bits))); \
                (a1) = ((b1) << (bits)) | ((b0) >> (64 - (bits))); \
            } while (0)
        leftRotate_128(x2, x3, b2, b3, 1);
        leftRotate_128(x4, x5, b4, b5, 16);
        leftRotate_128(x6, x7, b6, b7, 25);
    }

    /* Store the local variables to the output state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
    state->S[5] = x5;
    state->S[6] = x6;
    state->S[7] = x7;
#else
    le_store_word64(state->B,      x0);
    le_store_word64(state->B +  8, x1);
    le_store_word64(state->B + 16, x2);
    le_store_word64(state->B + 24, x3);
    le_store_word64(state->B + 32, x4);
    le_store_word64(state->B + 40, x5);
    le_store_word64(state->B + 48, x6);
    le_store_word64(state->B + 56, x7);
#endif
}

void knot512_permute_7(knot512_state_t *state, uint8_t rounds)
{
    knot512_permute(state, rc7, rounds);
}

void knot512_permute_8(knot512_state_t *state, uint8_t rounds)
{
    knot512_permute(state, rc8, rounds);
}
