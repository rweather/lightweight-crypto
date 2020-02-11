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

#include "internal-simp.h"

/**
 * \brief Number of rounds for the inner block cipher within SimP-256.
 */
#define SIMP_256_ROUNDS 34

/**
 * \brief Number of rounds for the inner block cipher within SimP-192.
 */
#define SIMP_192_ROUNDS 26

/**
 * \brief Round constants for each of the rounds in SimP-256 or SimP-192.
 *
 * Bit i is the round constant for round i, repeated every 62 rounds.
 */
#define SIMP_RC 0x3369F885192C0EF5ULL

void simp_256_permute(unsigned char state[SIMP_256_STATE_SIZE], unsigned steps)
{
    uint64_t z = SIMP_RC;
    uint64_t x0, x1, x2, x3, t0, t1;
    unsigned round;

    /* Load the state into local variables */
    x0 = be_load_word64(state);
    x1 = be_load_word64(state + 8);
    x2 = be_load_word64(state + 16);
    x3 = be_load_word64(state + 24);

    /* Perform all steps */
    for (; steps > 0; --steps) {
        /* Perform all rounds for this step, two at a time */
        for (round = 0; round < (SIMP_256_ROUNDS / 2); ++round) {
            t1 = x3 ^ (leftRotate1_64(x2) & leftRotate8_64(x2)) ^
                 leftRotate2_64(x2) ^ x1;
            t0 = x1 ^ rightRotate3_64(x0) ^ rightRotate4_64(x0) ^
                 0xFFFFFFFFFFFFFFFCULL ^ (z & 1);
            z = (z >> 1) | (z << 61); /* z repeats every 62 rounds */
            x2 = x2 ^ (leftRotate1_64(t1) & leftRotate8_64(t1)) ^
                 leftRotate2_64(t1) ^ x0;
            x0 = x0 ^ rightRotate3_64(t0) ^ rightRotate4_64(t0) ^
                 0xFFFFFFFFFFFFFFFCULL ^ (z & 1);
            x1 = t0;
            x3 = t1;
            z = (z >> 1) | (z << 61); /* z repeats every 62 rounds */
        }

        /* Swap the words of the state for all steps except the last */
        if (steps > 1) {
            t0 = x0;
            t1 = x1;
            x0 = x2;
            x1 = x3;
            x2 = t0;
            x3 = t1;
        }
    }

    /* Write the local variables back to the state */
    be_store_word64(state,      x0);
    be_store_word64(state +  8, x1);
    be_store_word64(state + 16, x2);
    be_store_word64(state + 24, x3);
}

/* Load a big-endian 48-bit word from a byte buffer */
#define be_load_word48(ptr) \
    ((((uint64_t)((ptr)[0])) << 40) | \
     (((uint64_t)((ptr)[1])) << 32) | \
     (((uint64_t)((ptr)[2])) << 24) | \
     (((uint64_t)((ptr)[3])) << 16) | \
     (((uint64_t)((ptr)[4])) << 8) | \
      ((uint64_t)((ptr)[5])))

/* Store a big-endian 48-bit word into a byte buffer */
#define be_store_word48(ptr, x) \
    do { \
        uint64_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 40); \
        (ptr)[1] = (uint8_t)(_x >> 32); \
        (ptr)[2] = (uint8_t)(_x >> 24); \
        (ptr)[3] = (uint8_t)(_x >> 16); \
        (ptr)[4] = (uint8_t)(_x >> 8); \
        (ptr)[5] = (uint8_t)_x; \
    } while (0)

/* 48-bit rotations with the high bits set to garbage - truncated later */
#define rightRotate3_48(x) (((x) >> 3) | ((x) << 45))
#define rightRotate4_48(x) (((x) >> 4) | ((x) << 44))
#define leftRotate1_48(x)  (((x) << 1) | ((x) >> 47))
#define leftRotate2_48(x)  (((x) << 2) | ((x) >> 46))
#define leftRotate8_48(x)  (((x) << 8) | ((x) >> 40))

void simp_192_permute(unsigned char state[SIMP_192_STATE_SIZE], unsigned steps)
{
    uint64_t z = SIMP_RC;
    uint64_t x0, x1, x2, x3, t0, t1;
    unsigned round;

    /* Load the state into local variables */
    x0 = be_load_word48(state);
    x1 = be_load_word48(state + 6);
    x2 = be_load_word48(state + 12);
    x3 = be_load_word48(state + 18);

    /* Perform all steps */
    for (; steps > 0; --steps) {
        /* Perform all rounds for this step, two at a time */
        for (round = 0; round < (SIMP_192_ROUNDS / 2); ++round) {
            t1 = x3 ^ (leftRotate1_48(x2) & leftRotate8_48(x2)) ^
                 leftRotate2_48(x2) ^ x1;
            t0 = x1 ^ rightRotate3_48(x0) ^ rightRotate4_48(x0) ^
                 0xFFFFFFFFFFFFFFFCULL ^ (z & 1);
            t0 &= 0x0000FFFFFFFFFFFFULL; /* Truncate back to 48 bits */
            t1 &= 0x0000FFFFFFFFFFFFULL;
            z = (z >> 1) | (z << 61); /* z repeats every 62 rounds */
            x2 = x2 ^ (leftRotate1_48(t1) & leftRotate8_48(t1)) ^
                 leftRotate2_48(t1) ^ x0;
            x0 = x0 ^ rightRotate3_48(t0) ^ rightRotate4_48(t0) ^
                 0xFFFFFFFFFFFFFFFCULL ^ (z & 1);
            x0 &= 0x0000FFFFFFFFFFFFULL;
            x2 &= 0x0000FFFFFFFFFFFFULL;
            x1 = t0;
            x3 = t1;
            z = (z >> 1) | (z << 61); /* z repeats every 62 rounds */
        }

        /* Swap the words of the state for all steps except the last */
        if (steps > 1) {
            t0 = x0;
            t1 = x1;
            x0 = x2;
            x1 = x3;
            x2 = t0;
            x3 = t1;
        }
    }

    /* Write the local variables back to the state */
    be_store_word48(state,      x0);
    be_store_word48(state +  6, x1);
    be_store_word48(state + 12, x2);
    be_store_word48(state + 18, x3);
}
