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

#include "internal-tinyjambu.h"

/* Determine if the permutations should be accelerated with assembly code */
#if defined(__AVR__)
#define TINYJAMBU_ASM 1
#elif defined(__ARM_ARCH_ISA_THUMB) && __ARM_ARCH == 7
#define TINYJAMBU_ASM 1
#else
#define TINYJAMBU_ASM 0
#endif

#if !TINYJAMBU_ASM

#define tiny_jambu_steps_32(s0, s1, s2, s3, kword) \
    do { \
        t1 = (s1 >> 15) | (s2 << 17); \
        t2 = (s2 >> 6)  | (s3 << 26); \
        t3 = (s2 >> 21) | (s3 << 11); \
        t4 = (s2 >> 27) | (s3 << 5); \
        s0 ^= t1 ^ (~(t2 & t3)) ^ t4 ^ kword; \
    } while (0)

void tiny_jambu_permutation_128
    (uint32_t state[TINY_JAMBU_STATE_SIZE], const uint32_t *key,
     unsigned rounds)
{
    uint32_t t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t s0 = state[0];
    uint32_t s1 = state[1];
    uint32_t s2 = state[2];
    uint32_t s3 = state[3];

    /* Perform all permutation rounds 128 at a time */
    for (; rounds > 0; --rounds) {
        /* Perform the first set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[0]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[1]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[2]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[3]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the second set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[0]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[1]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[2]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[3]);
    }

    /* Store the local variables back to the state */
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
}

void tiny_jambu_permutation_192
    (uint32_t state[TINY_JAMBU_STATE_SIZE], const uint32_t *key,
     unsigned rounds)
{
    uint32_t t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t s0 = state[0];
    uint32_t s1 = state[1];
    uint32_t s2 = state[2];
    uint32_t s3 = state[3];

    /* Perform all permutation rounds 128 at a time */
    for (; rounds > 0; --rounds) {
        /* Perform the first set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[0]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[1]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[2]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[3]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the second set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[4]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[5]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[0]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[1]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the third set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[2]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[3]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[4]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[5]);
    }

    /* Store the local variables back to the state */
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
}

void tiny_jambu_permutation_256
    (uint32_t state[TINY_JAMBU_STATE_SIZE], const uint32_t *key,
     unsigned rounds)
{
    uint32_t t1, t2, t3, t4;

    /* Load the state into local variables */
    uint32_t s0 = state[0];
    uint32_t s1 = state[1];
    uint32_t s2 = state[2];
    uint32_t s3 = state[3];

    /* Perform all permutation rounds 128 at a time */
    for (; rounds > 0; --rounds) {
        /* Perform the first set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[0]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[1]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[2]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[3]);

        /* Bail out if this is the last round */
        if ((--rounds) == 0)
            break;

        /* Perform the second set of 128 steps */
        tiny_jambu_steps_32(s0, s1, s2, s3, key[4]);
        tiny_jambu_steps_32(s1, s2, s3, s0, key[5]);
        tiny_jambu_steps_32(s2, s3, s0, s1, key[6]);
        tiny_jambu_steps_32(s3, s0, s1, s2, key[7]);
    }

    /* Store the local variables back to the state */
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
}

#endif /* !TINYJAMBU_ASM */
