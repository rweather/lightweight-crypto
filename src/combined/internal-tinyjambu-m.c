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

#include "internal-tinyjambu-m.h"

/* Perform most of the TinyJAMBU step on a single share except for the AND */
#define tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, share) \
    do { \
        uint32_t s2temp = s2.share; \
        uint32_t s3temp = s3.share; \
        s0.share ^= ((s1.share >> 15) | (s2temp << 17)) ^ \
                    ((s2temp   >> 27) | (s3temp <<  5)) ^ \
                    k[offset].share; \
        t2.share = (s2temp >> 6)  | (s3temp << 26); \
        t3.share = (s2temp >> 21) | (s3temp << 11); \
    } while (0)

/* Perform most of the TinyJAMBU step on all shares except for the AND.
 * The AND part operates on the shares in order, so we process the shares
 * in the first part of the step in reverse order.  This will tend to
 * keep the earlier shares live in registers when we reach the AND step. */
#if AEAD_MASKING_SHARES == 2
#define tiny_jambu_steps_32_masked_all_shares(s0, s1, s2, s3, offset) \
    do { \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, b); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 3
#define tiny_jambu_steps_32_masked_all_shares(s0, s1, s2, s3, offset) \
    do { \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, c); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, b); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 4
#define tiny_jambu_steps_32_masked_all_shares(s0, s1, s2, s3, offset) \
    do { \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, d); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, c); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, b); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 5
#define tiny_jambu_steps_32_masked_all_shares(s0, s1, s2, s3, offset) \
    do { \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, e); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, d); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, c); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, b); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 6
#define tiny_jambu_steps_32_masked_all_shares(s0, s1, s2, s3, offset) \
    do { \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, f); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, e); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, d); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, c); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, b); \
        tiny_jambu_steps_32_masked_share(s0, s1, s2, s3, offset, a); \
    } while (0)
#else
#error "Unknown number of shares"
#endif

void tiny_jambu_permutation_masked
    (mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE],
     const mask_uint32_t *key, unsigned key_words, unsigned rounds)
{
    mask_uint32_t t2, t3;
    uint32_t temp;
    unsigned round;

    /* Create aliases for the masked state words */
    #define s0 (state[0])
    #define s1 (state[1])
    #define s2 (state[2])
    #define s3 (state[3])

    /* Perform all permutation rounds.  Each round consists of 128 steps,
     * which can be performed 32 at a time plus a rotation.  After four
     * sets of 32 steps, the rotation order returns to the original position.
     * So we can hide the rotations by doing 128 steps each round */
    for (round = 0; round < rounds; ++round) {
        /* Get the key words to use during this round */
        const mask_uint32_t *k = &(key[(round * 4) % key_words]);

        /* Perform the 128 steps of this round in groups of 32 */
        #define tiny_jambu_steps_32_masked(s0, s1, s2, s3, offset) \
            do { \
                /* t1 = (s1 >> 15) | (s2 << 17) */ \
                /* t2 = (s2 >> 6)  | (s3 << 26) */ \
                /* t3 = (s2 >> 21) | (s3 << 11) */ \
                /* t4 = (s2 >> 27) | (s3 << 5)  */ \
                /* s0 ^= t1 ^ (~(t2 & t3)) ^ t4 ^ k[offset] */ \
                tiny_jambu_steps_32_masked_all_shares(s0, s1, s2, s3, offset); \
                mask_not(s0); \
                mask_and(s0, t2, t3); \
            } while (0)
        tiny_jambu_steps_32_masked(s0, s1, s2, s3, 0);
        tiny_jambu_steps_32_masked(s1, s2, s3, s0, 1);
        tiny_jambu_steps_32_masked(s2, s3, s0, s1, 2);
        tiny_jambu_steps_32_masked(s3, s0, s1, s2, 3);
    }
}
