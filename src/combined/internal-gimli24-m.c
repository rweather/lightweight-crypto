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

#include "internal-gimli24-m.h"
#include "internal-util.h"

/* Sub-phases of GIMLI24_SP, split into separate shares */
#define GIMLI24_SP_1_SHARE(s0, s4, s8, share) \
    do { \
        x.share = leftRotate24(s0.share); \
        y.share = leftRotate9(s4.share); \
        s4.share = y.share ^ x.share; \
    } while (0)
#define GIMLI24_SP_2_SHARE(s0, s4, s8, share) \
    do { \
        s4.share ^= (t.share << 1); \
        s0.share = s8.share ^ y.share; \
    } while (0)
#define GIMLI24_SP_3_SHARE(s0, s4, s8, share) \
    do { \
        s0.share ^= (t.share << 3); \
    } while (0)
#define GIMLI24_SP_4_SHARE(s0, s4, s8, share) \
    do { \
        s8.share = (s8.share << 1) ^ (t.share << 2) ^ x.share; \
    } while (0)
#if AEAD_MASKING_SHARES == 2
#define GIMLI24_SP_1(s0, s4, s8) \
    do { \
        GIMLI24_SP_1_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_2(s0, s4, s8) \
    do { \
        GIMLI24_SP_2_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_3(s0, s4, s8) \
    do { \
        GIMLI24_SP_3_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_4(s0, s4, s8) \
    do { \
        GIMLI24_SP_4_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 3
#define GIMLI24_SP_1(s0, s4, s8) \
    do { \
        GIMLI24_SP_1_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_2(s0, s4, s8) \
    do { \
        GIMLI24_SP_2_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_3(s0, s4, s8) \
    do { \
        GIMLI24_SP_3_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_4(s0, s4, s8) \
    do { \
        GIMLI24_SP_4_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 4
#define GIMLI24_SP_1(s0, s4, s8) \
    do { \
        GIMLI24_SP_1_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_2(s0, s4, s8) \
    do { \
        GIMLI24_SP_2_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_3(s0, s4, s8) \
    do { \
        GIMLI24_SP_3_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_4(s0, s4, s8) \
    do { \
        GIMLI24_SP_4_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 5
#define GIMLI24_SP_1(s0, s4, s8) \
    do { \
        GIMLI24_SP_1_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_2(s0, s4, s8) \
    do { \
        GIMLI24_SP_2_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_3(s0, s4, s8) \
    do { \
        GIMLI24_SP_3_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_4(s0, s4, s8) \
    do { \
        GIMLI24_SP_4_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, a); \
    } while (0)
#elif AEAD_MASKING_SHARES == 6
#define GIMLI24_SP_1(s0, s4, s8) \
    do { \
        GIMLI24_SP_1_SHARE(s0, s4, s8, f); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_1_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_2(s0, s4, s8) \
    do { \
        GIMLI24_SP_2_SHARE(s0, s4, s8, f); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_2_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_3(s0, s4, s8) \
    do { \
        GIMLI24_SP_3_SHARE(s0, s4, s8, f); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_3_SHARE(s0, s4, s8, a); \
    } while (0)
#define GIMLI24_SP_4(s0, s4, s8) \
    do { \
        GIMLI24_SP_4_SHARE(s0, s4, s8, f); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, e); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, d); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, c); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, b); \
        GIMLI24_SP_4_SHARE(s0, s4, s8, a); \
    } while (0)
#else
#error "Unknown number of shares"
#endif

/* Apply the SP-box to a specific column in the state array */
#define GIMLI24_SP_MASKED(s0, s4, s8) \
    do { \
        GIMLI24_SP_1(s0, s4, s8); \
        mask_zero(t); \
        mask_or(t, x, s8); \
        GIMLI24_SP_2(s0, s4, s8); \
        mask_zero(t); \
        mask_and(t, x, y); \
        GIMLI24_SP_3(s0, s4, s8); \
        mask_zero(t); \
        mask_and(t, y, s8); \
        GIMLI24_SP_4(s0, s4, s8); \
    } while (0)

void gimli24_permute_masked(mask_uint32_t state[12])
{
    mask_uint32_t x, y, t;
    uint32_t temp;
    unsigned round;

    /* Create aliases for the masked state words */
    #define s0  (state[0])
    #define s1  (state[1])
    #define s2  (state[2])
    #define s3  (state[3])
    #define s4  (state[4])
    #define s5  (state[5])
    #define s6  (state[6])
    #define s7  (state[7])
    #define s8  (state[8])
    #define s9  (state[9])
    #define s10 (state[10])
    #define s11 (state[11])

    /* Unroll and perform the rounds 4 at a time */
    for (round = 24; round > 0; round -= 4) {
        /* Round 0: SP-box, small swap, add round constant */
        GIMLI24_SP_MASKED(s0, s4, s8);
        GIMLI24_SP_MASKED(s1, s5, s9);
        GIMLI24_SP_MASKED(s2, s6, s10);
        GIMLI24_SP_MASKED(s3, s7, s11);
        x = s0;
        y = s2;
        s0 = s1;
        mask_xor_const(s0, 0x9e377900U ^ round);
        s1 = x;
        s2 = s3;
        s3 = y;

        /* Round 1: SP-box only */
        GIMLI24_SP_MASKED(s0, s4, s8);
        GIMLI24_SP_MASKED(s1, s5, s9);
        GIMLI24_SP_MASKED(s2, s6, s10);
        GIMLI24_SP_MASKED(s3, s7, s11);

        /* Round 2: SP-box, big swap */
        GIMLI24_SP_MASKED(s0, s4, s8);
        GIMLI24_SP_MASKED(s1, s5, s9);
        GIMLI24_SP_MASKED(s2, s6, s10);
        GIMLI24_SP_MASKED(s3, s7, s11);
        x = s0;
        y = s1;
        s0 = s2;
        s1 = s3;
        s2 = x;
        s3 = y;

        /* Round 3: SP-box only */
        GIMLI24_SP_MASKED(s0, s4, s8);
        GIMLI24_SP_MASKED(s1, s5, s9);
        GIMLI24_SP_MASKED(s2, s6, s10);
        GIMLI24_SP_MASKED(s3, s7, s11);
    }
}

void gimli24_mask(mask_uint32_t output[12], const uint32_t input[12])
{
    int index;
    for (index = 0; index < 12; ++index) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        mask_input(output[index], input[index]);
#else
        mask_input(output[index],
                   le_load_word32((const unsigned char *)(&(input[index]))));
#endif
    }
}

void gimli24_unmask(uint32_t output[12], const mask_uint32_t input[12])
{
    int index;
    for (index = 0; index < 12; ++index) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        output[index] = mask_output(input[index]);
#else
        le_store_word32(((unsigned char *)(&(output[index]))),
                        mask_output(input[index]));
#endif
    }
}
