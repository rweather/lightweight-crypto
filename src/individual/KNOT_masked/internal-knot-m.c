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

#include "internal-knot-m.h"
#include "internal-util.h"

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

/* Masked version of x = (y ^ z) */
#define mask_xor_assign_share(x, y, z, share) \
    ((x).share = (y).share ^ (z).share)
#if AEAD_MASKING_SHARES == 2
#define mask_xor_assign(x, y, z) \
    do { \
        mask_xor_assign_share((x), (y), (z), a); \
        mask_xor_assign_share((x), (y), (z), b); \
    } while (0)
#elif AEAD_MASKING_SHARES == 3
#define mask_xor_assign(x, y, z) \
    do { \
        mask_xor_assign_share((x), (y), (z), a); \
        mask_xor_assign_share((x), (y), (z), b); \
        mask_xor_assign_share((x), (y), (z), c); \
    } while (0)
#elif AEAD_MASKING_SHARES == 4
#define mask_xor_assign(x, y, z) \
    do { \
        mask_xor_assign_share((x), (y), (z), a); \
        mask_xor_assign_share((x), (y), (z), b); \
        mask_xor_assign_share((x), (y), (z), c); \
        mask_xor_assign_share((x), (y), (z), d); \
    } while (0)
#elif AEAD_MASKING_SHARES == 5
#define mask_xor_assign(x, y, z) \
    do { \
        mask_xor_assign_share((x), (y), (z), a); \
        mask_xor_assign_share((x), (y), (z), b); \
        mask_xor_assign_share((x), (y), (z), c); \
        mask_xor_assign_share((x), (y), (z), d); \
        mask_xor_assign_share((x), (y), (z), e); \
    } while (0)
#elif AEAD_MASKING_SHARES == 6
#define mask_xor_assign(x, y, z) \
    do { \
        mask_xor_assign_share((x), (y), (z), a); \
        mask_xor_assign_share((x), (y), (z), b); \
        mask_xor_assign_share((x), (y), (z), c); \
        mask_xor_assign_share((x), (y), (z), d); \
        mask_xor_assign_share((x), (y), (z), e); \
        mask_xor_assign_share((x), (y), (z), f); \
    } while (0)
#else
#error "Unknown number of shares"
#endif

/* Applies the KNOT S-box to four 64-bit masked words in bit-sliced mode */
#define knot_masked_sbox64(a0, a1, a2, a3, b1, b2, b3) \
    do { \
        mask_uint64_t t1, t3, t6; \
        uint64_t temp; \
        t1 = (a0); \
        mask_not(t1); \
        t3 = (a2); \
        mask_and(t3, (a1), t1); \
        mask_xor_assign((b3), (a3), t3); \
        mask_xor_assign(t6, (a3), t1); \
        (b2) = (t6); \
        mask_or((b2), (a1), (a2)); \
        mask_xor_assign(t1, (a1), (a3)); \
        (a0) = t1; \
        mask_and((a0), t3, t6); \
        (b1) = t3; \
        mask_and((b1), (b2), t1); \
    } while (0)

/* Applies the KNOT S-box to four 32-bit masked words in bit-sliced mode */
#define knot_masked_sbox32(a0, a1, a2, a3, b1, b2, b3) \
    do { \
        mask_uint32_t t1, t3, t6; \
        uint32_t temp; \
        t1 = (a0); \
        mask_not(t1); \
        t3 = (a2); \
        mask_and(t3, (a1), t1); \
        mask_xor_assign((b3), (a3), t3); \
        mask_xor_assign(t6, (a3), t1); \
        (b2) = (t6); \
        mask_or((b2), (a1), (a2)); \
        mask_xor_assign(t1, (a1), (a3)); \
        (a0) = t1; \
        mask_and((a0), t3, t6); \
        (b1) = t3; \
        mask_and((b1), (b2), t1); \
    } while (0)

static void knot256_masked_permute
    (knot256_masked_state_t *state, const uint8_t *rc, uint8_t rounds)
{
    mask_uint64_t b1, b2, b3;

    /* Define aliases for the state words */
    #define x0 (state->S[0])
    #define x1 (state->S[1])
    #define x2 (state->S[2])
    #define x3 (state->S[3])

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds, rc++) {
        /* Add the next round constant to the state */
        mask_xor_const(x0, *rc);

        /* Substitution layer */
        knot_masked_sbox64(x0, x1, x2, x3, b1, b2, b3);

        /* Linear diffusion layer */
        mask_rol(x1, b1, 1);
        mask_rol(x2, b2, 8);
        mask_rol(x3, b3, 25);
    }

    /* Remove the aliases */
    #undef x0
    #undef x1
    #undef x2
    #undef x3
}

void knot256_masked_permute_6(knot256_masked_state_t *state, uint8_t rounds)
{
    knot256_masked_permute(state, rc6, rounds);
}

void knot256_masked_permute_7(knot256_masked_state_t *state, uint8_t rounds)
{
    knot256_masked_permute(state, rc7, rounds);
}

void knot256_mask(knot256_masked_state_t *output, const uint64_t input[4])
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    mask_input(output->S[0], input[0]);
    mask_input(output->S[1], input[1]);
    mask_input(output->S[2], input[2]);
    mask_input(output->S[3], input[3]);
#else
    mask_input(output->S[0], le_load_word64((const unsigned char *)&(input[0])));
    mask_input(output->S[1], le_load_word64((const unsigned char *)&(input[1])));
    mask_input(output->S[2], le_load_word64((const unsigned char *)&(input[2])));
    mask_input(output->S[3], le_load_word64((const unsigned char *)&(input[3])));
#endif
}

void knot256_unmask(uint64_t output[4], const knot256_masked_state_t *input)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    output[0] = mask_output(input->S[0]);
    output[1] = mask_output(input->S[1]);
    output[2] = mask_output(input->S[2]);
    output[3] = mask_output(input->S[3]);
#else
    le_store_word64((unsigned char *)&(output[0]), mask_output(input->S[0]));
    le_store_word64((unsigned char *)&(output[1]), mask_output(input->S[1]));
    le_store_word64((unsigned char *)&(output[2]), mask_output(input->S[2]));
    le_store_word64((unsigned char *)&(output[3]), mask_output(input->S[3]));
#endif
}

void knot384_masked_permute_7(knot384_masked_state_t *state, uint8_t rounds)
{
    const uint8_t *rc = rc7;
    mask_uint64_t b2, b4, b6;
    mask_uint32_t b3, b5, b7;

    /* Define aliases for the state words */
    #define x0 (state->L[0])
    #define x1 (state->H[0])
    #define x2 (state->L[1])
    #define x3 (state->H[1])
    #define x4 (state->L[2])
    #define x5 (state->H[2])
    #define x6 (state->L[3])
    #define x7 (state->H[3])

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds, rc++) {
        /* Add the next round constant to the state */
        mask_xor_const(x0, *rc);

        /* Substitution layer */
        knot_masked_sbox64(x0, x2, x4, x6, b2, b4, b6);
        knot_masked_sbox32(x1, x3, x5, x7, b3, b5, b7);

        /* Linear diffusion layer */
        #define leftRotateShort_96_share(a0, a1, b0, b1, bits, share) \
            do { \
                (a0).share = ((b0).share << (bits)) | \
                             ((b1).share >> (32 - (bits))); \
                (a1).share = ((b1).share << (bits)) | \
                             ((b0).share >> (64 - (bits))); \
            } while (0)
        #define leftRotateLong_96_share(a0, a1, b0, b1, bits, share) \
            do { \
                (a0).share = ((b0).share << (bits)) | \
                             (((uint64_t)((b1).share)) << ((bits) - 32)) | \
                             ((b0).share >> (96 - (bits))); \
                (a1).share = (uint32_t)(((b0).share << ((bits) - 32)) >> 32); \
            } while (0)
#if AEAD_MASKING_SHARES == 2
        #define leftRotateShort_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), b); \
            } while (0)
        #define leftRotateLong_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), b); \
            } while (0)
#elif AEAD_MASKING_SHARES == 3
        #define leftRotateShort_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), c); \
            } while (0)
        #define leftRotateLong_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), c); \
            } while (0)
#elif AEAD_MASKING_SHARES == 4
        #define leftRotateShort_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), d); \
            } while (0)
        #define leftRotateLong_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), d); \
            } while (0)
#elif AEAD_MASKING_SHARES == 5
        #define leftRotateShort_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), d); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), e); \
            } while (0)
        #define leftRotateLong_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), d); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), e); \
            } while (0)
#elif AEAD_MASKING_SHARES == 6
        #define leftRotateShort_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), d); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), e); \
                leftRotateShort_96_share((a0), (a1), (b0), (b1), (bits), f); \
            } while (0)
        #define leftRotateLong_96(a0, a1, b0, b1, bits) \
            do { \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), d); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), e); \
                leftRotateLong_96_share((a0), (a1), (b0), (b1), (bits), f); \
            } while (0)
#else
#error "Unknown number of shares"
#endif
        leftRotateShort_96(x2, x3, b2, b3, 1);
        leftRotateShort_96(x4, x5, b4, b5, 8);
        leftRotateLong_96(x6, x7, b6, b7, 55);
    }

    /* Remove the aliases */
    #undef x0
    #undef x1
    #undef x2
    #undef x3
    #undef x4
    #undef x5
    #undef x6
    #undef x7
}

void knot384_mask(knot384_masked_state_t *output, const uint32_t input[12])
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    mask_input(output->L[0], input[0] | (((uint64_t)(input[1]))  << 32));
    mask_input(output->L[1], input[3] | (((uint64_t)(input[4]))  << 32));
    mask_input(output->L[2], input[6] | (((uint64_t)(input[7]))  << 32));
    mask_input(output->L[3], input[9] | (((uint64_t)(input[10])) << 32));
    mask_input(output->H[0], input[2]);
    mask_input(output->H[1], input[5]);
    mask_input(output->H[2], input[8]);
    mask_input(output->H[3], input[11]);
#else
    mask_input(output->L[0], le_load_word64((const unsigned char *)&(input[0])));
    mask_input(output->H[0], le_load_word32((const unsigned char *)&(input[2])));
    mask_input(output->L[1], le_load_word64((const unsigned char *)&(input[3])));
    mask_input(output->H[1], le_load_word32((const unsigned char *)&(input[5])));
    mask_input(output->L[2], le_load_word64((const unsigned char *)&(input[6])));
    mask_input(output->H[2], le_load_word32((const unsigned char *)&(input[8])));
    mask_input(output->L[3], le_load_word64((const unsigned char *)&(input[9])));
    mask_input(output->H[3], le_load_word32((const unsigned char *)&(input[11])));
#endif
}

void knot384_unmask(uint32_t output[12], const knot384_masked_state_t *input)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t t;
    t = mask_output(input->L[0]);
    output[0]  = (uint32_t)t;
    output[1]  = (uint32_t)(t >> 32);
    t = mask_output(input->L[1]);
    output[3]  = (uint32_t)t;
    output[4]  = (uint32_t)(t >> 32);
    t = mask_output(input->L[2]);
    output[6]  = (uint32_t)t;
    output[7]  = (uint32_t)(t >> 32);
    t = mask_output(input->L[3]);
    output[9]  = (uint32_t)t;
    output[10] = (uint32_t)(t >> 32);
    output[2]  = mask_output(input->H[0]);
    output[5]  = mask_output(input->H[1]);
    output[8]  = mask_output(input->H[2]);
    output[11] = mask_output(input->H[3]);
#else
    le_store_word64((unsigned char *)&(output[0]),  mask_output(input->L[0]));
    le_store_word64((unsigned char *)&(output[3]),  mask_output(input->L[1]));
    le_store_word64((unsigned char *)&(output[6]),  mask_output(input->L[2]));
    le_store_word64((unsigned char *)&(output[9]),  mask_output(input->L[3]));
    le_store_word32((unsigned char *)&(output[2]),  mask_output(input->H[0]));
    le_store_word32((unsigned char *)&(output[5]),  mask_output(input->H[1]));
    le_store_word32((unsigned char *)&(output[8]),  mask_output(input->H[2]));
    le_store_word32((unsigned char *)&(output[11]), mask_output(input->H[3]));
#endif
}

static void knot512_masked_permute
    (knot512_masked_state_t *state, const uint8_t *rc, uint8_t rounds)
{
    mask_uint64_t b2, b3, b4, b5, b6, b7;

    /* Define aliases for the state words */
    #define x0 (state->S[0])
    #define x1 (state->S[1])
    #define x2 (state->S[2])
    #define x3 (state->S[3])
    #define x4 (state->S[4])
    #define x5 (state->S[5])
    #define x6 (state->S[6])
    #define x7 (state->S[7])

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds, rc++) {
        /* Add the next round constant to the state */
        mask_xor_const(x0, *rc);

        /* Substitution layer */
        knot_masked_sbox64(x0, x2, x4, x6, b2, b4, b6);
        knot_masked_sbox64(x1, x3, x5, x7, b3, b5, b7);

        /* Linear diffusion layer */
        #define leftRotate_128_share(a0, a1, b0, b1, bits, share) \
            do { \
                (a0).share = ((b0).share << (bits)) | \
                             ((b1).share >> (64 - (bits))); \
                (a1).share = ((b1).share << (bits)) | \
                             ((b0).share >> (64 - (bits))); \
            } while (0)
#if AEAD_MASKING_SHARES == 2
        #define leftRotate_128(a0, a1, b0, b1, bits) \
            do { \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), b); \
            } while (0)
#elif AEAD_MASKING_SHARES == 3
        #define leftRotate_128(a0, a1, b0, b1, bits) \
            do { \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), c); \
            } while (0)
#elif AEAD_MASKING_SHARES == 4
        #define leftRotate_128(a0, a1, b0, b1, bits) \
            do { \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), d); \
            } while (0)
#elif AEAD_MASKING_SHARES == 5
        #define leftRotate_128(a0, a1, b0, b1, bits) \
            do { \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), d); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), e); \
            } while (0)
#elif AEAD_MASKING_SHARES == 6
        #define leftRotate_128(a0, a1, b0, b1, bits) \
            do { \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), a); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), b); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), c); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), d); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), e); \
                leftRotate_128_share((a0), (a1), (b0), (b1), (bits), f); \
            } while (0)
#else
#error "Unknown number of shares"
#endif
        leftRotate_128(x2, x3, b2, b3, 1);
        leftRotate_128(x4, x5, b4, b5, 16);
        leftRotate_128(x6, x7, b6, b7, 25);
    }

    /* Remove the aliases */
    #undef x0
    #undef x1
    #undef x2
    #undef x3
    #undef x4
    #undef x5
    #undef x6
    #undef x7
}

void knot512_masked_permute_7(knot512_masked_state_t *state, uint8_t rounds)
{
    knot512_masked_permute(state, rc7, rounds);
}

void knot512_masked_permute_8(knot512_masked_state_t *state, uint8_t rounds)
{
    knot512_masked_permute(state, rc8, rounds);
}

void knot512_mask(knot512_masked_state_t *output, const uint64_t input[8])
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    mask_input(output->S[0], input[0]);
    mask_input(output->S[1], input[1]);
    mask_input(output->S[2], input[2]);
    mask_input(output->S[3], input[3]);
    mask_input(output->S[4], input[4]);
    mask_input(output->S[5], input[5]);
    mask_input(output->S[6], input[6]);
    mask_input(output->S[7], input[7]);
#else
    mask_input(output->S[0], le_load_word64((const unsigned char *)&(input[0])));
    mask_input(output->S[1], le_load_word64((const unsigned char *)&(input[1])));
    mask_input(output->S[2], le_load_word64((const unsigned char *)&(input[2])));
    mask_input(output->S[3], le_load_word64((const unsigned char *)&(input[3])));
    mask_input(output->S[4], le_load_word64((const unsigned char *)&(input[4])));
    mask_input(output->S[5], le_load_word64((const unsigned char *)&(input[5])));
    mask_input(output->S[6], le_load_word64((const unsigned char *)&(input[6])));
    mask_input(output->S[7], le_load_word64((const unsigned char *)&(input[7])));
#endif
}

void knot512_unmask(uint64_t output[8], const knot512_masked_state_t *input)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    output[0] = mask_output(input->S[0]);
    output[1] = mask_output(input->S[1]);
    output[2] = mask_output(input->S[2]);
    output[3] = mask_output(input->S[3]);
    output[4] = mask_output(input->S[4]);
    output[5] = mask_output(input->S[5]);
    output[6] = mask_output(input->S[6]);
    output[7] = mask_output(input->S[7]);
#else
    le_store_word64((unsigned char *)&(output[0]), mask_output(input->S[0]));
    le_store_word64((unsigned char *)&(output[1]), mask_output(input->S[1]));
    le_store_word64((unsigned char *)&(output[2]), mask_output(input->S[2]));
    le_store_word64((unsigned char *)&(output[3]), mask_output(input->S[3]));
    le_store_word64((unsigned char *)&(output[4]), mask_output(input->S[4]));
    le_store_word64((unsigned char *)&(output[5]), mask_output(input->S[5]));
    le_store_word64((unsigned char *)&(output[6]), mask_output(input->S[6]));
    le_store_word64((unsigned char *)&(output[7]), mask_output(input->S[7]));
#endif
}
