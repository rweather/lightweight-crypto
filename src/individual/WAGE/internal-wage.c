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

#include "internal-wage.h"

/**
 * \brief Number of rounds for the WAGE permutation.
 */
#define WAGE_NUM_ROUNDS 111

/**
 * \brief Define WAGE_64BIT to use the 64-bit version of the WAGE core
 * permutation.  Undefine to use the 8-bit version instead.
 */
#define WAGE_64BIT 1

/**
 * \brief RC0 and RC1 round constants for WAGE, interleaved with each other.
 */
static unsigned char const wage_rc[WAGE_NUM_ROUNDS * 2] = {
    0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x40, 0x20, 0x10, 0x08, 0x04,
    0x02, 0x41, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x43, 0x21, 0x50, 0x28, 0x14,
    0x0a, 0x45, 0x62, 0x71, 0x78, 0x3c, 0x1e, 0x4f, 0x27, 0x13, 0x09, 0x44,
    0x22, 0x51, 0x68, 0x34, 0x1a, 0x4d, 0x66, 0x73, 0x39, 0x5c, 0x2e, 0x57,
    0x2b, 0x15, 0x4a, 0x65, 0x72, 0x79, 0x7c, 0x3e, 0x5f, 0x2f, 0x17, 0x0b,
    0x05, 0x42, 0x61, 0x70, 0x38, 0x1c, 0x0e, 0x47, 0x23, 0x11, 0x48, 0x24,
    0x12, 0x49, 0x64, 0x32, 0x59, 0x6c, 0x36, 0x5b, 0x2d, 0x56, 0x6b, 0x35,
    0x5a, 0x6d, 0x76, 0x7b, 0x3d, 0x5e, 0x6f, 0x37, 0x1b, 0x0d, 0x46, 0x63,
    0x31, 0x58, 0x2c, 0x16, 0x4b, 0x25, 0x52, 0x69, 0x74, 0x3a, 0x5d, 0x6e,
    0x77, 0x3b, 0x1d, 0x4e, 0x67, 0x33, 0x19, 0x4c, 0x26, 0x53, 0x29, 0x54,
    0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d, 0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07,
    0x03, 0x01, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x41, 0x60, 0x30, 0x18,
    0x0c, 0x06, 0x43, 0x21, 0x50, 0x28, 0x14, 0x0a, 0x45, 0x62, 0x71, 0x78,
    0x3c, 0x1e, 0x4f, 0x27, 0x13, 0x09, 0x44, 0x22, 0x51, 0x68, 0x34, 0x1a,
    0x4d, 0x66, 0x73, 0x39, 0x5c, 0x2e, 0x57, 0x2b, 0x15, 0x4a, 0x65, 0x72,
    0x79, 0x7c, 0x3e, 0x5f, 0x2f, 0x17, 0x0b, 0x05, 0x42, 0x61, 0x70, 0x38,
    0x1c, 0x0e, 0x47, 0x23, 0x11, 0x48, 0x24, 0x12, 0x49, 0x64, 0x32, 0x59,
    0x6c, 0x36, 0x5b, 0x2d, 0x56, 0x6b, 0x35, 0x5a, 0x6d, 0x76, 0x7b, 0x3d,
    0x5e, 0x6f, 0x37, 0x1b, 0x0d, 0x46
};

/**
 * \brief Apply the WGP permutation to a 7-bit component.
 *
 * Warning: This is not constant cache.
 */
static unsigned char const wage_wgp[128] = {
    0x00, 0x12, 0x0a, 0x4b, 0x66, 0x0c, 0x48, 0x73, 0x79, 0x3e, 0x61, 0x51,
    0x01, 0x15, 0x17, 0x0e, 0x7e, 0x33, 0x68, 0x36, 0x42, 0x35, 0x37, 0x5e,
    0x53, 0x4c, 0x3f, 0x54, 0x58, 0x6e, 0x56, 0x2a, 0x1d, 0x25, 0x6d, 0x65,
    0x5b, 0x71, 0x2f, 0x20, 0x06, 0x18, 0x29, 0x3a, 0x0d, 0x7a, 0x6c, 0x1b,
    0x19, 0x43, 0x70, 0x41, 0x49, 0x22, 0x77, 0x60, 0x4f, 0x45, 0x55, 0x02,
    0x63, 0x47, 0x75, 0x2d, 0x40, 0x46, 0x7d, 0x5c, 0x7c, 0x59, 0x26, 0x0b,
    0x09, 0x03, 0x57, 0x5d, 0x27, 0x78, 0x30, 0x2e, 0x44, 0x52, 0x3b, 0x08,
    0x67, 0x2c, 0x05, 0x6b, 0x2b, 0x1a, 0x21, 0x38, 0x07, 0x0f, 0x4a, 0x11,
    0x50, 0x6a, 0x28, 0x31, 0x10, 0x4d, 0x5f, 0x72, 0x39, 0x16, 0x5a, 0x13,
    0x04, 0x3c, 0x34, 0x1f, 0x76, 0x1e, 0x14, 0x23, 0x1c, 0x32, 0x4e, 0x7b,
    0x24, 0x74, 0x7f, 0x3d, 0x69, 0x64, 0x62, 0x6f
};

/**
 * \brief Evaluate the WAGE S-box three times in parallel.
 *
 * \param x6 The input values to the S-box.
 * \return The output values from the S-box.
 *
 * This function directly evaluates the S-box in bit-sliced form
 * using the algorithm from the specification.
 */
STATIC_INLINE uint32_t wage_sbox_parallel_3(uint32_t x6)
{
    uint32_t x0 = x6 >> 6;
    uint32_t x1 = x6 >> 5;
    uint32_t x2 = x6 >> 4;
    uint32_t x3 = x6 >> 3;
    uint32_t x4 = x6 >> 2;
    uint32_t x5 = x6 >> 1;
    x0 ^= (x2 & x3); x3 = ~x3; x3 ^= (x5 & x6); x5 = ~x5; x5 ^= (x2 & x4);
    x6 ^= (x0 & x4); x4 = ~x4; x4 ^= (x5 & x1); x5 = ~x5; x5 ^= (x0 & x2);
    x1 ^= (x6 & x2); x2 = ~x2; x2 ^= (x5 & x3); x5 = ~x5; x5 ^= (x6 & x0);
    x3 ^= (x1 & x0); x0 = ~x0; x0 ^= (x5 & x4); x5 = ~x5; x5 ^= (x1 & x6);
    x4 ^= (x3 & x6); x6 = ~x6; x6 ^= (x5 & x2); x5 = ~x5; x5 ^= (x3 & x1);
    x2 ^= (x4 & x1); x1 = ~x1; x1 ^= (x5 & x0); x5 = ~x5; x5 ^= (x4 & x3);
    x2 = ~x2; x4 = ~x4;
    return ((x2 & 0x00010101U) << 6) ^
           ((x6 & 0x00010101U) << 5) ^
           ((x4 & 0x00010101U) << 4) ^
           ((x1 & 0x00010101U) << 3) ^
           ((x3 & 0x00010101U) << 2) ^
           ((x5 & 0x00010101U) << 1) ^
            (x0 & 0x00010101U);
}

void wage_permute(unsigned char s[WAGE_STATE_SIZE])
{
#if defined(WAGE_64BIT)
    const unsigned char *rc = wage_rc;
    unsigned char round;
    uint64_t x0, x1, x2, x3, x4;
    uint32_t fb, temp;

    /* Load the state into 64-bit words.  Each word will have up to eight
     * 7-bit components with the MSB of each component fixed at zero.
     *
     *      x0 = s[0]  .. s[7]
     *      x1 = s[8]  .. s[15]
     *      x2 = s[16] .. s[23]
     *      x3 = s[24] .. s[31]
     *      x4 = s[32] .. s[36]
     */
    x0 = le_load_word64(s);
    x1 = le_load_word64(s + 8);
    x2 = le_load_word64(s + 16);
    x3 = le_load_word64(s + 24);
    x4 = le_load_word32(s + 32) | (((uint64_t)(s[36])) << 32);

    /* Perform all rounds 3 at a time to reduce the state rotation overhead */
    for (round = 0; round < (WAGE_NUM_ROUNDS / 3); ++round, rc += 6) {
        /* Calculate the feedback value for the LFSR.
         *
         * fb = omega(s[0]) ^ s[6] ^ s[8] ^ s[12] ^ s[13] ^ s[19] ^
         *      s[24] ^ s[26] ^ s[30] ^ s[31] ^ WGP(s[36]) ^ RC1[round]
         *
         * where omega(x) is (x >> 1) if the low bit of x is zero and
         * (x >> 1) ^ 0x78 if the low bit of x is one.
         */
        /* fb0 = omega(s[0]), fb1 = omega(s[1]), fb2 = omega(s[2]) */
        temp = (uint32_t)x0;
        fb = (temp & 0x00010101U) << 6;
        fb ^= (fb >> 1);
        fb ^= (fb >> 2);
        fb ^= (temp >> 1) & 0x003F3F3FU;
        /* fb0 ^= s[6], fb1 ^= s[7], fb2 ^= s[8] */
        fb ^= (uint32_t)(x0 >> 48);
        fb ^= ((uint32_t)x1) << 16;
        /* fb0 ^= s[8], fb1 ^= s[9], fb2 ^= s[10] */
        fb ^= (uint32_t)x1;
        /* fb0 ^= s[12], fb1 ^= s[13], fb2 ^= s[14] */
        fb ^= (uint32_t)(x1 >> 32);
        /* fb0 ^= s[13], fb1 ^= s[14], fb2 ^= s[15] */
        fb ^= (uint32_t)(x1 >> 40);
        /* fb0 ^= s[19], fb1 ^= s[20], fb2 ^= s[21] */
        fb ^= (uint32_t)(x2 >> 24);
        /* fb0 ^= s[24], fb1 ^= s[25], fb2 ^= s[26] */
        fb ^= (uint32_t)x3;
        /* fb0 ^= s[26], fb1 ^= s[27], fb2 ^= s[28] */
        fb ^= (uint32_t)(x3 >> 16);
        /* fb0 ^= s[30], fb1 ^= s[31], fb2 ^= s[32] */
        fb ^= (uint32_t)(x3 >> 48);
        fb ^= ((uint32_t)x4) << 16;
        /* fb0 ^= s[31], fb1 ^= s[32], fb2 ^= s[33] */
        fb ^= (uint32_t)(x3 >> 56);
        fb ^= ((uint32_t)x4) << 8;
        /* fb0,1,2 ^= RC1 */
        temp = rc[1] | (((uint32_t)(rc[3])) << 8) | (((uint32_t)(rc[5])) << 16);
        fb ^= temp;
        /* fb0 ^= WGP(s[36]) */
        fb ^= wage_wgp[(uint8_t)(x4 >> 32)];
        /* fb1 ^= WGP(fb0) */
        fb ^= ((uint32_t)(wage_wgp[fb & 0xFF])) << 8;
        /* fb2 ^= WGP(fb1) */
        fb ^= ((uint32_t)(wage_wgp[(fb >> 8) & 0xFF])) << 16;

        /* Apply the S-box and WGP permutation to certain components */
        /* s[5] ^= sbox[s[8]], s[6] ^= sbox[s[9]], s[7] ^= sbox[s[10]] */
        x0 ^= ((uint64_t)wage_sbox_parallel_3((uint32_t)x1)) << 40;
        /* s[11] ^= sbox[s[15]], s[12] ^= sbox[s[16]], s[13] ^= sbox[s[17]] */
        x1 ^= ((uint64_t)wage_sbox_parallel_3
                    ((uint32_t)((x1 >> 56) | (x2 << 8)))) << 24;
        /* s[24] ^= sbox[s[27]], s[25] ^= sbox[s[28]], s[26] ^= sbox[s[29]] */
        x3 ^= (uint64_t)wage_sbox_parallel_3((uint32_t)(x3 >> 24));
        /* s[30] ^= sbox[s[34]], s[31] ^= sbox[s[35]], s[32] ^= sbox[s[36]] */
        temp = wage_sbox_parallel_3((uint32_t)(x4 >> 16));
        x3 ^= ((uint64_t)temp) << 48;
        x4 ^= temp >> 16;
        /* s[19] ^= WGP[s[18]] ^ RC0 */
        temp = (uint32_t)(x2 >> 16); /* s[18..21] */
        temp ^= ((uint32_t)(wage_wgp[temp & 0x7F])) << 8;
        temp ^= ((uint32_t)(rc[0])) << 8;
        /* s[20] ^= WGP[s[19]] ^ RC0 */
        temp ^= ((uint32_t)(wage_wgp[(temp >>  8) & 0x7F])) << 16;
        temp ^= ((uint32_t)(rc[2])) << 16;
        /* s[21] ^= WGP[s[20]] ^ RC0 */
        temp ^= ((uint32_t)(wage_wgp[(temp >> 16) & 0x7F])) << 24;
        temp ^= ((uint32_t)(rc[4])) << 24;
        temp &= 0x7F7F7F00U;
        x2 = (x2 & 0xFFFF000000FFFFFFULL) | (((uint64_t)temp) << 16);

        /* Rotate the components of the state by 3 positions */
        x0 = (x0 >> 24) | (x1 << 40);
        x1 = (x1 >> 24) | (x2 << 40);
        x2 = (x2 >> 24) | (x3 << 40);
        x3 = (x3 >> 24) | (x4 << 40);
        x4 = (x4 >> 24) | (((uint64_t)(fb & 0x00FFFFFFU)) << 16);
    }

    /* Save the words back to the state */
    le_store_word64(s, x0);
    le_store_word64(s +  8, x1);
    le_store_word64(s + 16, x2);
    le_store_word64(s + 24, x3);
    le_store_word32(s + 32, (uint32_t)x4);
    s[36] = (unsigned char)(x4 >> 32);
#else /* 8-bit version of WAGE */
    const unsigned char *rc = wage_rc;
    unsigned char round, index;
    unsigned char fb0, fb1, fb2;
    uint32_t temp;

    /* Perform all rounds 3 at a time to reduce the state rotation overhead */
    for (round = 0; round < (WAGE_NUM_ROUNDS / 3); ++round, rc += 6) {
        /* Calculate the feedback value for the LFSR.
         *
         * fb = omega(s[0]) ^ s[6] ^ s[8] ^ s[12] ^ s[13] ^ s[19] ^
         *      s[24] ^ s[26] ^ s[30] ^ s[31] ^ WGP(s[36]) ^ RC1[round]
         *
         * where omega(x) is (x >> 1) if the low bit of x is zero and
         * (x >> 1) ^ 0x78 if the low bit of x is one.
         */
        fb0 = (s[0] >> 1) ^ (0x78 & -(s[0] & 0x01));
        fb0 ^= s[6]  ^ s[8]  ^ s[12] ^ s[13] ^ s[19] ^
               s[24] ^ s[26] ^ s[30] ^ s[31] ^ rc[1];
        fb0   ^= wage_wgp[s[36]];
        fb1 = (s[1] >> 1) ^ (0x78 & -(s[1] & 0x01));
        fb1 ^= s[7]  ^ s[9]  ^ s[13] ^ s[14] ^ s[20] ^
               s[25] ^ s[27] ^ s[31] ^ s[32] ^ rc[3];
        fb1   ^= wage_wgp[fb0];
        fb2 = (s[2] >> 1) ^ (0x78 & -(s[2] & 0x01));
        fb2 ^= s[8]  ^ s[10] ^ s[14] ^ s[15] ^ s[21] ^
               s[26] ^ s[28] ^ s[32] ^ s[33] ^ rc[5];
        fb2   ^= wage_wgp[fb1];

        /* Apply the S-box and WGP permutation to certain components */
        temp = s[8] | (((uint32_t)(s[9])) << 8) | (((uint32_t)(s[10])) << 16);
        temp = wage_sbox_parallel_3(temp);
        s[5]  ^= (unsigned char)temp;
        s[6]  ^= (unsigned char)(temp >> 8);
        s[7]  ^= (unsigned char)(temp >> 16);
        temp = s[15] | (((uint32_t)(s[16])) << 8) | (((uint32_t)(s[17])) << 16);
        temp = wage_sbox_parallel_3(temp);
        s[11] ^= (unsigned char)temp;
        s[12] ^= (unsigned char)(temp >> 8);
        s[13] ^= (unsigned char)(temp >> 16);
        s[19] ^= wage_wgp[s[18]] ^ rc[0];
        s[20] ^= wage_wgp[s[19]] ^ rc[2];
        s[21] ^= wage_wgp[s[20]] ^ rc[4];
        temp = s[27] | (((uint32_t)(s[28])) << 8) | (((uint32_t)(s[29])) << 16);
        temp = wage_sbox_parallel_3(temp);
        s[24] ^= (unsigned char)temp;
        s[25] ^= (unsigned char)(temp >> 8);
        s[26] ^= (unsigned char)(temp >> 16);
        temp = s[34] | (((uint32_t)(s[35])) << 8) | (((uint32_t)(s[36])) << 16);
        temp = wage_sbox_parallel_3(temp);
        s[30] ^= (unsigned char)temp;
        s[31] ^= (unsigned char)(temp >> 8);
        s[32] ^= (unsigned char)(temp >> 16);

        /* Rotate the components of the state by 3 positions */
        for (index = 0; index < WAGE_STATE_SIZE - 3; ++index)
            s[index] = s[index + 3];
        s[WAGE_STATE_SIZE - 3] = fb0;
        s[WAGE_STATE_SIZE - 2] = fb1;
        s[WAGE_STATE_SIZE - 1] = fb2;
    }
#endif
}

/* 7-bit components for the rate: 8, 9, 15, 16, 18, 27, 28, 34, 35, 36 */

void wage_absorb
    (unsigned char s[WAGE_STATE_SIZE], const unsigned char data[8],
     unsigned char domain)
{
    uint32_t temp;
    temp = be_load_word32(data);
    s[8]  ^= (unsigned char)(temp  >> 25);
    s[9]  ^= (unsigned char)((temp >> 18) & 0x7F);
    s[15] ^= (unsigned char)((temp >> 11) & 0x7F);
    s[16] ^= (unsigned char)((temp >>  4) & 0x7F);
    s[18] ^= (unsigned char)((temp <<  3) & 0x7F);
    temp = be_load_word32(data + 4);
    s[18] ^= (unsigned char)(temp  >> 29);
    s[27] ^= (unsigned char)((temp >> 22) & 0x7F);
    s[28] ^= (unsigned char)((temp >> 15) & 0x7F);
    s[34] ^= (unsigned char)((temp >>  8) & 0x7F);
    s[35] ^= (unsigned char)((temp >>  1) & 0x7F);
    s[36] ^= (unsigned char)((temp <<  6) & 0x7F);
    s[0]  ^= domain;
}

void wage_get_rate
    (const unsigned char s[WAGE_STATE_SIZE], unsigned char data[8])
{
    uint32_t temp;
    temp  = ((uint32_t)(s[8]))  << 25;
    temp |= ((uint32_t)(s[9]))  << 18;
    temp |= ((uint32_t)(s[15])) << 11;
    temp |= ((uint32_t)(s[16])) << 4;
    temp |= ((uint32_t)(s[18])) >> 3;
    be_store_word32(data, temp);
    temp  = ((uint32_t)(s[18])) << 29;
    temp |= ((uint32_t)(s[27])) << 22;
    temp |= ((uint32_t)(s[28])) << 15;
    temp |= ((uint32_t)(s[34])) << 8;
    temp |= ((uint32_t)(s[35])) << 1;
    temp |= ((uint32_t)(s[36])) >> 6;
    be_store_word32(data + 4, temp);
}

void wage_set_rate
    (unsigned char s[WAGE_STATE_SIZE], const unsigned char data[8],
     unsigned char domain)
{
    uint32_t temp;
    temp = be_load_word32(data);
    s[8]  = (unsigned char)(temp  >> 25);
    s[9]  = (unsigned char)((temp >> 18) & 0x7F);
    s[15] = (unsigned char)((temp >> 11) & 0x7F);
    s[16] = (unsigned char)((temp >>  4) & 0x7F);
    s[18] = (unsigned char)((temp <<  3) & 0x7F);
    temp = be_load_word32(data + 4);
    s[18] ^= (unsigned char)(temp >> 29);
    s[27] = (unsigned char)((temp >> 22) & 0x7F);
    s[28] = (unsigned char)((temp >> 15) & 0x7F);
    s[34] = (unsigned char)((temp >>  8) & 0x7F);
    s[35] = (unsigned char)((temp >>  1) & 0x7F);
    s[36] = (unsigned char)(((temp << 6) & 0x40) ^ (s[36] & 0x3F));
    s[0] ^= domain;
}

/**
 * \brief Converts a 128-bit value into an array of 7-bit components.
 *
 * \param out Points to the output array of 7-bit components.
 * \param in Points to the 128-bit value to convert.
 */
static void wage_128bit_to_components
    (unsigned char out[19], const unsigned char *in)
{
    uint32_t temp;
    temp = be_load_word32(in);
    out[0]  = (unsigned char)(temp  >> 25);
    out[1]  = (unsigned char)((temp >> 18) & 0x7F);
    out[2]  = (unsigned char)((temp >> 11) & 0x7F);
    out[3]  = (unsigned char)((temp >>  4) & 0x7F);
    out[4]  = (unsigned char)((temp <<  3) & 0x7F);
    temp = be_load_word32(in + 4);
    out[4] ^= (unsigned char)(temp >> 29);
    out[5]  = (unsigned char)((temp >> 22) & 0x7F);
    out[6]  = (unsigned char)((temp >> 15) & 0x7F);
    out[7]  = (unsigned char)((temp >>  8) & 0x7F);
    out[8]  = (unsigned char)((temp >>  1) & 0x7F);
    out[18] = (unsigned char)((temp <<  6) & 0x7F);
    temp = be_load_word32(in + 8);
    out[9]  = (unsigned char)(temp  >> 25);
    out[10] = (unsigned char)((temp >> 18) & 0x7F);
    out[11] = (unsigned char)((temp >> 11) & 0x7F);
    out[12] = (unsigned char)((temp >>  4) & 0x7F);
    out[13] = (unsigned char)((temp <<  3) & 0x7F);
    temp = be_load_word32(in + 12);
    out[13] ^= (unsigned char)(temp >> 29);
    out[14] = (unsigned char)((temp >> 22) & 0x7F);
    out[15] = (unsigned char)((temp >> 15) & 0x7F);
    out[16] = (unsigned char)((temp >>  8) & 0x7F);
    out[17] = (unsigned char)((temp >>  1) & 0x7F);
    out[18] ^= (unsigned char)((temp << 5) & 0x20);
}

void wage_absorb_key
    (unsigned char s[WAGE_STATE_SIZE], const unsigned char *key)
{
    unsigned char components[19];
    wage_128bit_to_components(components, key);
    s[8]  ^= components[0];
    s[9]  ^= components[1];
    s[15] ^= components[2];
    s[16] ^= components[3];
    s[18] ^= components[4];
    s[27] ^= components[5];
    s[28] ^= components[6];
    s[34] ^= components[7];
    s[35] ^= components[8];
    s[36] ^= components[18] & 0x40;
    wage_permute(s);
    s[8]  ^= components[9];
    s[9]  ^= components[10];
    s[15] ^= components[11];
    s[16] ^= components[12];
    s[18] ^= components[13];
    s[27] ^= components[14];
    s[28] ^= components[15];
    s[34] ^= components[16];
    s[35] ^= components[17];
    s[36] ^= (components[18] << 1) & 0x40;
    wage_permute(s);
}

void wage_init
    (unsigned char s[WAGE_STATE_SIZE],
     const unsigned char *key, const unsigned char *nonce)
{
    unsigned char components[19];

    /* Initialize the state with the key and nonce */
    wage_128bit_to_components(components, key);
    s[0]  = components[0];
    s[1]  = components[2];
    s[2]  = components[4];
    s[3]  = components[6];
    s[4]  = components[8];
    s[5]  = components[10];
    s[6]  = components[12];
    s[7]  = components[14];
    s[8]  = components[16];
    s[18] = components[18];
    s[19] = components[1];
    s[20] = components[3];
    s[21] = components[5];
    s[22] = components[7];
    s[23] = components[9];
    s[24] = components[11];
    s[25] = components[13];
    s[26] = components[15];
    s[27] = components[17];
    wage_128bit_to_components(components, nonce);
    s[9]  = components[1];
    s[10] = components[3];
    s[11] = components[5];
    s[12] = components[7];
    s[13] = components[9];
    s[14] = components[11];
    s[15] = components[13];
    s[16] = components[17];
    s[17] = components[15];
    s[18] ^= (components[18] >> 2);
    s[28] = components[0];
    s[29] = components[2];
    s[30] = components[4];
    s[31] = components[6];
    s[32] = components[8];
    s[33] = components[10];
    s[34] = components[12];
    s[35] = components[14];
    s[36] = components[16];

    /* Permute the state to absorb the key and nonce */
    wage_permute(s);

    /* Absorb the key again and permute the state */
    wage_absorb_key(s, key);
}

void wage_extract_tag
    (const unsigned char s[WAGE_STATE_SIZE], unsigned char tag[16])
{
    unsigned char components[19];
    uint32_t temp;

    /* Extract the 7-bit components that make up the tag */
    for (temp = 0; temp < 9; ++temp) {
        components[temp * 2]     = s[28 + temp];
        components[temp * 2 + 1] = s[ 9 + temp];
    }
    components[18] = (s[18] << 2) & 0x60;

    /* Convert from 7-bit component form back into bytes */
    temp  = ((uint32_t)(components[0])) << 25;
    temp |= ((uint32_t)(components[1])) << 18;
    temp |= ((uint32_t)(components[2])) << 11;
    temp |= ((uint32_t)(components[3])) << 4;
    temp |= ((uint32_t)(components[4])) >> 3;
    be_store_word32(tag, temp);
    temp  = ((uint32_t)(components[4])) << 29;
    temp |= ((uint32_t)(components[5])) << 22;
    temp |= ((uint32_t)(components[6])) << 15;
    temp |= ((uint32_t)(components[7])) << 8;
    temp |= ((uint32_t)(components[8])) << 1;
    temp |= ((uint32_t)(components[9])) >> 6;
    be_store_word32(tag + 4, temp);
    temp  = ((uint32_t)(components[9]))  << 26;
    temp |= ((uint32_t)(components[10])) << 19;
    temp |= ((uint32_t)(components[11])) << 12;
    temp |= ((uint32_t)(components[12])) << 5;
    temp |= ((uint32_t)(components[13])) >> 2;
    be_store_word32(tag + 8, temp);
    temp  = ((uint32_t)(components[13])) << 30;
    temp |= ((uint32_t)(components[14])) << 23;
    temp |= ((uint32_t)(components[15])) << 16;
    temp |= ((uint32_t)(components[16])) << 9;
    temp |= ((uint32_t)(components[17])) << 2;
    temp |= ((uint32_t)(components[18])) >> 5;
    be_store_word32(tag + 12, temp);
}
