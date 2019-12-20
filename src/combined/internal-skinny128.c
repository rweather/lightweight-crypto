/*
 * Copyright (C) 2019 Southern Storm Software, Pty Ltd.
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

#include "internal-skinny128.h"
#include "internal-util.h"

STATIC_INLINE uint32_t skinny128_LFSR2(uint32_t x)
{
    return ((x << 1) & 0xFEFEFEFEU) ^ (((x >> 7) ^ (x >> 5)) & 0x01010101U);
}

STATIC_INLINE uint32_t skinny128_LFSR3(uint32_t x)
{
    return ((x >> 1) & 0x7F7F7F7FU) ^ (((x << 7) ^ (x << 1)) & 0x80808080U);
}

STATIC_INLINE void skinny128_permute_tk(uint32_t *tk)
{
    /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */
    uint32_t row2 = tk[2];
    uint32_t row3 = tk[3];
    tk[2] = tk[0];
    tk[3] = tk[1];
    row3 = (row3 << 16) | (row3 >> 16);
    tk[0] = ((row2 >>  8) & 0x000000FFU) |
            ((row2 << 16) & 0x00FF0000U) |
            ( row3        & 0xFF00FF00U);
    tk[1] = ((row2 >> 16) & 0x000000FFU) |
             (row2        & 0xFF000000U) |
            ((row3 <<  8) & 0x0000FF00U) |
            ( row3        & 0x00FF0000U);
}

STATIC_INLINE void skinny128_inv_permute_tk(uint32_t *tk)
{
    /* PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1] */
    uint32_t row0 = tk[0];
    uint32_t row1 = tk[1];
    tk[0] = tk[2];
    tk[1] = tk[3];
    tk[2] = ((row0 >> 16) & 0x000000FFU) |
            ((row0 <<  8) & 0x0000FF00U) |
            ((row1 << 16) & 0x00FF0000U) |
            ( row1        & 0xFF000000U);
    tk[3] = ((row0 >> 16) & 0x0000FF00U) |
            ((row0 << 16) & 0xFF000000U) |
            ((row1 >> 16) & 0x000000FFU) |
            ((row1 <<  8) & 0x00FF0000U);
}

STATIC_INLINE void skinny128_fast_forward_tk(uint32_t *tk)
{
    /* This function is used to fast-forward the TK1 tweak value
     * to the value at the end of the key schedule for decryption.
     *
     * The tweak permutation repeats every 16 rounds, so SKINNY-128-256
     * with 48 rounds does not need any fast forwarding applied.
     * SKINNY-128-128 with 40 rounds and SKINNY-128-384 with 56 rounds
     * are equivalent to applying the permutation 8 times:
     *
     * PT*8 = [5, 6, 3, 2, 7, 0, 1, 4, 13, 14, 11, 10, 15, 8, 9, 12]
     */
    uint32_t row0 = tk[0];
    uint32_t row1 = tk[1];
    uint32_t row2 = tk[2];
    uint32_t row3 = tk[3];
    tk[0] = ((row1 >>  8) & 0x0000FFFFU) |
            ((row0 >>  8) & 0x00FF0000U) |
            ((row0 <<  8) & 0xFF000000U);
    tk[1] = ((row1 >> 24) & 0x000000FFU) |
            ((row0 <<  8) & 0x00FFFF00U) |
            ((row1 << 24) & 0xFF000000U);
    tk[2] = ((row3 >>  8) & 0x0000FFFFU) |
            ((row2 >>  8) & 0x00FF0000U) |
            ((row2 <<  8) & 0xFF000000U);
    tk[3] = ((row3 >> 24) & 0x000000FFU) |
            ((row2 <<  8) & 0x00FFFF00U) |
            ((row3 << 24) & 0xFF000000U);
}

STATIC_INLINE uint32_t skinny128_sbox(uint32_t x)
{
    /* Original version from the specification is equivalent to:
     *
     * #define SBOX_MIX(x)
     *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
     * #define SBOX_SWAP(x)
     *     (((x) & 0xF9F9F9F9U) |
     *     (((x) >> 1) & 0x02020202U) |
     *     (((x) << 1) & 0x04040404U))
     * #define SBOX_PERMUTE(x)
     *     ((((x) & 0x01010101U) << 2) |
     *      (((x) & 0x06060606U) << 5) |
     *      (((x) & 0x20202020U) >> 5) |
     *      (((x) & 0xC8C8C8C8U) >> 2) |
     *      (((x) & 0x10101010U) >> 1))
     *
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE(x);
     * x = SBOX_MIX(x);
     * return SBOX_SWAP(x);
     *
     * However, we can mix the bits in their original positions and then
     * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
     * final permuatation.  This reduces the number of shift operations.
     */
    uint32_t y;

    /* Mix the bits */
    x = ~x;
    x ^= (((x >> 2) & (x >> 3)) & 0x11111111U);
    y  = (((x << 5) & (x << 1)) & 0x20202020U);
    x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x80808080U);
    x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y;
    y  = (((x >> 5) & (x << 1)) & 0x04040404U);
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
    x = ~x;

    /* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [2 7 6 1 3 0 4 5] */
    return ((x & 0x08080808U) << 1) |
           ((x & 0x32323232U) << 2) |
           ((x & 0x01010101U) << 5) |
           ((x & 0x80808080U) >> 6) |
           ((x & 0x40404040U) >> 4) |
           ((x & 0x04040404U) >> 2);
}

STATIC_INLINE uint32_t skinny128_inv_sbox(uint32_t x)
{
    /* Original version from the specification is equivalent to:
     *
     * #define SBOX_MIX(x)
     *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
     * #define SBOX_SWAP(x)
     *     (((x) & 0xF9F9F9F9U) |
     *     (((x) >> 1) & 0x02020202U) |
     *     (((x) << 1) & 0x04040404U))
     * #define SBOX_PERMUTE_INV(x)
     *     ((((x) & 0x08080808U) << 1) |
     *      (((x) & 0x32323232U) << 2) |
     *      (((x) & 0x01010101U) << 5) |
     *      (((x) & 0xC0C0C0C0U) >> 5) |
     *      (((x) & 0x04040404U) >> 2))
     *
     * x = SBOX_SWAP(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * x = SBOX_MIX(x);
     * x = SBOX_PERMUTE_INV(x);
     * return SBOX_MIX(x);
     *
     * However, we can mix the bits in their original positions and then
     * delay the SBOX_PERMUTE_INV and SBOX_SWAP steps to be performed with one
     * final permuatation.  This reduces the number of shift operations.
     */
    uint32_t y;

    /* Mix the bits */
    x = ~x;
    y  = (((x >> 1) & (x >> 3)) & 0x01010101U);
    x ^= (((x >> 2) & (x >> 3)) & 0x10101010U) ^ y;
    y  = (((x >> 6) & (x >> 1)) & 0x02020202U);
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y;
    y  = (((x << 2) & (x << 1)) & 0x80808080U);
    x ^= (((x >> 1) & (x << 2)) & 0x04040404U) ^ y;
    y  = (((x << 5) & (x << 1)) & 0x20202020U);
    x ^= (((x << 4) & (x << 5)) & 0x40404040U) ^ y;
    x = ~x;

    /* Permutation generated by http://programming.sirrida.de/calcperm.php
       The final permutation for each byte is [5 3 0 4 6 7 2 1] */
    return ((x & 0x01010101U) << 2) |
           ((x & 0x04040404U) << 4) |
           ((x & 0x02020202U) << 6) |
           ((x & 0x20202020U) >> 5) |
           ((x & 0xC8C8C8C8U) >> 2) |
           ((x & 0x10101010U) >> 1);
}

STATIC_INLINE uint32_t skinny128_rotate_right(uint32_t x, unsigned count)
{
    /* Note: we are rotating the cells right, which actually moves
       the values up closer to the MSB.  That is, we do a left shift
       on the word to rotate the cells in the word right */
    return (x << count) | (x >> (32 - count));
}

int skinny_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char *key,
     size_t key_len)
{
    int tweaked = (key_len == 32);
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;

    /* Validate the parameters */
    if (!ks || !key || (key_len != 32 && key_len != 48))
        return 0;

    /* Set the initial states of TK1, TK2, and TK3 */
    if (tweaked) {
        ks->TK1[0] = 0;
        ks->TK1[1] = 0;
        ks->TK1[2] = 0;
        ks->TK1[3] = 0;
        TK2[0] = le_load_word32(key);
        TK2[1] = le_load_word32(key + 4);
        TK2[2] = le_load_word32(key + 8);
        TK2[3] = le_load_word32(key + 12);
        TK3[0] = le_load_word32(key + 16);
        TK3[1] = le_load_word32(key + 20);
        TK3[2] = le_load_word32(key + 24);
        TK3[3] = le_load_word32(key + 28);
    } else {
        ks->TK1[0] = le_load_word32(key);
        ks->TK1[1] = le_load_word32(key + 4);
        ks->TK1[2] = le_load_word32(key + 8);
        ks->TK1[3] = le_load_word32(key + 12);
        TK2[0] = le_load_word32(key + 16);
        TK2[1] = le_load_word32(key + 20);
        TK2[2] = le_load_word32(key + 24);
        TK2[3] = le_load_word32(key + 28);
        TK3[0] = le_load_word32(key + 32);
        TK3[1] = le_load_word32(key + 36);
        TK3[2] = le_load_word32(key + 40);
        TK3[3] = le_load_word32(key + 44);
    }

    /* Set up the key schedule using TK2 and TK3.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule += 2) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ TK3[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ TK3[1] ^ (rc >> 4);

        /* If we have a tweak, then we need to XOR a 1 bit into the
         * second bit of the top cell of the third column as recommended
         * by the SKINNY specification. */
        if (tweaked)
            schedule[0] ^= 0x00020000;

        /* Permute TK2 and TK3 for the next round */
        skinny128_permute_tk(TK2);
        skinny128_permute_tk(TK3);

        /* Apply the LFSR's to TK2 and TK3 */
        TK2[0] = skinny128_LFSR2(TK2[0]);
        TK2[1] = skinny128_LFSR2(TK2[1]);
        TK3[0] = skinny128_LFSR3(TK3[0]);
        TK3[1] = skinny128_LFSR3(TK3[1]);
    }
    return 1;
}

int skinny_128_384_set_tweak
    (skinny_128_384_key_schedule_t *ks, const unsigned char *tweak,
     size_t tweak_len)
{
    /* Validate the parameters */
    if (!ks || !tweak || tweak_len != 16)
        return 0;

    /* Set TK1 directly from the tweak value */
    ks->TK1[0] = le_load_word32(tweak);
    ks->TK1[1] = le_load_word32(tweak + 4);
    ks->TK1[2] = le_load_word32(tweak + 8);
    ks->TK1[3] = le_load_word32(tweak + 12);
    return 1;
}

void skinny_128_384_encrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = ks->TK1[0];
    TK1[1] = ks->TK1[1];
    TK1[2] = ks->TK1[2];
    TK1[3] = ks->TK1[3];

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        s0 = skinny128_sbox(s0);
        s1 = skinny128_sbox(s1);
        s2 = skinny128_sbox(s2);
        s3 = skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 for the next round */
        skinny128_permute_tk(TK1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_384_decrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = ks->TK1[0];
    TK1[1] = ks->TK1[1];
    TK1[2] = ks->TK1[2];
    TK1[3] = ks->TK1[3];

    /* Permute TK1 to fast-forward it to the end of the key schedule */
    skinny128_fast_forward_tk(TK1);

    /* Perform all decryption rounds */
    schedule = &(ks->k[SKINNY_128_384_ROUNDS * 2 - 2]);
    for (round = 0; round < SKINNY_128_384_ROUNDS; ++round, schedule -= 2) {
        /* Inverse permutation on TK1 for this round */
        skinny128_inv_permute_tk(TK1);

        /* Inverse mix of the columns */
        temp = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s3 ^= temp;
        s2 = temp ^ s0;
        s1 ^= s2;

        /* Inverse shift of the rows */
        s1 = leftRotate24(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate8(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        s0 = skinny128_inv_sbox(s0);
        s1 = skinny128_inv_sbox(s1);
        s2 = skinny128_inv_sbox(s2);
        s3 = skinny128_inv_sbox(s3);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

int skinny_128_256_init
    (skinny_128_256_key_schedule_t *ks, const unsigned char *key,
     size_t key_len)
{
    int tweaked = (key_len == 16);
    uint32_t TK2[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;

    /* Validate the parameters */
    if (!ks || !key || (key_len != 16 && key_len != 32))
        return 0;

    /* Set the initial states of TK1 and TK2 */
    if (tweaked) {
        ks->TK1[0] = 0;
        ks->TK1[1] = 0;
        ks->TK1[2] = 0;
        ks->TK1[3] = 0;
        TK2[0] = le_load_word32(key);
        TK2[1] = le_load_word32(key + 4);
        TK2[2] = le_load_word32(key + 8);
        TK2[3] = le_load_word32(key + 12);
    } else {
        ks->TK1[0] = le_load_word32(key);
        ks->TK1[1] = le_load_word32(key + 4);
        ks->TK1[2] = le_load_word32(key + 8);
        ks->TK1[3] = le_load_word32(key + 12);
        TK2[0] = le_load_word32(key + 16);
        TK2[1] = le_load_word32(key + 20);
        TK2[2] = le_load_word32(key + 24);
        TK2[3] = le_load_word32(key + 28);
    }

    /* Set up the key schedule using TK2.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round, schedule += 2) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ (rc >> 4);

        /* If we have a tweak, then we need to XOR a 1 bit into the
         * second bit of the top cell of the third column as recommended
         * by the SKINNY specification. */
        if (tweaked)
            schedule[0] ^= 0x00020000;

        /* Permute TK2 for the next round */
        skinny128_permute_tk(TK2);

        /* Apply the LFSR to TK2 */
        TK2[0] = skinny128_LFSR2(TK2[0]);
        TK2[1] = skinny128_LFSR2(TK2[1]);
    }
    return 1;
}

int skinny_128_256_set_tweak
    (skinny_128_256_key_schedule_t *ks, const unsigned char *tweak,
     size_t tweak_len)
{
    /* Validate the parameters */
    if (!ks || !tweak || tweak_len != 16)
        return 0;

    /* Set TK1 directly from the tweak value */
    ks->TK1[0] = le_load_word32(tweak);
    ks->TK1[1] = le_load_word32(tweak + 4);
    ks->TK1[2] = le_load_word32(tweak + 8);
    ks->TK1[3] = le_load_word32(tweak + 12);
    return 1;
}

void skinny_128_256_encrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = ks->TK1[0];
    TK1[1] = ks->TK1[1];
    TK1[2] = ks->TK1[2];
    TK1[3] = ks->TK1[3];

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        s0 = skinny128_sbox(s0);
        s1 = skinny128_sbox(s1);
        s2 = skinny128_sbox(s2);
        s3 = skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 for the next round */
        skinny128_permute_tk(TK1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_256_decrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    const uint32_t *schedule;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1.
     * There is no need to fast-forward TK1 because the value at
     * the end of the key schedule is the same as at the start */
    TK1[0] = ks->TK1[0];
    TK1[1] = ks->TK1[1];
    TK1[2] = ks->TK1[2];
    TK1[3] = ks->TK1[3];

    /* Perform all decryption rounds */
    schedule = &(ks->k[SKINNY_128_256_ROUNDS * 2 - 2]);
    for (round = 0; round < SKINNY_128_256_ROUNDS; ++round, schedule -= 2) {
        /* Inverse permutation on TK1 for this round */
        skinny128_inv_permute_tk(TK1);

        /* Inverse mix of the columns */
        temp = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s3 ^= temp;
        s2 = temp ^ s0;
        s1 ^= s2;

        /* Inverse shift of the rows */
        s1 = leftRotate24(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate8(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0] ^ TK1[0];
        s1 ^= schedule[1] ^ TK1[1];
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        s0 = skinny128_inv_sbox(s0);
        s1 = skinny128_inv_sbox(s1);
        s2 = skinny128_inv_sbox(s2);
        s3 = skinny128_inv_sbox(s3);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

int skinny_128_128_init
    (skinny_128_128_key_schedule_t *ks, const unsigned char *key,
     size_t key_len)
{
    uint32_t TK1[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;

    /* Validate the parameters */
    if (!ks || !key || key_len != 16)
        return 0;

    /* Set the initial state of TK1 */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);

    /* Set up the key schedule using TK1 */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_128_ROUNDS; ++round, schedule += 2) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK1[0] ^ (rc & 0x0F);
        schedule[1] = TK1[1] ^ (rc >> 4);

        /* Permute TK1 for the next round */
        skinny128_permute_tk(TK1);
    }
    return 1;
}

void skinny_128_128_encrypt
    (const skinny_128_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    const uint32_t *schedule = ks->k;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Perform all encryption rounds */
    for (round = 0; round < SKINNY_128_128_ROUNDS; ++round, schedule += 2) {
        /* Apply the S-box to all bytes in the state */
        s0 = skinny128_sbox(s0);
        s1 = skinny128_sbox(s1);
        s2 = skinny128_sbox(s2);
        s3 = skinny128_sbox(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0];
        s1 ^= schedule[1];
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_128_decrypt
    (const skinny_128_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    const uint32_t *schedule;
    uint32_t temp;
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Perform all decryption rounds */
    schedule = &(ks->k[SKINNY_128_128_ROUNDS * 2 - 2]);
    for (round = 0; round < SKINNY_128_128_ROUNDS; ++round, schedule -= 2) {
        /* Inverse mix of the columns */
        temp = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s3 ^= temp;
        s2 = temp ^ s0;
        s1 ^= s2;

        /* Inverse shift of the rows */
        s1 = leftRotate24(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate8(s3);

        /* Apply the subkey for this round */
        s0 ^= schedule[0];
        s1 ^= schedule[1];
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all bytes in the state */
        s0 = skinny128_inv_sbox(s0);
        s1 = skinny128_inv_sbox(s1);
        s2 = skinny128_inv_sbox(s2);
        s3 = skinny128_inv_sbox(s3);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}
