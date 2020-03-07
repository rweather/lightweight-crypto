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

#include "internal-gift64.h"
#include "internal-util.h"
#include <string.h>

/* Round constants for GIFT-64 in the fixsliced representation */
static uint32_t const GIFT64_RC[28] = {
    0x22000011, 0x00002299, 0x11118811, 0x880000ff, 0x33111199, 0x990022ee,
    0x22119933, 0x880033bb, 0x22119999, 0x880022ff, 0x11119922, 0x880033cc,
    0x33008899, 0x99002299, 0x33118811, 0x880000ee, 0x33110099, 0x990022aa,
    0x22118833, 0x880022bb, 0x22111188, 0x88002266, 0x00009922, 0x88003300,
    0x22008811, 0x00002288, 0x00118811, 0x880000bb
};

int gift64b_init
    (gift64b_key_schedule_t *ks, const unsigned char *key, size_t key_len)
{
    if (!ks || !key || key_len != 16)
        return 0;
    ks->k[0] = be_load_word32(key);
    ks->k[1] = be_load_word32(key + 4);
    ks->k[2] = be_load_word32(key + 8);
    ks->k[3] = be_load_word32(key + 12);
    gift64b_update_round_keys(ks);
    return 1;
}

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/**
 * \brief Swaps bits within two words.
 *
 * \param a The first word.
 * \param b The second word.
 * \param mask Mask for the bits to shift.
 * \param shift Shift amount in bits.
 */
#define gift64b_swap_move(a, b, mask, shift) \
    do { \
        uint32_t t = ((b) ^ ((a) >> (shift))) & (mask); \
        (b) ^= t; \
        (a) ^= t << (shift); \
    } while (0)

/**
 * \brief Performs the GIFT-64 S-box on the bit-sliced state.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift64b_sbox(s0, s1, s2, s3) \
    do { \
        s1 ^= s0 & s2; \
        s0 ^= s1 & s3; \
        s2 ^= s0 | s1; \
        s3 ^= s2; \
        s1 ^= s3; \
        s2 ^= s0 & s1; \
    } while (0)

/**
 * \brief Performs the inverse of the GIFT-64 S-box on the bit-sliced state.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift64b_inv_sbox(s0, s1, s2, s3) \
    do { \
        s2 ^= s3 & s1; \
        s1 ^= s0; \
        s0 ^= s2; \
        s2 ^= s3 | s1; \
        s3 ^= s1 & s0; \
        s1 ^= s3 & s2; \
    } while (0)

/* Rotates a state word left by 1 position in the fixsliced representation:
 *
 *  0  1  2  3               1  2  3  0
 *  4  5  6  7      ==>      5  6  7  4
 *  8  9 10 11               9 10 11  8
 * 12 13 14 15              13 14 14 12
 */
#define gift64b_rotate_left_1(x) \
    ((((x) >> 1) & 0x77777777U) | (((x) & 0x11111111U) << 3))

/* Rotates a state word left by 2 positions in the fixsliced representation:
 *
 *  0  1  2  3               2  3  0  1
 *  4  5  6  7      ==>      6  7  4  5
 *  8  9 10 11              10 11  8  9
 * 12 13 14 15              14 15 12 13
 */
#define gift64b_rotate_left_2(x) \
    ((((x) >> 2) & 0x33333333U) | (((x) & 0x33333333U) << 2))

/* Rotates a state word left by 3 positions in the fixsliced representation:
 *
 *  0  1  2  3               3  0  1  2
 *  4  5  6  7      ==>      7  4  5  6
 *  8  9 10 11              11  8  9 10
 * 12 13 14 15              15 12 13 14
 */
#define gift64b_rotate_left_3(x) \
    ((((x) >> 3) & 0x11111111U) | (((x) & 0x77777777U) << 1))

/* Rotates a state word right by 1 position in the fixsliced representation */
#define gift64b_rotate_right_1(x) gift64b_rotate_left_3(x)

/* Rotates a state word right by 2 positions in the fixsliced representation */
#define gift64b_rotate_right_2(x) gift64b_rotate_left_2(x)

/* Rotates a state word right by 3 positions in the fixsliced representation */
#define gift64b_rotate_right_3(x) gift64b_rotate_left_1(x)

/* Rotates a state word up by 1 position in the fixsliced representation:
 *
 *  0  1  2  3               4  5  6  7
 *  4  5  6  7      ==>      8  9 10 11
 *  8  9 10 11              12 13 14 15
 * 12 13 14 15               0  1  2  3
 */
#define gift64b_rotate_up_1(x) (rightRotate8((x)))

/* Rotates a state word up by 2 positions in the fixsliced representation:
 *
 *  0  1  2  3               8  9 10 11
 *  4  5  6  7      ==>     12 13 14 15
 *  8  9 10 11               0  1  2  3
 * 12 13 14 15               4  5  6  7
 */
#define gift64b_rotate_up_2(x) (rightRotate16((x)))

/* Rotates a state word up by 3 positions in the fixsliced representation:
 *
 *  0  1  2  3              12 13 14 15
 *  4  5  6  7      ==>      0  1  2  3
 *  8  9 10 11               4  5  6  7
 * 12 13 14 15               8  9 10 11
 */
#define gift64b_rotate_up_3(x) (rightRotate24((x)))

/* Rotates a state word down by 1 position in the fixsliced representation */
#define gift64b_rotate_down_1(x) gift64b_rotate_up_3(x)

/* Rotates a state word down by 2 positions in the fixsliced representation */
#define gift64b_rotate_down_2(x) gift64b_rotate_up_2(x)

/* Rotates a state word down by 3 positions in the fixsliced representation */
#define gift64b_rotate_down_3(x) gift64b_rotate_up_1(x)

/* Permutation code to rearrange key bits into fixsliced form.  Permutations
 * generated wth "http://programming.sirrida.de/calcperm.php" */
#define gift64b_rearrange1_transpose_low(out, in) \
    do { \
        out = (in) & 0x0000FFFFU; \
        /* 0 8 16 24 3 11 19 27 2 10 18 26 1 9 17 25 * */ \
        bit_permute_step(out, 0x0000CCCCU, 16); \
        bit_permute_step(out, 0x30030330U, 2); \
        bit_permute_step(out, 0x00960096U, 8); \
        bit_permute_step(out, 0x05500550U, 1); \
        bit_permute_step(out, 0x0A0A0A0AU, 4); \
    } while (0)
#define gift64b_rearrange1_transpose_high(out, in) \
    do { \
        out = (in) >> 16; \
        /* 0 8 16 24 3 11 19 27 2 10 18 26 1 9 17 25 * */ \
        bit_permute_step(out, 0x0000CCCCU, 16); \
        bit_permute_step(out, 0x30030330U, 2); \
        bit_permute_step(out, 0x00960096U, 8); \
        bit_permute_step(out, 0x05500550U, 1); \
        bit_permute_step(out, 0x0A0A0A0AU, 4); \
    } while (0)
#define gift64b_rearrange1_low(out, in) \
    do { \
        out = (in) & 0x0000FFFFU; \
        /* 0 1 2 3 24 25 26 27 16 17 18 19 8 9 10 11 * */ \
        out = (out & 0x0000000FU)        | ((out & 0x00000F00U) << 8) | \
             ((out & 0x000000F0U) << 20) | ((out & 0x0000F000U) >> 4); \
    } while (0)
#define gift64b_rearrange1_high(out, in) \
    do { \
        out = (in) >> 16; \
        /* 0 1 2 3 24 25 26 27 16 17 18 19 8 9 10 11 * */ \
        out = (out & 0x0000000FU)        | ((out & 0x00000F00U) << 8) | \
             ((out & 0x000000F0U) << 20) | ((out & 0x0000F000U) >> 4); \
    } while (0)
#define gift64b_rearrange2_transpose_low(out, in) \
    do { \
        out = (in) & 0x0000FFFFU; \
        /* 0 8 16 24 1 9 17 25 2 10 18 26 3 11 19 27 * */ \
        bit_permute_step(out, 0x0A0A0A0AU, 3); \
        bit_permute_step(out, 0x00CC00CCU, 6); \
        bit_permute_step(out, 0x0000F0F0U, 12); \
        bit_permute_step(out, 0x0000FF00U, 8); \
    } while (0)
#define gift64b_rearrange2_transpose_high(out, in) \
    do { \
        out = (in) >> 16; \
        /* 0 8 16 24 1 9 17 25 2 10 18 26 3 11 19 27 * */ \
        bit_permute_step(out, 0x0A0A0A0AU, 3); \
        bit_permute_step(out, 0x00CC00CCU, 6); \
        bit_permute_step(out, 0x0000F0F0U, 12); \
        bit_permute_step(out, 0x0000FF00U, 8); \
    } while (0)
#define gift64b_rearrange2_low(out, in) \
    do { \
        out = (in) & 0x0000FFFFU; \
        /* 0 1 2 3 8 9 10 11 16 17 18 19 24 25 26 27 * */ \
        out = (out & 0x0000000FU)       | ((out & 0x000000F0U) << 4) | \
             ((out & 0x00000F00U) << 8) | ((out & 0x0000F000U) << 12); \
    } while (0)
#define gift64b_rearrange2_high(out, in) \
    do { \
        out = (in) >> 16; \
        /* 0 1 2 3 8 9 10 11 16 17 18 19 24 25 26 27 * */ \
        out = (out & 0x0000000FU)       | ((out & 0x000000F0U) << 4) | \
             ((out & 0x00000F00U) << 8) | ((out & 0x0000F000U) << 12); \
    } while (0)

void gift64b_update_round_keys(gift64b_key_schedule_t *ks)
{
    uint32_t x;

    /* First round */
    gift64b_rearrange1_transpose_low(x, ks->k[3]);
    ks->rk[0] = ~(x | (x << 4));
    gift64b_rearrange1_transpose_high(x, ks->k[3]);
    ks->rk[1] = x | (x << 4);

    /* Second round */
    gift64b_rearrange1_low(x, ks->k[2]);
    x = x | (x << 4);
    gift64b_swap_move(x, x, 0x22222222U, 2);
    ks->rk[2] = ~x;
    gift64b_rearrange1_high(x, ks->k[2]);
    x = x | (x << 4);
    gift64b_swap_move(x, x, 0x22222222U, 2);
    ks->rk[3] = x;

    /* Third round */
    gift64b_rearrange2_transpose_low(x, ks->k[1]);
    gift64b_swap_move(x, x, 0x00000F00U, 16);
    ks->rk[4] = ~(x | (x << 4));
    gift64b_rearrange2_transpose_high(x, ks->k[1]);
    gift64b_swap_move(x, x, 0x00000F00U, 16);
    ks->rk[5] = x | (x << 4);

    /* Fourth round */
    gift64b_rearrange2_low(x, ks->k[0]);
    ks->rk[6] = ~(x | (x << 4));
    gift64b_rearrange2_high(x, ks->k[0]);
    ks->rk[7] = x | (x << 4);
}

/**
 * \brief Perform the core of GIFT-64 encryption on two blocks in parallel.
 *
 * \param ks Points to the key schedule to use to encrypt the blocks.
 * \param state Buffer containing the two blocks in bit-sliced form,
 * on input and output.
 * \param Tweak value or zero if there is no tweak.
 */
static void gift64b_encrypt_core
    (const gift64b_key_schedule_t *ks, uint32_t state[4], uint32_t tweak)
{
    const uint32_t *rc = GIFT64_RC;
    uint32_t s0, s1, s2, s3, temp;
    uint32_t rk[8];
    uint8_t round;

    /* Start with the pre-computed round keys for the first four rounds */
    memcpy(rk, ks->rk, sizeof(ks->rk));

    /* Load the state into local variables */
    s0 = state[0];
    s1 = state[1];
    s2 = state[2];
    s3 = state[3];

    /* Perform all 28 rounds four at a time.  We use the "fixslicing" method.
     *
     * The permutation is restructured so that one of the words each round
     * does not need to be permuted, with the others rotating left, up, right,
     * and down to keep the bits in line with their non-moving counterparts.
     * This reduces the number of shifts required significantly.
     *
     * At the end of four rounds, the bit ordering will return to the
     * original position.  We then repeat the process for the next 4 rounds.
     */
    for (round = 0; round < 28; round += 4, rc += 4) {
        /* 1st round - S-box, rotate left, add round key */
        gift64b_sbox(s0, s1, s2, s3);
        s1 = gift64b_rotate_left_1(s1);
        s2 = gift64b_rotate_left_2(s2);
        s0 = gift64b_rotate_left_3(s0);
        s3 ^= rk[0];
        s1 ^= rk[1];
        s0 ^= rc[0];

        /* 2nd round - S-box, rotate up, add round key (s0 and s3 swapped) */
        gift64b_sbox(s3, s1, s2, s0);
        s1 = gift64b_rotate_up_1(s1);
        s2 = gift64b_rotate_up_2(s2);
        s3 = gift64b_rotate_up_3(s3);
        s0 ^= rk[2];
        s1 ^= rk[3];
        s3 ^= rc[1];

        /* 3rd round - S-box, rotate right, add round key */
        gift64b_sbox(s0, s1, s2, s3);
        s1 = gift64b_rotate_right_1(s1);
        s2 = gift64b_rotate_right_2(s2);
        s0 = gift64b_rotate_right_3(s0);
        s3 ^= rk[4];
        s1 ^= rk[5];
        s0 ^= rc[2];

        /* 4th round - S-box, rotate down, add round key (s0 and s3 swapped) */
        gift64b_sbox(s3, s1, s2, s0);
        s1 = gift64b_rotate_down_1(s1);
        s2 = gift64b_rotate_down_2(s2);
        s3 = gift64b_rotate_down_3(s3);
        s0 ^= rk[6];
        s1 ^= rk[7];
        s3 ^= rc[3];

        /* Add the tweak every four encryption rounds except the last */
        if (round < 24)
            s2 ^= tweak;

        /* Derive the round keys for the next 4 rounds */
        rk[0] = gift64b_rotate_left_1(rk[0]);
        rk[1] = (gift64b_rotate_left_3(rk[1]) << 16) | (rk[1] >> 16);
        rk[2] = rightRotate8(rk[2]);
        temp = gift64b_rotate_left_2(rk[3]);
        rk[3] = (temp & 0x99999999U) | leftRotate8(temp & 0x66666666U);
        rk[4] = gift64b_rotate_left_3(rk[4]);
        temp = rightRotate16(rk[5]);
        rk[5] = (gift64b_rotate_left_1(temp) & 0x00FFFF00U) |
                (temp & 0xFF0000FFU);
        rk[6] = leftRotate8(rk[6]);
        temp = gift64b_rotate_left_2(rk[7]);
        rk[7] = (temp & 0x33333333U) | rightRotate8(temp & 0xCCCCCCCCU);
    }

    /* Copy the local variables to the output state */
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
}

/**
 * \brief Perform the core of GIFT-64 decryption on two blocks in parallel.
 *
 * \param ks Points to the key schedule to use to encrypt the blocks.
 * \param state Buffer containing the two blocks in bit-sliced form,
 * on input and output.
 * \param Tweak value or zero if there is no tweak.
 */
static void gift64b_decrypt_core
    (const gift64b_key_schedule_t *ks, uint32_t state[4], uint32_t tweak)
{
    const uint32_t *rc = GIFT64_RC + 28 - 4;
    uint32_t s0, s1, s2, s3, temp;
    uint32_t rk[8];
    uint8_t round;

    /* Start with the pre-computed round keys for the first four rounds */
    memcpy(rk, ks->rk, sizeof(ks->rk));

    /* Fast forward the key schedule to the end by permuting each round
     * key by the amount it would see under the full set of rounds.
     * Generated with "http://programming.sirrida.de/calcperm.php" */
    /* P0: 1 2 3 0 5 6 7 4 9 10 11 8 13 14 15 12 17 18
     *     19 16 21 22 23 20 25 26 27 24 29 30 31 28 */
    rk[0] = ((rk[0] & 0x77777777U) << 1) | ((rk[0] & 0x88888888U) >> 3);
    /* P1: 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30
     *     31 3 0 1 2 7 4 5 6 11 8 9 10 15 12 13 14 */
    rk[1] = ((rk[1] & 0xEEEE0000U) >> 17) | ((rk[1] & 0x0000FFFFU) << 16) |
            ((rk[1] & 0x11110000U) >> 13);
    /* P2: 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23
     *     24 25 26 27 28 29 30 31 0 1 2 3 4 5 6 7 */
    rk[2] = leftRotate8(rk[2]);
    /* P3: 2 27 24 1 6 31 28 5 10 3 0 9 14 7 4 13 18 11
     *     8 17 22 15 12 21 26 19 16 25 30 23 20 29 */
    rk[3] = ((rk[3] & 0x11111111U) << 2) | leftRotate22(rk[3] & 0x44444444U) |
            leftRotate26(rk[3] & 0x22222222U) | ((rk[3] & 0x88888888U) >> 2);
    /* P4: 3 0 1 2 7 4 5 6 11 8 9 10 15 12 13 14 19 16
     *     17 18 23 20 21 22 27 24 25 26 31 28 29 30 */
    rk[4] = ((rk[4] & 0x11111111U) << 3) | ((rk[4] & 0xEEEEEEEEU) >> 1);
    /* P5: 16 17 18 19 20 21 22 23 25 26 27 24 29 30 31
     *     28 1 2 3 0 5 6 7 4 8 9 10 11 12 13 14 15 */
    rk[5] = leftRotate13(rk[5] & 0x00888800U) |
            leftRotate16(rk[5] & 0xFF0000FFU) |
            leftRotate17(rk[5] & 0x00777700U);
    /* P6: 24 25 26 27 28 29 30 31 0 1 2 3 4 5 6 7 8 9 10
     *     11 12 13 14 15 16 17 18 19 20 21 22 23 */
    rk[6] = leftRotate24(rk[6]);
    /* P7: 2 3 8 9 6 7 12 13 10 11 16 17 14 15 20 21 18 19
     *     24 25 22 23 28 29 26 27 0 1 30 31 4 5 */
    rk[7] = ((rk[7] & 0x33333333U) << 2) | leftRotate6(rk[7] & 0xCCCCCCCCU);

    /* Load the state into local variables */
    s0 = state[0];
    s1 = state[1];
    s2 = state[2];
    s3 = state[3];

    /* Perform all 28 rounds four at a time.  We use the "fixslicing" method.
     *
     * The permutation is restructured so that one of the words each round
     * does not need to be permuted, with the others rotating left, up, right,
     * and down to keep the bits in line with their non-moving counterparts.
     * This reduces the number of shifts required significantly.
     *
     * At the end of four rounds, the bit ordering will return to the
     * original position.  We then repeat the process for the next 4 rounds.
     */
    for (round = 0; round < 28; round += 4, rc -= 4) {
        /* Derive the round keys for the previous 4 rounds */
        rk[0] = gift64b_rotate_right_1(rk[0]);
        temp = rk[1] >> 16;
        rk[1] = gift64b_rotate_right_3(temp) | (rk[1] << 16);
        rk[2] = leftRotate8(rk[2]);
        temp = (rk[3] & 0x99999999U) | rightRotate8(rk[3] & 0x66666666U);
        rk[3] = gift64b_rotate_right_2(temp);
        rk[4] = gift64b_rotate_right_3(rk[4]);
        temp = (gift64b_rotate_right_1(rk[5]) & 0x00FFFF00U) |
                (rk[5] & 0xFF0000FFU);
        rk[5] = leftRotate16(temp);
        rk[6] = rightRotate8(rk[6]);
        temp = (rk[7] & 0x33333333U) | leftRotate8(rk[7] & 0xCCCCCCCCU);
        rk[7] = gift64b_rotate_right_2(temp);

        /* Add the tweak every four decryption rounds except the first */
        if (round != 0)
            s2 ^= tweak;

        /* 4th round - S-box, rotate down, add round key (s0 and s3 swapped) */
        s0 ^= rk[6];
        s1 ^= rk[7];
        s3 ^= rc[3];
        s1 = gift64b_rotate_up_1(s1);
        s2 = gift64b_rotate_up_2(s2);
        s3 = gift64b_rotate_up_3(s3);
        gift64b_inv_sbox(s0, s1, s2, s3);

        /* 3rd round - S-box, rotate right, add round key */
        s3 ^= rk[4];
        s1 ^= rk[5];
        s0 ^= rc[2];
        s1 = gift64b_rotate_left_1(s1);
        s2 = gift64b_rotate_left_2(s2);
        s0 = gift64b_rotate_left_3(s0);
        gift64b_inv_sbox(s3, s1, s2, s0);

        /* 2nd round - S-box, rotate up, add round key (s0 and s3 swapped) */
        s0 ^= rk[2];
        s1 ^= rk[3];
        s3 ^= rc[1];
        s1 = gift64b_rotate_down_1(s1);
        s2 = gift64b_rotate_down_2(s2);
        s3 = gift64b_rotate_down_3(s3);
        gift64b_inv_sbox(s0, s1, s2, s3);

        /* 1st round - S-box, rotate left, add round key */
        s3 ^= rk[0];
        s1 ^= rk[1];
        s0 ^= rc[0];
        s1 = gift64b_rotate_right_1(s1);
        s2 = gift64b_rotate_right_2(s2);
        s0 = gift64b_rotate_right_3(s0);
        gift64b_inv_sbox(s3, s1, s2, s0);
    }

    /* Copy the local variables to the output state */
    state[0] = s0;
    state[1] = s1;
    state[2] = s2;
    state[3] = s3;
}

int gift64n_init
    (gift64n_key_schedule_t *ks, const unsigned char *key, size_t key_len)
{
    /* Use the little-endian byte order from the LOTUS-AEAD submission */
    if (!ks || !key || key_len != 16)
        return 0;
    ks->k[0] = le_load_word32(key + 12);
    ks->k[1] = le_load_word32(key + 8);
    ks->k[2] = le_load_word32(key + 4);
    ks->k[3] = le_load_word32(key);
    gift64b_update_round_keys(ks);
    return 1;
}

/**
 * \brief Converts the GIFT-64 nibble-based representation into word-based
 * (littlen-endian version).
 *
 * \param output Output buffer to write the word-based version to.
 * \param input Input buffer to read the nibble-based version from.
 *
 * The output words will be in fixsliced form.  Technically the output will
 * contain two blocks for gift64b_encrypt_core() to process in parallel but
 * both blocks will have the same value.
 */
static void gift64n_to_words(uint32_t output[4], const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;

    /* Load the input block into 32-bit words */
    s0 = le_load_word32(input);
    s2 = le_load_word32(input + 4);

    /* Rearrange the bits in the block */
    gift64b_swap_move(s0, s0, 0x0A0A0A0AU, 3);
    gift64b_swap_move(s0, s0, 0x00CC00CCU, 6);
    gift64b_swap_move(s0, s0, 0x0000FF00U, 8);
    gift64b_swap_move(s2, s2, 0x0A0A0A0AU, 3);
    gift64b_swap_move(s2, s2, 0x00CC00CCU, 6);
    gift64b_swap_move(s2, s2, 0x0000FF00U, 8);

    /* Split into two identical blocks in fixsliced form */
    s1 = s0;
    s3 = s2;
    gift64b_swap_move(s0, s1, 0x0F0F0F0FU, 4);
    gift64b_swap_move(s2, s3, 0x0F0F0F0FU, 4);
    gift64b_swap_move(s0, s2, 0x0000FFFFU, 16);
    gift64b_swap_move(s1, s3, 0x0000FFFFU, 16);
    output[0] = s0;
    output[1] = s1;
    output[2] = s2;
    output[3] = s3;
}

/**
 * \brief Converts the GIFT-64 word-based representation into nibble-based
 * (little-endian version).
 *
 * \param output Output buffer to write the nibble-based version to.
 * \param input Input buffer to read the word-based version from.
 *
 * The input words are in fixsliced form.  Technically there are two
 * identical blocks in the input.  We drop one when we write to the output.
 */
static void gift64n_to_nibbles(unsigned char *output, const uint32_t input[4])
{
    uint32_t s0, s1, s2, s3;

    /* Load the state and split the two blocks into separate words */
    s0 = input[0];
    s1 = input[1];
    s2 = input[2];
    s3 = input[3];
    gift64b_swap_move(s0, s2, 0x0000FFFFU, 16);
    gift64b_swap_move(s1, s3, 0x0000FFFFU, 16);
    gift64b_swap_move(s0, s1, 0x0F0F0F0FU, 4);
    gift64b_swap_move(s2, s3, 0x0F0F0F0FU, 4);

    /* Rearrange the bits in the first block back into nibble form */
    gift64b_swap_move(s0, s0, 0x0000FF00U, 8);
    gift64b_swap_move(s0, s0, 0x00CC00CCU, 6);
    gift64b_swap_move(s0, s0, 0x0A0A0A0AU, 3);
    gift64b_swap_move(s2, s2, 0x0000FF00U, 8);
    gift64b_swap_move(s2, s2, 0x00CC00CCU, 6);
    gift64b_swap_move(s2, s2, 0x0A0A0A0AU, 3);
    le_store_word32(output, s0);
    le_store_word32(output + 4, s2);
}

void gift64n_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t state[4];
    gift64n_to_words(state, input);
    gift64b_encrypt_core(ks, state, 0);
    gift64n_to_nibbles(output, state);
}

void gift64n_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t state[4];
    gift64n_to_words(state, input);
    gift64b_decrypt_core(ks, state, 0);
    gift64n_to_nibbles(output, state);
}

/**
 * \brief Converts the GIFT-64 nibble-based representation into word-based
 * (big-endian version).
 *
 * \param output Output buffer to write the word-based version to.
 * \param input Input buffer to read the nibble-based version from.
 *
 * The output words will be in fixsliced form.  Technically the output will
 * contain two blocks for gift64b_encrypt_core() to process in parallel but
 * both blocks will have the same value.
 */
static void gift64nb_to_words(uint32_t output[4], const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;

    /* Load the input block into 32-bit words */
    s0 = be_load_word32(input + 4);
    s2 = be_load_word32(input);

    /* Rearrange the bits in the block */
    gift64b_swap_move(s0, s0, 0x0A0A0A0AU, 3);
    gift64b_swap_move(s0, s0, 0x00CC00CCU, 6);
    gift64b_swap_move(s0, s0, 0x0000FF00U, 8);
    gift64b_swap_move(s2, s2, 0x0A0A0A0AU, 3);
    gift64b_swap_move(s2, s2, 0x00CC00CCU, 6);
    gift64b_swap_move(s2, s2, 0x0000FF00U, 8);

    /* Split into two identical blocks in fixsliced form */
    s1 = s0;
    s3 = s2;
    gift64b_swap_move(s0, s1, 0x0F0F0F0FU, 4);
    gift64b_swap_move(s2, s3, 0x0F0F0F0FU, 4);
    gift64b_swap_move(s0, s2, 0x0000FFFFU, 16);
    gift64b_swap_move(s1, s3, 0x0000FFFFU, 16);
    output[0] = s0;
    output[1] = s1;
    output[2] = s2;
    output[3] = s3;
}

/**
 * \brief Converts the GIFT-64 word-based representation into nibble-based
 * (big-endian version).
 *
 * \param output Output buffer to write the nibble-based version to.
 * \param input Input buffer to read the word-based version from.
 *
 * The input words are in fixsliced form.  Technically there are two
 * identical blocks in the input.  We drop one when we write to the output.
 */
static void gift64nb_to_nibbles(unsigned char *output, const uint32_t input[4])
{
    uint32_t s0, s1, s2, s3;

    /* Load the state and split the two blocks into separate words */
    s0 = input[0];
    s1 = input[1];
    s2 = input[2];
    s3 = input[3];
    gift64b_swap_move(s0, s2, 0x0000FFFFU, 16);
    gift64b_swap_move(s1, s3, 0x0000FFFFU, 16);
    gift64b_swap_move(s0, s1, 0x0F0F0F0FU, 4);
    gift64b_swap_move(s2, s3, 0x0F0F0F0FU, 4);

    /* Rearrange the bits in the first block back into nibble form */
    gift64b_swap_move(s0, s0, 0x0000FF00U, 8);
    gift64b_swap_move(s0, s0, 0x00CC00CCU, 6);
    gift64b_swap_move(s0, s0, 0x0A0A0A0AU, 3);
    gift64b_swap_move(s2, s2, 0x0000FF00U, 8);
    gift64b_swap_move(s2, s2, 0x00CC00CCU, 6);
    gift64b_swap_move(s2, s2, 0x0A0A0A0AU, 3);
    be_store_word32(output, s2);
    be_store_word32(output + 4, s0);
}

void gift64nb_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t state[4];
    gift64nb_to_words(state, input);
    gift64b_encrypt_core(ks, state, 0);
    gift64nb_to_nibbles(output, state);
}

void gift64nb_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t state[4];
    gift64nb_to_words(state, input);
    gift64b_decrypt_core(ks, state, 0);
    gift64nb_to_nibbles(output, state);
}

/* 4-bit tweak values expanded to 32-bit in fixsliced form */
static uint32_t const GIFT64_tweaks[16] = {
    0x00000000, 0xee11ee11, 0xdd22dd22, 0x33333333, 0xbb44bb44, 0x55555555,
    0x66666666, 0x88778877, 0x77887788, 0x99999999, 0xaaaaaaaa, 0x44bb44bb,
    0xcccccccc, 0x22dd22dd, 0x11ee11ee, 0xffffffff
};

void gift64t_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak)
{
    uint32_t state[4];
    gift64n_to_words(state, input);
    gift64b_encrypt_core(ks, state, GIFT64_tweaks[tweak]);
    gift64n_to_nibbles(output, state);
}

void gift64t_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak)
{
    uint32_t state[4];
    gift64n_to_words(state, input);
    gift64b_decrypt_core(ks, state, GIFT64_tweaks[tweak]);
    gift64n_to_nibbles(output, state);
}
