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

#if !GIFT64_LOW_MEMORY

/* Round constants for GIFT-64 in the fixsliced representation */
static uint32_t const GIFT64_RC[28] = {
    0x22000011, 0x00002299, 0x11118811, 0x880000ff, 0x33111199, 0x990022ee,
    0x22119933, 0x880033bb, 0x22119999, 0x880022ff, 0x11119922, 0x880033cc,
    0x33008899, 0x99002299, 0x33118811, 0x880000ee, 0x33110099, 0x990022aa,
    0x22118833, 0x880022bb, 0x22111188, 0x88002266, 0x00009922, 0x88003300,
    0x22008811, 0x00002288, 0x00118811, 0x880000bb
};

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

void gift64n_update_round_keys(gift64n_key_schedule_t *ks)
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
    (const gift64n_key_schedule_t *ks, uint32_t state[4], uint32_t tweak)
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
    (const gift64n_key_schedule_t *ks, uint32_t state[4], uint32_t tweak)
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

void gift64n_init(gift64n_key_schedule_t *ks, const unsigned char *key)
{
    /* Use the little-endian byte order from the LOTUS-AEAD submission */
    ks->k[0] = le_load_word32(key + 12);
    ks->k[1] = le_load_word32(key + 8);
    ks->k[2] = le_load_word32(key + 4);
    ks->k[3] = le_load_word32(key);
    gift64n_update_round_keys(ks);
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

/* 4-bit tweak values expanded to 32-bit in fixsliced form */
static uint32_t const GIFT64_tweaks[16] = {
    0x00000000, 0xee11ee11, 0xdd22dd22, 0x33333333, 0xbb44bb44, 0x55555555,
    0x66666666, 0x88778877, 0x77887788, 0x99999999, 0xaaaaaaaa, 0x44bb44bb,
    0xcccccccc, 0x22dd22dd, 0x11ee11ee, 0xffffffff
};

void gift64t_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, uint16_t tweak)
{
    uint32_t state[4];
    gift64n_to_words(state, input);
    gift64b_encrypt_core(ks, state, GIFT64_tweaks[tweak & 0x0F]);
    gift64n_to_nibbles(output, state);
}

void gift64t_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, uint16_t tweak)
{
    uint32_t state[4];
    gift64n_to_words(state, input);
    gift64b_decrypt_core(ks, state, GIFT64_tweaks[tweak & 0x0F]);
    gift64n_to_nibbles(output, state);
}

#elif !defined(__AVR__) /* GIFT64_LOW_MEMORY */

/* Round constants for GIFT-64 */
static uint8_t const GIFT64_RC[28] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B
};

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define bit_permute_step(_y, mask, shift) \
    do { \
        uint16_t y = (_y); \
        uint16_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step_simple */
#define bit_permute_step_simple(_y, mask, shift) \
    do { \
        (_y) = (((_y) & (mask)) << (shift)) | (((_y) >> (shift)) & (mask)); \
    } while (0)

/*
 * The permutation below was generated by the online permuation generator at
 * "http://programming.sirrida.de/calcperm.php".
 *
 * All of the permutuations are essentially the same, except that each is
 * rotated by 4 bits with respect to the next:
 *
 * P0: 0 12 8 4 1 13 9 5 2 14 10 6 3 15 11 7
 * P1: 4 0 12 8 5 1 13 9 6 2 14 10 7 3 15 11
 * P2: 8 4 0 12 9 5 1 13 10 6 2 14 11 7 3 15
 * P3: 12 8 4 0 13 9 5 1 14 10 6 2 15 11 7 3
 *
 * The most efficient permutation from the online generator was P1, so we
 * perform it as the core of the others, and then perform a final rotation.
 *
 * It is possible to do slightly better than "P1 then rotate" on desktop and
 * server architectures for the other permutations.  But the advantage isn't
 * as evident on embedded platforms so we keep things simple.
 */
#define PERM1_INNER(x) \
    do { \
        bit_permute_step(x, 0x0a0a, 3); \
        bit_permute_step(x, 0x00cc, 6); \
        bit_permute_step_simple(x, 0x0f0f, 4); \
    } while (0)
#define PERM0(x) \
    do { \
        uint32_t _x = (x); \
        PERM1_INNER(_x); \
        (x) = leftRotate12_16(_x); \
    } while (0)
#define PERM1(x) PERM1_INNER(x)
#define PERM2(x) \
    do { \
        uint32_t _x = (x); \
        PERM1_INNER(_x); \
        (x) = leftRotate4_16(_x); \
    } while (0)
#define PERM3(x) \
    do { \
        uint32_t _x = (x); \
        PERM1_INNER(_x); \
        (x) = leftRotate8_16(_x); \
    } while (0)

#define INV_PERM1_INNER(x) \
    do { \
        bit_permute_step(x, 0x0505, 5); \
        bit_permute_step(x, 0x00cc, 6); \
        bit_permute_step_simple(x, 0x0f0f, 4); \
    } while (0)
#define INV_PERM0(x) \
    do { \
        uint32_t _x = rightRotate12_16(x); \
        INV_PERM1_INNER(_x); \
        (x) = _x; \
    } while (0)
#define INV_PERM1(x) INV_PERM1_INNER(x)
#define INV_PERM2(x) \
    do { \
        uint32_t _x = rightRotate4_16(x); \
        INV_PERM1_INNER(_x); \
        (x) = _x; \
    } while (0)
#define INV_PERM3(x) \
    do { \
        uint32_t _x = rightRotate8_16(x); \
        INV_PERM1_INNER(_x); \
        (x) = _x; \
    } while (0)

/**
 * \brief Encrypts a 64-bit block with GIFT-64 (bit-sliced).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
static void gift64b_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint16_t s0, s1, s2, s3;
    uint32_t w0, w1, w2, w3;
    uint32_t temp;
    uint8_t round;

    /* Copy the plaintext into the state buffer and convert from big endian */
    s0 = be_load_word16(input);
    s1 = be_load_word16(input + 2);
    s2 = be_load_word16(input + 4);
    s3 = be_load_word16(input + 6);

    /* The key schedule is initialized with the key itself */
    w0 = ks->k[0];
    w1 = ks->k[1];
    w2 = ks->k[2];
    w3 = ks->k[3];

    /* Perform all 28 rounds */
    for (round = 0; round < 28; ++round) {
        /* SubCells - apply the S-box */
        s1 ^= s0 & s2;
        s0 ^= s1 & s3;
        s2 ^= s0 | s1;
        s3 ^= s2;
        s1 ^= s3;
        s3 ^= 0xFFFFU;
        s2 ^= s0 & s1;
        temp = s0;
        s0 = s3;
        s3 = temp;

        /* PermBits - apply the 64-bit permutation */
        PERM0(s0);
        PERM1(s1);
        PERM2(s2);
        PERM3(s3);

        /* AddRoundKey - XOR in the key schedule and the round constant */
        s0 ^= (uint16_t)w3;
        s1 ^= (uint16_t)(w3 >> 16);
        s3 ^= 0x8000U ^ GIFT64_RC[round];

        /* Rotate the key schedule */
        temp = w3;
        w3 = w2;
        w2 = w1;
        w1 = w0;
        w0 = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
             ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
    }

    /* Pack the state into the ciphertext buffer in big endian */
    be_store_word16(output,     s0);
    be_store_word16(output + 2, s1);
    be_store_word16(output + 4, s2);
    be_store_word16(output + 6, s3);
}

/**
 * \brief Decrypts a 64-bit block with GIFT-64 (bit-sliced).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
static void gift64b_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint16_t s0, s1, s2, s3;
    uint32_t w0, w1, w2, w3;
    uint32_t temp;
    uint8_t round;

    /* Copy the ciphertext into the state buffer and convert from big endian */
    s0 = be_load_word16(input);
    s1 = be_load_word16(input + 2);
    s2 = be_load_word16(input + 4);
    s3 = be_load_word16(input + 6);

    /* Generate the decryption key at the end of the last round.
     *
     * To do that, we run the block operation forward to determine the
     * final state of the key schedule after the last round:
     *
     * w0 = ks->k[0];
     * w1 = ks->k[1];
     * w2 = ks->k[2];
     * w3 = ks->k[3];
     * for (round = 0; round < 28; ++round) {
     *     temp = w3;
     *     w3 = w2;
     *     w2 = w1;
     *     w1 = w0;
     *     w0 = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
     *          ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
     * }
     *
     * We can short-cut all of the above by noticing that we don't need
     * to do the word rotations.  Every 4 rounds, the rotation alignment
     * returns to the original position and each word has been rotated
     * by applying the "2 right and 4 left" bit-rotation step to it.
     * We then repeat that 7 times for the full 28 rounds.  The overall
     * effect is to apply a "14 right and 28 left" bit-rotation to every word
     * in the key schedule.  That is equivalent to "14 right and 12 left"
     * on the 16-bit sub-words.
     */
    w0 = ks->k[0];
    w1 = ks->k[1];
    w2 = ks->k[2];
    w3 = ks->k[3];
    w0 = ((w0 & 0xC0000000U) >> 14) | ((w0 & 0x3FFF0000U) << 2) |
         ((w0 & 0x0000000FU) << 12) | ((w0 & 0x0000FFF0U) >> 4);
    w1 = ((w1 & 0xC0000000U) >> 14) | ((w1 & 0x3FFF0000U) << 2) |
         ((w1 & 0x0000000FU) << 12) | ((w1 & 0x0000FFF0U) >> 4);
    w2 = ((w2 & 0xC0000000U) >> 14) | ((w2 & 0x3FFF0000U) << 2) |
         ((w2 & 0x0000000FU) << 12) | ((w2 & 0x0000FFF0U) >> 4);
    w3 = ((w3 & 0xC0000000U) >> 14) | ((w3 & 0x3FFF0000U) << 2) |
         ((w3 & 0x0000000FU) << 12) | ((w3 & 0x0000FFF0U) >> 4);

    /* Perform all 28 rounds */
    for (round = 28; round > 0; --round) {
        /* Rotate the key schedule backwards */
        temp = w0;
        w0 = w1;
        w1 = w2;
        w2 = w3;
        w3 = ((temp & 0x3FFF0000U) << 2) | ((temp & 0xC0000000U) >> 14) |
             ((temp & 0x0000FFF0U) >> 4) | ((temp & 0x0000000FU) << 12);

        /* AddRoundKey - XOR in the key schedule and the round constant */
        s0 ^= (uint16_t)w3;
        s1 ^= (uint16_t)(w3 >> 16);
        s3 ^= 0x8000U ^ GIFT64_RC[round - 1];

        /* InvPermBits - apply the inverse of the 128-bit permutation */
        INV_PERM0(s0);
        INV_PERM1(s1);
        INV_PERM2(s2);
        INV_PERM3(s3);

        /* InvSubCells - apply the inverse of the S-box */
        temp = s0;
        s0 = s3;
        s3 = temp;
        s2 ^= s0 & s1;
        s3 ^= 0xFFFFU;
        s1 ^= s3;
        s3 ^= s2;
        s2 ^= s0 | s1;
        s0 ^= s1 & s3;
        s1 ^= s0 & s2;
    }

    /* Pack the state into the plaintext buffer in big endian */
    be_store_word16(output,     s0);
    be_store_word16(output + 2, s1);
    be_store_word16(output + 4, s2);
    be_store_word16(output + 6, s3);
}

void gift64n_init(gift64n_key_schedule_t *ks, const unsigned char *key)
{
    /* Use the little-endian byte order from the LOTUS-AEAD submission */
    ks->k[0] = le_load_word32(key + 12);
    ks->k[1] = le_load_word32(key + 8);
    ks->k[2] = le_load_word32(key + 4);
    ks->k[3] = le_load_word32(key);
}

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define bit_permute_step_32(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/**
 * \brief Converts the GIFT-64 nibble-based representation into word-based.
 *
 * \param output Output buffer to write the word-based version to.
 * \param input Input buffer to read the nibble-based version from.
 *
 * The \a input and \a output buffers can be the same buffer.
 */
static void gift64n_to_words
    (unsigned char *output, const unsigned char *input)
{
    uint32_t s0, s1;

    /* Load the input buffer into 32-bit words.  We use the nibble order from
     * the LOTUS-AEAD submission to NIST which is byte-reversed with respect
     * to the nibble order of the original GIFT-64 paper.  Nibble zero is in
     * the first byte instead of the last, which means little-endian order. */
    s0 = le_load_word32(input + 4);
    s1 = le_load_word32(input);

    /* Rearrange the bits so that bits 0..3 of each nibble are
     * scattered to bytes 0..3 of each word.  The permutation is:
     *
     * 0 8 16 24 1 9 17 25 2 10 18 26 3 11 19 27 4 12 20 28 5 13 21 29 6 14 22 30 7 15 23 31
     *
     * Generated with "http://programming.sirrida.de/calcperm.php".
     */
    #define PERM_WORDS(_x) \
        do { \
            uint32_t x = (_x); \
            bit_permute_step_32(x, 0x0a0a0a0a, 3); \
            bit_permute_step_32(x, 0x00cc00cc, 6); \
            bit_permute_step_32(x, 0x0000f0f0, 12); \
            bit_permute_step_32(x, 0x0000ff00, 8); \
            (_x) = x; \
        } while (0)
    PERM_WORDS(s0);
    PERM_WORDS(s1);

    /* Rearrange the bytes and write them to the output buffer */
    output[0] = (uint8_t)s0;
    output[1] = (uint8_t)s1;
    output[2] = (uint8_t)(s0 >> 8);
    output[3] = (uint8_t)(s1 >> 8);
    output[4] = (uint8_t)(s0 >> 16);
    output[5] = (uint8_t)(s1 >> 16);
    output[6] = (uint8_t)(s0 >> 24);
    output[7] = (uint8_t)(s1 >> 24);
}

/**
 * \brief Converts the GIFT-64 word-based representation into nibble-based.
 *
 * \param output Output buffer to write the nibble-based version to.
 * \param input Input buffer to read the word-based version from.
 */
static void gift64n_to_nibbles
    (unsigned char *output, const unsigned char *input)
{
    uint32_t s0, s1;

    /* Load the input bytes and rearrange them so that s0 contains the
     * most significant nibbles and s1 contains the least significant */
    s0 = (((uint32_t)(input[6])) << 24) |
         (((uint32_t)(input[4])) << 16) |
         (((uint32_t)(input[2])) <<  8) |
          ((uint32_t)(input[0]));
    s1 = (((uint32_t)(input[7])) << 24) |
         (((uint32_t)(input[5])) << 16) |
         (((uint32_t)(input[3])) <<  8) |
          ((uint32_t)(input[1]));

    /* Apply the inverse of PERM_WORDS() from the function above */
    #define INV_PERM_WORDS(_x) \
        do { \
            uint32_t x = (_x); \
            bit_permute_step_32(x, 0x00aa00aa, 7); \
            bit_permute_step_32(x, 0x0000cccc, 14); \
            bit_permute_step_32(x, 0x00f000f0, 4); \
            bit_permute_step_32(x, 0x0000ff00, 8); \
            (_x) = x; \
        } while (0)
    INV_PERM_WORDS(s0);
    INV_PERM_WORDS(s1);

    /* Store the result into the output buffer as 32-bit words */
    le_store_word32(output + 4, s0);
    le_store_word32(output,     s1);
}

void gift64n_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift64n_to_words(output, input);
    gift64b_encrypt(ks, output, output);
    gift64n_to_nibbles(output, output);
}

void gift64n_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift64n_to_words(output, input);
    gift64b_decrypt(ks, output, output);
    gift64n_to_nibbles(output, output);
}

void gift64t_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, uint16_t tweak)
{
    uint16_t s0, s1, s2, s3;
    uint32_t w0, w1, w2, w3;
    uint32_t temp;
    uint8_t round;

    /* Copy the plaintext into the state buffer and convert from nibbles */
    gift64n_to_words(output, input);
    s0 = be_load_word16(output);
    s1 = be_load_word16(output + 2);
    s2 = be_load_word16(output + 4);
    s3 = be_load_word16(output + 6);

    /* The key schedule is initialized with the key itself */
    w0 = ks->k[0];
    w1 = ks->k[1];
    w2 = ks->k[2];
    w3 = ks->k[3];

    /* Perform all 28 rounds */
    for (round = 0; round < 28; ++round) {
        /* SubCells - apply the S-box */
        s1 ^= s0 & s2;
        s0 ^= s1 & s3;
        s2 ^= s0 | s1;
        s3 ^= s2;
        s1 ^= s3;
        s3 ^= 0xFFFFU;
        s2 ^= s0 & s1;
        temp = s0;
        s0 = s3;
        s3 = temp;

        /* PermBits - apply the 64-bit permutation */
        PERM0(s0);
        PERM1(s1);
        PERM2(s2);
        PERM3(s3);

        /* AddRoundKey - XOR in the key schedule and the round constant */
        s0 ^= (uint16_t)w3;
        s1 ^= (uint16_t)(w3 >> 16);
        s3 ^= 0x8000U ^ GIFT64_RC[round];

        /* AddTweak - XOR in the tweak every 4 rounds except the last */
        if (((round + 1) % 4) == 0 && round < 27)
            s2 ^= tweak;

        /* Rotate the key schedule */
        temp = w3;
        w3 = w2;
        w2 = w1;
        w1 = w0;
        w0 = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
             ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
    }

    /* Pack the state into the ciphertext buffer in nibble form */
    be_store_word16(output,     s0);
    be_store_word16(output + 2, s1);
    be_store_word16(output + 4, s2);
    be_store_word16(output + 6, s3);
    gift64n_to_nibbles(output, output);
}

void gift64t_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, uint16_t tweak)
{
    uint16_t s0, s1, s2, s3;
    uint32_t w0, w1, w2, w3;
    uint32_t temp;
    uint8_t round;

    /* Copy the ciphertext into the state buffer and convert from nibbles */
    gift64n_to_words(output, input);
    s0 = be_load_word16(output);
    s1 = be_load_word16(output + 2);
    s2 = be_load_word16(output + 4);
    s3 = be_load_word16(output + 6);

    /* Generate the decryption key at the end of the last round.
     *
     * To do that, we run the block operation forward to determine the
     * final state of the key schedule after the last round:
     *
     * w0 = ks->k[0];
     * w1 = ks->k[1];
     * w2 = ks->k[2];
     * w3 = ks->k[3];
     * for (round = 0; round < 28; ++round) {
     *     temp = w3;
     *     w3 = w2;
     *     w2 = w1;
     *     w1 = w0;
     *     w0 = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
     *          ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
     * }
     *
     * We can short-cut all of the above by noticing that we don't need
     * to do the word rotations.  Every 4 rounds, the rotation alignment
     * returns to the original position and each word has been rotated
     * by applying the "2 right and 4 left" bit-rotation step to it.
     * We then repeat that 7 times for the full 28 rounds.  The overall
     * effect is to apply a "14 right and 28 left" bit-rotation to every word
     * in the key schedule.  That is equivalent to "14 right and 12 left"
     * on the 16-bit sub-words.
     */
    w0 = ks->k[0];
    w1 = ks->k[1];
    w2 = ks->k[2];
    w3 = ks->k[3];
    w0 = ((w0 & 0xC0000000U) >> 14) | ((w0 & 0x3FFF0000U) << 2) |
         ((w0 & 0x0000000FU) << 12) | ((w0 & 0x0000FFF0U) >> 4);
    w1 = ((w1 & 0xC0000000U) >> 14) | ((w1 & 0x3FFF0000U) << 2) |
         ((w1 & 0x0000000FU) << 12) | ((w1 & 0x0000FFF0U) >> 4);
    w2 = ((w2 & 0xC0000000U) >> 14) | ((w2 & 0x3FFF0000U) << 2) |
         ((w2 & 0x0000000FU) << 12) | ((w2 & 0x0000FFF0U) >> 4);
    w3 = ((w3 & 0xC0000000U) >> 14) | ((w3 & 0x3FFF0000U) << 2) |
         ((w3 & 0x0000000FU) << 12) | ((w3 & 0x0000FFF0U) >> 4);

    /* Perform all 28 rounds */
    for (round = 28; round > 0; --round) {
        /* Rotate the key schedule backwards */
        temp = w0;
        w0 = w1;
        w1 = w2;
        w2 = w3;
        w3 = ((temp & 0x3FFF0000U) << 2) | ((temp & 0xC0000000U) >> 14) |
             ((temp & 0x0000FFF0U) >> 4) | ((temp & 0x0000000FU) << 12);

        /* AddTweak - XOR in the tweak every 4 rounds except the last */
        if ((round % 4) == 0 && round != 28)
            s2 ^= tweak;

        /* AddRoundKey - XOR in the key schedule and the round constant */
        s0 ^= (uint16_t)w3;
        s1 ^= (uint16_t)(w3 >> 16);
        s3 ^= 0x8000U ^ GIFT64_RC[round - 1];

        /* InvPermBits - apply the inverse of the 128-bit permutation */
        INV_PERM0(s0);
        INV_PERM1(s1);
        INV_PERM2(s2);
        INV_PERM3(s3);

        /* InvSubCells - apply the inverse of the S-box */
        temp = s0;
        s0 = s3;
        s3 = temp;
        s2 ^= s0 & s1;
        s3 ^= 0xFFFFU;
        s1 ^= s3;
        s3 ^= s2;
        s2 ^= s0 | s1;
        s0 ^= s1 & s3;
        s1 ^= s0 & s2;
    }

    /* Pack the state into the plaintext buffer in nibble form */
    be_store_word16(output,     s0);
    be_store_word16(output + 2, s1);
    be_store_word16(output + 4, s2);
    be_store_word16(output + 6, s3);
    gift64n_to_nibbles(output, output);
}

#endif /* GIFT64_LOW_MEMORY */
