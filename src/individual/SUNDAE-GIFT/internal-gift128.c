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

#include "internal-gift128.h"
#include "internal-util.h"

/* Round constants for GIFT-128 in the fixsliced representation */
static uint32_t const GIFT128_RC[40] = {
    0x10000008, 0x80018000, 0x54000002, 0x01010181, 0x8000001f, 0x10888880,
    0x6001e000, 0x51500002, 0x03030180, 0x8000002f, 0x10088880, 0x60016000,
    0x41500002, 0x03030080, 0x80000027, 0x10008880, 0x4001e000, 0x11500002,
    0x03020180, 0x8000002b, 0x10080880, 0x60014000, 0x01400002, 0x02020080,
    0x80000021, 0x10000080, 0x0001c000, 0x51000002, 0x03010180, 0x8000002e,
    0x10088800, 0x60012000, 0x40500002, 0x01030080, 0x80000006, 0x10008808,
    0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};

/**
 * \brief Swaps bits within two words.
 *
 * \param a The first word.
 * \param b The second word.
 * \param mask Mask for the bits to shift.
 * \param shift Shift amount in bits.
 */
#define gift128b_swap_move(a, b, mask, shift) \
    do { \
        uint32_t tmp = ((b) ^ ((a) >> (shift))) & (mask); \
        (b) ^= tmp; \
        (a) ^= tmp << (shift); \
    } while (0)

/**
 * \brief Derives the next 10 fixsliced keys in the key schedule.
 *
 * \param next Points to the buffer to receive the next 10 keys.
 * \param prev Points to the buffer holding the previous 10 keys.
 *
 * The \a next and \a prev buffers are allowed to be the same.
 */
#define gift128b_derive_keys(next, prev) \
    do { \
        /* Key 0 */ \
        uint32_t s = (prev)[0]; \
        uint32_t t = (prev)[1]; \
        gift128b_swap_move(t, t, 0x00003333U, 16); \
        gift128b_swap_move(t, t, 0x55554444U, 1); \
        (next)[0] = t; \
        /* Key 1 */ \
        s = leftRotate8(s & 0x33333333U) | leftRotate16(s & 0xCCCCCCCCU); \
        gift128b_swap_move(s, s, 0x55551100U, 1); \
        (next)[1] = s; \
        /* Key 2 */ \
        s = (prev)[2]; \
        t = (prev)[3]; \
        (next)[2] = ((t >> 4) & 0x0F000F00U) | ((t & 0x0F000F00U) << 4) | \
                    ((t >> 6) & 0x00030003U) | ((t & 0x003F003FU) << 2); \
        /* Key 3 */ \
        (next)[3] = ((s >> 6) & 0x03000300U) | ((s & 0x3F003F00U) << 2) | \
                    ((s >> 5) & 0x00070007U) | ((s & 0x001F001FU) << 3); \
        /* Key 4 */ \
        s = (prev)[4]; \
        t = (prev)[5]; \
        (next)[4] = leftRotate8(t & 0xAAAAAAAAU) | \
                   leftRotate16(t & 0x55555555U); \
        /* Key 5 */ \
        (next)[5] = leftRotate8(s & 0x55555555U) | \
                   leftRotate12(s & 0xAAAAAAAAU); \
        /* Key 6 */ \
        s = (prev)[6]; \
        t = (prev)[7]; \
        (next)[6] = ((t >> 2) & 0x03030303U) | ((t & 0x03030303U) << 2) | \
                    ((t >> 1) & 0x70707070U) | ((t & 0x10101010U) << 3); \
        /* Key 7 */ \
	(next)[7] = ((s >> 18) & 0x00003030U) | ((s & 0x01010101U) << 3)  | \
                    ((s >> 14) & 0x0000C0C0U) | ((s & 0x0000E0E0U) << 15) | \
                    ((s >>  1) & 0x07070707U) | ((s & 0x00001010U) << 19); \
        /* Key 8 */ \
        s = (prev)[8]; \
        t = (prev)[9]; \
        (next)[8] = ((t >> 4) & 0x0FFF0000U) | ((t & 0x000F0000U) << 12) | \
                    ((t >> 8) & 0x000000FFU) | ((t & 0x000000FFU) << 8); \
        /* Key 9 */ \
        (next)[9] = ((s >> 6) & 0x03FF0000U) | ((s & 0x003F0000U) << 10) | \
                    ((s >> 4) & 0x00000FFFU) | ((s & 0x0000000FU) << 12); \
    } while (0)

/**
 * \brief Compute the round keys for GIFT-128 in the fixsliced representation.
 *
 * \param ks Points to the key schedule to initialize.
 * \param k0 First key word.
 * \param k1 Second key word.
 * \param k2 Third key word.
 * \param k3 Fourth key word.
 */
static void gift128b_compute_round_keys
    (gift128b_key_schedule_t *ks,
     uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3)
{
    unsigned index;
    uint32_t temp;

    /* Set the regular key with k0 and k3 pre-swapped for the round function */
    ks->k[0] = k3;
    ks->k[1] = k1;
    ks->k[2] = k2;
    ks->k[3] = k0;

    /* Pre-compute the keys for rounds 3..10 and permute into fixsliced form */
    for (index = 4; index < 20; index += 2) {
        ks->k[index] = ks->k[index - 3];
        temp = ks->k[index - 4];
        temp = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
               ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
        ks->k[index + 1] = temp;
    }
    for (index = 0; index < 20; index += 10) {
        /* Keys 0 and 10 */
        temp = ks->k[index];
        gift128b_swap_move(temp, temp, 0x00550055U, 9);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index] = temp;

        /* Keys 1 and 11 */
        temp = ks->k[index + 1];
        gift128b_swap_move(temp, temp, 0x00550055U, 9);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 1] = temp;

        /* Keys 2 and 12 */
        temp = ks->k[index + 2];
        gift128b_swap_move(temp, temp, 0x11111111U, 3);
        gift128b_swap_move(temp, temp, 0x03030303U, 6);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 2] = temp;

        /* Keys 3 and 13 */
        temp = ks->k[index + 3];
        gift128b_swap_move(temp, temp, 0x11111111U, 3);
        gift128b_swap_move(temp, temp, 0x03030303U, 6);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 3] = temp;

        /* Keys 4 and 14 */
        temp = ks->k[index + 4];
        gift128b_swap_move(temp, temp, 0x0000AAAAU, 15);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 4] = temp;

        /* Keys 5 and 15 */
        temp = ks->k[index + 5];
        gift128b_swap_move(temp, temp, 0x0000AAAAU, 15);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 5] = temp;

        /* Keys 6 and 16 */
        temp = ks->k[index + 6];
        gift128b_swap_move(temp, temp, 0x0A0A0A0AU, 3);
        gift128b_swap_move(temp, temp, 0x00CC00CCU, 6);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 6] = temp;

        /* Keys 7 and 17 */
        temp = ks->k[index + 7];
        gift128b_swap_move(temp, temp, 0x0A0A0A0AU, 3);
        gift128b_swap_move(temp, temp, 0x00CC00CCU, 6);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        ks->k[index + 7] = temp;

        /* Keys 8, 9, 18, and 19 do not need any adjustment */
    }

    /* Derive the fixsliced keys for the remaining rounds 11..40 */
    for (index = 20; index < 80; index += 10) {
        gift128b_derive_keys(ks->k + index, ks->k + index - 20);
    }
}

int gift128b_init
    (gift128b_key_schedule_t *ks, const unsigned char *key, size_t key_len)
{
    if (!ks || !key || key_len != 16)
        return 0;
    gift128b_compute_round_keys
        (ks, be_load_word32(key), be_load_word32(key + 4),
             be_load_word32(key + 8), be_load_word32(key + 12));
    return 1;
}

/**
 * \brief Performs the GIFT-128 S-box on the bit-sliced state.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_sbox(s0, s1, s2, s3) \
    do { \
        s1 ^= s0 & s2; \
        s0 ^= s1 & s3; \
        s2 ^= s0 | s1; \
        s3 ^= s2; \
        s1 ^= s3; \
        s3 ^= 0xFFFFFFFFU; \
        s2 ^= s0 & s1; \
    } while (0)

/**
 * \brief Performs the inverse of the GIFT-128 S-box on the bit-sliced state.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_inv_sbox(s0, s1, s2, s3) \
    do { \
        s2 ^= s3 & s1; \
        s0 ^= 0xFFFFFFFFU; \
        s1 ^= s0; \
        s0 ^= s2; \
        s2 ^= s3 | s1; \
        s3 ^= s1 & s0; \
        s1 ^= s3 & s2; \
    } while (0)

/**
 * \brief Permutes the GIFT-128 state between the 1st and 2nd mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_permute_state_1(s0, s1, s2, s3) \
    do { \
        s1 = ((s1 >> 2) & 0x33333333U) | ((s1 & 0x33333333U) << 2); \
        s2 = ((s2 >> 3) & 0x11111111U) | ((s2 & 0x77777777U) << 1); \
        s3 = ((s3 >> 1) & 0x77777777U) | ((s3 & 0x11111111U) << 3); \
    } while (0);

/**
 * \brief Permutes the GIFT-128 state between the 2nd and 3rd mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_permute_state_2(s0, s1, s2, s3) \
    do { \
        s0 = ((s0 >>  4) & 0x0FFF0FFFU) | ((s0 & 0x000F000FU) << 12); \
        s1 = ((s1 >>  8) & 0x00FF00FFU) | ((s1 & 0x00FF00FFU) << 8); \
        s2 = ((s2 >> 12) & 0x000F000FU) | ((s2 & 0x0FFF0FFFU) << 4); \
    } while (0);

/**
 * \brief Permutes the GIFT-128 state between the 3rd and 4th mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_permute_state_3(s0, s1, s2, s3) \
    do { \
        gift128b_swap_move(s1, s1, 0x55555555U, 1); \
        s2 = leftRotate16(s2); \
        gift128b_swap_move(s2, s2, 0x00005555U, 1); \
        s3 = leftRotate16(s3); \
        gift128b_swap_move(s3, s3, 0x55550000U, 1); \
    } while (0);

/**
 * \brief Permutes the GIFT-128 state between the 4th and 5th mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_permute_state_4(s0, s1, s2, s3) \
    do { \
        s0 = ((s0 >> 6) & 0x03030303U) | ((s0 & 0x3F3F3F3FU) << 2); \
        s1 = ((s1 >> 4) & 0x0F0F0F0FU) | ((s1 & 0x0F0F0F0FU) << 4); \
        s2 = ((s2 >> 2) & 0x3F3F3F3FU) | ((s2 & 0x03030303U) << 6); \
    } while (0);

/**
 * \brief Permutes the GIFT-128 state between the 5th and 1st mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_permute_state_5(s0, s1, s2, s3) \
    do { \
        s1 = leftRotate16(s1); \
        s2 = rightRotate8(s2); \
        s3 = leftRotate8(s3); \
    } while (0);

/**
 * \brief Inverts the GIFT-128 state between the 1st and 2nd mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_inv_permute_state_1(s0, s1, s2, s3) \
    do { \
        s1 = ((s1 >> 2) & 0x33333333U) | ((s1 & 0x33333333U) << 2); \
        s2 = ((s2 >> 1) & 0x77777777U) | ((s2 & 0x11111111U) << 3); \
        s3 = ((s3 >> 3) & 0x11111111U) | ((s3 & 0x77777777U) << 1); \
    } while (0);

/**
 * \brief Inverts the GIFT-128 state between the 2nd and 3rd mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_inv_permute_state_2(s0, s1, s2, s3) \
    do { \
        s0 = ((s0 >> 12) & 0x000F000FU) | ((s0 & 0x0FFF0FFFU) << 4); \
        s1 = ((s1 >>  8) & 0x00FF00FFU) | ((s1 & 0x00FF00FFU) << 8); \
        s2 = ((s2 >>  4) & 0x0FFF0FFFU) | ((s2 & 0x000F000FU) << 12); \
    } while (0);

/**
 * \brief Inverts the GIFT-128 state between the 3rd and 4th mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_inv_permute_state_3(s0, s1, s2, s3) \
    do { \
        gift128b_swap_move(s1, s1, 0x55555555U, 1); \
        gift128b_swap_move(s2, s2, 0x00005555U, 1); \
        s2 = leftRotate16(s2); \
        gift128b_swap_move(s3, s3, 0x55550000U, 1); \
        s3 = leftRotate16(s3); \
    } while (0);

/**
 * \brief Inverts the GIFT-128 state between the 4th and 5th mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_inv_permute_state_4(s0, s1, s2, s3) \
    do { \
        s0 = ((s0 >> 2) & 0x3F3F3F3FU) | ((s0 & 0x03030303U) << 6); \
        s1 = ((s1 >> 4) & 0x0F0F0F0FU) | ((s1 & 0x0F0F0F0FU) << 4); \
        s2 = ((s2 >> 6) & 0x03030303U) | ((s2 & 0x3F3F3F3FU) << 2); \
    } while (0);

/**
 * \brief Inverts the GIFT-128 state between the 5th and 1st mini-rounds.
 *
 * \param s0 First word of the bit-sliced state.
 * \param s1 Second word of the bit-sliced state.
 * \param s2 Third word of the bit-sliced state.
 * \param s3 Fourth word of the bit-sliced state.
 */
#define gift128b_inv_permute_state_5(s0, s1, s2, s3) \
    do { \
        s1 = leftRotate16(s1); \
        s2 = leftRotate8(s2); \
        s3 = rightRotate8(s3); \
    } while (0);

/**
 * \brief Performs five fixsliced encryption rounds for GIFT-128.
 *
 * \param rk Points to the 10 round keys for these rounds.
 * \param rc Points to the round constants for these rounds.
 *
 * We perform all 40 rounds of the fixsliced GIFT-128 five at a time.
 *
 * The permutation is restructured so that one of the words each round
 * does not need to be permuted, with the others rotating left, up, right,
 * and down to keep the bits in line with their non-moving counterparts.
 * This reduces the number of shifts required significantly.
 *
 * At the end of five rounds, the bit ordering will return to the
 * original position.  We then repeat the process for the next 5 rounds.
 */
#define gift128b_encrypt_5_rounds(rk, rc) \
    do { \
        /* 1st round - S-box, rotate left, add round key */ \
        gift128b_sbox(s0, s1, s2, s3); \
        gift128b_permute_state_1(s0, s1, s2, s3); \
        s1 ^= (rk)[0]; \
        s2 ^= (rk)[1]; \
        s0 ^= (rc)[0]; \
        \
        /* 2nd round - S-box, rotate up, add round key */ \
        gift128b_sbox(s3, s1, s2, s0); \
        gift128b_permute_state_2(s0, s1, s2, s3); \
        s1 ^= (rk)[2]; \
        s2 ^= (rk)[3]; \
        s3 ^= (rc)[1]; \
        \
        /* 3rd round - S-box, swap columns, add round key */ \
        gift128b_sbox(s0, s1, s2, s3); \
        gift128b_permute_state_3(s0, s1, s2, s3); \
        s1 ^= (rk)[4]; \
        s2 ^= (rk)[5]; \
        s0 ^= (rc)[2]; \
        \
        /* 4th round - S-box, rotate left and swap rows, add round key */ \
        gift128b_sbox(s3, s1, s2, s0); \
        gift128b_permute_state_4(s0, s1, s2, s3); \
        s1 ^= (rk)[6]; \
        s2 ^= (rk)[7]; \
        s3 ^= (rc)[3]; \
        \
        /* 5th round - S-box, rotate up, add round key */ \
        gift128b_sbox(s0, s1, s2, s3); \
        gift128b_permute_state_5(s0, s1, s2, s3); \
        s1 ^= (rk)[8]; \
        s2 ^= (rk)[9]; \
        s0 ^= (rc)[4]; \
        \
        /* Swap s0 and s3 in preparation for the next 1st round */ \
        s0 ^= s3; \
        s3 ^= s0; \
        s0 ^= s3; \
    } while (0)

/**
 * \brief Performs five fixsliced decryption rounds for GIFT-128.
 *
 * \param rk Points to the 10 round keys for these rounds.
 * \param rc Points to the round constants for these rounds.
 *
 * We perform all 40 rounds of the fixsliced GIFT-128 five at a time.
 */
#define gift128b_decrypt_5_rounds(rk, rc) \
    do { \
        /* Swap s0 and s3 in preparation for the next 5th round */ \
        s0 ^= s3; \
        s3 ^= s0; \
        s0 ^= s3; \
        \
        /* 5th round - S-box, rotate down, add round key */ \
        s1 ^= (rk)[8]; \
        s2 ^= (rk)[9]; \
        s0 ^= (rc)[4]; \
        gift128b_inv_permute_state_5(s0, s1, s2, s3); \
        gift128b_inv_sbox(s3, s1, s2, s0); \
        \
        /* 4th round - S-box, rotate right and swap rows, add round key */ \
        s1 ^= (rk)[6]; \
        s2 ^= (rk)[7]; \
        s3 ^= (rc)[3]; \
        gift128b_inv_permute_state_4(s0, s1, s2, s3); \
        gift128b_inv_sbox(s0, s1, s2, s3); \
        \
        /* 3rd round - S-box, swap columns, add round key */ \
        s1 ^= (rk)[4]; \
        s2 ^= (rk)[5]; \
        s0 ^= (rc)[2]; \
        gift128b_inv_permute_state_3(s0, s1, s2, s3); \
        gift128b_inv_sbox(s3, s1, s2, s0); \
        \
        /* 2nd round - S-box, rotate down, add round key */ \
        s1 ^= (rk)[2]; \
        s2 ^= (rk)[3]; \
        s3 ^= (rc)[1]; \
        gift128b_inv_permute_state_2(s0, s1, s2, s3); \
        gift128b_inv_sbox(s0, s1, s2, s3); \
        \
        /* 1st round - S-box, rotate right, add round key */ \
        s1 ^= (rk)[0]; \
        s2 ^= (rk)[1]; \
        s0 ^= (rc)[0]; \
        gift128b_inv_permute_state_1(s0, s1, s2, s3); \
        gift128b_inv_sbox(s3, s1, s2, s0); \
    } while (0)

void gift128b_encrypt
    (const gift128b_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;

    /* Copy the plaintext into the state buffer and convert from big endian */
    s0 = be_load_word32(input);
    s1 = be_load_word32(input + 4);
    s2 = be_load_word32(input + 8);
    s3 = be_load_word32(input + 12);

    /* Perform all 40 rounds five at a time using the fixsliced method */
    gift128b_encrypt_5_rounds(ks->k, GIFT128_RC);
    gift128b_encrypt_5_rounds(ks->k + 10, GIFT128_RC + 5);
    gift128b_encrypt_5_rounds(ks->k + 20, GIFT128_RC + 10);
    gift128b_encrypt_5_rounds(ks->k + 30, GIFT128_RC + 15);
    gift128b_encrypt_5_rounds(ks->k + 40, GIFT128_RC + 20);
    gift128b_encrypt_5_rounds(ks->k + 50, GIFT128_RC + 25);
    gift128b_encrypt_5_rounds(ks->k + 60, GIFT128_RC + 30);
    gift128b_encrypt_5_rounds(ks->k + 70, GIFT128_RC + 35);

    /* Pack the state into the ciphertext buffer in big endian */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
}

void gift128b_decrypt
    (const gift128b_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;

    /* Copy the plaintext into the state buffer and convert from big endian */
    s0 = be_load_word32(input);
    s1 = be_load_word32(input + 4);
    s2 = be_load_word32(input + 8);
    s3 = be_load_word32(input + 12);

    /* Perform all 40 rounds five at a time using the fixsliced method */
    gift128b_decrypt_5_rounds(ks->k + 70, GIFT128_RC + 35);
    gift128b_decrypt_5_rounds(ks->k + 60, GIFT128_RC + 30);
    gift128b_decrypt_5_rounds(ks->k + 50, GIFT128_RC + 25);
    gift128b_decrypt_5_rounds(ks->k + 40, GIFT128_RC + 20);
    gift128b_decrypt_5_rounds(ks->k + 30, GIFT128_RC + 15);
    gift128b_decrypt_5_rounds(ks->k + 20, GIFT128_RC + 10);
    gift128b_decrypt_5_rounds(ks->k + 10, GIFT128_RC + 5);
    gift128b_decrypt_5_rounds(ks->k, GIFT128_RC);

    /* Pack the state into the ciphertext buffer in big endian */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
}

int gift128n_init
    (gift128n_key_schedule_t *ks, const unsigned char *key, size_t key_len)
{
    /* Use the little-endian key byte order from the HYENA submission */
    if (!ks || !key || key_len != 16)
        return 0;
    gift128b_compute_round_keys
        (ks, le_load_word32(key + 12), le_load_word32(key + 8),
             le_load_word32(key + 4), le_load_word32(key));
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
 * \brief Converts the GIFT-128 nibble-based representation into word-based.
 *
 * \param output Output buffer to write the word-based version to.
 * \param input Input buffer to read the nibble-based version from.
 *
 * The \a input and \a output buffers can be the same buffer.
 */
static void gift128n_to_words
    (unsigned char *output, const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;

    /* Load the input buffer into 32-bit words.  We use the nibble order
     * from the HYENA submission to NIST which is byte-reversed with respect
     * to the nibble order of the original GIFT-128 paper.  Nibble zero is in
     * the first byte instead of the last, which means little-endian order. */
    s0 = le_load_word32(input + 12);
    s1 = le_load_word32(input + 8);
    s2 = le_load_word32(input + 4);
    s3 = le_load_word32(input);

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
            bit_permute_step(x, 0x0a0a0a0a, 3); \
            bit_permute_step(x, 0x00cc00cc, 6); \
            bit_permute_step(x, 0x0000f0f0, 12); \
            bit_permute_step(x, 0x0000ff00, 8); \
            (_x) = x; \
        } while (0)
    PERM_WORDS(s0);
    PERM_WORDS(s1);
    PERM_WORDS(s2);
    PERM_WORDS(s3);

    /* Rearrange the bytes and write them to the output buffer */
    output[0]  = (uint8_t)s0;
    output[1]  = (uint8_t)s1;
    output[2]  = (uint8_t)s2;
    output[3]  = (uint8_t)s3;
    output[4]  = (uint8_t)(s0 >> 8);
    output[5]  = (uint8_t)(s1 >> 8);
    output[6]  = (uint8_t)(s2 >> 8);
    output[7]  = (uint8_t)(s3 >> 8);
    output[8]  = (uint8_t)(s0 >> 16);
    output[9]  = (uint8_t)(s1 >> 16);
    output[10] = (uint8_t)(s2 >> 16);
    output[11] = (uint8_t)(s3 >> 16);
    output[12] = (uint8_t)(s0 >> 24);
    output[13] = (uint8_t)(s1 >> 24);
    output[14] = (uint8_t)(s2 >> 24);
    output[15] = (uint8_t)(s3 >> 24);
}

/**
 * \brief Converts the GIFT-128 word-based representation into nibble-based.
 *
 * \param output Output buffer to write the nibble-based version to.
 * \param input Input buffer to read the word-based version from.
 */
static void gift128n_to_nibbles
    (unsigned char *output, const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;

    /* Load the input bytes and rearrange them so that s0 contains the
     * most significant nibbles and s3 contains the least significant */
    s0 = (((uint32_t)(input[12])) << 24) |
         (((uint32_t)(input[8]))  << 16) |
         (((uint32_t)(input[4]))  <<  8) |
          ((uint32_t)(input[0]));
    s1 = (((uint32_t)(input[13])) << 24) |
         (((uint32_t)(input[9]))  << 16) |
         (((uint32_t)(input[5]))  <<  8) |
          ((uint32_t)(input[1]));
    s2 = (((uint32_t)(input[14])) << 24) |
         (((uint32_t)(input[10])) << 16) |
         (((uint32_t)(input[6]))  <<  8) |
          ((uint32_t)(input[2]));
    s3 = (((uint32_t)(input[15])) << 24) |
         (((uint32_t)(input[11])) << 16) |
         (((uint32_t)(input[7]))  <<  8) |
          ((uint32_t)(input[3]));

    /* Apply the inverse of PERM_WORDS() from the function above */
    #define INV_PERM_WORDS(_x) \
        do { \
            uint32_t x = (_x); \
            bit_permute_step(x, 0x00aa00aa, 7); \
            bit_permute_step(x, 0x0000cccc, 14); \
            bit_permute_step(x, 0x00f000f0, 4); \
            bit_permute_step(x, 0x0000ff00, 8); \
            (_x) = x; \
        } while (0)
    INV_PERM_WORDS(s0);
    INV_PERM_WORDS(s1);
    INV_PERM_WORDS(s2);
    INV_PERM_WORDS(s3);

    /* Store the result into the output buffer as 32-bit words */
    le_store_word32(output + 12, s0);
    le_store_word32(output + 8,  s1);
    le_store_word32(output + 4,  s2);
    le_store_word32(output,      s3);
}

void gift128n_encrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128n_to_words(output, input);
    gift128b_encrypt(ks, output, output);
    gift128n_to_nibbles(output, output);
}

void gift128n_decrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128n_to_words(output, input);
    gift128b_decrypt(ks, output, output);
    gift128n_to_nibbles(output, output);
}

/* 4-bit tweak values expanded to 32-bit */
static uint32_t const GIFT128_tweaks[16] = {
    0x00000000, 0xe1e1e1e1, 0xd2d2d2d2, 0x33333333,
    0xb4b4b4b4, 0x55555555, 0x66666666, 0x87878787,
    0x78787878, 0x99999999, 0xaaaaaaaa, 0x4b4b4b4b,
    0xcccccccc, 0x2d2d2d2d, 0x1e1e1e1e, 0xffffffff
};

void gift128t_encrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak)
{
    uint32_t s0, s1, s2, s3, tword;

    /* Copy the plaintext into the state buffer and convert from nibbles */
    gift128n_to_words(output, input);
    s0 = be_load_word32(output);
    s1 = be_load_word32(output + 4);
    s2 = be_load_word32(output + 8);
    s3 = be_load_word32(output + 12);

    /* Perform all 40 rounds five at a time using the fixsliced method.
     * Every 5 rounds except the last we add the tweak value to the state */
    tword = GIFT128_tweaks[tweak];
    gift128b_encrypt_5_rounds(ks->k, GIFT128_RC);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 10, GIFT128_RC + 5);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 20, GIFT128_RC + 10);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 30, GIFT128_RC + 15);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 40, GIFT128_RC + 20);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 50, GIFT128_RC + 25);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 60, GIFT128_RC + 30);
    s0 ^= tword;
    gift128b_encrypt_5_rounds(ks->k + 70, GIFT128_RC + 35);

    /* Pack the state into the ciphertext buffer in nibble form */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
    gift128n_to_nibbles(output, output);
}

void gift128t_decrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak)
{
    uint32_t s0, s1, s2, s3, tword;

    /* Copy the ciphertext into the state buffer and convert from nibbles */
    gift128n_to_words(output, input);
    s0 = be_load_word32(output);
    s1 = be_load_word32(output + 4);
    s2 = be_load_word32(output + 8);
    s3 = be_load_word32(output + 12);

    /* Perform all 40 rounds five at a time using the fixsliced method.
     * Every 5 rounds except the first we add the tweak value to the state */
    tword = GIFT128_tweaks[tweak];
    gift128b_decrypt_5_rounds(ks->k + 70, GIFT128_RC + 35);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k + 60, GIFT128_RC + 30);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k + 50, GIFT128_RC + 25);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k + 40, GIFT128_RC + 20);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k + 30, GIFT128_RC + 15);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k + 20, GIFT128_RC + 10);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k + 10, GIFT128_RC + 5);
    s0 ^= tword;
    gift128b_decrypt_5_rounds(ks->k, GIFT128_RC);

    /* Pack the state into the plaintext buffer in nibble form */
    be_store_word32(output,      s0);
    be_store_word32(output + 4,  s1);
    be_store_word32(output + 8,  s2);
    be_store_word32(output + 12, s3);
    gift128n_to_nibbles(output, output);
}
