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

#include "internal-skinny128.h"
#include "internal-skinnyutil.h"
#include "internal-util.h"
#include <string.h>

#if !defined(__AVR__)

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

void skinny_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char key[48])
{
#if !SKINNY_128_SMALL_SCHEDULE
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;
#endif

#if SKINNY_128_SMALL_SCHEDULE
    /* Copy the input key as-is when using the small key schedule version */
    memcpy(ks->TK1, key, sizeof(ks->TK1));
    memcpy(ks->TK2, key + 16, sizeof(ks->TK2));
    memcpy(ks->TK3, key + 32, sizeof(ks->TK3));
#else
    /* Set the initial states of TK1, TK2, and TK3 */
    memcpy(ks->TK1, key, 16);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);
    TK3[0] = le_load_word32(key + 32);
    TK3[1] = le_load_word32(key + 36);
    TK3[2] = le_load_word32(key + 40);
    TK3[3] = le_load_word32(key + 44);

    /* Set up the key schedule using TK2 and TK3.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_384_ROUNDS; round += 2, schedule += 4) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ TK3[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ TK3[1] ^ (rc >> 4);

        /* Permute the bottom half of TK2 and TK3 for the next round */
        skinny128_permute_tk_half(TK2[2], TK2[3]);
        skinny128_permute_tk_half(TK3[2], TK3[3]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
        skinny128_LFSR3(TK3[2]);
        skinny128_LFSR3(TK3[3]);

        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[2] = TK2[2] ^ TK3[2] ^ (rc & 0x0F);
        schedule[3] = TK2[3] ^ TK3[3] ^ (rc >> 4);

        /* Permute the top half of TK2 and TK3 for the next round */
        skinny128_permute_tk_half(TK2[0], TK2[1]);
        skinny128_permute_tk_half(TK3[0], TK3[1]);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
    }
#endif
}

/**
 * \brief Performs an unrolled round for Skinny-128-384 when only TK1 is
 * computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_128_384_round(s0, s1, s2, s3, half, offset) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        s0 ^= schedule[offset * 2]     ^ TK1[half * 2]; \
        s1 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1]; \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
    } while (0)

/**
 * \brief Performs an unrolled round for Skinny-128-384 when the entire
 * tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_128_384_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01; \
        rc &= 0x3F; \
        s0 ^= TK1[half * 2] ^ TK2[half * 2] ^ TK3[half * 2] ^ (rc & 0x0F); \
        s1 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ TK3[half * 2 + 1] ^ \
              (rc >> 4); \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1, TK2, and TK3 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK3[(1 - half) * 2], TK3[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK2[(1 - half) * 2]); \
        skinny128_LFSR2(TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR3(TK3[(1 - half) * 2]); \
        skinny128_LFSR3(TK3[(1 - half) * 2 + 1]); \
    } while (0)

void skinny_128_384_encrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_128_SMALL_SCHEDULE
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint8_t rc = 0;
#else
    const uint32_t *schedule = ks->k;
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_128_SMALL_SCHEDULE
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_128_384_ROUNDS; round += 4) {
#if SKINNY_128_SMALL_SCHEDULE
        skinny_128_384_round_tk_full(s0, s1, s2, s3, 0);
        skinny_128_384_round_tk_full(s3, s0, s1, s2, 1);
        skinny_128_384_round_tk_full(s2, s3, s0, s1, 0);
        skinny_128_384_round_tk_full(s1, s2, s3, s0, 1);
#else
        skinny_128_384_round(s0, s1, s2, s3, 0, 0);
        skinny_128_384_round(s3, s0, s1, s2, 1, 1);
        skinny_128_384_round(s2, s3, s0, s1, 0, 2);
        skinny_128_384_round(s1, s2, s3, s0, 1, 3);
        schedule += 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

/**
 * \brief Performs an unrolled inverse round for Skinny-128-384 when
 * only TK1 is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_128_384_inv_round(s0, s1, s2, s3, half, offset) \
    do { \
        /* Inverse permutation on TK1 for this round */ \
        skinny128_inv_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        \
        /* Inverse mix of the columns, without word rotation */ \
        s0 ^= s3; \
        s3 ^= s1; \
        s2 ^= s3; \
        \
        /* Inverse shift of the rows */ \
        s2 = leftRotate24(s2); \
        s3 = leftRotate16(s3); \
        s0 = leftRotate8(s0); \
        \
        /* Apply the subkey for this round */ \
        s1 ^= schedule[offset * 2]     ^ TK1[half * 2]; \
        s2 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1]; \
        s3 ^= 0x02; \
        \
        /* Apply the inverse of the S-box to all bytes in the state */ \
        skinny128_inv_sbox(s0); \
        skinny128_inv_sbox(s1); \
        skinny128_inv_sbox(s2); \
        skinny128_inv_sbox(s3); \
    } while (0)

/**
 * \brief Performs an unrolled inverse round for Skinny-128-384 when the
 * entire tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_128_384_inv_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Inverse permutation on the tweakey for this round */ \
        skinny128_inv_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_inv_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_inv_permute_tk_half \
            (TK3[(1 - half) * 2], TK3[(1 - half) * 2 + 1]); \
        skinny128_LFSR3(TK2[(1 - half) * 2]); \
        skinny128_LFSR3(TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK3[(1 - half) * 2]); \
        skinny128_LFSR2(TK3[(1 - half) * 2 + 1]); \
        \
        /* Inverse mix of the columns, without word rotation */ \
        s0 ^= s3; \
        s3 ^= s1; \
        s2 ^= s3; \
        \
        /* Inverse shift of the rows */ \
        s2 = leftRotate24(s2); \
        s3 = leftRotate16(s3); \
        s0 = leftRotate8(s0); \
        \
        /* Apply the subkey for this round */ \
        rc = (rc >> 1) ^ (((rc << 5) ^ rc ^ 0x20) & 0x20); \
        s1 ^= TK1[half * 2] ^ TK2[half * 2] ^ TK3[half * 2] ^ (rc & 0x0F); \
        s2 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ TK3[half * 2 + 1] ^ \
              (rc >> 4); \
        s3 ^= 0x02; \
        \
        /* Apply the inverse of the S-box to all bytes in the state */ \
        skinny128_inv_sbox(s0); \
        skinny128_inv_sbox(s1); \
        skinny128_inv_sbox(s2); \
        skinny128_inv_sbox(s3); \
    } while (0)

void skinny_128_384_decrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_128_SMALL_SCHEDULE
    uint32_t TK2[4];
    uint32_t TK3[4];
    uint8_t rc = 0x15;
#else
    const uint32_t *schedule = &(ks->k[SKINNY_128_384_ROUNDS * 2 - 8]);
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_128_SMALL_SCHEDULE
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Permute TK1 to fast-forward it to the end of the key schedule */
    skinny128_fast_forward_tk(TK1);
#if SKINNY_128_SMALL_SCHEDULE
    skinny128_fast_forward_tk(TK2);
    skinny128_fast_forward_tk(TK3);
    for (round = 0; round < SKINNY_128_384_ROUNDS; round += 2) {
        /* Also fast-forward the LFSR's on every byte of TK2 and TK3 */
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
        skinny128_LFSR3(TK3[0]);
        skinny128_LFSR3(TK3[1]);
        skinny128_LFSR3(TK3[2]);
        skinny128_LFSR3(TK3[3]);
    }
#endif

    /* Perform all decryption rounds four at a time */
    for (round = 0; round < SKINNY_128_384_ROUNDS; round += 4) {
#if SKINNY_128_SMALL_SCHEDULE
        skinny_128_384_inv_round_tk_full(s0, s1, s2, s3, 1);
        skinny_128_384_inv_round_tk_full(s1, s2, s3, s0, 0);
        skinny_128_384_inv_round_tk_full(s2, s3, s0, s1, 1);
        skinny_128_384_inv_round_tk_full(s3, s0, s1, s2, 0);
#else
        skinny_128_384_inv_round(s0, s1, s2, s3, 1, 3);
        skinny_128_384_inv_round(s1, s2, s3, s0, 0, 2);
        skinny_128_384_inv_round(s2, s3, s0, s1, 1, 1);
        skinny_128_384_inv_round(s3, s0, s1, s2, 0, 0);
        schedule -= 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

/**
 * \def skinny_128_384_round_tk2(s0, s1, s2, s3, half)
 * \brief Performs an unrolled round for skinny_128_384_encrypt_tk2().
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#if SKINNY_128_SMALL_SCHEDULE
#define skinny_128_384_round_tk2(s0, s1, s2, s3, half, offset) \
    skinny_128_384_round_tk_full(s0, s1, s2, s3, half)
#else /* !SKINNY_128_SMALL_SCHEDULE */
#define skinny_128_384_round_tk2(s0, s1, s2, s3, half, offset) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        s0 ^= schedule[offset * 2] ^ TK1[half * 2] ^ TK2[half * 2]; \
        s1 ^= schedule[offset * 2 + 1] ^ TK1[half * 2 + 1] ^ \
              TK2[half * 2 + 1]; \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1 and TK2 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK2[(1 - half) * 2]); \
        skinny128_LFSR2(TK2[(1 - half) * 2 + 1]); \
    } while (0)
#endif /* !SKINNY_128_SMALL_SCHEDULE */

void skinny_128_384_encrypt_tk2
    (skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk2)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
#if SKINNY_128_SMALL_SCHEDULE
    uint32_t TK3[4];
    uint8_t rc = 0;
#else
    const uint32_t *schedule = ks->k;
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
    TK2[0] = le_load_word32(tk2);
    TK2[1] = le_load_word32(tk2 + 4);
    TK2[2] = le_load_word32(tk2 + 8);
    TK2[3] = le_load_word32(tk2 + 12);
#if SKINNY_128_SMALL_SCHEDULE
    TK3[0] = le_load_word32(ks->TK3);
    TK3[1] = le_load_word32(ks->TK3 + 4);
    TK3[2] = le_load_word32(ks->TK3 + 8);
    TK3[3] = le_load_word32(ks->TK3 + 12);
#endif

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_128_384_ROUNDS; round += 4) {
        skinny_128_384_round_tk2(s0, s1, s2, s3, 0, 0);
        skinny_128_384_round_tk2(s3, s0, s1, s2, 1, 1);
        skinny_128_384_round_tk2(s2, s3, s0, s1, 0, 2);
        skinny_128_384_round_tk2(s1, s2, s3, s0, 1, 3);
#if !SKINNY_128_SMALL_SCHEDULE
        schedule += 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_384_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    uint32_t TK3[4];
    unsigned round;
    uint8_t rc = 0;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakey */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);
    TK3[0] = le_load_word32(key + 32);
    TK3[1] = le_load_word32(key + 36);
    TK3[2] = le_load_word32(key + 40);
    TK3[3] = le_load_word32(key + 44);

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_128_384_ROUNDS; round += 4) {
        skinny_128_384_round_tk_full(s0, s1, s2, s3, 0);
        skinny_128_384_round_tk_full(s3, s0, s1, s2, 1);
        skinny_128_384_round_tk_full(s2, s3, s0, s1, 0);
        skinny_128_384_round_tk_full(s1, s2, s3, s0, 1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_256_init
    (skinny_128_256_key_schedule_t *ks, const unsigned char key[32])
{
#if !SKINNY_128_SMALL_SCHEDULE
    uint32_t TK2[4];
    uint32_t *schedule;
    unsigned round;
    uint8_t rc;
#endif

#if SKINNY_128_SMALL_SCHEDULE
    /* Copy the input key as-is when using the small key schedule version */
    memcpy(ks->TK1, key, sizeof(ks->TK1));
    memcpy(ks->TK2, key + 16, sizeof(ks->TK2));
#else
    /* Set the initial states of TK1 and TK2 */
    memcpy(ks->TK1, key, 16);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);

    /* Set up the key schedule using TK2.  TK1 is not added
     * to the key schedule because we will derive that part of the
     * schedule during encryption operations */
    schedule = ks->k;
    rc = 0;
    for (round = 0; round < SKINNY_128_256_ROUNDS; round += 2, schedule += 4) {
        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[0] = TK2[0] ^ (rc & 0x0F);
        schedule[1] = TK2[1] ^ (rc >> 4);

        /* Permute the bottom half of TK2 for the next round */
        skinny128_permute_tk_half(TK2[2], TK2[3]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);

        /* XOR the round constants with the current schedule words.
         * The round constants for the 3rd and 4th rows are
         * fixed and will be applied during encryption. */
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
        rc &= 0x3F;
        schedule[2] = TK2[2] ^ (rc & 0x0F);
        schedule[3] = TK2[3] ^ (rc >> 4);

        /* Permute the top half of TK2 for the next round */
        skinny128_permute_tk_half(TK2[0], TK2[1]);
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
    }
#endif
}

/**
 * \brief Performs an unrolled round for Skinny-128-256 when only TK1 is
 * computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_128_256_round(s0, s1, s2, s3, half, offset) \
    skinny_128_384_round(s0, s1, s2, s3, half, offset)

/**
 * \brief Performs an unrolled round for Skinny-128-256 when the entire
 * tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_128_256_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Apply the S-box to all bytes in the state */ \
        skinny128_sbox(s0); \
        skinny128_sbox(s1); \
        skinny128_sbox(s2); \
        skinny128_sbox(s3); \
        \
        /* XOR the round constant and the subkey for this round */ \
        rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01; \
        rc &= 0x3F; \
        s0 ^= TK1[half * 2] ^ TK2[half * 2] ^ (rc & 0x0F); \
        s1 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ (rc >> 4); \
        s2 ^= 0x02; \
        \
        /* Shift the cells in the rows right, which moves the cell \
         * values up closer to the MSB.  That is, we do a left rotate \
         * on the word to rotate the cells in the word right */ \
        s1 = leftRotate8(s1); \
        s2 = leftRotate16(s2); \
        s3 = leftRotate24(s3); \
        \
        /* Mix the columns, but don't rotate the words yet */ \
        s1 ^= s2; \
        s2 ^= s0; \
        s3 ^= s2; \
        \
        /* Permute TK1, TK2, and TK3 in-place for the next round */ \
        skinny128_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR2(TK2[(1 - half) * 2]); \
        skinny128_LFSR2(TK2[(1 - half) * 2 + 1]); \
    } while (0)

void skinny_128_256_encrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_128_SMALL_SCHEDULE
    uint32_t TK2[4];
    uint8_t rc = 0;
#else
    const uint32_t *schedule = ks->k;
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1 */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_128_SMALL_SCHEDULE
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
#endif

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_128_256_ROUNDS; round += 4) {
#if SKINNY_128_SMALL_SCHEDULE
        skinny_128_256_round_tk_full(s0, s1, s2, s3, 0);
        skinny_128_256_round_tk_full(s3, s0, s1, s2, 1);
        skinny_128_256_round_tk_full(s2, s3, s0, s1, 0);
        skinny_128_256_round_tk_full(s1, s2, s3, s0, 1);
#else
        skinny_128_256_round(s0, s1, s2, s3, 0, 0);
        skinny_128_256_round(s3, s0, s1, s2, 1, 1);
        skinny_128_256_round(s2, s3, s0, s1, 0, 2);
        skinny_128_256_round(s1, s2, s3, s0, 1, 3);
        schedule += 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

/**
 * \brief Performs an unrolled inverse round for Skinny-128-256 when
 * only TK1 is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 * \param offset Offset between 0 and 3 of the current unrolled round.
 */
#define skinny_128_256_inv_round(s0, s1, s2, s3, half, offset) \
    skinny_128_384_inv_round(s0, s1, s2, s3, half, offset)

/**
 * \brief Performs an unrolled inverse round for Skinny-128-256 when the
 * entire tweakey schedule is computed on the fly.
 *
 * \param s0 First word of the state.
 * \param s1 Second word of the state.
 * \param s2 Third word of the state.
 * \param s3 Fourth word of the state.
 * \param half 0 for the bottom half and 1 for the top half of the TK values.
 */
#define skinny_128_256_inv_round_tk_full(s0, s1, s2, s3, half) \
    do { \
        /* Inverse permutation on the tweakey for this round */ \
        skinny128_inv_permute_tk_half \
            (TK1[(1 - half) * 2], TK1[(1 - half) * 2 + 1]); \
        skinny128_inv_permute_tk_half \
            (TK2[(1 - half) * 2], TK2[(1 - half) * 2 + 1]); \
        skinny128_LFSR3(TK2[(1 - half) * 2]); \
        skinny128_LFSR3(TK2[(1 - half) * 2 + 1]); \
        \
        /* Inverse mix of the columns, without word rotation */ \
        s0 ^= s3; \
        s3 ^= s1; \
        s2 ^= s3; \
        \
        /* Inverse shift of the rows */ \
        s2 = leftRotate24(s2); \
        s3 = leftRotate16(s3); \
        s0 = leftRotate8(s0); \
        \
        /* Apply the subkey for this round */ \
        rc = (rc >> 1) ^ (((rc << 5) ^ rc ^ 0x20) & 0x20); \
        s1 ^= TK1[half * 2] ^ TK2[half * 2] ^ (rc & 0x0F); \
        s2 ^= TK1[half * 2 + 1] ^ TK2[half * 2 + 1] ^ (rc >> 4); \
        s3 ^= 0x02; \
        \
        /* Apply the inverse of the S-box to all bytes in the state */ \
        skinny128_inv_sbox(s0); \
        skinny128_inv_sbox(s1); \
        skinny128_inv_sbox(s2); \
        skinny128_inv_sbox(s3); \
    } while (0)

void skinny_128_256_decrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
#if SKINNY_128_SMALL_SCHEDULE
    uint32_t TK2[4];
    uint8_t rc = 0x09;
#else
    const uint32_t *schedule = &(ks->k[SKINNY_128_256_ROUNDS * 2 - 8]);
#endif
    unsigned round;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakable part of the state, TK1.
     * There is no need to fast-forward TK1 because the value at
     * the end of the key schedule is the same as at the start */
    TK1[0] = le_load_word32(ks->TK1);
    TK1[1] = le_load_word32(ks->TK1 + 4);
    TK1[2] = le_load_word32(ks->TK1 + 8);
    TK1[3] = le_load_word32(ks->TK1 + 12);
#if SKINNY_128_SMALL_SCHEDULE
    TK2[0] = le_load_word32(ks->TK2);
    TK2[1] = le_load_word32(ks->TK2 + 4);
    TK2[2] = le_load_word32(ks->TK2 + 8);
    TK2[3] = le_load_word32(ks->TK2 + 12);
    for (round = 0; round < SKINNY_128_256_ROUNDS; round += 2) {
        /* Also fast-forward the LFSR's on every byte of TK2 */
        skinny128_LFSR2(TK2[0]);
        skinny128_LFSR2(TK2[1]);
        skinny128_LFSR2(TK2[2]);
        skinny128_LFSR2(TK2[3]);
    }
#endif

    /* Perform all decryption rounds four at a time */
    for (round = 0; round < SKINNY_128_256_ROUNDS; round += 4) {
#if SKINNY_128_SMALL_SCHEDULE
        skinny_128_256_inv_round_tk_full(s0, s1, s2, s3, 1);
        skinny_128_256_inv_round_tk_full(s1, s2, s3, s0, 0);
        skinny_128_256_inv_round_tk_full(s2, s3, s0, s1, 1);
        skinny_128_256_inv_round_tk_full(s3, s0, s1, s2, 0);
#else
        skinny_128_256_inv_round(s0, s1, s2, s3, 1, 3);
        skinny_128_256_inv_round(s1, s2, s3, s0, 0, 2);
        skinny_128_256_inv_round(s2, s3, s0, s1, 1, 1);
        skinny_128_256_inv_round(s3, s0, s1, s2, 0, 0);
        schedule -= 8;
#endif
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

void skinny_128_256_encrypt_tk_full
    (const unsigned char key[32], unsigned char *output,
     const unsigned char *input)
{
    uint32_t s0, s1, s2, s3;
    uint32_t TK1[4];
    uint32_t TK2[4];
    unsigned round;
    uint8_t rc = 0;

    /* Unpack the input block into the state array */
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Make a local copy of the tweakey */
    TK1[0] = le_load_word32(key);
    TK1[1] = le_load_word32(key + 4);
    TK1[2] = le_load_word32(key + 8);
    TK1[3] = le_load_word32(key + 12);
    TK2[0] = le_load_word32(key + 16);
    TK2[1] = le_load_word32(key + 20);
    TK2[2] = le_load_word32(key + 24);
    TK2[3] = le_load_word32(key + 28);

    /* Perform all encryption rounds four at a time */
    for (round = 0; round < SKINNY_128_256_ROUNDS; round += 4) {
        skinny_128_256_round_tk_full(s0, s1, s2, s3, 0);
        skinny_128_256_round_tk_full(s3, s0, s1, s2, 1);
        skinny_128_256_round_tk_full(s2, s3, s0, s1, 0);
        skinny_128_256_round_tk_full(s1, s2, s3, s0, 1);
    }

    /* Pack the result into the output buffer */
    le_store_word32(output,      s0);
    le_store_word32(output + 4,  s1);
    le_store_word32(output + 8,  s2);
    le_store_word32(output + 12, s3);
}

#else /* __AVR__ */

void skinny_128_384_encrypt_tk2
    (skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk2)
{
    memcpy(ks->TK2, tk2, 16);
    skinny_128_384_encrypt(ks, output, input);
}

#endif /* __AVR__ */
