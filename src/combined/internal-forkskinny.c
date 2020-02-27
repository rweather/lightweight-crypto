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

#include "internal-forkskinny.h"
#include "internal-skinnyutil.h"

/**
 * \brief 7-bit round constants for all ForkSkinny block ciphers.
 */
static unsigned char const RC[87] = {
    0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d,
    0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73,
    0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57,
    0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d,
    0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53,
    0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15,
    0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02,
    0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71,
    0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b,
    0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25,
    0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10
};

/**
 * \brief Number of rounds of ForkSkinny-128-256 before forking.
 */
#define FORKSKINNY_128_256_ROUNDS_BEFORE 21

/**
 * \brief Number of rounds of ForkSkinny-128-256 after forking.
 */
#define FORKSKINNY_128_256_ROUNDS_AFTER 27

/**
 * \brief State information for ForkSkinny-128-256.
 */
typedef struct
{
    uint32_t TK1[4];        /**< First part of the tweakey */
    uint32_t TK2[4];        /**< Second part of the tweakey */
    uint32_t S[4];          /**< Current block state */

} forkskinny_128_256_state_t;

/**
 * \brief Applies one round of ForkSkinny-128-256.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_round
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny128_sbox(s0);
    skinny128_sbox(s1);
    skinny128_sbox(s2);
    skinny128_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
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

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1 and TK2 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
}

void forkskinny_128_256_encrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_128_256_ROUNDS_BEFORE; ++round) {
        forkskinny_128_256_round(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                         FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
            forkskinny_128_256_round(&state, round);
        }
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x08040201U; /* Branching constant */
        state.S[1] ^= 0x82412010U;
        state.S[2] ^= 0x28140a05U;
        state.S[3] ^= 0x8844a251U;
        for (round = (FORKSKINNY_128_256_ROUNDS_BEFORE +
                      FORKSKINNY_128_256_ROUNDS_AFTER);
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                          FORKSKINNY_128_256_ROUNDS_AFTER * 2); ++round) {
            forkskinny_128_256_round(&state, round);
        }
        le_store_word32(output_left,      state.S[0]);
        le_store_word32(output_left + 4,  state.S[1]);
        le_store_word32(output_left + 8,  state.S[2]);
        le_store_word32(output_left + 12, state.S[3]);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                         FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
            forkskinny_128_256_round(&state, round);
        }
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);
    }
}

/**
 * \brief Applies one round of ForkSkinny-128-256 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_256_inv_round
    (forkskinny_128_256_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left, which moves the cell
     * values down closer to the LSB.  That is, we do a right
     * rotate on the word to rotate the cells in the word left */
    s1 = rightRotate8(s1);
    s2 = rightRotate16(s2);
    s3 = rightRotate24(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny128_inv_sbox(s0);
    skinny128_inv_sbox(s1);
    skinny128_inv_sbox(s2);
    skinny128_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_256_decrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_256_state_t state;
    forkskinny_128_256_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                             FORKSKINNY_128_256_ROUNDS_AFTER * 2); ++round) {
        skinny128_permute_tk(state.TK1);
        skinny128_permute_tk(state.TK2);
        skinny128_LFSR2(state.TK2[0]);
        skinny128_LFSR2(state.TK2[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_128_256_ROUNDS_BEFORE +
                  FORKSKINNY_128_256_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER); --round) {
        forkskinny_128_256_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_128_256_ROUNDS_AFTER; ++round) {
        skinny128_inv_LFSR2(state.TK2[0]);
        skinny128_inv_LFSR2(state.TK2[1]);
        skinny128_inv_permute_tk(state.TK1);
        skinny128_inv_permute_tk(state.TK2);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_128_256_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_128_256_inv_round(&state, round - 1);
    }
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_128_256_ROUNDS_BEFORE;
            round < (FORKSKINNY_128_256_ROUNDS_BEFORE +
                     FORKSKINNY_128_256_ROUNDS_AFTER); ++round) {
        forkskinny_128_256_round(&fstate, round);
    }
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

/**
 * \brief Number of rounds of ForkSkinny-128-384 before forking.
 */
#define FORKSKINNY_128_384_ROUNDS_BEFORE 25

/**
 * \brief Number of rounds of ForkSkinny-128-384 after forking.
 */
#define FORKSKINNY_128_384_ROUNDS_AFTER 31

/**
 * \brief State information for ForkSkinny-128-384.
 */
typedef struct
{
    uint32_t TK1[4];        /**< First part of the tweakey */
    uint32_t TK2[4];        /**< Second part of the tweakey */
    uint32_t TK3[4];        /**< Third part of the tweakey */
    uint32_t S[4];          /**< Current block state */

} forkskinny_128_384_state_t;

/**
 * \brief Applies one round of ForkSkinny-128-384.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_round
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny128_sbox(s0);
    skinny128_sbox(s1);
    skinny128_sbox(s2);
    skinny128_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
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

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny128_permute_tk(state->TK1);
    skinny128_permute_tk(state->TK2);
    skinny128_permute_tk(state->TK3);
    skinny128_LFSR2(state->TK2[0]);
    skinny128_LFSR2(state->TK2[1]);
    skinny128_LFSR3(state->TK3[0]);
    skinny128_LFSR3(state->TK3[1]);
}

void forkskinny_128_384_encrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.TK3[0] = le_load_word32(key + 32);
    state.TK3[1] = le_load_word32(key + 36);
    state.TK3[2] = le_load_word32(key + 40);
    state.TK3[3] = le_load_word32(key + 44);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_128_384_ROUNDS_BEFORE; ++round) {
        forkskinny_128_384_round(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint32_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                         FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
            forkskinny_128_384_round(&state, round);
        }
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x08040201U; /* Branching constant */
        state.S[1] ^= 0x82412010U;
        state.S[2] ^= 0x28140a05U;
        state.S[3] ^= 0x8844a251U;
        for (round = (FORKSKINNY_128_384_ROUNDS_BEFORE +
                      FORKSKINNY_128_384_ROUNDS_AFTER);
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                          FORKSKINNY_128_384_ROUNDS_AFTER * 2); ++round) {
            forkskinny_128_384_round(&state, round);
        }
        le_store_word32(output_left,      state.S[0]);
        le_store_word32(output_left + 4,  state.S[1]);
        le_store_word32(output_left + 8,  state.S[2]);
        le_store_word32(output_left + 12, state.S[3]);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
                round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                         FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
            forkskinny_128_384_round(&state, round);
        }
        le_store_word32(output_right,      state.S[0]);
        le_store_word32(output_right + 4,  state.S[1]);
        le_store_word32(output_right + 8,  state.S[2]);
        le_store_word32(output_right + 12, state.S[3]);
    }
}

/**
 * \brief Applies one round of ForkSkinny-128-384 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_128_384_inv_round
    (forkskinny_128_384_state_t *state, unsigned round)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1 and TK2 for the next round */
    skinny128_inv_LFSR2(state->TK2[0]);
    skinny128_inv_LFSR2(state->TK2[1]);
    skinny128_inv_LFSR3(state->TK3[0]);
    skinny128_inv_LFSR3(state->TK3[1]);
    skinny128_inv_permute_tk(state->TK1);
    skinny128_inv_permute_tk(state->TK2);
    skinny128_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left, which moves the cell
     * values down closer to the LSB.  That is, we do a right
     * rotate on the word to rotate the cells in the word left */
    s1 = rightRotate8(s1);
    s2 = rightRotate16(s2);
    s3 = rightRotate24(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          (rc & 0x0F) ^ 0x00020000;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
    s2 ^= 0x02;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny128_inv_sbox(s0);
    skinny128_inv_sbox(s1);
    skinny128_inv_sbox(s2);
    skinny128_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_384_decrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_128_384_state_t state;
    forkskinny_128_384_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = le_load_word32(key);
    state.TK1[1] = le_load_word32(key + 4);
    state.TK1[2] = le_load_word32(key + 8);
    state.TK1[3] = le_load_word32(key + 12);
    state.TK2[0] = le_load_word32(key + 16);
    state.TK2[1] = le_load_word32(key + 20);
    state.TK2[2] = le_load_word32(key + 24);
    state.TK2[3] = le_load_word32(key + 28);
    state.TK3[0] = le_load_word32(key + 32);
    state.TK3[1] = le_load_word32(key + 36);
    state.TK3[2] = le_load_word32(key + 40);
    state.TK3[3] = le_load_word32(key + 44);
    state.S[0] = le_load_word32(input);
    state.S[1] = le_load_word32(input + 4);
    state.S[2] = le_load_word32(input + 8);
    state.S[3] = le_load_word32(input + 12);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                             FORKSKINNY_128_384_ROUNDS_AFTER * 2); ++round) {
        skinny128_permute_tk(state.TK1);
        skinny128_permute_tk(state.TK2);
        skinny128_permute_tk(state.TK3);
        skinny128_LFSR2(state.TK2[0]);
        skinny128_LFSR2(state.TK2[1]);
        skinny128_LFSR3(state.TK3[0]);
        skinny128_LFSR3(state.TK3[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_128_384_ROUNDS_BEFORE +
                  FORKSKINNY_128_384_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER); --round) {
        forkskinny_128_384_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x08040201U;
    state.S[1] ^= 0x82412010U;
    state.S[2] ^= 0x28140a05U;
    state.S[3] ^= 0x8844a251U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_128_384_ROUNDS_AFTER; ++round) {
        skinny128_inv_LFSR2(state.TK2[0]);
        skinny128_inv_LFSR2(state.TK2[1]);
        skinny128_inv_LFSR3(state.TK3[0]);
        skinny128_inv_LFSR3(state.TK3[1]);
        skinny128_inv_permute_tk(state.TK1);
        skinny128_inv_permute_tk(state.TK2);
        skinny128_inv_permute_tk(state.TK3);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_128_384_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_128_384_inv_round(&state, round - 1);
    }
    le_store_word32(output_left,      state.S[0]);
    le_store_word32(output_left + 4,  state.S[1]);
    le_store_word32(output_left + 8,  state.S[2]);
    le_store_word32(output_left + 12, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_128_384_ROUNDS_BEFORE;
            round < (FORKSKINNY_128_384_ROUNDS_BEFORE +
                     FORKSKINNY_128_384_ROUNDS_AFTER); ++round) {
        forkskinny_128_384_round(&fstate, round);
    }
    le_store_word32(output_right,      fstate.S[0]);
    le_store_word32(output_right + 4,  fstate.S[1]);
    le_store_word32(output_right + 8,  fstate.S[2]);
    le_store_word32(output_right + 12, fstate.S[3]);
}

/**
 * \brief Number of rounds of ForkSkinny-64-192 before forking.
 */
#define FORKSKINNY_64_192_ROUNDS_BEFORE 17

/**
 * \brief Number of rounds of ForkSkinny-64-192 after forking.
 */
#define FORKSKINNY_64_192_ROUNDS_AFTER 23

/**
 * \brief State information for ForkSkinny-64-192.
 */
typedef struct
{
    uint16_t TK1[4];    /**< First part of the tweakey */
    uint16_t TK2[4];    /**< Second part of the tweakey */
    uint16_t TK3[4];    /**< Third part of the tweakey */
    uint16_t S[4];      /**< Current block state */

} forkskinny_64_192_state_t;

/**
 * \brief Applies one round of ForkSkinny-64-192.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 *
 * Note: The cells of each row are order in big-endian nibble order
 * so it is easiest to manage the rows in bit-endian byte order.
 */
static void forkskinny_64_192_round
    (forkskinny_64_192_state_t *state, unsigned round)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Apply the S-box to all cells in the state */
    skinny64_sbox(s0);
    skinny64_sbox(s1);
    skinny64_sbox(s2);
    skinny64_sbox(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          ((rc & 0x0F) << 12) ^ 0x0020;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
          ((rc & 0x70) << 8);
    s2 ^= 0x2000;

    /* Shift the cells in the rows right */
    s1 = rightRotate4_16(s1);
    s2 = rightRotate8_16(s2);
    s3 = rightRotate12_16(s3);

    /* Mix the columns */
    s1 ^= s2;
    s2 ^= s0;
    temp = s3 ^ s2;
    s3 = s2;
    s2 = s1;
    s1 = s0;
    s0 = temp;

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny64_permute_tk(state->TK1);
    skinny64_permute_tk(state->TK2);
    skinny64_permute_tk(state->TK3);
    skinny64_LFSR2(state->TK2[0]);
    skinny64_LFSR2(state->TK2[1]);
    skinny64_LFSR3(state->TK3[0]);
    skinny64_LFSR3(state->TK3[1]);
}

void forkskinny_64_192_encrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = be_load_word16(key);
    state.TK1[1] = be_load_word16(key + 2);
    state.TK1[2] = be_load_word16(key + 4);
    state.TK1[3] = be_load_word16(key + 6);
    state.TK2[0] = be_load_word16(key + 8);
    state.TK2[1] = be_load_word16(key + 10);
    state.TK2[2] = be_load_word16(key + 12);
    state.TK2[3] = be_load_word16(key + 14);
    state.TK3[0] = be_load_word16(key + 16);
    state.TK3[1] = be_load_word16(key + 18);
    state.TK3[2] = be_load_word16(key + 20);
    state.TK3[3] = be_load_word16(key + 22);
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Run all of the rounds before the forking point */
    for (round = 0; round < FORKSKINNY_64_192_ROUNDS_BEFORE; ++round) {
        forkskinny_64_192_round(&state, round);
    }

    /* Determine which output blocks we need */
    if (output_left && output_right) {
        /* We need both outputs so save the state at the forking point */
        uint16_t F[4];
        F[0] = state.S[0];
        F[1] = state.S[1];
        F[2] = state.S[2];
        F[3] = state.S[3];

        /* Generate the right output block */
        for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                         FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);

        /* Restore the state at the forking point */
        state.S[0] = F[0];
        state.S[1] = F[1];
        state.S[2] = F[2];
        state.S[3] = F[3];
    }
    if (output_left) {
        /* Generate the left output block */
        state.S[0] ^= 0x1249U;  /* Branching constant */
        state.S[1] ^= 0x36daU;
        state.S[2] ^= 0x5b7fU;
        state.S[3] ^= 0xec81U;
        for (round = (FORKSKINNY_64_192_ROUNDS_BEFORE +
                      FORKSKINNY_64_192_ROUNDS_AFTER);
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                          FORKSKINNY_64_192_ROUNDS_AFTER * 2); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_left,     state.S[0]);
        be_store_word16(output_left + 2, state.S[1]);
        be_store_word16(output_left + 4, state.S[2]);
        be_store_word16(output_left + 6, state.S[3]);
    } else {
        /* We only need the right output block */
        for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
                round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                         FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
            forkskinny_64_192_round(&state, round);
        }
        be_store_word16(output_right,     state.S[0]);
        be_store_word16(output_right + 2, state.S[1]);
        be_store_word16(output_right + 4, state.S[2]);
        be_store_word16(output_right + 6, state.S[3]);
    }
}

/**
 * \brief Applies one round of ForkSkinny-64-192 in reverse.
 *
 * \param state State to apply the round to.
 * \param round Number of the round to apply.
 */
static void forkskinny_64_192_inv_round
    (forkskinny_64_192_state_t *state, unsigned round)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Permute TK1, TK2, and TK3 for the next round */
    skinny64_inv_LFSR2(state->TK2[0]);
    skinny64_inv_LFSR2(state->TK2[1]);
    skinny64_inv_LFSR3(state->TK3[0]);
    skinny64_inv_LFSR3(state->TK3[1]);
    skinny64_inv_permute_tk(state->TK1);
    skinny64_inv_permute_tk(state->TK2);
    skinny64_inv_permute_tk(state->TK3);

    /* Inverse mix of the columns */
    temp = s0;
    s0 = s1;
    s1 = s2;
    s2 = s3;
    s3 = temp ^ s2;
    s2 ^= s0;
    s1 ^= s2;

    /* Shift the cells in the rows left */
    s1 = leftRotate4_16(s1);
    s2 = leftRotate8_16(s2);
    s3 = leftRotate12_16(s3);

    /* XOR the round constant and the subkey for this round */
    rc = RC[round];
    s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
          ((rc & 0x0F) << 12) ^ 0x0020;
    s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
          ((rc & 0x70) << 8);
    s2 ^= 0x2000;

    /* Apply the inverse of the S-box to all cells in the state */
    skinny64_inv_sbox(s0);
    skinny64_inv_sbox(s1);
    skinny64_inv_sbox(s2);
    skinny64_inv_sbox(s3);

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_decrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input)
{
    forkskinny_64_192_state_t state;
    forkskinny_64_192_state_t fstate;
    unsigned round;

    /* Unpack the tweakey and the input */
    state.TK1[0] = be_load_word16(key);
    state.TK1[1] = be_load_word16(key + 2);
    state.TK1[2] = be_load_word16(key + 4);
    state.TK1[3] = be_load_word16(key + 6);
    state.TK2[0] = be_load_word16(key + 8);
    state.TK2[1] = be_load_word16(key + 10);
    state.TK2[2] = be_load_word16(key + 12);
    state.TK2[3] = be_load_word16(key + 14);
    state.TK3[0] = be_load_word16(key + 16);
    state.TK3[1] = be_load_word16(key + 18);
    state.TK3[2] = be_load_word16(key + 20);
    state.TK3[3] = be_load_word16(key + 22);
    state.S[0] = be_load_word16(input);
    state.S[1] = be_load_word16(input + 2);
    state.S[2] = be_load_word16(input + 4);
    state.S[3] = be_load_word16(input + 6);

    /* Fast-forward the tweakey to the end of the key schedule */
    for (round = 0; round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                             FORKSKINNY_64_192_ROUNDS_AFTER * 2); ++round) {
        skinny64_permute_tk(state.TK1);
        skinny64_permute_tk(state.TK2);
        skinny64_permute_tk(state.TK3);
        skinny64_LFSR2(state.TK2[0]);
        skinny64_LFSR2(state.TK2[1]);
        skinny64_LFSR3(state.TK3[0]);
        skinny64_LFSR3(state.TK3[1]);
    }

    /* Perform the "after" rounds on the input to get back
     * to the forking point in the cipher */
    for (round = (FORKSKINNY_64_192_ROUNDS_BEFORE +
                  FORKSKINNY_64_192_ROUNDS_AFTER * 2);
            round > (FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER); --round) {
        forkskinny_64_192_inv_round(&state, round - 1);
    }

    /* Remove the branching constant */
    state.S[0] ^= 0x1249U;
    state.S[1] ^= 0x36daU;
    state.S[2] ^= 0x5b7fU;
    state.S[3] ^= 0xec81U;

    /* Roll the tweakey back another "after" rounds */
    for (round = 0; round < FORKSKINNY_64_192_ROUNDS_AFTER; ++round) {
        skinny64_inv_LFSR2(state.TK2[0]);
        skinny64_inv_LFSR2(state.TK2[1]);
        skinny64_inv_LFSR3(state.TK3[0]);
        skinny64_inv_LFSR3(state.TK3[1]);
        skinny64_inv_permute_tk(state.TK1);
        skinny64_inv_permute_tk(state.TK2);
        skinny64_inv_permute_tk(state.TK3);
    }

    /* Save the state and the tweakey at the forking point */
    fstate = state;

    /* Generate the left output block after another "before" rounds */
    for (round = FORKSKINNY_64_192_ROUNDS_BEFORE; round > 0; --round) {
        forkskinny_64_192_inv_round(&state, round - 1);
    }
    be_store_word16(output_left,     state.S[0]);
    be_store_word16(output_left + 2, state.S[1]);
    be_store_word16(output_left + 4, state.S[2]);
    be_store_word16(output_left + 6, state.S[3]);

    /* Generate the right output block by going forward "after"
     * rounds from the forking point */
    for (round = FORKSKINNY_64_192_ROUNDS_BEFORE;
            round < (FORKSKINNY_64_192_ROUNDS_BEFORE +
                     FORKSKINNY_64_192_ROUNDS_AFTER); ++round) {
        forkskinny_64_192_round(&fstate, round);
    }
    be_store_word16(output_right,     fstate.S[0]);
    be_store_word16(output_right + 2, fstate.S[1]);
    be_store_word16(output_right + 4, fstate.S[2]);
    be_store_word16(output_right + 6, fstate.S[3]);
}
