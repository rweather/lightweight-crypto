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

#include "internal-blake2s.h"
#include "internal-util.h"
#include <string.h>

aead_hash_algorithm_t const internal_blake2s_hash_algorithm = {
    "BLAKE2s",
    sizeof(int),
    BLAKE2S_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    internal_blake2s_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \brief Structure of the BLAKE2s hash state.
 */
typedef struct
{
    uint32_t h[8];      /**< Rolling hash value from block to block */
    uint32_t m[16];     /**< Next message block */
    uint64_t length;    /**< Length of the input so far */

} blake2s_state_t;

/* Initialization vectors for BLAKE2s */
#define BLAKE2s_IV0 0x6A09E667
#define BLAKE2s_IV1 0xBB67AE85
#define BLAKE2s_IV2 0x3C6EF372
#define BLAKE2s_IV3 0xA54FF53A
#define BLAKE2s_IV4 0x510E527F
#define BLAKE2s_IV5 0x9B05688C
#define BLAKE2s_IV6 0x1F83D9AB
#define BLAKE2s_IV7 0x5BE0CD19

/* Permutation on the message input state for BLAKE2s */
static unsigned char const sigma[10][16] = {
    { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
    {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
    {11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4},
    { 7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8},
    { 9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13},
    { 2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9},
    {12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11},
    {13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10},
    { 6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5},
    {10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13 , 0}
};

/* Perform a BLAKE2s quarter round operation */
#define quarterRound(a, b, c, d, i)    \
    do { \
        uint32_t _b = (b); \
        uint32_t _a = (a) + _b + state->m[sigma[index][2 * (i)]]; \
        uint32_t _d = rightRotate16((d) ^ _a); \
        uint32_t _c = (c) + _d; \
        _b = rightRotate12(_b ^ _c); \
        _a += _b + state->m[sigma[index][2 * (i) + 1]]; \
        (d) = _d = rightRotate8(_d ^ _a); \
        _c += _d; \
        (a) = _a; \
        (b) = rightRotate7(_b ^ _c); \
        (c) = _c; \
    } while (0)

/**
 * \brief Processes a full chunk of hash input.
 *
 * \param state BLAKE2s state.
 * \param f0 All-zeroes for regular blocks, all-ones for the last block.
 */
static void blake2s_process_chunk(blake2s_state_t *state, uint32_t f0)
{
    uint8_t index;
    uint32_t v[16];

    /* Byte-swap the message buffer into little-endian if necessary */
#if !defined(LW_UTIL_LITTLE_ENDIAN)
    for (index = 0; index < 16; ++index)
        state.m[index] = le32toh(state.m[index]);
#endif

    /* Format the block to be hashed */
    memcpy(v, state->h, sizeof(state->h));
    v[8]  = BLAKE2s_IV0;
    v[9]  = BLAKE2s_IV1;
    v[10] = BLAKE2s_IV2;
    v[11] = BLAKE2s_IV3;
    v[12] = BLAKE2s_IV4 ^ (uint32_t)(state->length);
    v[13] = BLAKE2s_IV5 ^ (uint32_t)(state->length >> 32);
    v[14] = BLAKE2s_IV6 ^ f0;
    v[15] = BLAKE2s_IV7;

    /* Perform the 10 BLAKE2s rounds */
    for (index = 0; index < 10; ++index) {
        /* Column round */
        quarterRound(v[0], v[4], v[8],  v[12], 0);
        quarterRound(v[1], v[5], v[9],  v[13], 1);
        quarterRound(v[2], v[6], v[10], v[14], 2);
        quarterRound(v[3], v[7], v[11], v[15], 3);

        /* Diagonal round */
        quarterRound(v[0], v[5], v[10], v[15], 4);
        quarterRound(v[1], v[6], v[11], v[12], 5);
        quarterRound(v[2], v[7], v[8],  v[13], 6);
        quarterRound(v[3], v[4], v[9],  v[14], 7);
    }

    /* Combine the new and old hash values */
    for (index = 0; index < 8; ++index)
        state->h[index] ^= (v[index] ^ v[index + 8]);
}

int internal_blake2s_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    blake2s_state_t state;
    unsigned temp;

    /* Initialize the BLAKE2s state */
    state.h[0] = BLAKE2s_IV0 ^ 0x01010020; /* Default output length of 32 */
    state.h[1] = BLAKE2s_IV1;
    state.h[2] = BLAKE2s_IV2;
    state.h[3] = BLAKE2s_IV3;
    state.h[4] = BLAKE2s_IV4;
    state.h[5] = BLAKE2s_IV5;
    state.h[6] = BLAKE2s_IV6;
    state.h[7] = BLAKE2s_IV7;
    state.length = 0;

    /* Process all blocks except the last */
    while (inlen > 64) {
        memcpy(state.m, in, 64);
        state.length += 64;
        blake2s_process_chunk(&state, 0);
        in += 64;
        inlen -= 64;
    }

    /* Pad and process the last block */
    temp = (unsigned)inlen;
    memcpy(state.m, in, temp);
    memset(((uint8_t *)state.m) + temp, 0, sizeof(state.m) - temp);
    state.length += temp;
    blake2s_process_chunk(&state, 0xFFFFFFFFU);

    /* Convert the hash into little-endian and write it to the output buffer */
    le_store_word32(out,      state.h[0]);
    le_store_word32(out + 4,  state.h[1]);
    le_store_word32(out + 8,  state.h[2]);
    le_store_word32(out + 12, state.h[3]);
    le_store_word32(out + 16, state.h[4]);
    le_store_word32(out + 20, state.h[5]);
    le_store_word32(out + 24, state.h[6]);
    le_store_word32(out + 28, state.h[7]);
    return 0;
}
