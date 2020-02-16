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

#include "skinny-hash.h"
#include "internal-skinny128.h"
#include "internal-util.h"
#include <string.h>

aead_hash_algorithm_t const skinny_tk3_hash_algorithm = {
    "SKINNY-tk3-HASH",
    sizeof(int),
    SKINNY_HASH_SIZE,
    AEAD_FLAG_NONE,
    skinny_tk3_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const skinny_tk2_hash_algorithm = {
    "SKINNY-tk2-HASH",
    sizeof(int),
    SKINNY_HASH_SIZE,
    AEAD_FLAG_NONE,
    skinny_tk2_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \brief Size of the permutation state for SKINNY-tk3-HASH.
 */
#define SKINNY_TK3_STATE_SIZE 48

/**
 * \brief Size of the permutation state for SKINNY-tk2-HASH.
 */
#define SKINNY_TK2_STATE_SIZE 32

/**
 * \brief Rate of absorbing data for SKINNY-tk3-HASH.
 */
#define SKINNY_TK3_HASH_RATE 16

/**
 * \brief Rate of absorbing data for SKINNY-tk2-HASH.
 */
#define SKINNY_TK2_HASH_RATE 4

/**
 * \brief Input block that is encrypted with the state for each
 * block permutation of SKINNY-tk3-HASH or SKINNY-tk2-HASH.
 */
static unsigned char const skinny_hash_block[48] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/**
 * \brief Permutes the internal state for SKINNY-tk3-HASH.
 *
 * \param state The state to be permuted.
 */
static void skinny_tk3_permute(unsigned char state[SKINNY_TK3_STATE_SIZE])
{
    unsigned char temp[SKINNY_TK3_STATE_SIZE];
    skinny_128_384_encrypt_tk_full(state, temp, skinny_hash_block);
    skinny_128_384_encrypt_tk_full(state, temp + 16, skinny_hash_block + 16);
    skinny_128_384_encrypt_tk_full(state, temp + 32, skinny_hash_block + 32);
    memcpy(state, temp, SKINNY_TK3_STATE_SIZE);
}

/**
 * \brief Permutes the internal state for SKINNY-tk2-HASH.
 *
 * \param state The state to be permuted.
 */
static void skinny_tk2_permute(unsigned char state[SKINNY_TK2_STATE_SIZE])
{
    unsigned char temp[SKINNY_TK2_STATE_SIZE];
    skinny_128_256_encrypt_tk_full(state, temp, skinny_hash_block);
    skinny_128_256_encrypt_tk_full(state, temp + 16, skinny_hash_block + 16);
    memcpy(state, temp, SKINNY_TK2_STATE_SIZE);
}

int skinny_tk3_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char state[SKINNY_TK3_STATE_SIZE];
    unsigned temp;

    /* Initialize the hash state */
    memset(state, 0, sizeof(state));
    state[SKINNY_TK3_HASH_RATE] = 0x80;

    /* Process as many full blocks as possible */
    while (inlen >= SKINNY_TK3_HASH_RATE) {
        lw_xor_block(state, in, SKINNY_TK3_HASH_RATE);
        skinny_tk3_permute(state);
        in += SKINNY_TK3_HASH_RATE;
        inlen -= SKINNY_TK3_HASH_RATE;
    }

    /* Pad and process the last block */
    temp = (unsigned)inlen;
    lw_xor_block(state, in, temp);
    state[temp] ^= 0x80; /* padding */
    skinny_tk3_permute(state);

    /* Generate the hash output */
    memcpy(out, state, 16);
    skinny_tk3_permute(state);
    memcpy(out + 16, state, 16);
    return 0;
}

int skinny_tk2_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char state[SKINNY_TK2_STATE_SIZE];
    unsigned temp;

    /* Initialize the hash state */
    memset(state, 0, sizeof(state));
    state[SKINNY_TK2_HASH_RATE] = 0x80;

    /* Process as many full blocks as possible */
    while (inlen >= SKINNY_TK2_HASH_RATE) {
        lw_xor_block(state, in, SKINNY_TK2_HASH_RATE);
        skinny_tk2_permute(state);
        in += SKINNY_TK2_HASH_RATE;
        inlen -= SKINNY_TK2_HASH_RATE;
    }

    /* Pad and process the last block */
    temp = (unsigned)inlen;
    lw_xor_block(state, in, temp);
    state[temp] ^= 0x80; /* padding */
    skinny_tk2_permute(state);

    /* Generate the hash output */
    memcpy(out, state, 16);
    skinny_tk2_permute(state);
    memcpy(out + 16, state, 16);
    return 0;
}
