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

#include "knot.h"
#include "internal-knot.h"
#include <string.h>

aead_hash_algorithm_t const knot_hash_256_256_algorithm = {
    "KNOT-HASH-256-256",
    sizeof(int),
    KNOT_HASH_256_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_hash_256_256,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const knot_hash_256_384_algorithm = {
    "KNOT-HASH-256-384",
    sizeof(int),
    KNOT_HASH_256_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_hash_256_384,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const knot_hash_384_384_algorithm = {
    "KNOT-HASH-384-384",
    sizeof(int),
    KNOT_HASH_384_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_hash_384_384,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const knot_hash_512_512_algorithm = {
    "KNOT-HASH-512-512",
    sizeof(int),
    KNOT_HASH_512_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_hash_512_512,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \brief Input rate for KNOT-HASH-256-256.
 */
#define KNOT_HASH_256_256_RATE 4

/**
 * \brief Input rate for KNOT-HASH-256-384.
 */
#define KNOT_HASH_256_384_RATE 16

/**
 * \brief Input rate for KNOT-HASH-384-384.
 */
#define KNOT_HASH_384_384_RATE 6

/**
 * \brief Input rate for KNOT-HASH-512-512.
 */
#define KNOT_HASH_512_512_RATE 8

int knot_hash_256_256
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    knot256_state_t state;
    unsigned temp;
    memset(state.B, 0, sizeof(state.B));
    while (inlen >= KNOT_HASH_256_256_RATE) {
        lw_xor_block(state.B, in, KNOT_HASH_256_256_RATE);
        knot256_permute_7(&state, 68);
        in += KNOT_HASH_256_256_RATE;
        inlen -= KNOT_HASH_256_256_RATE;
    }
    temp = (unsigned)inlen;
    lw_xor_block(state.B, in, temp);
    state.B[temp] ^= 0x01;
    knot256_permute_7(&state, 68);
    memcpy(out, state.B, KNOT_HASH_256_SIZE / 2);
    knot256_permute_7(&state, 68);
    memcpy(out + KNOT_HASH_256_SIZE / 2, state.B, KNOT_HASH_256_SIZE / 2);
    return 0;
}

int knot_hash_256_384
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    knot384_state_t state;
    unsigned temp;
    memset(state.B, 0, sizeof(state.B));
    state.B[sizeof(state.B) - 1] ^= 0x80;
    while (inlen >= KNOT_HASH_256_384_RATE) {
        lw_xor_block(state.B, in, KNOT_HASH_256_384_RATE);
        knot384_permute_7(&state, 80);
        in += KNOT_HASH_256_384_RATE;
        inlen -= KNOT_HASH_256_384_RATE;
    }
    temp = (unsigned)inlen;
    lw_xor_block(state.B, in, temp);
    state.B[temp] ^= 0x01;
    knot384_permute_7(&state, 80);
    memcpy(out, state.B, KNOT_HASH_256_SIZE / 2);
    knot384_permute_7(&state, 80);
    memcpy(out + KNOT_HASH_256_SIZE / 2, state.B, KNOT_HASH_256_SIZE / 2);
    return 0;
}

int knot_hash_384_384
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    knot384_state_t state;
    unsigned temp;
    memset(state.B, 0, sizeof(state.B));
    while (inlen >= KNOT_HASH_384_384_RATE) {
        lw_xor_block(state.B, in, KNOT_HASH_384_384_RATE);
        knot384_permute_7(&state, 104);
        in += KNOT_HASH_384_384_RATE;
        inlen -= KNOT_HASH_384_384_RATE;
    }
    temp = (unsigned)inlen;
    lw_xor_block(state.B, in, temp);
    state.B[temp] ^= 0x01;
    knot384_permute_7(&state, 104);
    memcpy(out, state.B, KNOT_HASH_384_SIZE / 2);
    knot384_permute_7(&state, 104);
    memcpy(out + KNOT_HASH_384_SIZE / 2, state.B, KNOT_HASH_384_SIZE / 2);
    return 0;
}

int knot_hash_512_512
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    knot512_state_t state;
    unsigned temp;
    memset(state.B, 0, sizeof(state.B));
    while (inlen >= KNOT_HASH_512_512_RATE) {
        lw_xor_block(state.B, in, KNOT_HASH_512_512_RATE);
        knot512_permute_8(&state, 140);
        in += KNOT_HASH_512_512_RATE;
        inlen -= KNOT_HASH_512_512_RATE;
    }
    temp = (unsigned)inlen;
    lw_xor_block(state.B, in, temp);
    state.B[temp] ^= 0x01;
    knot512_permute_8(&state, 140);
    memcpy(out, state.B, KNOT_HASH_512_SIZE / 2);
    knot512_permute_8(&state, 140);
    memcpy(out + KNOT_HASH_512_SIZE / 2, state.B, KNOT_HASH_512_SIZE / 2);
    return 0;
}
