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

#ifndef LW_INTERNAL_GRAIN128_H
#define LW_INTERNAL_GRAIN128_H

#include "internal-util.h"

/**
 * \file internal-grain128.h
 * \brief Internal implementation of the Grain-128 stream cipher.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Representation of the state of Grain-128.
 *
 * Note: The specification numbers bits starting with the most significant,
 * so bit 0 is in the highest bit of the first word of each field below.
 */
typedef struct
{
    uint32_t lfsr[4];       /**< 128-bit LFSR state for Grain-128 */
    uint32_t nfsr[4];       /**< 128-bit NFSR state for Grain-128 */
    uint64_t accum;         /**< 64-bit accumulator for authentication */
    uint64_t sr;            /**< 64-bit shift register for authentication */
    unsigned char ks[16];   /**< Keystream block for auth or encrypt mode */
    unsigned posn;          /**< Current position within the keystream */

} grain128_state_t;

/**
 * \brief Sets up the initial Grain-128 state with the key and nonce.
 *
 * \param state Grain-128 state to be initialized.
 * \param key Points to the 128-bit key.
 * \param nonce Points to the 96-bit nonce.
 */
void grain128_setup
    (grain128_state_t *state, const unsigned char *key,
     const unsigned char *nonce);

/**
 * \brief Authenticates data with Grain-128.
 *
 * \param state Grain-128 state.
 * \param data Points to the data to be authenticated.
 * \param len Length of the data to be authenticated.
 */
void grain128_authenticate
    (grain128_state_t *state, const unsigned char *data,
     unsigned long long len);

/**
 * \brief Encrypts and authenticates data with Grain-128.
 *
 * \param state Grain-128 state.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param len Length of the data to be encrypted.
 */
void grain128_encrypt
    (grain128_state_t *state, unsigned char *c, const unsigned char *m,
     unsigned long long len);

/**
 * \brief Decrypts and authenticates data with Grain-128.
 *
 * \param state Grain-128 state.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param len Length of the data to be decrypted.
 */
void grain128_decrypt
    (grain128_state_t *state, unsigned char *m, const unsigned char *c,
     unsigned long long len);

/**
 * \brief Computes the final authentiation tag.
 *
 * \param state Grain-128 state.
 *
 * The final authentication tag is written to the first 8 bytes of state->ks.
 */
void grain128_compute_tag(grain128_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
