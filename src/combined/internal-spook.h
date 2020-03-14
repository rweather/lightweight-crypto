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

#ifndef LW_INTERNAL_SPOOK_H
#define LW_INTERNAL_SPOOK_H

#include "internal-util.h"

/**
 * \file internal-spook.h
 * \brief Internal implementation details of the Spook AEAD mode.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the block for the Clyde-128 block cipher.
 */
#define CLYDE128_BLOCK_SIZE 16

/**
 * \brief Size of the key for the Clyde-128 block cipher.
 */
#define CLYDE128_KEY_SIZE 16

/**
 * \brief Size of the tweak for the Clyde-128 block cipher.
 */
#define CLYDE128_TWEAK_SIZE 16

/**
 * \brief Size of the state for Shadow-512.
 */
#define SHADOW512_STATE_SIZE 64

/**
 * \brief Rate to absorb data into or squeeze data out of a Shadow-512 state.
 */
#define SHADOW512_RATE 32

/**
 * \brief Size of the state for Shadow-384.
 */
#define SHADOW384_STATE_SIZE 48

/**
 * \brief Rate to absorb data into or squeeze data out of a Shadow-384 state.
 */
#define SHADOW384_RATE 16

/**
 * \brief Internal state of the Shadow-512 permutation.
 */
typedef union
{
    uint32_t W[SHADOW512_STATE_SIZE / 4];   /**< Words of the state */
    uint8_t B[SHADOW512_STATE_SIZE];        /**< Bytes of the state */

} shadow512_state_t;

/**
 * \brief Internal state of the Shadow-384 permutation.
 */
typedef union
{
    uint32_t W[SHADOW384_STATE_SIZE / 4];   /**< Words of the state */
    uint8_t B[SHADOW384_STATE_SIZE];        /**< Bytes of the state */

} shadow384_state_t;

/**
 * \brief Encrypts a block with the Clyde-128 block cipher.
 *
 * \param key Points to the key to encrypt with.
 * \param tweak Points to the tweak to encrypt with.
 * \param output Output buffer for the ciphertext.
 * \param input Input buffer for the plaintext.
 *
 * \sa clyde128_decrypt()
 */
void clyde128_encrypt(const unsigned char key[CLYDE128_KEY_SIZE],
                      const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4],
                      uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                      const uint32_t input[CLYDE128_BLOCK_SIZE / 4]);

/**
 * \brief Decrypts a block with the Clyde-128 block cipher.
 *
 * \param key Points to the key to decrypt with.
 * \param tweak Points to the tweak to decrypt with.
 * \param output Output buffer for the plaintext.
 * \param input Input buffer for the ciphertext.
 *
 * \sa clyde128_encrypt()
 */
void clyde128_decrypt(const unsigned char key[CLYDE128_KEY_SIZE],
                      const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4],
                      uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                      const unsigned char input[CLYDE128_BLOCK_SIZE]);

/**
 * \brief Performs the Shadow-512 permutation on a state.
 *
 * \param state The Shadow-512 state which will be in little-endian
 * byte order on input and output.
 *
 * \sa shadow384()
 */
void shadow512(shadow512_state_t *state);

/**
 * \brief Performs the Shadow-384 permutation on a state.
 *
 * \param state The Shadow-384 state which will be in little-endian
 * byte order on input and output.
 *
 * \sa shadow512()
 */
void shadow384(shadow384_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
