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

#ifndef LW_INTERNAL_FORKSKINNY_H
#define LW_INTERNAL_FORKSKINNY_H

#include "internal-util.h"

/**
 * \file internal-forkskinny.h
 * \brief ForkSkinny block cipher family.
 *
 * ForkSkinny is a modified version of the SKINNY block cipher that
 * supports "forking": half-way through the rounds the cipher is
 * forked in two different directions to produce two different outputs.
 *
 * References: https://www.esat.kuleuven.be/cosic/forkae/
 */

#ifdef __cplusplus
extern "C" {
#endif

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
 * \brief Applies several rounds of ForkSkinny-128-256.
 *
 * \param state State to apply the rounds to.
 * \param first First round to apply.
 * \param last Last round to apply plus 1.
 */
void forkskinny_128_256_rounds
    (forkskinny_128_256_state_t *state, unsigned first, unsigned last);

/**
 * \brief Applies several rounds of ForkSkinny-128-256 in reverse.
 *
 * \param state State to apply the rounds to.
 * \param first First round to apply plus 1.
 * \param last Last round to apply.
 */
void forkskinny_128_256_inv_rounds
    (forkskinny_128_256_state_t *state, unsigned first, unsigned last);

/**
 * \brief Forwards the tweakey for ForkSkinny-128-256.
 *
 * \param state Points to the ForkSkinny-128-256 state.
 * \param rounds Number of rounds to forward by.
 */
void forkskinny_128_256_forward_tk
    (forkskinny_128_256_state_t *state, unsigned rounds);

/**
 * \brief Reverses the tweakey for ForkSkinny-128-256.
 *
 * \param state Points to the ForkSkinny-128-256 state.
 * \param rounds Number of rounds to reverse by.
 */
void forkskinny_128_256_reverse_tk
    (forkskinny_128_256_state_t *state, unsigned rounds);

/**
 * \brief Applies several rounds of ForkSkinny-128-384.
 *
 * \param state State to apply the rounds to.
 * \param first First round to apply.
 * \param last Last round to apply plus 1.
 */
void forkskinny_128_384_rounds
    (forkskinny_128_384_state_t *state, unsigned first, unsigned last);

/**
 * \brief Applies several rounds of ForkSkinny-128-384 in reverse.
 *
 * \param state State to apply the rounds to.
 * \param first First round to apply plus 1.
 * \param last Last round to apply.
 */
void forkskinny_128_384_inv_rounds
    (forkskinny_128_384_state_t *state, unsigned first, unsigned last);

/**
 * \brief Forwards the tweakey for ForkSkinny-128-384.
 *
 * \param state Points to the ForkSkinny-128-384 state.
 * \param rounds Number of rounds to forward by.
 */
void forkskinny_128_384_forward_tk
    (forkskinny_128_384_state_t *state, unsigned rounds);

/**
 * \brief Reverses the tweakey for ForkSkinny-128-384.
 *
 * \param state Points to the ForkSkinny-128-384 state.
 * \param rounds Number of rounds to reverse by.
 */
void forkskinny_128_384_reverse_tk
    (forkskinny_128_384_state_t *state, unsigned rounds);

/**
 * \brief Applies several rounds of ForkSkinny-64-192.
 *
 * \param state State to apply the rounds to.
 * \param first First round to apply.
 * \param last Last round to apply plus 1.
 *
 * Note: The cells of each row are ordered in big-endian nibble order
 * so it is simplest to manage the rows in big-endian byte order.
 */
void forkskinny_64_192_rounds
    (forkskinny_64_192_state_t *state, unsigned first, unsigned last);

/**
 * \brief Applies several rounds of ForkSkinny-64-192 in reverse.
 *
 * \param state State to apply the rounds to.
 * \param first First round to apply plus 1.
 * \param last Last round to apply.
 */
void forkskinny_64_192_inv_rounds
    (forkskinny_64_192_state_t *state, unsigned first, unsigned last);

/**
 * \brief Forwards the tweakey for ForkSkinny-64-192.
 *
 * \param state Points to the ForkSkinny-64-192 state.
 * \param rounds Number of rounds to forward by.
 */
void forkskinny_64_192_forward_tk
    (forkskinny_64_192_state_t *state, unsigned rounds);

/**
 * \brief Reverses the tweakey for ForkSkinny-64-192.
 *
 * \param state Points to the ForkSkinny-64-192 state.
 * \param rounds Number of rounds to reverse by.
 */
void forkskinny_64_192_reverse_tk
    (forkskinny_64_192_state_t *state, unsigned rounds);

/**
 * \brief Encrypts a block of plaintext with ForkSkinny-128-256.
 *
 * \param key 256-bit tweakey for ForkSkinny-128-256.
 * \param output_left Left output block for the ciphertext, or NULL if
 * the left output is not required.
 * \param output_right Right output block for the authentication tag,
 * or NULL if the right output is not required.
 * \param input 128-bit input plaintext block.
 *
 * ForkSkinny-128-192 also uses this function with a padded tweakey.
 */
void forkskinny_128_256_encrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input);

/**
 * \brief Decrypts a block of ciphertext with ForkSkinny-128-256.
 *
 * \param key 256-bit tweakey for ForkSkinny-128-256.
 * \param output_left Left output block, which is the plaintext.
 * \param output_right Right output block for the authentication tag.
 * \param input 128-bit input ciphertext block.
 *
 * Both output blocks will be populated; neither is optional.
 */
void forkskinny_128_256_decrypt
    (const unsigned char key[32], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input);

/**
 * \brief Encrypts a block of plaintext with ForkSkinny-128-384.
 *
 * \param key 384-bit tweakey for ForkSkinny-128-384.
 * \param output_left Left output block for the ciphertext, or NULL if
 * the left output is not required.
 * \param output_right Right output block for the authentication tag,
 * or NULL if the right output is not required.
 * \param input 128-bit input plaintext block.
 *
 * ForkSkinny-128-288 also uses this function with a padded tweakey.
 */
void forkskinny_128_384_encrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input);

/**
 * \brief Decrypts a block of ciphertext with ForkSkinny-128-384.
 *
 * \param key 384-bit tweakey for ForkSkinny-128-384.
 * \param output_left Left output block, which is the plaintext.
 * \param output_right Right output block for the authentication tag.
 * \param input 128-bit input ciphertext block.
 *
 * Both output blocks will be populated; neither is optional.
 */
void forkskinny_128_384_decrypt
    (const unsigned char key[48], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input);

/**
 * \brief Encrypts a block of input with ForkSkinny-64-192.
 *
 * \param key 192-bit tweakey for ForkSkinny-64-192.
 * \param output_left First output block, or NULL if left is not required.
 * \param output_right Second output block, or NULL if right is not required.
 * \param input 64-bit input block.
 */
/**
 * \brief Encrypts a block of plaintext with ForkSkinny-64-192.
 *
 * \param key 192-bit tweakey for ForkSkinny-64-192.
 * \param output_left Left output block for the ciphertext, or NULL if
 * the left output is not required.
 * \param output_right Right output block for the authentication tag,
 * or NULL if the right output is not required.
 * \param input 64-bit input plaintext block.
 */
void forkskinny_64_192_encrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input);

/**
 * \brief Decrypts a block of ciphertext with ForkSkinny-64-192.
 *
 * \param key 192-bit tweakey for ForkSkinny-64-192.
 * \param output_left Left output block, which is the plaintext.
 * \param output_right Right output block for the authentication tag.
 * \param input 64-bit input ciphertext block.
 *
 * Both output blocks will be populated; neither is optional.
 */
void forkskinny_64_192_decrypt
    (const unsigned char key[24], unsigned char *output_left,
     unsigned char *output_right, const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
