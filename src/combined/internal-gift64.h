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

#ifndef LW_INTERNAL_GIFT64_H
#define LW_INTERNAL_GIFT64_H

/**
 * \file internal-gift64.h
 * \brief GIFT-64 block cipher.
 *
 * References: https://eprint.iacr.org/2017/622.pdf,
 * https://giftcipher.github.io/gift/
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \var GIFT64_LOW_MEMORY
 * \brief Define this to 1 to use a low memory version of the key schedule.
 *
 * The default is to use the fix-sliced version of GIFT-64 which is very
 * fast on 32-bit platforms but requires 48 bytes to store the key schedule.
 * The large key schedule may be a problem on 8-bit and 16-bit platforms.
 * The fix-sliced version also encrypts two blocks at a time in 32-bit
 * words which is an unnecessary optimization for 8-bit platforms.
 *
 * GIFT64_LOW_MEMORY can be defined to 1 to select the original non
 * fix-sliced version which only requires 16 bytes to store the key,
 * with the rest of the key schedule expanded on the fly.
 */
#if !defined(GIFT64_LOW_MEMORY)
#if defined(__AVR__)
#define GIFT64_LOW_MEMORY 1
#else
#define GIFT64_LOW_MEMORY 0
#endif
#endif

/**
 * \brief Size of a GIFT-64 block in bytes.
 */
#define GIFT64_BLOCK_SIZE 8

/**
 * \brief Structure of the key schedule for GIFT-64 (bit-sliced).
 */
typedef struct
{
    uint32_t k[4];      /**< Words of the key schedule */
#if !GIFT64_LOW_MEMORY
    uint32_t rk[8];     /**< Pre-computed round keys for fixsliced form */
#endif

} gift64b_key_schedule_t;

/**
 * \brief Initializes the key schedule for GIFT-64 (bit-sliced).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int gift64b_init
    (gift64b_key_schedule_t *ks, const unsigned char *key, size_t key_len);

/**
 * \brief Updates the round keys after a change in the base key.
 *
 * \param ks Points to the key schedule to update.
 */
void gift64b_update_round_keys(gift64b_key_schedule_t *ks);

/**
 * \brief Structure of the key schedule for GIFT-64 (nibble-based).
 */
typedef gift64b_key_schedule_t gift64n_key_schedule_t;

/**
 * \brief Initializes the key schedule for GIFT-64 (nibble-based).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int gift64n_init
    (gift64n_key_schedule_t *ks, const unsigned char *key, size_t key_len);

/**
 * \brief Encrypts a 64-bit block with GIFT-64 (nibble-based).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void gift64n_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 64-bit block with GIFT-64 (nibble-based).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
void gift64n_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Encrypts a 64-bit block with GIFT-64 (nibble-based big-endian).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void gift64nb_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 64-bit block with GIFT-64 (nibble-based big-endian).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
void gift64nb_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Encrypts a 64-bit block with TweGIFT-64 (tweakable variant).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 * \param tweak 4-bit tweak value.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This variant of GIFT-64 is used by the LOTUS/LOCUS submission to the
 * NIST Lightweight Cryptography Competition.  A 4-bit tweak is added to
 * some of the rounds to provide domain separation.  If the tweak is
 * zero, then this function is identical to gift64n_encrypt().
 */
void gift64t_encrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak);

/**
 * \brief Decrypts a 64-bit block with TweGIFT-64 (tweakable variant).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 * \param tweak 4-bit tweak value.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This variant of GIFT-64 is used by the LOTUS/LOCUS submission to the
 * NIST Lightweight Cryptography Competition.  A 4-bit tweak is added to
 * some of the rounds to provide domain separation.  If the tweak is
 * zero, then this function is identical to gift64n_decrypt().
 */
void gift64t_decrypt
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak);

#ifdef __cplusplus
}
#endif

#endif
