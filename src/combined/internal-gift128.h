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

#ifndef LW_INTERNAL_GIFT128_H
#define LW_INTERNAL_GIFT128_H

/**
 * \file internal-gift128.h
 * \brief GIFT-128 block cipher.
 *
 * There are two versions of GIFT-128 in use within the second round
 * submissions to the NIST lightweight cryptography competition.  The most
 * efficient for 32-bit software implementation is the bit-sliced version 
 * from GIFT-COFB and SUNDAE-GIFT.  The other is the nibble-based version
 * from HYENA.  We implement the nibble-based version as a wrapper around
 * the bit-sliced version.
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
 * \brief Structure of the key schedule for GIFT-128 (bit-sliced).
 */
typedef struct
{
    uint32_t k[4];      /**< Words of the key schedule */

} gift128b_key_schedule_t;

/**
 * \brief Initializes the key schedule for GIFT-128 (bit-sliced).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int gift128b_init
    (gift128b_key_schedule_t *ks, const unsigned char *key, size_t key_len);

/**
 * \brief Encrypts a 128-bit block with GIFT-128 (bit-sliced).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void gift128b_encrypt
    (const gift128b_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with GIFT-128 (bit-sliced).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
void gift128b_decrypt
    (const gift128b_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Structure of the key schedule for GIFT-128 (nibble-based).
 */
typedef gift128b_key_schedule_t gift128n_key_schedule_t;

/**
 * \brief Initializes the key schedule for GIFT-128 (nibble-based).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int gift128n_init
    (gift128n_key_schedule_t *ks, const unsigned char *key, size_t key_len);

/**
 * \brief Encrypts a 128-bit block with GIFT-128 (nibble-based).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void gift128n_encrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with GIFT-128 (nibble-based).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
void gift128n_decrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
