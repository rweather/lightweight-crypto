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
 * There are three versions of GIFT-128 in use within the second round
 * submissions to the NIST lightweight cryptography competition.
 *
 * The most efficient version for 32-bit software implementation is the
 * GIFT-128-b bit-sliced version from GIFT-COFB and SUNDAE-GIFT.
 *
 * The second is the nibble-based version from HYENA.  We implement the
 * HYENA version as a wrapper around the bit-sliced version.
 *
 * The third version is a variant on the HYENA nibble-based version that
 * includes a 4-bit tweak value for domain separation.  It is used by
 * the ESTATE submission to NIST.
 *
 * Technically there is a fourth version of GIFT-128 which is the one that
 * appeared in the original GIFT-128 paper.  It is almost the same as the
 * HYENA version except that the byte ordering is big-endian instead of
 * HYENA's little-endian.  The original version of GIFT-128 doesn't appear
 * in any of the NIST submissions so we don't bother with it in this library.
 *
 * References: https://eprint.iacr.org/2017/622.pdf,
 * https://eprint.iacr.org/2020/412.pdf,
 * https://giftcipher.github.io/gift/
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \var GIFT128_LOW_MEMORY
 * \brief Define this to 1 to use a low memory version of the key schedule.
 *
 * The default is to use the fix-sliced version of GIFT-128 which is very
 * fast on 32-bit platforms but requires 320 bytes to store the key schedule.
 * The large key schedule may be a problem on 8-bit and 16-bit platforms.
 *
 * GIFT128_LOW_MEMORY can be defined to 1 to select the original non
 * fix-sliced version which only requires 16 bytes to store the key,
 * with the rest of the key schedule expanded on the fly.
 */
#if !defined(GIFT128_LOW_MEMORY)
#if defined(__AVR__)
#define GIFT128_LOW_MEMORY 1
#else
#define GIFT128_LOW_MEMORY 0
#endif
#endif

/**
 * \brief Size of a GIFT-128 block in bytes.
 */
#define GIFT128_BLOCK_SIZE 16

/**
 * \var GIFT128_ROUND_KEYS
 * \brief Number of round keys for the GIFT-128 key schedule.
 */
#if GIFT128_LOW_MEMORY
#define GIFT128_ROUND_KEYS 4
#else
#define GIFT128_ROUND_KEYS 80
#endif

/**
 * \brief Structure of the key schedule for GIFT-128 (bit-sliced).
 */
typedef struct
{
    /** Pre-computed round keys for bit-sliced GIFT-128 */
    uint32_t k[GIFT128_ROUND_KEYS];

} gift128b_key_schedule_t;

/**
 * \brief Initializes the key schedule for GIFT-128 (bit-sliced).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the 16 bytes of the key data.
 */
void gift128b_init(gift128b_key_schedule_t *ks, const unsigned char *key);

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
 * \brief Encrypts a 128-bit block with GIFT-128 (bit-sliced and pre-loaded).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This version assumes that the input has already been pre-loaded from
 * big-endian into host byte order in the supplied word array.  The output
 * is delivered in the same way.
 */
void gift128b_encrypt_preloaded
    (const gift128b_key_schedule_t *ks, uint32_t output[4],
     const uint32_t input[4]);

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
 * \param key Points to the 16 bytes of the key data.
 */
void gift128n_init(gift128n_key_schedule_t *ks, const unsigned char *key);

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

/**
 * \brief Encrypts a 128-bit block with TweGIFT-128 (tweakable variant).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 * \param tweak 4-bit tweak value.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This variant of GIFT-128 is used by the ESTATE submission to the
 * NIST Lightweight Cryptography Competition.  A 4-bit tweak is added to
 * some of the rounds to provide domain separation.  If the tweak is
 * zero, then this function is identical to gift128n_encrypt().
 */
void gift128t_encrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak);

/**
 * \brief Decrypts a 128-bit block with TweGIFT-128 (tweakable variant).
 *
 * \param ks Points to the GIFT-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 * \param tweak 4-bit tweak value.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This variant of GIFT-128 is used by the ESTATE submission to the
 * NIST Lightweight Cryptography Competition.  A 4-bit tweak is added to
 * some of the rounds to provide domain separation.  If the tweak is
 * zero, then this function is identical to gift128n_encrypt().
 */
void gift128t_decrypt
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned char tweak);

#ifdef __cplusplus
}
#endif

#endif
