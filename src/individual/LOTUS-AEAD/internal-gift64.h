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
 * \brief Structure of the key schedule for GIFT-64.
 */
typedef struct
{
    uint32_t k[4];      /**< Words of the key schedule */
#if !GIFT64_LOW_MEMORY
    uint32_t rk[8];     /**< Pre-computed round keys for fixsliced form */
#endif

} gift64n_key_schedule_t;

/**
 * \fn void gift64n_update_round_keys(gift64n_key_schedule_t *ks);
 * \brief Updates the round keys after a change in the base key.
 *
 * \param ks Points to the key schedule to update.
 */
#if GIFT64_LOW_MEMORY
#define gift64n_update_round_keys(ks) do { ; } while (0) /* Not needed */
#else
void gift64n_update_round_keys(gift64n_key_schedule_t *ks);
#endif

/**
 * \brief Initializes the key schedule for GIFT-64 (nibble-based).
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the 16 bytes of the key data.
 */
void gift64n_init(gift64n_key_schedule_t *ks, const unsigned char *key);

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

/* 4-bit tweak values expanded to 16-bit for TweGIFT-64 */
#define GIFT64T_TWEAK_0     0x0000      /**< TweGIFT-64 tweak value 0 */
#define GIFT64T_TWEAK_1     0xe1e1      /**< TweGIFT-64 tweak value 1 */
#define GIFT64T_TWEAK_2     0xd2d2      /**< TweGIFT-64 tweak value 2 */
#define GIFT64T_TWEAK_3     0x3333      /**< TweGIFT-64 tweak value 3 */
#define GIFT64T_TWEAK_4     0xb4b4      /**< TweGIFT-64 tweak value 4 */
#define GIFT64T_TWEAK_5     0x5555      /**< TweGIFT-64 tweak value 5 */
#define GIFT64T_TWEAK_6     0x6666      /**< TweGIFT-64 tweak value 6 */
#define GIFT64T_TWEAK_7     0x8787      /**< TweGIFT-64 tweak value 7 */
#define GIFT64T_TWEAK_8     0x7878      /**< TweGIFT-64 tweak value 8 */
#define GIFT64T_TWEAK_9     0x9999      /**< TweGIFT-64 tweak value 9 */
#define GIFT64T_TWEAK_10    0xaaaa      /**< TweGIFT-64 tweak value 10 */
#define GIFT64T_TWEAK_11    0x4b4b      /**< TweGIFT-64 tweak value 11 */
#define GIFT64T_TWEAK_12    0xcccc      /**< TweGIFT-64 tweak value 12 */
#define GIFT64T_TWEAK_13    0x2d2d      /**< TweGIFT-64 tweak value 13 */
#define GIFT64T_TWEAK_14    0x1e1e      /**< TweGIFT-64 tweak value 14 */
#define GIFT64T_TWEAK_15    0xffff      /**< TweGIFT-64 tweak value 15 */

/**
 * \brief Encrypts a 64-bit block with TweGIFT-64 (tweakable variant).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 * \param tweak 4-bit tweak value expanded to 16-bit.
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
     const unsigned char *input, uint16_t tweak);

/**
 * \brief Decrypts a 64-bit block with TweGIFT-64 (tweakable variant).
 *
 * \param ks Points to the GIFT-64 key schedule.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 * \param tweak 4-bit tweak value expanded to 16-bit.
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
     const unsigned char *input, uint16_t tweak);

#ifdef __cplusplus
}
#endif

#endif
