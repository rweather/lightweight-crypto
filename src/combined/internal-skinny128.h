/*
 * Copyright (C) 2019 Southern Storm Software, Pty Ltd.
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

#ifndef LW_INTERNAL_SKINNY128_H
#define LW_INTERNAL_SKINNY128_H

/**
 * \file internal-skinny128.h
 * \brief SKINNY-128 block cipher family.
 *
 * References: https://eprint.iacr.org/2016/660.pdf,
 * https://sites.google.com/site/skinnycipher/
 */

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Number of rounds for SKINNY-128-384.
 */
#define SKINNY_128_384_ROUNDS 56

/**
 * \brief Structure of the key schedule for SKINNY-128-384.
 */
typedef struct
{
    /** TK1 for the tweakable part of the key schedule */
    uint32_t TK1[4];

    /** Words of the key schedule */
    uint32_t k[SKINNY_128_384_ROUNDS * 2];

} skinny_128_384_key_schedule_t;

/**
 * \brief Initializes the key schedule for SKINNY-128-384.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 32 or 48,
 * where 32 is used for the tweakable variant.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int skinny_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char *key,
     size_t key_len);

/**
 * \brief Sets the tweakable part of the key schedule for SKINNY-128-384.
 *
 * \param ks Points to the key schedule to modify.
 * \param tweak Points to the tweak data.
 * \param tweak_len Length of the tweak data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int skinny_128_384_set_tweak
    (skinny_128_384_key_schedule_t *ks, const unsigned char *tweak,
     size_t tweak_len);

/**
 * \brief Encrypts a 128-bit block with SKINNY-128-384.
 *
 * \param ks Points to the SKINNY-128-384 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_128_384_encrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with SKINNY-128-384.
 *
 * \param ks Points to the SKINNY-128-384 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_128_384_decrypt
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Number of rounds for SKINNY-128-256.
 */
#define SKINNY_128_256_ROUNDS 48

/**
 * \brief Structure of the key schedule for SKINNY-128-256.
 */
typedef struct
{
    /** TK1 for the tweakable part of the key schedule */
    uint32_t TK1[4];

    /** Words of the key schedule */
    uint32_t k[SKINNY_128_256_ROUNDS * 2];

} skinny_128_256_key_schedule_t;

/**
 * \brief Initializes the key schedule for SKINNY-128-256.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 16 or 32,
 * where 16 is used for the tweakable variant.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int skinny_128_256_init
    (skinny_128_256_key_schedule_t *ks, const unsigned char *key,
     size_t key_len);

/**
 * \brief Sets the tweakable part of the key schedule for SKINNY-128-256.
 *
 * \param ks Points to the key schedule to modify.
 * \param tweak Points to the tweak data.
 * \param tweak_len Length of the tweak data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int skinny_128_256_set_tweak
    (skinny_128_256_key_schedule_t *ks, const unsigned char *tweak,
     size_t tweak_len);

/**
 * \brief Encrypts a 128-bit block with SKINNY-128-256.
 *
 * \param ks Points to the SKINNY-128-256 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_128_256_encrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with SKINNY-128-256.
 *
 * \param ks Points to the SKINNY-128-256 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_128_256_decrypt
    (const skinny_128_256_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Number of rounds for SKINNY-128-128.
 */
#define SKINNY_128_128_ROUNDS 40

/**
 * \brief Structure of the key schedule for SKINNY-128-128.
 */
typedef struct
{
    /** Words of the key schedule */
    uint32_t k[SKINNY_128_128_ROUNDS * 2];

} skinny_128_128_key_schedule_t;

/**
 * \brief Initializes the key schedule for SKINNY-128-128.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 * \param key_len Length of the key data, which must be 16.
 *
 * \return Non-zero on success or zero if there is something wrong
 * with the parameters.
 */
int skinny_128_128_init
    (skinny_128_128_key_schedule_t *ks, const unsigned char *key,
     size_t key_len);

/**
 * \brief Encrypts a 128-bit block with SKINNY-128-128.
 *
 * \param ks Points to the SKINNY-128-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_128_128_encrypt
    (const skinny_128_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with SKINNY-128-128.
 *
 * \param ks Points to the SKINNY-128-128 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void skinny_128_128_decrypt
    (const skinny_128_128_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
