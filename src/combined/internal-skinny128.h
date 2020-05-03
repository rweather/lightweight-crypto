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
 * \def SKINNY_128_SMALL_SCHEDULE
 * \brief Defined to 1 to use the small key schedule version of SKINNY-128.
 */
#if defined(__AVR__)
#define SKINNY_128_SMALL_SCHEDULE 1
#else
#define SKINNY_128_SMALL_SCHEDULE 0
#endif

/**
 * \brief Size of a block for SKINNY-128 block ciphers.
 */
#define SKINNY_128_BLOCK_SIZE 16

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
    uint8_t TK1[16];

#if SKINNY_128_SMALL_SCHEDULE
    /** TK2 for the small key schedule */
    uint8_t TK2[16];

    /** TK3 for the small key schedule */
    uint8_t TK3[16];
#else
    /** Words of the full key schedule */
    uint32_t k[SKINNY_128_384_ROUNDS * 2];
#endif

} skinny_128_384_key_schedule_t;

/**
 * \brief Initializes the key schedule for SKINNY-128-384.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 */
void skinny_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char key[48]);

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
 * \brief Encrypts a 128-bit block with SKINNY-128-384 and an explicitly
 * provided TK2 value.
 *
 * \param ks Points to the SKINNY-128-384 key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 * \param tk2 TK2 value that should be updated on the fly.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This version is useful when both TK1 and TK2 change from block to block.
 * When the key is initialized with skinny_128_384_init(), the TK2 part of
 * the key value should be set to zero.
 */
void skinny_128_384_encrypt_tk2
    (const skinny_128_384_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, const unsigned char *tk2);

/**
 * \brief Encrypts a 128-bit block with SKINNY-128-384 and a
 * fully specified tweakey value.
 *
 * \param key Points to the 384-bit tweakey value.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This version is useful when the entire tweakey changes from block to
 * block.  It is slower than the other versions of SKINNY-128-384 but
 * more memory-efficient.
 */
void skinny_128_384_encrypt_tk_full
    (const unsigned char key[48], unsigned char *output,
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
    uint8_t TK1[16];

#if SKINNY_128_SMALL_SCHEDULE
    /** TK2 for the small key schedule */
    uint8_t TK2[16];
#else
    /** Words of the full key schedule */
    uint32_t k[SKINNY_128_256_ROUNDS * 2];
#endif

} skinny_128_256_key_schedule_t;

/**
 * \brief Initializes the key schedule for SKINNY-128-256.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the key data.
 */
void skinny_128_256_init
    (skinny_128_256_key_schedule_t *ks, const unsigned char key[32]);

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
 * \brief Encrypts a 128-bit block with SKINNY-128-256 and a
 * fully specified tweakey value.
 *
 * \param key Points to the 256-bit tweakey value.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * This version is useful when the entire tweakey changes from block to
 * block.  It is slower than the other versions of SKINNY-128-256 but
 * more memory-efficient.
 */
void skinny_128_256_encrypt_tk_full
    (const unsigned char key[32], unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
