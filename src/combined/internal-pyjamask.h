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

#ifndef LW_INTERNAL_PYJAMASK_H
#define LW_INTERNAL_PYJAMASK_H

#include "internal-util.h"

/**
 * \file internal-pyjamask.h
 * \brief Pyjamask block cipher.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Number of rounds in the Pyjamask block cipher.
 */
#define PYJAMASK_ROUNDS 14

/**
 * \brief Structure of the key schedule for Pyjamask block ciphers.
 */
typedef struct
{
    uint32_t k[(PYJAMASK_ROUNDS + 1) * 4]; /**< Words of the key schedule */

} pyjamask_key_schedule_t;

/**
 * \brief Sets up the key schedule for the Pyjamask block cipher.
 *
 * \param ks The key schedule on output.
 * \param key The 16 bytes of the key on input.
 */
void pyjamask_setup_key(pyjamask_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Encrypts a 128-bit block with Pyjamask-128.
 *
 * \param ks Points to the key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \sa pyjamask_128_decrypt()
 */
void pyjamask_128_encrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 128-bit block with Pyjamask-128.
 *
 * \param ks Points to the key schedule.
 * \param output Output buffer which must be at least 16 bytes in length.
 * \param input Input buffer which must be at least 16 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * \sa pyjamask_128_encrypt()
 */
void pyjamask_128_decrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Encrypts a 96-bit block with Pyjamask-96.
 *
 * \param ks Points to the key schedule.
 * \param output Output buffer which must be at least 12 bytes in length.
 * \param input Input buffer which must be at least 12 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \sa pyjamask_96_decrypt()
 */
void pyjamask_96_encrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Decrypts a 96-bit block with Pyjamask-96.
 *
 * \param ks Points to the key schedule.
 * \param output Output buffer which must be at least 12 bytes in length.
 * \param input Input buffer which must be at least 12 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 *
 * \sa pyjamask_96_encrypt()
 */
void pyjamask_96_decrypt
    (const pyjamask_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
