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

#ifndef NIST_LW_INTERNAL_H
#define NIST_LW_INTERNAL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Metainformation for a block cipher.
 */
typedef struct lw_block_cipher_s lw_block_cipher_t;

/**
 * \brief Initialises a block cipher to encrypt in ECB mode.
 *
 * \param ks Points to the key schedule block to be initialized.  This should
 * be aligned on at least a 64-bit boundary.
 * \param ks_len Length of the key schedule block in bytes.
 * \param key Points to the key to use to initialize the key schedule.
 * \param key_len Length of the key in bytes.
 *
 * \return Returns non-zero if the key schedule was initialized or zero if
 * there is something wrong with the parameters.
 */
typedef int (*lw_block_init_t)
    (void *ks, size_t ks_len, const unsigned char *key, size_t key_len);

/**
 * \brief Encrypts a block in ECB mode.
 *
 * \param ks Points to the key schedule.
 * \param output Points to the output block which must be at least
 * 16 bytes in length.
 * \param input Points to the input block which must be at least
 * 16 bytes in length.
 *
 * The \a input and \a output blocks are allowed to be the same for
 * in-place encryption of the input plaintext.
 */
typedef void (*lw_block_encrypt_t)
    (const void *ks, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Metainformation for a block cipher that may be used as a
 * parameter for a higher-level AEAD mode.
 *
 * \note All block ciphers in this library have a 128-bit block.
 */
struct lw_block_cipher_s
{
    /** Minimum size of the key in bytes */
    unsigned short min_key_size;

    /** Maximum size of the key in bytes */
    unsigned short max_key_size;

    /** Size of the key schedule in bytes */
    unsigned key_schedule_size;

    /** Function for encrypting a block in ECB mode */
    lw_block_encrypt_t encrypt;
};

#ifdef __cplusplus
}
#endif

#endif
