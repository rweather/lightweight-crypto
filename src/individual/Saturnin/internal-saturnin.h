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

#ifndef LW_INTERNAL_SATURNIN_H
#define LW_INTERNAL_SATURNIN_H

/**
 * \file internal-saturnin.h
 * \brief Saturnin block cipher.
 *
 * References: https://project.inria.fr/saturnin/
 */

#include "internal-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of a Saturnin block in bytes.
 */
#define SATURNIN_BLOCK_SIZE 32

/**
 * \brief Domain separator index 1 for the 10-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_10_1 0

/**
 * \brief Domain separator index 2 for the 10-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_10_2 10

/**
 * \brief Domain separator index 3 for the 10-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_10_3 20

/**
 * \brief Domain separator index 4 for the 10-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_10_4 30

/**
 * \brief Domain separator index 5 for the 10-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_10_5 40

/**
 * \brief Domain separator index 6 for the 10-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_10_6 50

/**
 * \brief Domain separator index 7 for the 16-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_16_7 60

/**
 * \brief Domain separator index 8 for the 16-round version of Saturnin.
 */
#define SATURNIN_DOMAIN_16_8 76

/**
 * \brief Structure of the key schedule for Saturnin.
 */
typedef struct
{
    /** Pre-computed round keys for Saturnin */
    uint32_t k[16];

} saturnin_key_schedule_t;

/**
 * \brief Sets up a key schedule for Saturnin.
 *
 * \param ks Points to the key schedule to initialize.
 * \param key Points to the 32 bytes of the key data.
 */
void saturnin_setup_key
    (saturnin_key_schedule_t *ks, const unsigned char *key);

/**
 * \brief Encrypts a 256-bit block with Saturnin.
 *
 * \param ks Points to the Saturnin key schedule.
 * \param output Output buffer which must be at least 32 bytes in length.
 * \param input Input buffer which must be at least 32 bytes in length.
 * \param domain Domain separator and round count indicator.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 */
void saturnin_encrypt_block
    (const saturnin_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned domain);

/**
 * \brief Decrypts a 256-bit block with Saturnin.
 *
 * \param ks Points to the Saturnin key schedule.
 * \param output Output buffer which must be at least 32 bytes in length.
 * \param input Input buffer which must be at least 32 bytes in length.
 * \param domain Domain separator and round count indicator.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place decryption.
 */
void saturnin_decrypt_block
    (const saturnin_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned domain);

#ifdef __cplusplus
}
#endif

#endif
