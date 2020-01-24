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

#ifndef LW_INTERNAL_MASKING_H
#define LW_INTERNAL_MASKING_H

#include <stdint.h>

/**
 * \file internal-masking.h
 * \brief Generation of random masking material.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes the system random number generator for the
 * generation of masking material.
 */
void aead_masking_init(void);

/**
 * \brief Generates random data into a buffer for masking purposes.
 *
 * \param data The buffer to fill with random data.
 * \param size Number of bytes of random data to generate.
 *
 * This function is intended to generate masking material that needs to
 * be generated quickly but which will not be used in the derivation of
 * public keys or public nonce material.
 */
void aead_masking_generate(void *data, unsigned size);

/**
 * \brief Generate a single random 32-bit word for masking purposes.
 *
 * \return The random word.
 */
uint32_t aead_masking_generate_32(void);

#ifdef __cplusplus
}
#endif

#endif
