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

#ifndef LWCRYPTO_SKINNY_HASH_H
#define LWCRYPTO_SKINNY_HASH_H

#include "aead-common.h"

/**
 * \file skinny-hash.h
 * \brief Hash algorithms based on the SKINNY block cipher.
 *
 * The SKINNY-AEAD family includes two hash algorithms:
 *
 * \li SKINNY-tk3-HASH with a 256-bit hash output, based around the
 * SKINNY-128-384 tweakable block cipher.  This is the primary hashing
 * member of the family.
 * \li SKINNY-tk2-HASH with a 256-bit hash output, based around the
 * SKINNY-128-256 tweakable block cipher.
 *
 * References: https://sites.google.com/site/skinnycipher/home
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the hash output for SKINNY-tk3-HASH and SKINNY-tk2-HASH.
 */
#define SKINNY_HASH_SIZE 32

/**
 * \brief Meta-information block for the SKINNY-tk3-HASH algorithm.
 */
extern aead_hash_algorithm_t const skinny_tk3_hash_algorithm;

/**
 * \brief Meta-information block for the SKINNY-tk2-HASH algorithm.
 */
extern aead_hash_algorithm_t const skinny_tk2_hash_algorithm;

/**
 * \brief Hashes a block of input data with SKINNY-tk3-HASH to
 * generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * SKINNY_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int skinny_tk3_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Hashes a block of input data with SKINNY-tk2-HASH to
 * generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * SKINNY_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int skinny_tk2_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif

#endif
