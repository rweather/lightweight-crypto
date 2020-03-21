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

#ifndef LW_INTERNAL_SPECK64_H
#define LW_INTERNAL_SPECK64_H

/**
 * \file internal-speck64.h
 * \brief SPECK-64 block cipher.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts a 64-bit block with SPECK-64-128 in COMET byte order.
 *
 * \param key Points to the 16 bytes of the key.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \note This version expects the key, input, and output to be in
 * little-endian byte order, as expected by the COMET specification.
 */
void speck64_128_encrypt
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input);

#ifdef __cplusplus
}
#endif

#endif
