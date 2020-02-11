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

#ifndef LW_INTERNAL_SPARKLE_H
#define LW_INTERNAL_SPARKLE_H

#include "internal-util.h"

/**
 * \file internal-sparkle.h
 * \brief Internal implementation of the SPARKLE permutation.
 *
 * References: https://www.cryptolux.org/index.php/Sparkle
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the state for SPARKLE-256.
 */
#define SPARKLE_256_STATE_SIZE 8

/**
 * \brief Size of the state for SPARKLE-384.
 */
#define SPARKLE_384_STATE_SIZE 12

/**
 * \brief Size of the state for SPARKLE-512.
 */
#define SPARKLE_512_STATE_SIZE 16

/**
 * \brief Performs the SPARKLE-256 permutation.
 *
 * \param s The words of the SPARKLE-256 state in little-endian byte order.
 * \param steps The number of steps to perform, 7 or 10.
 */
void sparkle_256(uint32_t s[SPARKLE_256_STATE_SIZE], unsigned steps);

/**
 * \brief Performs the SPARKLE-384 permutation.
 *
 * \param s The words of the SPARKLE-384 state in little-endian byte order.
 * \param steps The number of steps to perform, 7 or 11.
 */
void sparkle_384(uint32_t s[SPARKLE_384_STATE_SIZE], unsigned steps);

/**
 * \brief Performs the SPARKLE-512 permutation.
 *
 * \param s The words of the SPARKLE-512 state in little-endian byte order.
 * \param steps The number of steps to perform, 8 or 12.
 */
void sparkle_512(uint32_t s[SPARKLE_512_STATE_SIZE], unsigned steps);

#ifdef __cplusplus
}
#endif

#endif
