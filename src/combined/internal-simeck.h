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

#ifndef LW_INTERNAL_SIMECK_H
#define LW_INTERNAL_SIMECK_H

/**
 * \file internal-simeck.h
 * \brief Simeck-64 and Simeck-48 block ciphers.
 *
 * The Simeck-64 block cipher is used as an S-box as part of the core
 * permutations for ACE, SPIX, and 256-bit SpoC.
 *
 * The Simeck-48 block cipher is used as an S-box as part of the core
 * permutations for 192-bit SpoC.
 */

#include "internal-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts a 64-bit block with the 8 round version of Simeck-64.
 *
 * \param block Block to be encrypted, on input and output.
 * \param rc Round constants for the 8 rounds, 1 bit per round.
 *
 * It is assumed that the 64-bit input has already been converted from
 * big-endian to host byte order before calling this function.  The output
 * will also be in host byte order.
 */
void simeck64_box(uint32_t block[2], uint8_t rc);

/**
 * \brief Encrypts a 48-bit block with the 6 round version of Simeck-48.
 *
 * \param block Block to be encrypted, on input and output.
 * \param rc Round constants for the 6 rounds, 1 bit per round.
 *
 * It is assumed that the 48-bit input has already been converted from
 * big-endian to host byte order before calling this function with three
 * bytes of each half in the two words of \a block.  The output will also
 * be in host byte order.
 */
void simeck48_box(uint32_t block[2], uint8_t rc);

#ifdef __cplusplus
}
#endif

#endif
