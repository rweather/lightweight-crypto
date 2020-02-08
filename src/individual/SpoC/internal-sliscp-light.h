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

#ifndef LW_INTERNAL_SLISCP_LIGHT_H
#define LW_INTERNAL_SLISCP_LIGHT_H

/**
 * \file internal-sliscp-light.h
 * \brief sLiSCP-light permutation
 *
 * There are three variants of sLiSCP-light in use in the NIST submissions:
 *
 * \li sLiSCP-light-256 with a 256-bit block size, used in SPIX and SpoC.
 * \li sLiSCP-light-192 with a 192-bit block size, used in SpoC.
 * \li sLiSCP-light-320 with a 320-bit block size, used in ACE.
 *
 * References: https://uwaterloo.ca/communications-security-lab/lwc/ace,
 * https://uwaterloo.ca/communications-security-lab/lwc/spix,
 * https://uwaterloo.ca/communications-security-lab/lwc/spoc
 */

#include "internal-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the state for sLiSCP-light-256.
 */
#define SLISCP_LIGHT256_STATE_SIZE 32

/**
 * \brief Size of the state for sLiSCP-light-192.
 */
#define SLISCP_LIGHT192_STATE_SIZE 24

/**
 * \brief Size of the state for sLiSCP-light-320.
 */
#define SLISCP_LIGHT320_STATE_SIZE 40

/**
 * \brief Performs the sLiSCP-light permutation on a 256-bit block.
 *
 * \param block Points to the block to be permuted.
 * \param rounds Number of rounds to be performed, usually 9 or 18.
 */
void sliscp_light256_permute(unsigned char block[32], unsigned rounds);

/**
 * \brief Performs the sLiSCP-light permutation on a 192-bit block.
 *
 * \param block Points to the block to be permuted.
 */
void sliscp_light192_permute(unsigned char block[24]);

/**
 * \brief Performs the sLiSCP-light permutation on a 320-bit block.
 *
 * \param block Points to the block to be permuted.
 *
 * The ACE specification refers to this permutation as "ACE" but that
 * can be confused with the name of the AEAD mode so we call this
 * permutation "sLiSCP-light-320" instead.
 */
void sliscp_light320_permute(unsigned char block[40]);

#ifdef __cplusplus
}
#endif

#endif
