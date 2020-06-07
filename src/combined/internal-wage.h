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

#ifndef LW_INTERNAL_WAGE_H
#define LW_INTERNAL_WAGE_H

#include "internal-util.h"

/**
 * \file internal-wage.h
 * \brief Internal implementation of the WAGE permutation.
 *
 * References: https://uwaterloo.ca/communications-security-lab/lwc/wage
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the WAGE state in bytes.
 *
 * The state is 259 bits, divided into 37 7-bit components, one per byte.
 */
#define WAGE_STATE_SIZE 37

/**
 * \brief Permutes the WAGE state.
 *
 * \param s The WAGE state to be permuted.
 */
void wage_permute(unsigned char s[WAGE_STATE_SIZE]);

/**
 * \brief Absorbs 8 bytes into the WAGE state.
 *
 * \param s The WAGE state to be permuted.
 * \param data The data to be absorbed.
 */
void wage_absorb
    (unsigned char s[WAGE_STATE_SIZE], const unsigned char data[8]);

/**
 * \brief Gets the 8 bytes of the rate from the WAGE state.
 *
 * \param s The WAGE state to get the bytes from.
 * \param data Points to the buffer to receive the extracted bytes.
 */
void wage_get_rate
    (const unsigned char s[WAGE_STATE_SIZE], unsigned char data[8]);

/**
 * \brief Sets the 8 bytes of the rate in the WAGE state.
 *
 * \param s The WAGE state to set the rate in.
 * \param data Points to the bytes to set into the rate.
 */
void wage_set_rate
    (unsigned char s[WAGE_STATE_SIZE], const unsigned char data[8]);

/**
 * \brief Absorbs 16 key bytes into the WAGE state.
 *
 * \param s The WAGE state to be permuted.
 * \param key Points to the key data to be absorbed.
 */
void wage_absorb_key
    (unsigned char s[WAGE_STATE_SIZE], const unsigned char *key);

/**
 * \brief Initializes the WAGE state with a key and nonce.
 *
 * \param s The WAGE state to be initialized.
 * \param key Points to the 128-bit key.
 * \param nonce Points to the 128-bit nonce.
 */
void wage_init
    (unsigned char s[WAGE_STATE_SIZE],
     const unsigned char *key, const unsigned char *nonce);

/**
 * \brief Extracts the 128-bit authentication tag from the WAGE state.
 *
 * \param s The WAGE state to extract the tag from.
 * \param tag Points to the buffer to receive the extracted tag.
 */
void wage_extract_tag
    (const unsigned char s[WAGE_STATE_SIZE], unsigned char tag[16]);

#ifdef __cplusplus
}
#endif

#endif
