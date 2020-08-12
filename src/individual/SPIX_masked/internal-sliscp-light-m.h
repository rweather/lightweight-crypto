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

#ifndef LW_INTERNAL_SLISCP_LIGHT_M_H
#define LW_INTERNAL_SLISCP_LIGHT_M_H

/**
 * \file internal-sliscp-light-m.h
 * \brief Masked version of the sLiSCP-light permutation
 */

#include "internal-masking.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @cond load_store_word24 */

/* Load a big-endian 24-bit word from a byte buffer */
#define be_load_word24(ptr) \
    ((((uint32_t)((ptr)[0])) << 16) | \
     (((uint32_t)((ptr)[1])) << 8) | \
      ((uint32_t)((ptr)[2])))

/* Store a big-endian 24-bit word into a byte buffer */
#define be_store_word24(ptr, x) \
    do { \
        uint32_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 16); \
        (ptr)[1] = (uint8_t)(_x >> 8); \
        (ptr)[2] = (uint8_t)_x; \
    } while (0)

/** @endcond */

/**
 * \brief Performs the masked sLiSCP-light permutation on a 192-bit block.
 *
 * \param block Points to the block to be permuted in host byte order.
 */
void sliscp_light192_permute_masked(mask_uint32_t block[8]);

/**
 * \brief Reduces masked 32-bit words into 24-bit words for sLiSCP-light-192.
 *
 * \param block Points to the block to be reduced.
 */
void sliscp_light192_reduce_masked(mask_uint32_t block[8]);

/**
 * \brief Converts an unmasked sLiSCP-light-192 state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in big-endian byte order.
 */
void sliscp_light192_mask
    (mask_uint32_t output[8], const unsigned char input[24]);

/**
 * \brief Converts a masked sLiSCP-light-192 state into an unmasked state.
 *
 * \param output The output unmasked state, in big-endian byte order.
 * \param input The input masked state in host byte order.
 */
void sliscp_light192_unmask
    (unsigned char output[24], const mask_uint32_t input[8]);

/**
 * \brief Performs the masked sLiSCP-light permutation on a 256-bit block.
 *
 * \param block Points to the block to be permuted in host byte order.
 * \param rounds Number of rounds to be performed, usually 9 or 18.
 */
void sliscp_light256_permute_masked(mask_uint32_t block[8], unsigned rounds);

/**
 * \brief Converts an unmasked sLiSCP-light-256 state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in big-endian byte order.
 */
void sliscp_light256_mask
    (mask_uint32_t output[8], const unsigned char input[32]);

/**
 * \brief Converts a masked sLiSCP-light-256 state into an unmasked state.
 *
 * \param output The output unmasked state, in big-endian byte order.
 * \param input The input masked state in host byte order.
 */
void sliscp_light256_unmask
    (unsigned char output[32], const mask_uint32_t input[8]);

/**
 * \brief Performs the masked sLiSCP-light permutation on a 320-bit block.
 *
 * \param block Points to the block to be permuted in host byte order.
 */
void sliscp_light320_permute_masked(mask_uint32_t block[10]);

/**
 * \brief Converts an unmasked sLiSCP-light-320 state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in big-endian byte order.
 */
void sliscp_light320_mask
    (mask_uint32_t output[10], const unsigned char input[40]);

/**
 * \brief Converts a masked sLiSCP-light-320 state into an unmasked state.
 *
 * \param output The output unmasked state, in big-endian byte order.
 * \param input The input masked state in host byte order.
 */
void sliscp_light320_unmask
    (unsigned char output[40], const mask_uint32_t input[10]);

#ifdef __cplusplus
}
#endif

#endif
