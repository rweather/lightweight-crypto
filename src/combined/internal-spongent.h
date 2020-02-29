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

#ifndef LW_INTERNAL_SPONGENT_H
#define LW_INTERNAL_SPONGENT_H

#include "internal-util.h"

/**
 * \file internal-spongent.h
 * \brief Internal implementation of the Spongent-pi permutation.
 *
 * References: https://www.esat.kuleuven.be/cosic/elephant/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the Spongent-pi[160] state in bytes.
 */
#define SPONGENT160_STATE_SIZE 20

/**
 * \brief Size of the Spongent-pi[176] state in bytes.
 */
#define SPONGENT176_STATE_SIZE 22

/**
 * \brief Structure of the internal state of the Spongent-pi[160] permutation.
 */
typedef union
{
    uint32_t W[5];      /**< Spongent-pi[160] state as 32-bit words */
    uint8_t B[20];      /**< Spongent-pi[160] state as bytes */

} spongent160_state_t;

/**
 * \brief Structure of the internal state of the Spongent-pi[176] permutation.
 *
 * Note: The state is technically only 176 bits, but we increase it to
 * 192 bits so that we can use 32-bit word operations to manipulate the
 * state.  The extra bits in the last word are fixed to zero.
 */
typedef union
{
    uint32_t W[6];      /**< Spongent-pi[176] state as 32-bit words */
    uint8_t B[24];      /**< Spongent-pi[176] state as bytes */

} spongent176_state_t;

/**
 * \brief Permutes the Spongent-pi[160] state.
 *
 * \param state The Spongent-pi[160] state to be permuted.
 */
void spongent160_permute(spongent160_state_t *state);

/**
 * \brief Permutes the Spongent-pi[176] state.
 *
 * \param state The Spongent-pi[176] state to be permuted.
 */
void spongent176_permute(spongent176_state_t *state);

#ifdef __cplusplus
}
#endif

#endif
