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

#ifndef LW_INTERNAL_KNOT_H
#define LW_INTERNAL_KNOT_H

#include "internal-util.h"

/**
 * \file internal-knot.h
 * \brief Permutations that are used by the KNOT AEAD and hash algorithms.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Internal state of the KNOT-256 permutation.
 */
typedef union
{
    uint64_t S[4];      /**< Words of the state */
    uint8_t B[32];      /**< Bytes of the state */

} knot256_state_t;

/**
 * \brief Internal state of the KNOT-384 permutation.
 */
typedef union
{
    uint64_t S[6];      /**< 64-bit words of the state */
    uint32_t W[12];     /**< 32-bit words of the state */
    uint8_t B[48];      /**< Bytes of the state */

} knot384_state_t;

/**
 * \brief Internal state of the KNOT-512 permutation.
 */
typedef union
{
    uint64_t S[8];      /**< Words of the state */
    uint8_t B[64];      /**< Bytes of the state */

} knot512_state_t;

/**
 * \brief Permutes the KNOT-256 state, using 6-bit round constants.
 *
 * \param state The KNOT-256 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 52.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void knot256_permute_6(knot256_state_t *state, uint8_t rounds);

/**
 * \brief Permutes the KNOT-256 state, using 7-bit round constants.
 *
 * \param state The KNOT-256 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 104.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void knot256_permute_7(knot256_state_t *state, uint8_t rounds);

/**
 * \brief Permutes the KNOT-384 state, using 7-bit round constants.
 *
 * \param state The KNOT-384 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 104.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void knot384_permute_7(knot384_state_t *state, uint8_t rounds);

/**
 * \brief Permutes the KNOT-512 state, using 7-bit round constants.
 *
 * \param state The KNOT-512 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 104.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void knot512_permute_7(knot512_state_t *state, uint8_t rounds);

/**
 * \brief Permutes the KNOT-512 state, using 8-bit round constants.
 *
 * \param state The KNOT-512 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 140.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void knot512_permute_8(knot512_state_t *state, uint8_t rounds);

/**
 * \brief Generic pointer to a function that performs a KNOT permutation.
 *
 * \param state Points to the permutation state.
 * \param round Number of rounds to perform.
 */
typedef void (*knot_permute_t)(void *state, uint8_t rounds);

#ifdef __cplusplus
}
#endif

#endif
