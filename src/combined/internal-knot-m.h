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

#ifndef LW_INTERNAL_KNOT_M_H
#define LW_INTERNAL_KNOT_M_H

#include "internal-masking.h"

/**
 * \file internal-knot-m.h
 * \brief Masked implementation of the KNOT permutation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Internal state of the masked KNOT-256 permutation.
 */
typedef struct
{
    mask_uint64_t S[4]; /**< Masked words of the state */

} knot256_masked_state_t;

/**
 * \brief Internal state of the masked KNOT-384 permutation.
 *
 * Each row of the state is 96 bits in length.  We split it each row
 * into two sections to make it easier to access the masked words.
 */
typedef struct
{
    mask_uint64_t L[4]; /**< Low 64 bits of the masked words in the state */
    mask_uint32_t H[4]; /**< High 32 bits of the masked words in the state */

} knot384_masked_state_t;

/**
 * \brief Internal state of the masked KNOT-512 permutation.
 */
typedef struct
{
    mask_uint64_t S[8]; /**< Masked words of the state */

} knot512_masked_state_t;

/**
 * \brief Permutes the KNOT-256 state, using 6-bit round constants.
 *
 * \param state The KNOT-256 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 52.
 *
 * The input and output \a state will be in host byte order.
 */
void knot256_masked_permute_6(knot256_masked_state_t *state, uint8_t rounds);

/**
 * \brief Permutes the KNOT-256 state, using 7-bit round constants.
 *
 * \param state The KNOT-256 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 104.
 *
 * The input and output \a state will be in host byte order.
 */
void knot256_masked_permute_7(knot256_masked_state_t *state, uint8_t rounds);

/**
 * \brief Converts an unmasked KNOT-256 state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in little-endian byte order.
 */
void knot256_mask(knot256_masked_state_t *output, const uint64_t input[4]);

/**
 * \brief Converts a masked KNOT-256 state into an unmasked state.
 *
 * \param output The output unmasked state, in little-endian byte order.
 * \param input The input masked state in host byte order.
 */
void knot256_unmask(uint64_t output[4], const knot256_masked_state_t *input);

/**
 * \brief Permutes the KNOT-384 state, using 7-bit round constants.
 *
 * \param state The KNOT-384 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 104.
 *
 * The input and output \a state will be in host byte order.
 */
void knot384_masked_permute_7(knot384_masked_state_t *state, uint8_t rounds);

/**
 * \brief Converts an unmasked KNOT-384 state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in little-endian byte order.
 */
void knot384_mask(knot384_masked_state_t *output, const uint32_t input[12]);

/**
 * \brief Converts a masked KNOT-384 state into an unmasked state.
 *
 * \param output The output unmasked state, in little-endian byte order.
 * \param input The input masked state in host byte order.
 */
void knot384_unmask(uint32_t output[12], const knot384_masked_state_t *input);

/**
 * \brief Permutes the KNOT-512 state, using 7-bit round constants.
 *
 * \param state The KNOT-512 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 104.
 *
 * The input and output \a state will be in host byte order.
 */
void knot512_masked_permute_7(knot512_masked_state_t *state, uint8_t rounds);

/**
 * \brief Permutes the KNOT-512 state, using 8-bit round constants.
 *
 * \param state The KNOT-512 state to be permuted.
 * \param rounds The number of rounds to be performed, 1 to 140.
 *
 * The input and output \a state will be in host byte order.
 */
void knot512_masked_permute_8(knot512_masked_state_t *state, uint8_t rounds);

/**
 * \brief Converts an unmasked KNOT-512 state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in little-endian byte order.
 */
void knot512_mask(knot512_masked_state_t *output, const uint64_t input[8]);

/**
 * \brief Converts a masked KNOT-512 state into an unmasked state.
 *
 * \param output The output unmasked state, in little-endian byte order.
 * \param input The input masked state in host byte order.
 */
void knot512_unmask(uint64_t output[8], const knot512_masked_state_t *input);

#ifdef __cplusplus
}
#endif

#endif
