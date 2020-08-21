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

#ifndef LW_INTERNAL_ASCON_M_H
#define LW_INTERNAL_ASCON_M_H

#include "internal-masking.h"
#include "internal-ascon.h"

/**
 * \file internal-ascon-m.h
 * \brief Masked implementation of the ASCON permutation.
 *
 * References: http://competitions.cr.yp.to/round3/asconv12.pdf,
 * http://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Structure of the internal state of the masked ASCON permutation.
 */
typedef struct
{
    mask_uint64_t S[5];     /**< Masked 64-bit words of the state */

} ascon_masked_state_t;

/**
 * \brief Permutes the masked ASCON state.
 *
 * \param state The masked ASCON state to be permuted.
 * \param first_round The first round (of 12) to be performed; 0, 4, or 6.
 *
 * The input and output \a state will be in host byte order.
 */
void ascon_permute_masked(ascon_masked_state_t *state, uint8_t first_round);

/**
 * \brief Converts an unmasked ASCON state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, in big-endian byte order.
 */
void ascon_mask(ascon_masked_state_t *output, const ascon_state_t *input);

/**
 * \brief Converts a masked ASCON state into an unmasked state.
 *
 * \param output The output unmasked state, in big-endian byte order.
 * \param input The input masked state in host byte order.
 */
void ascon_unmask(ascon_state_t *output, const ascon_masked_state_t *input);

#if ASCON_SLICED

/**
 * \brief Converts an unmasked sliced ASCON state into a masked state.
 *
 * \param output The output masked state in host byte order.
 * \param input The input unmasked state, sliced, in host byte order.
 */
void ascon_mask_sliced
    (ascon_masked_state_t *output, const ascon_state_t *input);

/**
 * \brief Converts a masked ASCON state into an unmasked sliced state.
 *
 * \param output The output unmasked state, sliced, in host byte order.
 * \param input The input masked state in host byte order.
 */
void ascon_unmask_sliced
    (ascon_state_t *output, const ascon_masked_state_t *input);

#endif

#ifdef __cplusplus
}
#endif

#endif
