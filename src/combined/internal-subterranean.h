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

#ifndef LW_INTERNAL_SUBTERRANEAN_H
#define LW_INTERNAL_SUBTERRANEAN_H

#include "internal-util.h"

/**
 * \file internal-subterranean.h
 * \brief Internal implementation of the Subterranean block operation.
 *
 * References: https://cs.ru.nl/~joan/subterranean.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Representation of the 257-bit state of Subterranean.
 *
 * The 257-bit state is represented as nine 32-bit words with only a single
 * bit in the last word.
 */
typedef struct
{
    uint32_t x[9];      /**< State words */

} subterranean_state_t;

/**
 * \brief Performs a single Subterranean round.
 *
 * \param state Subterranean state to be transformed.
 */
void subterranean_round(subterranean_state_t *state);

/**
 * \brief Performs 8 Subterranean rounds with no absorption or squeezing
 * of data; i.e. data input and output is "blanked".
 *
 * \param state Subterranean state to be transformed.
 */
void subterranean_blank(subterranean_state_t *state);

/**
 * \brief Performs a single Subterranean round and absorbs 0 bytes.
 *
 * \param state Subterranean state to be transformed.
 */
#define subterranean_duplex_0(state) \
    do { \
        subterranean_round((state)); \
        (state)->x[0] ^= 2; /* padding for an empty block */ \
    } while (0)

/**
 * \brief Absorbs a single byte into the Subterranean state.
 *
 * \param state Subterranean state to be transformed.
 * \param data The single byte to be absorbed.
 */
void subterranean_absorb_1(subterranean_state_t *state, unsigned char data);

/**
 * \brief Performs a single Subterranean round and absorbs one byte.
 *
 * \param state Subterranean state to be transformed.
 * \param data The single byte to be absorbed.
 */
#define subterranean_duplex_1(state, data) \
    do { \
        subterranean_round((state)); \
        subterranean_absorb_1((state), (data)); \
    } while (0)

/**
 * \brief Absorbs a 32-bit word into the Subterranean state.
 *
 * \param state Subterranean state to be transformed.
 * \param x The word to absorb into the state.
 */
void subterranean_absorb_word(subterranean_state_t *state, uint32_t x);

/**
 * \brief Absorbs a 32-bit word into the Subterranean state after performing
 * the round function.
 *
 * \param state Subterranean state to be transformed.
 * \param x The word to absorb into the state.
 */
#define subterranean_duplex_word(state, x) \
    do { \
        subterranean_round((state)); \
        subterranean_absorb_word((state), (x)); \
    } while (0)

/**
 * \brief Performs a single Subterranean round and absorbs four bytes.
 *
 * \param state Subterranean state to be transformed.
 * \param data 32-bit word containing the four data bytes to be absorbed.
 */
#define subterranean_duplex_4(state, data) \
    do { \
        subterranean_duplex_word((state), (data)); \
        (state)->x[8] ^= 1; \
    } while (0)

/**
 * \brief Performs a single Subterranean round and absorbs between
 * zero and four bytes.
 *
 * \param state Subterranean state to be transformed.
 * \param data Points to the data bytes to be absorbed.
 * \param len Length of the data to be absorbed.
 */
void subterranean_duplex_n
    (subterranean_state_t *state, const unsigned char *data, unsigned len);

/**
 * \brief Extracts 32 bits of output from the Subterranean state.
 *
 * \param state Subterranean state to extract the output from.
 *
 * \return Returns the 32-bit word that was extracted.
 */
uint32_t subterranean_extract(subterranean_state_t *state);

/**
 * \brief Absorbs an arbitrary amount of data, four bytes at a time.
 *
 * \param state Subterranean state to be transformed.
 * \param data Points to the bytes to be absorbed.
 * \param len Number of bytes to absorb.
 */
void subterranean_absorb
    (subterranean_state_t *state, const unsigned char *data,
     unsigned long long len);

/**
 * \brief Squeezes an arbitrary amount of data out of a Subterranean state.
 *
 * \param state Subterranean state to extract the output from.
 * \param data Points to the data buffer to receive the output.
 * \param len Number of bytes to be extracted.
 */
void subterranean_squeeze
    (subterranean_state_t *state, unsigned char *data, unsigned len);

#ifdef __cplusplus
}
#endif

#endif
