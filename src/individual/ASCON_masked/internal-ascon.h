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

#ifndef LW_INTERNAL_ASCON_H
#define LW_INTERNAL_ASCON_H

#include "internal-util.h"

/**
 * \file internal-ascon.h
 * \brief Internal implementation of the ASCON permutation.
 *
 * References: http://competitions.cr.yp.to/round3/asconv12.pdf,
 * http://ascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Defined to 1 if the 32-bit sliced version of ASCON is available.
 */
#if !defined(__AVR__)
#define ASCON_SLICED 1
#else
#define ASCON_SLICED 0
#endif

/**
 * \brief Structure of the internal state of the ASCON permutation.
 */
typedef union
{
    uint64_t S[5];      /**< 64-bit words of the state */
    uint32_t W[10];     /**< 32-bit words of the state */
    uint8_t B[40];      /**< Bytes of the state */

} ascon_state_t;

/**
 * \brief Permutes the ASCON state.
 *
 * \param state The ASCON state to be permuted.
 * \param first_round The first round (of 12) to be performed; 0, 4, or 6.
 *
 * The input and output \a state will be in big-endian byte order.
 */
void ascon_permute(ascon_state_t *state, uint8_t first_round);

#if ASCON_SLICED

/**
 * \brief Converts an ASCON state from byte form into sliced form.
 *
 * \param state The ASCON state to be converted, in big-endian byte order
 * on entry and in host byte order on exit.
 */
void ascon_to_sliced(ascon_state_t *state);

/**
 * \brief Converts an ASCON state from sliced form into byte form.
 *
 * \param state The ASCON state to be converted, in host byte order
 * on entry and in big-endian byte order on exit.
 */
void ascon_from_sliced(ascon_state_t *state);

/**
 * \brief Permutes the ASCON state in sliced form.
 *
 * \param state The ASCON state to be permuted.
 * \param first_round The first round (of 12) to be performed; 0, 4, or 6.
 *
 * The input and output \a state will be in host byte order.
 */
void ascon_permute_sliced(ascon_state_t *state, uint8_t first_round);

/** @cond ascon_bit_separation */

/* http://programming.sirrida.de/perm_fn.html#bit_permute_step */
#define ascon_bit_permute_step(_y, mask, shift) \
    do { \
        uint32_t y = (_y); \
        uint32_t t = ((y >> (shift)) ^ y) & (mask); \
        (_y) = (y ^ t) ^ (t << (shift)); \
    } while (0)

/* Separates a 32-bit word into two 16-bit halves with all the even
 * bits in the bottom half and all the odd bits in the top half.
 *
 * Permutation generated with "http://programming.sirrida.de/calcperm.php"
 *
 * P = [0 16 1 17 2 18 3 19 4 20 5 21 6 22 7 23 8 24
 *      9 25 10 26 11 27 12 28 13 29 14 30 15 31]
 */
#define ascon_separate(x) \
    do { \
        ascon_bit_permute_step((x), 0x22222222, 1); \
        ascon_bit_permute_step((x), 0x0c0c0c0c, 2); \
        ascon_bit_permute_step((x), 0x00f000f0, 4); \
        ascon_bit_permute_step((x), 0x0000ff00, 8); \
    } while (0)
#define ascon_combine(x) \
    do { \
        ascon_bit_permute_step((x), 0x0000aaaa, 15); \
        ascon_bit_permute_step((x), 0x0000cccc, 14); \
        ascon_bit_permute_step((x), 0x0000f0f0, 12); \
        ascon_bit_permute_step((x), 0x0000ff00, 8); \
    } while (0)

/** @endcond */

/**
 * \brief Sets data into the ASCON state in sliced form.
 *
 * \param state The ASCON state for the data to be absorbed into.
 * \param data Points to 8 bytes of data in big-endian byte order to set.
 * \param offset Offset of the 64-bit word within the state to set at,
 * between 0 and 4.
 */
#define ascon_set_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((data)); \
        uint32_t low  = be_load_word32((data) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] = (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] = (high & 0xFFFF0000U) | (low >> 16); \
    } while (0)

/**
 * \brief Absorbs data into the ASCON state in sliced form.
 *
 * \param state The ASCON state for the data to be absorbed into.
 * \param data Points to 8 bytes of data in big-endian byte order to absorb.
 * \param offset Offset of the 64-bit word within the state to absorb at,
 * between 0 and 4.
 */
#define ascon_absorb_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((data)); \
        uint32_t low  = be_load_word32((data) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] ^= (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] ^= (high & 0xFFFF0000U) | (low >> 16); \
    } while (0)

/**
 * \brief Absorbs 32 bits of data into the ASCON state in sliced form.
 *
 * \param state The ASCON state for the data to be absorbed into.
 * \param data Points to 4 bytes of data in big-endian byte order to absorb.
 * \param offset Offset of the 64-bit word within the state to absorb at,
 * between 0 and 4.
 *
 * The data is absorbed into the low bits of the 64-bit word at \a offset.
 */
#define ascon_absorb32_low_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t low  = be_load_word32((data)); \
        ascon_separate(low); \
        s->W[(offset) * 2] ^= (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] ^= (low >> 16); \
    } while (0)

/**
 * \brief Absorbs 32 bits of data into the ASCON state in sliced form.
 *
 * \param state The ASCON state for the data to be absorbed into.
 * \param data Points to 4 bytes of data in big-endian byte order to absorb.
 * \param offset Offset of the 64-bit word within the state to absorb at,
 * between 0 and 4.
 *
 * The data is absorbed into the high bits of the 64-bit word at \a offset.
 */
#define ascon_absorb32_high_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((data)); \
        ascon_separate(high); \
        s->W[(offset) * 2] ^= (high << 16); \
        s->W[(offset) * 2 + 1] ^= (high & 0xFFFF0000U); \
    } while (0)

/**
 * \brief Squeezes data from the ASCON state in sliced form.
 *
 * \param state The ASCON state to extract the data from.
 * \param data Points to the 8 bytes to be extracted from the state.
 * \param offset Offset of the 64-bit word within the state to extract,
 * between 0 and 4.
 */
#define ascon_squeeze_sliced(state, data, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high, low; \
        high = (s->W[(offset) * 2] >> 16) | \
               (s->W[(offset) * 2 + 1] & 0xFFFF0000U); \
        low  = (s->W[(offset) * 2] & 0x0000FFFFU) | \
               (s->W[(offset) * 2 + 1] << 16); \
        ascon_combine(high); \
        ascon_combine(low); \
        be_store_word32((data), high); \
        be_store_word32((data) + 4, low); \
    } while (0)

/**
 * \brief Encrypts data using the ASCON state in sliced form.
 *
 * \param state The ASCON state.
 * \param c Points to 8 bytes of output ciphertext in big-endian byte order.
 * \param m Points to 8 bytes of input plaintext in big-endian byte order.
 * \param offset Offset of the 64-bit word within the state to absorb
 * and squeeze at, between 0 and 4.
 */
#define ascon_encrypt_sliced(state, c, m, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high = be_load_word32((m)); \
        uint32_t low  = be_load_word32((m) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        s->W[(offset) * 2] ^= (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] ^= (high & 0xFFFF0000U) | (low >> 16); \
        high = (s->W[(offset) * 2] >> 16) | \
               (s->W[(offset) * 2 + 1] & 0xFFFF0000U); \
        low  = (s->W[(offset) * 2] & 0x0000FFFFU) | \
               (s->W[(offset) * 2 + 1] << 16); \
        ascon_combine(high); \
        ascon_combine(low); \
        be_store_word32((c), high); \
        be_store_word32((c) + 4, low); \
    } while (0)

/**
 * \brief Decrypts data using the ASCON state in sliced form.
 *
 * \param state The ASCON state.
 * \param m Points to 8 bytes of output plaintext in big-endian byte order.
 * \param c Points to 8 bytes of input ciphertext in big-endian byte order.
 * \param offset Offset of the 64-bit word within the state to absorb
 * and squeeze at, between 0 and 4.
 */
#define ascon_decrypt_sliced(state, m, c, offset) \
    do { \
        ascon_state_t *s = (state); \
        uint32_t high, low, high2, low2; \
        high = be_load_word32((c)); \
        low  = be_load_word32((c) + 4); \
        ascon_separate(high); \
        ascon_separate(low); \
        high2 = high ^ ((s->W[(offset) * 2] >> 16) | \
                        (s->W[(offset) * 2 + 1] & 0xFFFF0000U)); \
        low2 = low ^ ((s->W[(offset) * 2] & 0x0000FFFFU) | \
                      (s->W[(offset) * 2 + 1] << 16)); \
        s->W[(offset) * 2] = (high << 16) | (low & 0x0000FFFFU); \
        s->W[(offset) * 2 + 1] = (high & 0xFFFF0000U) | (low >> 16); \
        ascon_combine(high2); \
        ascon_combine(low2); \
        be_store_word32((m), high2); \
        be_store_word32((m) + 4, low2); \
    } while (0)

#endif /* ASCON_SLICED */

#ifdef __cplusplus
}
#endif

#endif
