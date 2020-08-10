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

#ifndef LW_INTERNAL_MASKING_H
#define LW_INTERNAL_MASKING_H

#include "aead-random.h"

/**
 * \file internal-masking.h
 * \brief Utilities that help to implement masked ciphers.
 *
 * See \ref masking "masking.dox" for more information on the
 * definitions in this file.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \def AEAD_MASKING_SHARES
 * \brief Sets the default number of shares for the masked word operations.
 *
 * This value should be between 2 and 6.  If left undefined, the default is 4.
 */
#if !defined(AEAD_MASKING_SHARES)
#define AEAD_MASKING_SHARES 4
#endif

/**
 * \def AEAD_MASKING_KEY_ONLY
 * \brief Degree of masking to apply to AEAD modes.
 *
 * Permutation-based AEAD modes typically absorb the key and nonce in the
 * first block and then no longer have any use for the key.  If the goal
 * of the masking is to protect the key, then masking may not be required
 * for the remaining block operations once the key has been randomized
 * by combining it with the nonce.
 *
 * Define this macro to 1 to only mask block operations that involve
 * the key.  Define this macro to 0 to mask all block operations regardless.
 * The default is 0 because it is safer, albeit slower.
 */
#if !defined(AEAD_MASKING_KEY_ONLY)
#define AEAD_MASKING_KEY_ONLY 0
#endif

/**
 * \brief Masked 16-bit word with two shares.
 */
typedef struct
{
    uint16_t a;     /**< First share of the masked word state */
    uint16_t b;     /**< Second share of the masked word state */

} mask_x2_uint16_t;

/**
 * \brief Masked 16-bit word with three shares.
 */
typedef struct
{
    uint16_t a;     /**< First share of the masked word state */
    uint16_t b;     /**< Second share of the masked word state */
    uint16_t c;     /**< Third share of the masked word state */

} mask_x3_uint16_t;

/**
 * \brief Masked 16-bit word with four shares.
 */
typedef struct
{
    uint16_t a;     /**< First share of the masked word state */
    uint16_t b;     /**< Second share of the masked word state */
    uint16_t c;     /**< Third share of the masked word state */
    uint16_t d;     /**< Fourth share of the masked word state */

} mask_x4_uint16_t;

/**
 * \brief Masked 16-bit word with five shares.
 */
typedef struct
{
    uint16_t a;     /**< First share of the masked word state */
    uint16_t b;     /**< Second share of the masked word state */
    uint16_t c;     /**< Third share of the masked word state */
    uint16_t d;     /**< Fourth share of the masked word state */
    uint16_t e;     /**< Fifth share of the masked word state */

} mask_x5_uint16_t;

/**
 * \brief Masked 16-bit word with six shares.
 */
typedef struct
{
    uint16_t a;     /**< First share of the masked word state */
    uint16_t b;     /**< Second share of the masked word state */
    uint16_t c;     /**< Third share of the masked word state */
    uint16_t d;     /**< Fourth share of the masked word state */
    uint16_t e;     /**< Fifth share of the masked word state */
    uint16_t f;     /**< Sixth share of the masked word state */

} mask_x6_uint16_t;

/**
 * \brief Masked 32-bit word with two shares.
 */
typedef struct
{
    uint32_t a;     /**< First share of the masked word state */
    uint32_t b;     /**< Second share of the masked word state */

} mask_x2_uint32_t;

/**
 * \brief Masked 32-bit word with three shares.
 */
typedef struct
{
    uint32_t a;     /**< First share of the masked word state */
    uint32_t b;     /**< Second share of the masked word state */
    uint32_t c;     /**< Third share of the masked word state */

} mask_x3_uint32_t;

/**
 * \brief Masked 32-bit word with four shares.
 */
typedef struct
{
    uint32_t a;     /**< First share of the masked word state */
    uint32_t b;     /**< Second share of the masked word state */
    uint32_t c;     /**< Third share of the masked word state */
    uint32_t d;     /**< Fourth share of the masked word state */

} mask_x4_uint32_t;

/**
 * \brief Masked 32-bit word with five shares.
 */
typedef struct
{
    uint32_t a;     /**< First share of the masked word state */
    uint32_t b;     /**< Second share of the masked word state */
    uint32_t c;     /**< Third share of the masked word state */
    uint32_t d;     /**< Fourth share of the masked word state */
    uint32_t e;     /**< Fifth share of the masked word state */

} mask_x5_uint32_t;

/**
 * \brief Masked 32-bit word with six shares.
 */
typedef struct
{
    uint32_t a;     /**< First share of the masked word state */
    uint32_t b;     /**< Second share of the masked word state */
    uint32_t c;     /**< Third share of the masked word state */
    uint32_t d;     /**< Fourth share of the masked word state */
    uint32_t e;     /**< Fifth share of the masked word state */
    uint32_t f;     /**< Sixth share of the masked word state */

} mask_x6_uint32_t;

/**
 * \brief Masked 64-bit word with two shares.
 */
typedef struct
{
    uint64_t a;     /**< First share of the masked word state */
    uint64_t b;     /**< Second share of the masked word state */

} mask_x2_uint64_t;

/**
 * \brief Masked 64-bit word with three shares.
 */
typedef struct
{
    uint64_t a;     /**< First share of the masked word state */
    uint64_t b;     /**< Second share of the masked word state */
    uint64_t c;     /**< Third share of the masked word state */

} mask_x3_uint64_t;

/**
 * \brief Masked 64-bit word with four shares.
 */
typedef struct
{
    uint64_t a;     /**< First share of the masked word state */
    uint64_t b;     /**< Second share of the masked word state */
    uint64_t c;     /**< Third share of the masked word state */
    uint64_t d;     /**< Fourth share of the masked word state */

} mask_x4_uint64_t;

/**
 * \brief Masked 64-bit word with five shares.
 */
typedef struct
{
    uint64_t a;     /**< First share of the masked word state */
    uint64_t b;     /**< Second share of the masked word state */
    uint64_t c;     /**< Third share of the masked word state */
    uint64_t d;     /**< Fourth share of the masked word state */
    uint64_t e;     /**< Fifth share of the masked word state */

} mask_x5_uint64_t;

/**
 * \brief Masked 64-bit word with six shares.
 */
typedef struct
{
    uint64_t a;     /**< First share of the masked word state */
    uint64_t b;     /**< Second share of the masked word state */
    uint64_t c;     /**< Third share of the masked word state */
    uint64_t d;     /**< Fourth share of the masked word state */
    uint64_t e;     /**< Fifth share of the masked word state */
    uint64_t f;     /**< Sixth share of the masked word state */

} mask_x6_uint64_t;

/**
 * \brief Masks an input value to produce a 2-share masked word.
 *
 * \param value The masked word on output.
 * \param input The input value to be masked.
 */
#define mask_x2_input(value, input) \
    do { \
        if (sizeof((value).b) <= 4) \
            (value).b = aead_random_generate_32(); \
        else \
            (value).b = aead_random_generate_64(); \
        (value).a = (input) ^ (value).b; \
    } while (0)

/**
 * \brief Unmasks a 2-share masked word to produce an output value.
 *
 * \param value The masked word.
 * \return The unmasked version of \a value.
 */
#define mask_x2_output(value) ((value).a ^ (value).b)

/**
 * \brief Sets all shares of a 2-share word to zero.
 *
 * \param value The masked word to set to zero.
 */
#define mask_x2_zero(value) \
    do { \
        (value).a = 0; \
        (value).b = 0; \
    } while (0)

/**
 * \brief Adds a constant to a 2-share masked word.
 *
 * \param value The masked word.
 * \param cvalue The constant value to add using XOR.
 *
 * This function performs "value ^= cvalue" where "cvalue" is a constant
 * or external data value rather than another masked word.
 */
#define mask_x2_xor_const(value, cvalue) \
    do { \
        (value).a ^= (cvalue); \
    } while (0)

/**
 * \brief XOR's two 2-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The source masked word.
 *
 * This function performs "value1 ^= value2".
 */
#define mask_x2_xor(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
    } while (0)

/**
 * \brief XOR's three 2-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The first source masked word.
 * \param value3 The second source masked word.
 *
 * This function performs "value1 ^= (value2 ^ value3)".
 */
#define mask_x2_xor3(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a ^ (value3).a); \
        (value1).b ^= ((value2).b ^ (value3).b); \
    } while (0)

/**
 * \brief NOT's a 2-share masked word.
 *
 * \param value The masked word to NOT.
 *
 * Equivalent to adding the all-1's constant to the masked word.
 */
#define mask_x2_not(value) \
    do { \
        (value).a = ~((value).a); \
    } while (0)

/** @cond masked_mix_and */

/* Inner implementation of AND'ing two 2-share masked words */
#define mask_mix_and(x2, x1, x0, y2, y1, y0) \
    do { \
        if (sizeof(temp) <= 4) \
            temp = aead_random_generate_32(); \
        else \
            temp = aead_random_generate_64(); \
        (x2) ^= temp; \
        temp ^= ((y0) & (x1)); \
        (y2) = ((y2) ^ temp) ^ ((y1) & (x0)); \
    } while (0)

/** @endcond */

/**
 * \brief AND's two 2-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x2_and(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a & (value3).a); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        (value1).b ^= ((value2).b & (value3).b); \
    } while (0)

/**
 * \brief AND's two 2-share masked words and XOR's the result with
 * another word, where the first input word is inverted.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument to be inverted.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= ((~value2) & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x2_and_not(value1, value2, value3) \
    do { \
        (value1).a ^= ((~(value2).a) & (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        (value1).b ^= ((value2).b & (value3).b); \
    } while (0)

/**
 * \brief OR's two 2-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 | value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x2_or(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a) | ((value3).a); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        (value1).b ^= ((value2).b & (value3).b); \
    } while (0)

/**
 * \brief Performs a left shift on a 2-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x2_shl(value1, value2, bits) \
    do { \
        (value1).a = (value2).a << (bits); \
        (value1).b = (value2).b << (bits); \
    } while (0)

/**
 * \brief Performs a right shift on a 2-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x2_shr(value1, value2, bits) \
    do { \
        (value1).a = (value2).a >> (bits); \
        (value1).b = (value2).b >> (bits); \
    } while (0)

/**
 * \brief Performs a left rotate on a 2-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x2_rol(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a << (bits)) | \
                     ((value2).a >> (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b << (bits)) | \
                     ((value2).b >> (sizeof((value1).b) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a right rotate on a 2-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x2_ror(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a >> (bits)) | \
                     ((value2).a << (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b >> (bits)) | \
                     ((value2).b << (sizeof((value1).b) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a swap on two 2-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 */
#define mask_x2_swap(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value2).a ^= (value1).a; \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value2).b ^= (value1).b; \
        (value1).b ^= (value2).b; \
    } while (0)

/** @@cond mask_swap_move */

#define mask_swap_move_internal(a, b, mask, shift) \
    do { \
        temp = ((b) ^ ((a) >> (shift))) & (mask); \
        (b) ^= temp; \
        (a) ^= temp << (shift); \
    } while (0)

/** @endcond */

/**
 * \brief Performs a swap and move on two 2-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 * \param mask The mask to extract the bits to move.
 * \param shift The number of bits to move by.
 */
#define mask_x2_swap_move(value1, value2, mask, shift) \
    do { \
        mask_swap_move_internal((value1).a, (value2).a, (mask), (shift)); \
        mask_swap_move_internal((value1).b, (value2).b, (mask), (shift)); \
    } while (0)

/**
 * \brief Masks an input value to produce a 3-share masked word.
 *
 * \param value The masked word on output.
 * \param input The input value to be masked.
 */
#define mask_x3_input(value, input) \
    do { \
        if (sizeof((value).b) <= 4) { \
            (value).b = aead_random_generate_32(); \
            (value).c = aead_random_generate_32(); \
        } else { \
            (value).b = aead_random_generate_64(); \
            (value).c = aead_random_generate_64(); \
        } \
        (value).a = (input) ^ (value).b ^ (value).c; \
    } while (0)

/**
 * \brief Unmasks a 3-share masked word to produce an output value.
 *
 * \param value The masked word.
 * \return The unmasked version of \a value.
 */
#define mask_x3_output(value) ((value).a ^ (value).b ^ (value).c)

/**
 * \brief Sets all shares of a 3-share word to zero.
 *
 * \param value The masked word to set to zero.
 */
#define mask_x3_zero(value) \
    do { \
        (value).a = 0; \
        (value).b = 0; \
        (value).c = 0; \
    } while (0)

/**
 * \brief Adds a constant to a 3-share masked word.
 *
 * \param value The masked word.
 * \param cvalue The constant value to add using XOR.
 *
 * This function performs "value ^= cvalue" where "cvalue" is a constant
 * or external data value rather than another masked word.
 */
#define mask_x3_xor_const(value, cvalue) \
    do { \
        (value).a ^= (cvalue); \
    } while (0)

/**
 * \brief XOR's two 3-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The source masked word.
 *
 * This function performs "value1 ^= value2".
 */
#define mask_x3_xor(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
    } while (0)

/**
 * \brief XOR's three 3-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The first source masked word.
 * \param value3 The second source masked word.
 *
 * This function performs "value1 ^= (value2 ^ value3)".
 */
#define mask_x3_xor3(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a ^ (value3).a); \
        (value1).b ^= ((value2).b ^ (value3).b); \
        (value1).c ^= ((value2).c ^ (value3).c); \
    } while (0)

/**
 * \brief NOT's a 3-share masked word.
 *
 * \param value The masked word to NOT.
 *
 * Equivalent to adding the all-1's constant to the masked word.
 */
#define mask_x3_not(value) \
    do { \
        (value).a = ~((value).a); \
    } while (0)

/**
 * \brief AND's two 3-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x3_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x3_and(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a & (value3).a); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        (value1).c ^= ((value2).c & (value3).c); \
    } while (0)

/**
 * \brief AND's two 3-share masked words and XOR's the result with
 * another word, where the first input word is inverted.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument to be inverted.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= ((~value2) & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x3_and_not(value1, value2, value3) \
    do { \
        (value1).a ^= ((~(value2).a) & (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        (value1).c ^= ((value2).c & (value3).c); \
    } while (0)

/**
 * \brief OR's two 3-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 | value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x3_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x3_or(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a | (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        (value1).c ^= ((value2).c & (value3).c); \
    } while (0)

/**
 * \brief Performs a left shift on a 3-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x3_shl(value1, value2, bits) \
    do { \
        (value1).a = (value2).a << (bits); \
        (value1).b = (value2).b << (bits); \
        (value1).c = (value2).c << (bits); \
    } while (0)

/**
 * \brief Performs a right shift on a 3-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x3_shr(value1, value2, bits) \
    do { \
        (value1).a = (value2).a >> (bits); \
        (value1).b = (value2).b >> (bits); \
        (value1).c = (value2).c >> (bits); \
    } while (0)

/**
 * \brief Performs a left rotate on a 3-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x3_rol(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a << (bits)) | \
                     ((value2).a >> (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b << (bits)) | \
                     ((value2).b >> (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c << (bits)) | \
                     ((value2).c >> (sizeof((value1).c) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a right rotate on a 3-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x3_ror(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a >> (bits)) | \
                     ((value2).a << (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b >> (bits)) | \
                     ((value2).b << (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c >> (bits)) | \
                     ((value2).c << (sizeof((value1).c) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a swap on two 3-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 */
#define mask_x3_swap(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value2).a ^= (value1).a; \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value2).b ^= (value1).b; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value2).c ^= (value1).c; \
        (value1).c ^= (value2).c; \
    } while (0)

/**
 * \brief Performs a swap and move on two 3-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 * \param mask The mask to extract the bits to move.
 * \param shift The number of bits to move by.
 */
#define mask_x3_swap_move(value1, value2, mask, shift) \
    do { \
        mask_swap_move_internal((value1).a, (value2).a, (mask), (shift)); \
        mask_swap_move_internal((value1).b, (value2).b, (mask), (shift)); \
        mask_swap_move_internal((value1).c, (value2).c, (mask), (shift)); \
    } while (0)

/**
 * \brief Masks an input value to produce a 4-share masked word.
 *
 * \param value The masked word on output.
 * \param input The input value to be masked.
 */
#define mask_x4_input(value, input) \
    do { \
        if (sizeof((value).b) <= 4) { \
            (value).b = aead_random_generate_32(); \
            (value).c = aead_random_generate_32(); \
            (value).d = aead_random_generate_32(); \
        } else { \
            (value).b = aead_random_generate_64(); \
            (value).c = aead_random_generate_64(); \
            (value).d = aead_random_generate_64(); \
        } \
        (value).a = (input) ^ (value).b ^ (value).c ^ (value).d; \
    } while (0)

/**
 * \brief Unmasks a 4-share masked word to produce an output value.
 *
 * \param value The masked word.
 * \return The unmasked version of \a value.
 */
#define mask_x4_output(value) ((value).a ^ (value).b ^ (value).c ^ (value).d)

/**
 * \brief Sets all shares of a 4-share word to zero.
 *
 * \param value The masked word to set to zero.
 */
#define mask_x4_zero(value) \
    do { \
        (value).a = 0; \
        (value).b = 0; \
        (value).c = 0; \
        (value).d = 0; \
    } while (0)

/**
 * \brief Adds a constant to a 4-share masked word.
 *
 * \param value The masked word.
 * \param cvalue The constant value to add using XOR.
 *
 * This function performs "value ^= cvalue" where "cvalue" is a constant
 * or external data value rather than another masked word.
 */
#define mask_x4_xor_const(value, cvalue) \
    do { \
        (value).a ^= (cvalue); \
    } while (0)

/**
 * \brief XOR's two 4-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The source masked word.
 *
 * This function performs "value1 ^= value2".
 */
#define mask_x4_xor(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value1).d ^= (value2).d; \
    } while (0)

/**
 * \brief XOR's three 4-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The first source masked word.
 * \param value3 The second source masked word.
 *
 * This function performs "value1 ^= (value2 ^ value3)".
 */
#define mask_x4_xor3(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a ^ (value3).a); \
        (value1).b ^= ((value2).b ^ (value3).b); \
        (value1).c ^= ((value2).c ^ (value3).c); \
        (value1).d ^= ((value2).d ^ (value3).d); \
    } while (0)

/**
 * \brief NOT's a 4-share masked word.
 *
 * \param value The masked word to NOT.
 *
 * Equivalent to adding the all-1's constant to the masked word.
 */
#define mask_x4_not(value) \
    do { \
        (value).a = ~((value).a); \
    } while (0)

/**
 * \brief AND's two 4-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x4_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x4_and(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a & (value3).a); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).d ^= ((value2).d & (value3).d); \
    } while (0)

/**
 * \brief AND's two 4-share masked words and XOR's the result with
 * another word, where the first input word is inverted.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument to be inverted.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= ((~value2) & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x4_and_not(value1, value2, value3) \
    do { \
        (value1).a ^= ((~(value2).a) & (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).d ^= ((value2).d & (value3).d); \
    } while (0)

/**
 * \brief OR's two 4-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 | value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x4_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x4_or(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a | (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        (value1).d ^= ((value2).d & (value3).d); \
    } while (0)

/**
 * \brief Performs a left shift on a 4-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x4_shl(value1, value2, bits) \
    do { \
        (value1).a = (value2).a << (bits); \
        (value1).b = (value2).b << (bits); \
        (value1).c = (value2).c << (bits); \
        (value1).d = (value2).d << (bits); \
    } while (0)

/**
 * \brief Performs a right shift on a 4-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x4_shr(value1, value2, bits) \
    do { \
        (value1).a = (value2).a >> (bits); \
        (value1).b = (value2).b >> (bits); \
        (value1).c = (value2).c >> (bits); \
        (value1).d = (value2).d >> (bits); \
    } while (0)

/**
 * \brief Performs a left rotate on a 4-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x4_rol(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a << (bits)) | \
                     ((value2).a >> (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b << (bits)) | \
                     ((value2).b >> (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c << (bits)) | \
                     ((value2).c >> (sizeof((value1).c) * 8 - (bits))); \
        (value1).d = ((value2).d << (bits)) | \
                     ((value2).d >> (sizeof((value1).d) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a right rotate on a 4-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x4_ror(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a >> (bits)) | \
                     ((value2).a << (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b >> (bits)) | \
                     ((value2).b << (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c >> (bits)) | \
                     ((value2).c << (sizeof((value1).c) * 8 - (bits))); \
        (value1).d = ((value2).d >> (bits)) | \
                     ((value2).d << (sizeof((value1).d) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a swap on two 4-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 */
#define mask_x4_swap(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value2).a ^= (value1).a; \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value2).b ^= (value1).b; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value2).c ^= (value1).c; \
        (value1).c ^= (value2).c; \
        (value1).d ^= (value2).d; \
        (value2).d ^= (value1).d; \
        (value1).d ^= (value2).d; \
    } while (0)

/**
 * \brief Performs a swap and move on two 4-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 * \param mask The mask to extract the bits to move.
 * \param shift The number of bits to move by.
 */
#define mask_x4_swap_move(value1, value2, mask, shift) \
    do { \
        mask_swap_move_internal((value1).a, (value2).a, (mask), (shift)); \
        mask_swap_move_internal((value1).b, (value2).b, (mask), (shift)); \
        mask_swap_move_internal((value1).c, (value2).c, (mask), (shift)); \
        mask_swap_move_internal((value1).d, (value2).d, (mask), (shift)); \
    } while (0)

/**
 * \brief Masks an input value to produce a 5-share masked word.
 *
 * \param value The masked word on output.
 * \param input The input value to be masked.
 */
#define mask_x5_input(value, input) \
    do { \
        if (sizeof((value).b) <= 4) { \
            (value).b = aead_random_generate_32(); \
            (value).c = aead_random_generate_32(); \
            (value).d = aead_random_generate_32(); \
            (value).e = aead_random_generate_32(); \
        } else { \
            (value).b = aead_random_generate_64(); \
            (value).c = aead_random_generate_64(); \
            (value).d = aead_random_generate_64(); \
            (value).e = aead_random_generate_64(); \
        } \
        (value).a = (input) ^ (value).b ^ (value).c ^ (value).d ^ (value).e; \
    } while (0)

/**
 * \brief Unmasks a 5-share masked word to produce an output value.
 *
 * \param value The masked word.
 * \return The unmasked version of \a value.
 */
#define mask_x5_output(value) \
    ((value).a ^ (value).b ^ (value).c ^ (value).d ^ (value).e)

/**
 * \brief Sets all shares of a 5-share word to zero.
 *
 * \param value The masked word to set to zero.
 */
#define mask_x5_zero(value) \
    do { \
        (value).a = 0; \
        (value).b = 0; \
        (value).c = 0; \
        (value).d = 0; \
        (value).e = 0; \
    } while (0)

/**
 * \brief Adds a constant to a 5-share masked word.
 *
 * \param value The masked word.
 * \param cvalue The constant value to add using XOR.
 *
 * This function performs "value ^= cvalue" where "cvalue" is a constant
 * or external data value rather than another masked word.
 */
#define mask_x5_xor_const(value, cvalue) \
    do { \
        (value).a ^= (cvalue); \
    } while (0)

/**
 * \brief XOR's two 5-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The source masked word.
 *
 * This function performs "value1 ^= value2".
 */
#define mask_x5_xor(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value1).d ^= (value2).d; \
        (value1).e ^= (value2).e; \
    } while (0)

/**
 * \brief XOR's three 5-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The first source masked word.
 * \param value3 The second source masked word.
 *
 * This function performs "value1 ^= (value2 ^ value3)".
 */
#define mask_x5_xor3(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a ^ (value3).a); \
        (value1).b ^= ((value2).b ^ (value3).b); \
        (value1).c ^= ((value2).c ^ (value3).c); \
        (value1).d ^= ((value2).d ^ (value3).d); \
        (value1).e ^= ((value2).e ^ (value3).e); \
    } while (0)

/**
 * \brief NOT's a 5-share masked word.
 *
 * \param value The masked word to NOT.
 *
 * Equivalent to adding the all-1's constant to the masked word.
 */
#define mask_x5_not(value) \
    do { \
        (value).a = ~((value).a); \
    } while (0)

/**
 * \brief AND's two 5-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x5_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x5_and(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a & (value3).a); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).d ^= ((value2).d & (value3).d); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).e ^= ((value2).e & (value3).e); \
    } while (0)

/**
 * \brief AND's two 5-share masked words and XOR's the result with
 * another word, where the first input word is inverted.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument to be inverted.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= ((~value2) & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x5_and_not(value1, value2, value3) \
    do { \
        (value1).a ^= ((~(value2).a) & (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).d ^= ((value2).d & (value3).d); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).e ^= ((value2).e & (value3).e); \
    } while (0)

/**
 * \brief OR's two 5-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 | value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x5_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x5_or(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a | (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).d ^= ((value2).d & (value3).d); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).e, (value2).e, (value3).e); \
        (value1).e ^= ((value2).e & (value3).e); \
    } while (0)

/**
 * \brief Performs a left shift on a 5-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x5_shl(value1, value2, bits) \
    do { \
        (value1).a = (value2).a << (bits); \
        (value1).b = (value2).b << (bits); \
        (value1).c = (value2).c << (bits); \
        (value1).d = (value2).d << (bits); \
        (value1).e = (value2).e << (bits); \
    } while (0)

/**
 * \brief Performs a right shift on a 5-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x5_shr(value1, value2, bits) \
    do { \
        (value1).a = (value2).a >> (bits); \
        (value1).b = (value2).b >> (bits); \
        (value1).c = (value2).c >> (bits); \
        (value1).d = (value2).d >> (bits); \
        (value1).e = (value2).e >> (bits); \
    } while (0)

/**
 * \brief Performs a left rotate on a 5-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x5_rol(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a << (bits)) | \
                     ((value2).a >> (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b << (bits)) | \
                     ((value2).b >> (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c << (bits)) | \
                     ((value2).c >> (sizeof((value1).c) * 8 - (bits))); \
        (value1).d = ((value2).d << (bits)) | \
                     ((value2).d >> (sizeof((value1).d) * 8 - (bits))); \
        (value1).e = ((value2).e << (bits)) | \
                     ((value2).e >> (sizeof((value1).d) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a right rotate on a 5-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x5_ror(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a >> (bits)) | \
                     ((value2).a << (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b >> (bits)) | \
                     ((value2).b << (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c >> (bits)) | \
                     ((value2).c << (sizeof((value1).c) * 8 - (bits))); \
        (value1).d = ((value2).d >> (bits)) | \
                     ((value2).d << (sizeof((value1).d) * 8 - (bits))); \
        (value1).e = ((value2).e >> (bits)) | \
                     ((value2).e << (sizeof((value1).d) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a swap on two 5-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 */
#define mask_x5_swap(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value2).a ^= (value1).a; \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value2).b ^= (value1).b; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value2).c ^= (value1).c; \
        (value1).c ^= (value2).c; \
        (value1).d ^= (value2).d; \
        (value2).d ^= (value1).d; \
        (value1).d ^= (value2).d; \
        (value1).e ^= (value2).e; \
        (value2).e ^= (value1).e; \
        (value1).e ^= (value2).e; \
    } while (0)

/**
 * \brief Performs a swap and move on two 5-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 * \param mask The mask to extract the bits to move.
 * \param shift The number of bits to move by.
 */
#define mask_x5_swap_move(value1, value2, mask, shift) \
    do { \
        mask_swap_move_internal((value1).a, (value2).a, (mask), (shift)); \
        mask_swap_move_internal((value1).b, (value2).b, (mask), (shift)); \
        mask_swap_move_internal((value1).c, (value2).c, (mask), (shift)); \
        mask_swap_move_internal((value1).d, (value2).d, (mask), (shift)); \
        mask_swap_move_internal((value1).e, (value2).e, (mask), (shift)); \
    } while (0)

/**
 * \brief Masks an input value to produce a 6-share masked word.
 *
 * \param value The masked word on output.
 * \param input The input value to be masked.
 */
#define mask_x6_input(value, input) \
    do { \
        if (sizeof((value).b) <= 4) { \
            (value).b = aead_random_generate_32(); \
            (value).c = aead_random_generate_32(); \
            (value).d = aead_random_generate_32(); \
            (value).e = aead_random_generate_32(); \
            (value).f = aead_random_generate_32(); \
        } else { \
            (value).b = aead_random_generate_64(); \
            (value).c = aead_random_generate_64(); \
            (value).d = aead_random_generate_64(); \
            (value).e = aead_random_generate_64(); \
            (value).f = aead_random_generate_64(); \
        } \
        (value).a = (input) ^ (value).b ^ (value).c ^ \
                  (value).d ^ (value).e ^ (value).f; \
    } while (0)

/**
 * \brief Unmasks a 6-share masked word to produce an output value.
 *
 * \param value The masked word.
 * \return The unmasked version of \a value.
 */
#define mask_x6_output(value) \
    ((value).a ^ (value).b ^ (value).c ^ (value).d ^ (value).e ^ (value).f)

/**
 * \brief Sets all shares of a 6-share word to zero.
 *
 * \param value The masked word to set to zero.
 */
#define mask_x6_zero(value) \
    do { \
        (value).a = 0; \
        (value).b = 0; \
        (value).c = 0; \
        (value).d = 0; \
        (value).e = 0; \
        (value).f = 0; \
    } while (0)

/**
 * \brief Adds a constant to a 6-share masked word.
 *
 * \param value The masked word.
 * \param cvalue The constant value to add using XOR.
 *
 * This function performs "value ^= cvalue" where "cvalue" is a constant
 * or external data value rather than another masked word.
 */
#define mask_x6_xor_const(value, cvalue) \
    do { \
        (value).a ^= (cvalue); \
    } while (0)

/**
 * \brief XOR's two 6-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The source masked word.
 *
 * This function performs "value1 ^= value2".
 */
#define mask_x6_xor(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value1).d ^= (value2).d; \
        (value1).e ^= (value2).e; \
        (value1).f ^= (value2).f; \
    } while (0)

/**
 * \brief XOR's three 6-share masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The first source masked word.
 * \param value3 The second source masked word.
 *
 * This function performs "value1 ^= (value2 ^ value3)".
 */
#define mask_x6_xor3(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a ^ (value3).a); \
        (value1).b ^= ((value2).b ^ (value3).b); \
        (value1).c ^= ((value2).c ^ (value3).c); \
        (value1).d ^= ((value2).d ^ (value3).d); \
        (value1).e ^= ((value2).e ^ (value3).e); \
        (value1).f ^= ((value2).f ^ (value3).f); \
    } while (0)

/**
 * \brief NOT's a 6-share masked word.
 *
 * \param value The masked word to NOT.
 *
 * Equivalent to adding the all-1's constant to the masked word.
 */
#define mask_x6_not(value) \
    do { \
        (value).a = ~((value).a); \
    } while (0)

/**
 * \brief AND's two 6-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x6_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x6_and(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a & (value3).a); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).a, (value2).a, (value3).a, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).d ^= ((value2).d & (value3).d); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).e ^= ((value2).e & (value3).e); \
        mask_mix_and((value1).e, (value2).e, (value3).e, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).f ^= ((value2).f & (value3).f); \
    } while (0)

/**
 * \brief AND's two 6-share masked words and XOR's the result with
 * another word, where the first input word is inverted.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument to be inverted.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= ((~value2) & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x6_and_not(value1, value2, value3) \
    do { \
        (value1).a ^= ((~(value2).a) & (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).a, ~(value2).a, (value3).a, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).d ^= ((value2).d & (value3).d); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).e ^= ((value2).e & (value3).e); \
        mask_mix_and((value1).e, (value2).e, (value3).e, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).f ^= ((value2).f & (value3).f); \
    } while (0)

/**
 * \brief OR's two 6-share masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 | value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x6_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_x6_or(value1, value2, value3) \
    do { \
        (value1).a ^= ((value2).a | (value3).a); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).b, (value2).b, (value3).b); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).a, ~(value2).a, ~(value3).a, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).b ^= ((value2).b & (value3).b); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).c, (value2).c, (value3).c); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).b, (value2).b, (value3).b, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).c ^= ((value2).c & (value3).c); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).d, (value2).d, (value3).d); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).c, (value2).c, (value3).c, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).d ^= ((value2).d & (value3).d); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).e, (value2).e, (value3).e); \
        mask_mix_and((value1).d, (value2).d, (value3).d, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).e ^= ((value2).e & (value3).e); \
        mask_mix_and((value1).e, (value2).e, (value3).e, \
                     (value1).f, (value2).f, (value3).f); \
        (value1).f ^= ((value2).f & (value3).f); \
    } while (0)

/**
 * \brief Performs a left shift on a 6-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x6_shl(value1, value2, bits) \
    do { \
        (value1).a = (value2).a << (bits); \
        (value1).b = (value2).b << (bits); \
        (value1).c = (value2).c << (bits); \
        (value1).d = (value2).d << (bits); \
        (value1).e = (value2).e << (bits); \
        (value1).f = (value2).f << (bits); \
    } while (0)

/**
 * \brief Performs a right shift on a 6-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_x6_shr(value1, value2, bits) \
    do { \
        (value1).a = (value2).a >> (bits); \
        (value1).b = (value2).b >> (bits); \
        (value1).c = (value2).c >> (bits); \
        (value1).d = (value2).d >> (bits); \
        (value1).e = (value2).e >> (bits); \
        (value1).f = (value2).f >> (bits); \
    } while (0)

/**
 * \brief Performs a left rotate on a 6-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x6_rol(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a << (bits)) | \
                     ((value2).a >> (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b << (bits)) | \
                     ((value2).b >> (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c << (bits)) | \
                     ((value2).c >> (sizeof((value1).c) * 8 - (bits))); \
        (value1).d = ((value2).d << (bits)) | \
                     ((value2).d >> (sizeof((value1).d) * 8 - (bits))); \
        (value1).e = ((value2).e << (bits)) | \
                     ((value2).e >> (sizeof((value1).e) * 8 - (bits))); \
        (value1).f = ((value2).f << (bits)) | \
                     ((value2).f >> (sizeof((value1).f) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a right rotate on a 6-share masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_x6_ror(value1, value2, bits) \
    do { \
        (value1).a = ((value2).a >> (bits)) | \
                     ((value2).a << (sizeof((value1).a) * 8 - (bits))); \
        (value1).b = ((value2).b >> (bits)) | \
                     ((value2).b << (sizeof((value1).b) * 8 - (bits))); \
        (value1).c = ((value2).c >> (bits)) | \
                     ((value2).c << (sizeof((value1).c) * 8 - (bits))); \
        (value1).d = ((value2).d >> (bits)) | \
                     ((value2).d << (sizeof((value1).d) * 8 - (bits))); \
        (value1).e = ((value2).e >> (bits)) | \
                     ((value2).e << (sizeof((value1).e) * 8 - (bits))); \
        (value1).f = ((value2).f >> (bits)) | \
                     ((value2).f << (sizeof((value1).f) * 8 - (bits))); \
    } while (0)

/**
 * \brief Performs a swap on two 6-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 */
#define mask_x6_swap(value1, value2) \
    do { \
        (value1).a ^= (value2).a; \
        (value2).a ^= (value1).a; \
        (value1).a ^= (value2).a; \
        (value1).b ^= (value2).b; \
        (value2).b ^= (value1).b; \
        (value1).b ^= (value2).b; \
        (value1).c ^= (value2).c; \
        (value2).c ^= (value1).c; \
        (value1).c ^= (value2).c; \
        (value1).d ^= (value2).d; \
        (value2).d ^= (value1).d; \
        (value1).d ^= (value2).d; \
        (value1).e ^= (value2).e; \
        (value2).e ^= (value1).e; \
        (value1).e ^= (value2).e; \
        (value1).f ^= (value2).f; \
        (value2).f ^= (value1).f; \
        (value1).f ^= (value2).f; \
    } while (0)

/**
 * \brief Performs a swap and move on two 6-share masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 * \param mask The mask to extract the bits to move.
 * \param shift The number of bits to move by.
 */
#define mask_x6_swap_move(value1, value2, mask, shift) \
    do { \
        mask_swap_move_internal((value1).a, (value2).a, (mask), (shift)); \
        mask_swap_move_internal((value1).b, (value2).b, (mask), (shift)); \
        mask_swap_move_internal((value1).c, (value2).c, (mask), (shift)); \
        mask_swap_move_internal((value1).d, (value2).d, (mask), (shift)); \
        mask_swap_move_internal((value1).e, (value2).e, (mask), (shift)); \
        mask_swap_move_internal((value1).f, (value2).f, (mask), (shift)); \
    } while (0)

/* Define aliases for operating on shares in a generic fashion */
#if AEAD_MASKING_SHARES == 2
typedef mask_x2_uint16_t mask_uint16_t;
typedef mask_x2_uint32_t mask_uint32_t;
typedef mask_x2_uint64_t mask_uint64_t;
#define mask_input(value, input) mask_x2_input((value), (input))
#define mask_output(value) mask_x2_output((value))
#define mask_zero(value) mask_x2_zero((value))
#define mask_xor_const(value, cvalue) mask_x2_xor_const((value), (cvalue))
#define mask_xor(value1, value2) mask_x2_xor((value1), (value2))
#define mask_xor3(value1, value2, value3) mask_x2_xor3((value1), (value2), (value3))
#define mask_not(value) mask_x2_not((value))
#define mask_and(value1, value2, value3) mask_x2_and((value1), (value2), (value3))
#define mask_and_not(value1, value2, value3) mask_x2_and_not((value1), (value2), (value3))
#define mask_or(value1, value2, value3) mask_x2_or((value1), (value2), (value3))
#define mask_shl(value1, value2, bits) mask_x2_shl((value1), (value2), (bits))
#define mask_shr(value1, value2, bits) mask_x2_shr((value1), (value2), (bits))
#define mask_rol(value1, value2, bits) mask_x2_rol((value1), (value2), (bits))
#define mask_ror(value1, value2, bits) mask_x2_ror((value1), (value2), (bits))
#define mask_swap(value1, value2) mask_x2_swap((value1), (value2))
#define mask_swap_move(value1, value2, mask, shift) mask_x2_swap_move((value1), (value2), (mask), (shift))
#elif AEAD_MASKING_SHARES == 3
typedef mask_x3_uint16_t mask_uint16_t;
typedef mask_x3_uint32_t mask_uint32_t;
typedef mask_x3_uint64_t mask_uint64_t;
#define mask_input(value, input) mask_x3_input((value), (input))
#define mask_output(value) mask_x3_output((value))
#define mask_zero(value) mask_x3_zero((value))
#define mask_xor_const(value, cvalue) mask_x3_xor_const((value), (cvalue))
#define mask_xor(value1, value2) mask_x3_xor((value1), (value2))
#define mask_xor3(value1, value2, value3) mask_x3_xor3((value1), (value2), (value3))
#define mask_not(value) mask_x3_not((value))
#define mask_and(value1, value2, value3) mask_x3_and((value1), (value2), (value3))
#define mask_and_not(value1, value2, value3) mask_x3_and_not((value1), (value2), (value3))
#define mask_or(value1, value2, value3) mask_x3_or((value1), (value2), (value3))
#define mask_shl(value1, value2, bits) mask_x3_shl((value1), (value2), (bits))
#define mask_shr(value1, value2, bits) mask_x3_shr((value1), (value2), (bits))
#define mask_rol(value1, value2, bits) mask_x3_rol((value1), (value2), (bits))
#define mask_ror(value1, value2, bits) mask_x3_ror((value1), (value2), (bits))
#define mask_swap(value1, value2) mask_x3_swap((value1), (value2))
#define mask_swap_move(value1, value2, mask, shift) mask_x3_swap_move((value1), (value2), (mask), (shift))
#elif AEAD_MASKING_SHARES == 4

/**
 * \brief Generic masked 16-bit word.
 */
typedef mask_x4_uint16_t mask_uint16_t;

/**
 * \brief Generic masked 32-bit word.
 */
typedef mask_x4_uint32_t mask_uint32_t;

/**
 * \brief Generic masked 64-bit word.
 */
typedef mask_x4_uint64_t mask_uint64_t;

/**
 * \brief Masks an input value to produce a generic masked word.
 *
 * \param value The masked word on output.
 * \param input The input value to be masked.
 */
#define mask_input(value, input) mask_x4_input((value), (input))

/**
 * \brief Unmasks a generic masked word to produce an output value.
 *
 * \param value The masked word.
 * \return The unmasked version of \a value.
 */
#define mask_output(value) mask_x4_output((value))

/**
 * \brief Sets all shares of a generic masked word to zero.
 *
 * \param value The masked word to set to zero.
 */
#define mask_zero(value) mask_x4_zero((value))

/**
 * \brief Adds a constant to a generic masked word.
 *
 * \param value The masked word.
 * \param cvalue The constant value to add using XOR.
 *
 * This function performs "value ^= cvalue" where "cvalue" is a constant
 * or external data value rather than another masked word.
 */
#define mask_xor_const(value, cvalue) mask_x4_xor_const((value), (cvalue))

/**
 * \brief XOR's two generic masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The source masked word.
 *
 * This function performs "value1 ^= value2".
 */
#define mask_xor(value1, value2) mask_x4_xor((value1), (value2))

/**
 * \brief XOR's three generic masked words.
 *
 * \param value1 The destination masked word.
 * \param value2 The first source masked word.
 * \param value3 The second source masked word.
 *
 * This function performs "value1 ^= (value2 ^ value3)".
 */
#define mask_xor3(value1, value2, value3) mask_x4_xor3((value1), (value2), (value3))

/**
 * \brief NOT's a generic masked word.
 *
 * \param value The masked word to NOT.
 *
 * Equivalent to adding the all-1's constant to the masked word.
 */
#define mask_not(value) mask_x4_not((value))

/**
 * \brief AND's two generic masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x4_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_and(value1, value2, value3) mask_x4_and((value1), (value2), (value3))

/**
 * \brief AND's two generic masked words and XOR's the result with
 * another word, where the first input word is inverted.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument to be inverted.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= ((~value2) & value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x2_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_and_not(value1, value2, value3) mask_x4_and_not((value1), (value2), (value3))

/**
 * \brief OR's two generic masked words and XOR's the result with another word.
 *
 * \param value1 The destination masked word.
 * \param value2 The first masked word argument.
 * \param value3 The second masked word argument.
 *
 * This function performs "value1 ^= (value2 | value3)".
 *
 * \note This macro assumes that there is a local variable called "temp"
 * in the current scope that is the same size as the masked word's shares.
 * For example, if the values are instances of mask_x4_uint32_t, then
 * "temp" must be of type uint32_t.
 */
#define mask_or(value1, value2, value3) mask_x4_or((value1), (value2), (value3))

/**
 * \brief Performs a left shift on a generic masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_shl(value1, value2, bits) mask_x4_shl((value1), (value2), (bits))

/**
 * \brief Performs a right shift on a generic masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to shift by, which should be a constant.
 */
#define mask_shr(value1, value2, bits) mask_x4_shr((value1), (value2), (bits))

/**
 * \brief Performs a left rotate on a generic masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_rol(value1, value2, bits) mask_x4_rol((value1), (value2), (bits))

/**
 * \brief Performs a right rotate on a generic masked word.
 *
 * \param value1 The destination mask word.
 * \param value2 The source mask word.
 * \param bits The number of bits to rotate by, which should be a constant.
 */
#define mask_ror(value1, value2, bits) mask_x4_ror((value1), (value2), (bits))

/**
 * \brief Performs a swap on two generic masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 */
#define mask_swap(value1, value2) mask_x4_swap((value1), (value2))

/**
 * \brief Performs a swap and move on two generic masked words.
 *
 * \param value1 The first masked word.
 * \param value2 The second masked word.
 * \param mask The mask to extract the bits to move.
 * \param shift The number of bits to move by.
 */
#define mask_swap_move(value1, value2, mask, shift) mask_x4_swap_move((value1), (value2), (mask), (shift))

#elif AEAD_MASKING_SHARES == 5
typedef mask_x5_uint16_t mask_uint16_t;
typedef mask_x5_uint32_t mask_uint32_t;
typedef mask_x5_uint64_t mask_uint64_t;
#define mask_input(value, input) mask_x5_input((value), (input))
#define mask_output(value) mask_x5_output((value))
#define mask_zero(value) mask_x5_zero((value))
#define mask_xor_const(value, cvalue) mask_x5_xor_const((value), (cvalue))
#define mask_xor(value1, value2) mask_x5_xor((value1), (value2))
#define mask_xor3(value1, value2, value3) mask_x5_xor3((value1), (value2), (value3))
#define mask_not(value) mask_x5_not((value))
#define mask_and(value1, value2, value3) mask_x5_and((value1), (value2), (value3))
#define mask_and_not(value1, value2, value3) mask_x5_and_not((value1), (value2), (value3))
#define mask_or(value1, value2, value3) mask_x5_or((value1), (value2), (value3))
#define mask_shl(value1, value2, bits) mask_x5_shl((value1), (value2), (bits))
#define mask_shr(value1, value2, bits) mask_x5_shr((value1), (value2), (bits))
#define mask_rol(value1, value2, bits) mask_x5_rol((value1), (value2), (bits))
#define mask_ror(value1, value2, bits) mask_x5_ror((value1), (value2), (bits))
#define mask_swap(value1, value2) mask_x5_swap((value1), (value2))
#define mask_swap_move(value1, value2, mask, shift) mask_x5_swap_move((value1), (value2), (mask), (shift))
#elif AEAD_MASKING_SHARES == 6
typedef mask_x6_uint16_t mask_uint16_t;
typedef mask_x6_uint32_t mask_uint32_t;
typedef mask_x6_uint64_t mask_uint64_t;
#define mask_input(value, input) mask_x6_input((value), (input))
#define mask_output(value) mask_x6_output((value))
#define mask_zero(value) mask_x6_zero((value))
#define mask_xor_const(value, cvalue) mask_x6_xor_const((value), (cvalue))
#define mask_xor(value1, value2) mask_x6_xor((value1), (value2))
#define mask_xor3(value1, value2, value3) mask_x6_xor3((value1), (value2), (value3))
#define mask_not(value) mask_x6_not((value))
#define mask_and(value1, value2, value3) mask_x6_and((value1), (value2), (value3))
#define mask_and_not(value1, value2, value3) mask_x6_and_not((value1), (value2), (value3))
#define mask_or(value1, value2, value3) mask_x6_or((value1), (value2), (value3))
#define mask_shl(value1, value2, bits) mask_x6_shl((value1), (value2), (bits))
#define mask_shr(value1, value2, bits) mask_x6_shr((value1), (value2), (bits))
#define mask_rol(value1, value2, bits) mask_x6_rol((value1), (value2), (bits))
#define mask_ror(value1, value2, bits) mask_x6_ror((value1), (value2), (bits))
#define mask_swap(value1, value2) mask_x6_swap((value1), (value2))
#define mask_swap_move(value1, value2, mask, shift) mask_x6_swap_move((value1), (value2), (mask), (shift))
#else
#error "AEAD_MASKING_SHARES value is not supported"
#endif

#ifdef __cplusplus
}
#endif

#endif
