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

#ifndef LW_INTERNAL_SKINNYUTIL_H
#define LW_INTERNAL_SKINNYUTIL_H

/**
 * \file internal-skinnyutil.h
 * \brief Utilities to help implement SKINNY and its variants.
 */

#include "internal-util.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @cond skinnyutil */

/* Utilities for implementing SKINNY-128 */

#define skinny128_LFSR2(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x << 1) & 0xFEFEFEFEU) ^ \
             (((_x >> 7) ^ (_x >> 5)) & 0x01010101U); \
    } while (0)


#define skinny128_LFSR3(x) \
    do { \
        uint32_t _x = (x); \
        (x) = ((_x >> 1) & 0x7F7F7F7FU) ^ \
              (((_x << 7) ^ (_x << 1)) & 0x80808080U); \
    } while (0)

/* LFSR2 and LFSR3 are inverses of each other */
#define skinny128_inv_LFSR2(x) skinny128_LFSR3(x)
#define skinny128_inv_LFSR3(x) skinny128_LFSR2(x)

#define skinny128_permute_tk(tk) \
    do { \
        /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
        uint32_t row2 = tk[2]; \
        uint32_t row3 = tk[3]; \
        tk[2] = tk[0]; \
        tk[3] = tk[1]; \
        row3 = (row3 << 16) | (row3 >> 16); \
        tk[0] = ((row2 >>  8) & 0x000000FFU) | \
                ((row2 << 16) & 0x00FF0000U) | \
                ( row3        & 0xFF00FF00U); \
        tk[1] = ((row2 >> 16) & 0x000000FFU) | \
                 (row2        & 0xFF000000U) | \
                ((row3 <<  8) & 0x0000FF00U) | \
                ( row3        & 0x00FF0000U); \
    } while (0)

#define skinny128_permute_tk_half(tk2, tk3) \
    do { \
        /* Permute the bottom half of the tweakey state in place, no swap */ \
        uint32_t row2 = tk2; \
        uint32_t row3 = tk3; \
        row3 = (row3 << 16) | (row3 >> 16); \
        tk2 = ((row2 >>  8) & 0x000000FFU) | \
              ((row2 << 16) & 0x00FF0000U) | \
              ( row3        & 0xFF00FF00U); \
        tk3 = ((row2 >> 16) & 0x000000FFU) | \
               (row2        & 0xFF000000U) | \
              ((row3 <<  8) & 0x0000FF00U) | \
              ( row3        & 0x00FF0000U); \
    } while (0)

#define skinny128_inv_permute_tk(tk) \
    do { \
        /* PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1] */ \
        uint32_t row0 = tk[0]; \
        uint32_t row1 = tk[1]; \
        tk[0] = tk[2]; \
        tk[1] = tk[3]; \
        tk[2] = ((row0 >> 16) & 0x000000FFU) | \
                ((row0 <<  8) & 0x0000FF00U) | \
                ((row1 << 16) & 0x00FF0000U) | \
                ( row1        & 0xFF000000U); \
        tk[3] = ((row0 >> 16) & 0x0000FF00U) | \
                ((row0 << 16) & 0xFF000000U) | \
                ((row1 >> 16) & 0x000000FFU) | \
                ((row1 <<  8) & 0x00FF0000U); \
    } while (0)

#define skinny128_inv_permute_tk_half(tk0, tk1) \
    do { \
        /* Permute the top half of the tweakey state in place, no swap */ \
        uint32_t row0 = tk0; \
        uint32_t row1 = tk1; \
        tk0 = ((row0 >> 16) & 0x000000FFU) | \
              ((row0 <<  8) & 0x0000FF00U) | \
              ((row1 << 16) & 0x00FF0000U) | \
              ( row1        & 0xFF000000U); \
        tk1 = ((row0 >> 16) & 0x0000FF00U) | \
              ((row0 << 16) & 0xFF000000U) | \
              ((row1 >> 16) & 0x000000FFU) | \
              ((row1 <<  8) & 0x00FF0000U); \
    } while (0)

/*
 * Apply the SKINNY sbox.  The original version from the specification is
 * equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
 * #define SBOX_SWAP(x)
 *     (((x) & 0xF9F9F9F9U) |
 *     (((x) >> 1) & 0x02020202U) |
 *     (((x) << 1) & 0x04040404U))
 * #define SBOX_PERMUTE(x)
 *     ((((x) & 0x01010101U) << 2) |
 *      (((x) & 0x06060606U) << 5) |
 *      (((x) & 0x20202020U) >> 5) |
 *      (((x) & 0xC8C8C8C8U) >> 2) |
 *      (((x) & 0x10101010U) >> 1))
 *
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE(x);
 * x = SBOX_MIX(x);
 * return SBOX_SWAP(x);
 *
 * However, we can mix the bits in their original positions and then
 * delay the SBOX_PERMUTE and SBOX_SWAP steps to be performed with one
 * final permuatation.  This reduces the number of shift operations.
 */
#define skinny128_sbox(x) \
do { \
    uint32_t y; \
    \
    /* Mix the bits */ \
    x = ~x; \
    x ^= (((x >> 2) & (x >> 3)) & 0x11111111U); \
    y  = (((x << 5) & (x << 1)) & 0x20202020U); \
    x ^= (((x << 5) & (x << 4)) & 0x40404040U) ^ y; \
    y  = (((x << 2) & (x << 1)) & 0x80808080U); \
    x ^= (((x >> 2) & (x << 1)) & 0x02020202U) ^ y; \
    y  = (((x >> 5) & (x << 1)) & 0x04040404U); \
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y; \
    x = ~x; \
    \
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */ \
    /* The final permutation for each byte is [2 7 6 1 3 0 4 5] */ \
    x = ((x & 0x08080808U) << 1) | \
        ((x & 0x32323232U) << 2) | \
        ((x & 0x01010101U) << 5) | \
        ((x & 0x80808080U) >> 6) | \
        ((x & 0x40404040U) >> 4) | \
        ((x & 0x04040404U) >> 2); \
} while (0)

/*
 * Apply the inverse of the SKINNY sbox.  The original version from the
 * specification is equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x11111111U) ^ (x))
 * #define SBOX_SWAP(x)
 *     (((x) & 0xF9F9F9F9U) |
 *     (((x) >> 1) & 0x02020202U) |
 *     (((x) << 1) & 0x04040404U))
 * #define SBOX_PERMUTE_INV(x)
 *     ((((x) & 0x08080808U) << 1) |
 *      (((x) & 0x32323232U) << 2) |
 *      (((x) & 0x01010101U) << 5) |
 *      (((x) & 0xC0C0C0C0U) >> 5) |
 *      (((x) & 0x04040404U) >> 2))
 *
 * x = SBOX_SWAP(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE_INV(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE_INV(x);
 * x = SBOX_MIX(x);
 * x = SBOX_PERMUTE_INV(x);
 * return SBOX_MIX(x);
 *
 * However, we can mix the bits in their original positions and then
 * delay the SBOX_PERMUTE_INV and SBOX_SWAP steps to be performed with one
 * final permuatation.  This reduces the number of shift operations.
 */
#define skinny128_inv_sbox(x) \
do { \
    uint32_t y; \
    \
    /* Mix the bits */ \
    x = ~x; \
    y  = (((x >> 1) & (x >> 3)) & 0x01010101U); \
    x ^= (((x >> 2) & (x >> 3)) & 0x10101010U) ^ y; \
    y  = (((x >> 6) & (x >> 1)) & 0x02020202U); \
    x ^= (((x >> 1) & (x >> 2)) & 0x08080808U) ^ y; \
    y  = (((x << 2) & (x << 1)) & 0x80808080U); \
    x ^= (((x >> 1) & (x << 2)) & 0x04040404U) ^ y; \
    y  = (((x << 5) & (x << 1)) & 0x20202020U); \
    x ^= (((x << 4) & (x << 5)) & 0x40404040U) ^ y; \
    x = ~x; \
    \
    /* Permutation generated by http://programming.sirrida.de/calcperm.php */ \
    /* The final permutation for each byte is [5 3 0 4 6 7 2 1] */ \
    x = ((x & 0x01010101U) << 2) | \
        ((x & 0x04040404U) << 4) | \
        ((x & 0x02020202U) << 6) | \
        ((x & 0x20202020U) >> 5) | \
        ((x & 0xC8C8C8C8U) >> 2) | \
        ((x & 0x10101010U) >> 1); \
} while (0)

/* Utilities for implementing SKINNY-64 */

#define skinny64_LFSR2(x) \
    do { \
        uint16_t _x = (x); \
        (x) = ((_x << 1) & 0xEEEEU) ^ (((_x >> 3) ^ (_x >> 2)) & 0x1111U); \
    } while (0)

#define skinny64_LFSR3(x) \
    do { \
        uint16_t _x = (x); \
        (x) = ((_x >> 1) & 0x7777U) ^ ((_x ^ (_x << 3)) & 0x8888U); \
    } while (0)

/* LFSR2 and LFSR3 are inverses of each other */
#define skinny64_inv_LFSR2(x) skinny64_LFSR3(x)
#define skinny64_inv_LFSR3(x) skinny64_LFSR2(x)

#define skinny64_permute_tk(tk) \
    do { \
        /* PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7] */ \
        uint16_t row2 = tk[2]; \
        uint16_t row3 = tk[3]; \
        tk[2] = tk[0]; \
        tk[3] = tk[1]; \
        row3 = (row3 << 8) | (row3 >> 8); \
        tk[0] = ((row2 << 4) & 0xF000U) | \
                ((row2 >> 8) & 0x00F0U) | \
                ( row3       & 0x0F0FU); \
        tk[1] = ((row2 << 8) & 0xF000U) | \
                ((row3 >> 4) & 0x0F00U) | \
                ( row3       & 0x00F0U) | \
                ( row2       & 0x000FU); \
    } while (0)

#define skinny64_inv_permute_tk(tk) \
    do { \
        /* PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1] */ \
        uint16_t row0 = tk[0]; \
        uint16_t row1 = tk[1]; \
        tk[0] = tk[2]; \
        tk[1] = tk[3]; \
        tk[2] = ((row0 << 8) & 0xF000U) | \
                ((row0 >> 4) & 0x0F00U) | \
                ((row1 >> 8) & 0x00F0U) | \
                ( row1       & 0x000FU); \
        tk[3] = ((row1 << 8) & 0xF000U) | \
                ((row0 << 8) & 0x0F00U) | \
                ((row1 >> 4) & 0x00F0U) | \
                ((row0 >> 8) & 0x000FU); \
    } while (0)

/*
 * Apply the SKINNY-64 sbox.  The original version from the
 * specification is equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x1111U) ^ (x))
 * #define SBOX_SHIFT(x)
 *     ((((x) << 1) & 0xEEEEU) | (((x) >> 3) & 0x1111U))
 *
 * x = SBOX_MIX(x);
 * x = SBOX_SHIFT(x);
 * x = SBOX_MIX(x);
 * x = SBOX_SHIFT(x);
 * x = SBOX_MIX(x);
 * x = SBOX_SHIFT(x);
 * return SBOX_MIX(x);
 *
 * However, we can mix the bits in their original positions and then
 * delay the SBOX_SHIFT steps to be performed with one final rotation.
 * This reduces the number of required shift operations from 14 to 10.
 *
 * We can further reduce the number of NOT operations from 4 to 2
 * using the technique from https://github.com/kste/skinny_avx to
 * convert NOR-XOR operations into AND-XOR operations by converting
 * the S-box into its NOT-inverse.
 */
#define skinny64_sbox(x) \
do { \
    x = ~x; \
    x = (((x >> 3) & (x >> 2)) & 0x1111U) ^ x; \
    x = (((x << 1) & (x << 2)) & 0x8888U) ^ x; \
    x = (((x << 1) & (x << 2)) & 0x4444U) ^ x; \
    x = (((x >> 2) & (x << 1)) & 0x2222U) ^ x; \
    x = ~x; \
    x = ((x >> 1) & 0x7777U) | ((x << 3) & 0x8888U); \
} while (0)

/*
 * Apply the inverse of the SKINNY-64 sbox.  The original version
 * from the specification is equivalent to:
 *
 * #define SBOX_MIX(x)
 *     (((~((((x) >> 1) | (x)) >> 2)) & 0x1111U) ^ (x))
 * #define SBOX_SHIFT_INV(x)
 *     ((((x) >> 1) & 0x7777U) | (((x) << 3) & 0x8888U))
 *
 * x = SBOX_MIX(x);
 * x = SBOX_SHIFT_INV(x);
 * x = SBOX_MIX(x);
 * x = SBOX_SHIFT_INV(x);
 * x = SBOX_MIX(x);
 * x = SBOX_SHIFT_INV(x);
 * return SBOX_MIX(x);
 */
#define skinny64_inv_sbox(x) \
do { \
    x = ~x; \
    x = (((x >> 3) & (x >> 2)) & 0x1111U) ^ x; \
    x = (((x << 1) & (x >> 2)) & 0x2222U) ^ x; \
    x = (((x << 1) & (x << 2)) & 0x4444U) ^ x; \
    x = (((x << 1) & (x << 2)) & 0x8888U) ^ x; \
    x = ~x; \
    x = ((x << 1) & 0xEEEEU) | ((x >> 3) & 0x1111U); \
} while (0)

/** @endcond */

#ifdef __cplusplus
}
#endif

#endif
