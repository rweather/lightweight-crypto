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

#include "internal-subterranean.h"
#include <string.h>

#if !defined(__AVR__)

void subterranean_round(subterranean_state_t *state)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8;
    uint32_t t0, t1;

    /* Load the state up into local variables */
    x0 = state->x[0];
    x1 = state->x[1];
    x2 = state->x[2];
    x3 = state->x[3];
    x4 = state->x[4];
    x5 = state->x[5];
    x6 = state->x[6];
    x7 = state->x[7];
    x8 = state->x[8];

    /* Step chi: s[i] = s[i] ^ (~(s[i+1) & s[i+2]) */
    #define CHI(a, b) \
        do { \
            t0 = ((a) >> 1) | ((b) << 31); \
            t1 = ((a) >> 2) | ((b) << 30); \
            (a) ^= (~t0) & t1; \
        } while (0)
    x8 ^= (x0 << 1);
    CHI(x0, x1); CHI(x1, x2);
    CHI(x2, x3); CHI(x3, x4);
    CHI(x4, x5); CHI(x5, x6);
    CHI(x6, x7); CHI(x7, x8);
    x8 ^= (~(x8 >> 1)) & (x8 >> 2);

    /* Step itoa: invert s[0] */
    x0 ^= 1U;

    /* Step theta: s[i] = s[i] ^ s[i + 3] ^ s[i + 8] */
    #define THETA(a, b) \
        do { \
            t0 = ((a) >> 3) | ((b) << 29); \
            t1 = ((a) >> 8) | ((b) << 24); \
            (a) ^= t0 ^ t1; \
        } while (0)
    x8 = (x8 & 1U) ^ (x0 << 1);
    THETA(x0, x1); THETA(x1, x2);
    THETA(x2, x3); THETA(x3, x4);
    THETA(x4, x5); THETA(x5, x6);
    THETA(x6, x7); THETA(x7, x8);
    x8 ^= (x8 >> 3) ^ (x8 >> 8);

    /* Step pi: permute the bits with the rule s[i] = s[(i * 12) % 257].
     * BCP = bit copy, BUP = move bit up, BDN = move bit down */
    #define BCP(x, bit) ((x) & (((uint32_t)1) << (bit)))
    #define BUP(x, from, to) \
        (((x) << ((to) - (from))) & (((uint32_t)1) << (to)))
    #define BDN(x, from, to) \
        (((x) >> ((from) - (to))) & (((uint32_t)1) << (to)))
    state->x[0] = BCP(x0,  0)     ^ BDN(x0, 12,  1) ^ BDN(x0, 24,  2) ^
                  BDN(x1,  4,  3) ^ BDN(x1, 16,  4) ^ BDN(x1, 28,  5) ^
                  BDN(x2,  8,  6) ^ BDN(x2, 20,  7) ^ BUP(x3,  0,  8) ^
                  BDN(x3, 12,  9) ^ BDN(x3, 24, 10) ^ BUP(x4,  4, 11) ^
                  BDN(x4, 16, 12) ^ BDN(x4, 28, 13) ^ BUP(x5,  8, 14) ^
                  BDN(x5, 20, 15) ^ BUP(x6,  0, 16) ^ BUP(x6, 12, 17) ^
                  BDN(x6, 24, 18) ^ BUP(x7,  4, 19) ^ BUP(x7, 16, 20) ^
                  BDN(x7, 28, 21) ^ BUP(x0,  7, 22) ^ BUP(x0, 19, 23) ^
                  BDN(x0, 31, 24) ^ BUP(x1, 11, 25) ^ BUP(x1, 23, 26) ^
                  BUP(x2,  3, 27) ^ BUP(x2, 15, 28) ^ BUP(x2, 27, 29) ^
                  BUP(x3,  7, 30) ^ BUP(x3, 19, 31);
    state->x[1] = BDN(x3, 31,  0) ^ BDN(x4, 11,  1) ^ BDN(x4, 23,  2) ^
                  BCP(x5,  3)     ^ BDN(x5, 15,  4) ^ BDN(x5, 27,  5) ^
                  BDN(x6,  7,  6) ^ BDN(x6, 19,  7) ^ BDN(x6, 31,  8) ^
                  BDN(x7, 11,  9) ^ BDN(x7, 23, 10) ^ BUP(x0,  2, 11) ^
                  BDN(x0, 14, 12) ^ BDN(x0, 26, 13) ^ BUP(x1,  6, 14) ^
                  BDN(x1, 18, 15) ^ BDN(x1, 30, 16) ^ BUP(x2, 10, 17) ^
                  BDN(x2, 22, 18) ^ BUP(x3,  2, 19) ^ BUP(x3, 14, 20) ^
                  BDN(x3, 26, 21) ^ BUP(x4,  6, 22) ^ BUP(x4, 18, 23) ^
                  BDN(x4, 30, 24) ^ BUP(x5, 10, 25) ^ BUP(x5, 22, 26) ^
                  BUP(x6,  2, 27) ^ BUP(x6, 14, 28) ^ BUP(x6, 26, 29) ^
                  BUP(x7,  6, 30) ^ BUP(x7, 18, 31);
    state->x[2] = BDN(x7, 30,  0) ^ BDN(x0,  9,  1) ^ BDN(x0, 21,  2) ^
                  BUP(x1,  1,  3) ^ BDN(x1, 13,  4) ^ BDN(x1, 25,  5) ^
                  BUP(x2,  5,  6) ^ BDN(x2, 17,  7) ^ BDN(x2, 29,  8) ^
                  BCP(x3,  9)     ^ BDN(x3, 21, 10) ^ BUP(x4,  1, 11) ^
                  BDN(x4, 13, 12) ^ BDN(x4, 25, 13) ^ BUP(x5,  5, 14) ^
                  BDN(x5, 17, 15) ^ BDN(x5, 29, 16) ^ BUP(x6,  9, 17) ^
                  BDN(x6, 21, 18) ^ BUP(x7,  1, 19) ^ BUP(x7, 13, 20) ^
                  BDN(x7, 25, 21) ^ BUP(x0,  4, 22) ^ BUP(x0, 16, 23) ^
                  BDN(x0, 28, 24) ^ BUP(x1,  8, 25) ^ BUP(x1, 20, 26) ^
                  BUP(x2,  0, 27) ^ BUP(x2, 12, 28) ^ BUP(x2, 24, 29) ^
                  BUP(x3,  4, 30) ^ BUP(x3, 16, 31);
    state->x[3] = BDN(x3, 28,  0) ^ BDN(x4,  8,  1) ^ BDN(x4, 20,  2) ^
                  BUP(x5,  0,  3) ^ BDN(x5, 12,  4) ^ BDN(x5, 24,  5) ^
                  BUP(x6,  4,  6) ^ BDN(x6, 16,  7) ^ BDN(x6, 28,  8) ^
                  BUP(x7,  8,  9) ^ BDN(x7, 20, 10) ^ BUP(x8,  0, 11) ^
                  BUP(x0, 11, 12) ^ BDN(x0, 23, 13) ^ BUP(x1,  3, 14) ^
                  BCP(x1, 15)     ^ BDN(x1, 27, 16) ^ BUP(x2,  7, 17) ^
                  BDN(x2, 19, 18) ^ BDN(x2, 31, 19) ^ BUP(x3, 11, 20) ^
                  BDN(x3, 23, 21) ^ BUP(x4,  3, 22) ^ BUP(x4, 15, 23) ^
                  BDN(x4, 27, 24) ^ BUP(x5,  7, 25) ^ BUP(x5, 19, 26) ^
                  BDN(x5, 31, 27) ^ BUP(x6, 11, 28) ^ BUP(x6, 23, 29) ^
                  BUP(x7,  3, 30) ^ BUP(x7, 15, 31);
    state->x[4] = BDN(x7, 27,  0) ^ BDN(x0,  6,  1) ^ BDN(x0, 18,  2) ^
                  BDN(x0, 30,  3) ^ BDN(x1, 10,  4) ^ BDN(x1, 22,  5) ^
                  BUP(x2,  2,  6) ^ BDN(x2, 14,  7) ^ BDN(x2, 26,  8) ^
                  BUP(x3,  6,  9) ^ BDN(x3, 18, 10) ^ BDN(x3, 30, 11) ^
                  BUP(x4, 10, 12) ^ BDN(x4, 22, 13) ^ BUP(x5,  2, 14) ^
                  BUP(x5, 14, 15) ^ BDN(x5, 26, 16) ^ BUP(x6,  6, 17) ^
                  BCP(x6, 18)     ^ BDN(x6, 30, 19) ^ BUP(x7, 10, 20) ^
                  BDN(x7, 22, 21) ^ BUP(x0,  1, 22) ^ BUP(x0, 13, 23) ^
                  BDN(x0, 25, 24) ^ BUP(x1,  5, 25) ^ BUP(x1, 17, 26) ^
                  BDN(x1, 29, 27) ^ BUP(x2,  9, 28) ^ BUP(x2, 21, 29) ^
                  BUP(x3,  1, 30) ^ BUP(x3, 13, 31);
    state->x[5] = BDN(x3, 25,  0) ^ BDN(x4,  5,  1) ^ BDN(x4, 17,  2) ^
                  BDN(x4, 29,  3) ^ BDN(x5,  9,  4) ^ BDN(x5, 21,  5) ^
                  BUP(x6,  1,  6) ^ BDN(x6, 13,  7) ^ BDN(x6, 25,  8) ^
                  BUP(x7,  5,  9) ^ BDN(x7, 17, 10) ^ BDN(x7, 29, 11) ^
                  BUP(x0,  8, 12) ^ BDN(x0, 20, 13) ^ BUP(x1,  0, 14) ^
                  BUP(x1, 12, 15) ^ BDN(x1, 24, 16) ^ BUP(x2,  4, 17) ^
                  BUP(x2, 16, 18) ^ BDN(x2, 28, 19) ^ BUP(x3,  8, 20) ^
                  BUP(x3, 20, 21) ^ BUP(x4,  0, 22) ^ BUP(x4, 12, 23) ^
                  BCP(x4, 24)     ^ BUP(x5,  4, 25) ^ BUP(x5, 16, 26) ^
                  BDN(x5, 28, 27) ^ BUP(x6,  8, 28) ^ BUP(x6, 20, 29) ^
                  BUP(x7,  0, 30) ^ BUP(x7, 12, 31);
    state->x[6] = BDN(x7, 24,  0) ^ BDN(x0,  3,  1) ^ BDN(x0, 15,  2) ^
                  BDN(x0, 27,  3) ^ BDN(x1,  7,  4) ^ BDN(x1, 19,  5) ^
                  BDN(x1, 31,  6) ^ BDN(x2, 11,  7) ^ BDN(x2, 23,  8) ^
                  BUP(x3,  3,  9) ^ BDN(x3, 15, 10) ^ BDN(x3, 27, 11) ^
                  BUP(x4,  7, 12) ^ BDN(x4, 19, 13) ^ BDN(x4, 31, 14) ^
                  BUP(x5, 11, 15) ^ BDN(x5, 23, 16) ^ BUP(x6,  3, 17) ^
                  BUP(x6, 15, 18) ^ BDN(x6, 27, 19) ^ BUP(x7,  7, 20) ^
                  BUP(x7, 19, 21) ^ BDN(x7, 31, 22) ^ BUP(x0, 10, 23) ^
                  BUP(x0, 22, 24) ^ BUP(x1,  2, 25) ^ BUP(x1, 14, 26) ^
                  BUP(x1, 26, 27) ^ BUP(x2,  6, 28) ^ BUP(x2, 18, 29) ^
                  BCP(x2, 30)     ^ BUP(x3, 10, 31);
    state->x[7] = BDN(x3, 22,  0) ^ BDN(x4,  2,  1) ^ BDN(x4, 14,  2) ^
                  BDN(x4, 26,  3) ^ BDN(x5,  6,  4) ^ BDN(x5, 18,  5) ^
                  BDN(x5, 30,  6) ^ BDN(x6, 10,  7) ^ BDN(x6, 22,  8) ^
                  BUP(x7,  2,  9) ^ BDN(x7, 14, 10) ^ BDN(x7, 26, 11) ^
                  BUP(x0,  5, 12) ^ BDN(x0, 17, 13) ^ BDN(x0, 29, 14) ^
                  BUP(x1,  9, 15) ^ BDN(x1, 21, 16) ^ BUP(x2,  1, 17) ^
                  BUP(x2, 13, 18) ^ BDN(x2, 25, 19) ^ BUP(x3,  5, 20) ^
                  BUP(x3, 17, 21) ^ BDN(x3, 29, 22) ^ BUP(x4,  9, 23) ^
                  BUP(x4, 21, 24) ^ BUP(x5,  1, 25) ^ BUP(x5, 13, 26) ^
                  BUP(x5, 25, 27) ^ BUP(x6,  5, 28) ^ BUP(x6, 17, 29) ^
                  BUP(x6, 29, 30) ^ BUP(x7,  9, 31);
    state->x[8] = BDN(x7, 21,  0);
}

void subterranean_absorb_1(subterranean_state_t *state, unsigned char data)
{
    uint32_t x = data;

    /* Rearrange the bits and absorb them into the state */
    state->x[0] ^= (x << 1) & 0x00000002U;
    state->x[1] ^= x & 0x00000008U;
    state->x[2] ^= 0x00000001U; /* 9th padding bit is always 1 */
    state->x[4] ^= ((x << 6) & 0x00000100U) ^ ((x <<  1) & 0x00000040U);
    state->x[5] ^= (x << 15) & 0x00010000U;
    state->x[6] ^= (x >> 1) & 0x00000020U;
    state->x[7] ^= ((x << 21) & 0x02000000U) ^ ((x << 3) & 0x00000400U);
}

void subterranean_absorb_word(subterranean_state_t *state, uint32_t x)
{
    uint32_t y;

    /* To absorb the word into the state, we first rearrange the source
     * bits to be in the right target bit positions.  Then we mask and
     * XOR them into the relevant words of the state.
     *
     * Some of the source bits end up in the same target bit but a different
     * word so we have to permute the input word twice to get all the source
     * bits into the locations we want for masking and XOR'ing.
     *
     * Permutations generated with "http://programming.sirrida.de/calcperm.php".
     */

    /* P1 = [1 16 8 3 25 * * 10 0 21 * 24 2 31 15 6 * 11 9 19 * * 29 * 4 * 30 12 * 22 17 5] */
    y =  (x & 0x00080008U)
      | ((x & 0x00004001U) << 1)
      | ((x & 0x00000080U) << 3)
      | ((x & 0x04000000U) << 4)
      | leftRotate6(x & 0x80000004U)
      | ((x & 0x00400000U) << 7)
      | leftRotate12(x & 0x01000200U)
      | ((x & 0x00000800U) << 13)
      | ((x & 0x00000002U) << 15)
      | ((x & 0x08000000U) >> 15)
      | ((x & 0x00002000U) << 18)
      | ((x & 0x40000000U) >> 13)
      | ((x & 0x00000010U) << 21)
      | ((x & 0x00001000U) >> 10)
      | ((x & 0x00048000U) >> 9)
      | ((x & 0x00000100U) >> 8)
      | ((x & 0x20000000U) >> 7)
      | ((x & 0x00020000U) >> 6);

    /* P2 = [* * * * * 6 5 * * * 31 * * * * * 17 * * * 0 9 * 15 * 30 * * 1 * * *] */
    x = ((x & 0x00010020U) << 1)
      | leftRotate5(x & 0x12000000U)
      | ((x & 0x00100000U) >> 20)
      | ((x & 0x00200000U) >> 12)
      | ((x & 0x00000400U) << 21)
      | ((x & 0x00800000U) >> 8)
      | ((x & 0x00000040U) >> 1);

    /* Integrate the rearranged bits into the state */
    state->x[0] ^= (y & 0x40428816U);
    state->x[1] ^= (y & 0x00000008U);
    state->x[2] ^= (y & 0x80000041U);
    state->x[3] ^= (x & 0x00008000U);
    state->x[4] ^= (y & 0x00001300U) ^ (x & 0x00000041U);
    state->x[5] ^= (y & 0x21010020U) ^ (x & 0x40000200U);
    state->x[6] ^= (y & 0x00280000U) ^ (x & 0x80000020U);
    state->x[7] ^= (y & 0x02000400U) ^ (x & 0x00020002U);
}

uint32_t subterranean_extract(subterranean_state_t *state)
{
    uint32_t x, y;

    /* We need to extract 64 bits from the state, and then XOR the two
     * halves together to get the result.
     *
     * Extract words from the state and permute the bits into the target
     * bit order.  Then mask off the unnecessary bits and combine.
     *
     * Permutations generated with "http://programming.sirrida.de/calcperm.php".
     */

    /* P0 = [* 0 12 * 24 * * * 4 * * 17 * * * 14 16 30 * * * * 29 7 * * * * * * 26 *] */
    x = state->x[0];
    x =  (x & 0x00010000U)
      | ((x & 0x00000800U) << 6)
      | ((x & 0x00400000U) << 7)
      | ((x & 0x00000004U) << 10)
      | ((x & 0x00020000U) << 13)
      | ((x & 0x00800000U) >> 16)
      | ((x & 0x00000010U) << 20)
      | ((x & 0x40000100U) >> 4)
      | ((x & 0x00008002U) >> 1);
    y = x & 0x65035091U;

    /* P1 = [28 * 10 3 * * * * * * * * 9 * 19 * * * * * * * * * * * * * 6 * * *] */
    x = state->x[1];
    x =  (x & 0x00000008U)
      | ((x & 0x00004000U) << 5)
      | ((x & 0x00000004U) << 8)
      | ((x & 0x10000000U) >> 22)
      | ((x & 0x00000001U) << 28)
      | ((x & 0x00001000U) >> 3);
    y ^= x & 0x10080648U;

    /* P2 = [8 * * 25 22 * 15 * * 11 * * * * * * * 1 * * * * * * 21 * * * 31 * * 13] */
    x = state->x[2];
    x = ((x & 0x00000200U) << 2)
      | ((x & 0x10000000U) << 3)
      | ((x & 0x00000001U) << 8)
      | ((x & 0x00000040U) << 9)
      | ((x & 0x80000000U) >> 18)
      | ((x & 0x00020000U) >> 16)
      | ((x & 0x00000010U) << 18)
      | ((x & 0x00000008U) << 22)
      | ((x & 0x01000000U) >> 3);
    y ^= x & 0x8260a902U;

    /* P3 = [* * * * * * * * * * * * * * * 23 * * * * * 27 * * 18 2 * 5 * * * *] */
    x = state->x[3];
    x = ((x & 0x00200000U) << 6)
      | ((x & 0x00008000U) << 8)
      | ((x & 0x02000000U) >> 23)
      | ((x & 0x08000000U) >> 22)
      | ((x & 0x01000000U) >> 6);
    y ^= x & 0x08840024U;

    /* P4 = [20 20 * * * * 5 * 2 18 * * 27 * * * * * 23 * * * * * * * * * * * * *] */
    x = state->x[4];
    y ^= (x << 20) & 0x00100000U; /* Handle duplicated bit 20 separately */
    x = ((x & 0x00040000U) << 5)
      | ((x & 0x00000200U) << 9)
      | ((x & 0x00001000U) << 15)
      | ((x & 0x00000002U) << 19)
      | ((x & 0x00000100U) >> 6)
      | ((x & 0x00000040U) >> 1);
    y ^= x & 0x08940024U;

    /* P5 = [* * 13 * * 31 * * * 21 * * * * * * 1 * * * * * * * 11 * * 15 * 22 25 *] */
    x = state->x[5];
    x = ((x & 0x00000004U) << 11)
      | ((x & 0x00000200U) << 12)
      | ((x & 0x00010000U) >> 15)
      | ((x & 0x01000000U) >> 13)
      | ((x & 0x08000000U) >> 12)
      | ((x & 0x20000000U) >> 7)
      | ((x & 0x00000020U) << 26)
      | ((x & 0x40000000U) >> 5);
    y ^= x & 0x8260a802U;

    /* P6 = [* 8 * * * 6 * * * * * * * * * * * * * 19 * 9 * * * * * * * * 3 10] */
    x = state->x[6];
    x =  (x & 0x00080000U)
      | ((x & 0x00000020U) << 1)
      | ((x & 0x40000000U) >> 27)
      | ((x & 0x00000002U) << 7)
      | ((x & 0x80000000U) >> 21)
      | ((x & 0x00200000U) >> 12);
    y ^= x & 0x00080748U;

    /* P7 = [* 28 * 26 * * * * * * 7 29 * * * * 30 16 14 * * * 17 * * 4 * * * 24 * 12] */
    x = state->x[7];
    x = ((x & 0x02000000U) >> 21)
      | ((x & 0x80000000U) >> 19)
      | ((x & 0x00010000U) << 14)
      | ((x & 0x00000800U) << 18)
      | ((x & 0x00000008U) << 23)
      | leftRotate27(x & 0x20400002U)
      | ((x & 0x00040000U) >> 4)
      | ((x & 0x00000400U) >> 3)
      | ((x & 0x00020000U) >> 1);
    y ^= x & 0x75035090U;

    /* Word 8 has a single bit - XOR it directly into the result and return */
    return y ^ state->x[8];
}

#endif /* !__AVR__ */

void subterranean_blank(subterranean_state_t *state)
{
    unsigned round;
    for (round = 0; round < 8; ++round) {
        subterranean_round(state);
        state->x[0] ^= 0x02; /* padding for an empty block is in state bit 1 */
    }
}

void subterranean_duplex_n
    (subterranean_state_t *state, const unsigned char *data, unsigned len)
{
    subterranean_round(state);
    switch (len) {
    case 0:
        state->x[0] ^= 0x02; /* padding for an empty block */
        break;
    case 1:
        subterranean_absorb_1(state, data[0]);
        break;
    case 2:
        /* Load 16 bits and add the padding bit to the 17th bit */
        subterranean_absorb_word
            (state, ((uint32_t)(data[0]) |
                   (((uint32_t)(data[1])) << 8) |
                    0x10000U));
        break;
    case 3:
        /* Load 24 bits and add the padding bit to the 25th bit */
        subterranean_absorb_word
            (state, ((uint32_t)(data[0]) |
                   (((uint32_t)(data[1])) << 8) |
                   (((uint32_t)(data[2])) << 16) |
                    0x01000000U));
        break;
    default:
        /* Load 32 bits and add the padding bit to the 33rd bit */
        subterranean_absorb_word(state, le_load_word32(data));
        state->x[8] ^= 0x00000001U;
        break;
    }
}

void subterranean_absorb
    (subterranean_state_t *state, const unsigned char *data,
     unsigned long long len)
{
    while (len >= 4) {
        subterranean_duplex_4(state, le_load_word32(data));
        data += 4;
        len -= 4;
    }
    subterranean_duplex_n(state, data, (unsigned)len);
}

void subterranean_squeeze
    (subterranean_state_t *state, unsigned char *data, unsigned len)
{
    uint32_t word;
    while (len > 4) {
        word = subterranean_extract(state);
        subterranean_duplex_0(state);
        le_store_word32(data, word);
        data += 4;
        len -= 4;
    }
    if (len == 4) {
        word = subterranean_extract(state);
        le_store_word32(data, word);
    } else if (len == 1) {
        word = subterranean_extract(state);
        data[0] = (unsigned char)word;
    } else if (len == 2) {
        word = subterranean_extract(state);
        data[0] = (unsigned char)word;
        data[1] = (unsigned char)(word >> 8);
    } else if (len == 3) {
        word = subterranean_extract(state);
        data[0] = (unsigned char)word;
        data[1] = (unsigned char)(word >> 8);
        data[2] = (unsigned char)(word >> 16);
    }
}
