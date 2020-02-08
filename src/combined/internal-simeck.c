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

#include "internal-simeck.h"

void simeck64_box(uint32_t block[2], uint8_t rc)
{
    uint32_t x = block[0];
    uint32_t y = block[1];
    #define SIMECK64_ROUND(x, y) \
        do { \
            (y) ^= (leftRotate5((x)) & (x)) ^ leftRotate1((x)) ^ \
                   0xFFFFFFFEU ^ (rc & 1); \
            rc >>= 1; \
        } while (0)
    SIMECK64_ROUND(x, y);   /* Round 1 */
    SIMECK64_ROUND(y, x);   /* Round 2 */
    SIMECK64_ROUND(x, y);   /* Round 3 */
    SIMECK64_ROUND(y, x);   /* Round 4 */
    SIMECK64_ROUND(x, y);   /* Round 5 */
    SIMECK64_ROUND(y, x);   /* Round 6 */
    SIMECK64_ROUND(x, y);   /* Round 7 */
    SIMECK64_ROUND(y, x);   /* Round 8 */
    block[0] = x;
    block[1] = y;
}

#define leftRotate5_48(x) (((x) << 5) | ((x) >> 19))
#define leftRotate1_48(x) (((x) << 1) | ((x) >> 23))

void simeck48_box(uint32_t block[2], uint8_t rc)
{
    uint32_t x = block[0];
    uint32_t y = block[1];
    #define SIMECK48_ROUND(x, y) \
        do { \
            (y) ^= (leftRotate5_48((x)) & (x)) ^ leftRotate1_48((x)) ^ \
                   0x00FFFFFEU ^ (rc & 1); \
            (y) &= 0x00FFFFFFU; \
            rc >>= 1; \
        } while (0)
    SIMECK48_ROUND(x, y);   /* Round 1 */
    SIMECK48_ROUND(y, x);   /* Round 2 */
    SIMECK48_ROUND(x, y);   /* Round 3 */
    SIMECK48_ROUND(y, x);   /* Round 4 */
    SIMECK48_ROUND(x, y);   /* Round 5 */
    SIMECK48_ROUND(y, x);   /* Round 6 */
    block[0] = x;
    block[1] = y;
}
