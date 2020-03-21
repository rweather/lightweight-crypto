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

#include "internal-speck64.h"
#include "internal-util.h"

#if !defined(__AVR__)

void speck64_128_encrypt
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input)
{
    uint32_t l0, l1, l2, s;
    uint32_t x, y;
    uint8_t round;

    /* Unpack the key and the input block */
    s  = le_load_word32(key);
    l0 = le_load_word32(key + 4);
    l1 = le_load_word32(key + 8);
    l2 = le_load_word32(key + 12);
    y = le_load_word32(input);
    x = le_load_word32(input + 4);

    /* Perform all 27 encryption rounds, in groups of 3 */
    #define round_xy() \
        do { \
            x = (rightRotate8(x) + y) ^ s; \
            y = leftRotate3(y) ^ x; \
        } while (0)
    #define schedule(l) \
        do { \
            l = (s + rightRotate8(l)) ^ round; \
            s = leftRotate3(s) ^ l; \
            ++round; \
        } while (0)
    for (round = 0; round < 27; ) {
        round_xy();
        schedule(l0);
        round_xy();
        schedule(l1);
        round_xy();
        schedule(l2);
    }

    /* Write the result to the output */
    le_store_word32(output, y);
    le_store_word32(output + 4, x);
}

#endif
