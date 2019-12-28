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

void speck64_128_encrypt
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input)
{
    uint32_t l[4];
    uint32_t x, y, s;
    uint8_t round;
    uint8_t li_in = 0;
    uint8_t li_out = 3;

    /* Unpack the key and the input block */
    l[2] = be_load_word32(key);
    l[1] = be_load_word32(key + 4);
    l[0] = be_load_word32(key + 8);
    s    = be_load_word32(key + 12);
    x = be_load_word32(input);
    y = be_load_word32(input + 4);

    /* Perform all encryption rounds except the last */
    for (round = 0; round < 26; ++round) {
        /* Perform the round with the current key schedule word */
        x = (rightRotate8(x) + y) ^ s;
        y = leftRotate3(y) ^ x;

        /* Calculate the next key schedule word */
        l[li_out] = (s + rightRotate8(l[li_in])) ^ round;
        s = leftRotate3(s) ^ l[li_out];
        li_in = (li_in + 1) & 0x03;
        li_out = (li_out + 1) & 0x03;
    }

    /* Perform the last encryption round and write the result to the output */
    x = (rightRotate8(x) + y) ^ s;
    y = leftRotate3(y) ^ x;
    be_store_word32(output, x);
    be_store_word32(output + 4, y);
}
