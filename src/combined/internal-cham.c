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

#include "internal-cham.h"
#include "internal-util.h"

void cham128_128_encrypt
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input)
{
    uint32_t x0, x1, x2, x3;
    uint32_t k[8];
    uint8_t round;

    /* Unpack the key and generate the key schedule */
    k[0] = le_load_word32(key);
    k[1] = le_load_word32(key + 4);
    k[2] = le_load_word32(key + 8);
    k[3] = le_load_word32(key + 12);
    k[4] = k[1] ^ leftRotate1(k[1]) ^ leftRotate11(k[1]);
    k[5] = k[0] ^ leftRotate1(k[0]) ^ leftRotate11(k[0]);
    k[6] = k[3] ^ leftRotate1(k[3]) ^ leftRotate11(k[3]);
    k[7] = k[2] ^ leftRotate1(k[2]) ^ leftRotate11(k[2]);
    k[0] ^= leftRotate1(k[0]) ^ leftRotate8(k[0]);
    k[1] ^= leftRotate1(k[1]) ^ leftRotate8(k[1]);
    k[2] ^= leftRotate1(k[2]) ^ leftRotate8(k[2]);
    k[3] ^= leftRotate1(k[3]) ^ leftRotate8(k[3]);

    /* Unpack the input block */
    x0 = le_load_word32(input);
    x1 = le_load_word32(input + 4);
    x2 = le_load_word32(input + 8);
    x3 = le_load_word32(input + 12);

    /* Perform the 80 rounds four at a time */
    for (round = 0; round < 80; round += 4) {
        x0 = leftRotate8((x0 ^ round) +
                         (leftRotate1(x1) ^ k[round % 8]));
        x1 = leftRotate1((x1 ^ (round + 1)) +
                         (leftRotate8(x2) ^ k[(round + 1) % 8]));
        x2 = leftRotate8((x2 ^ (round + 2)) +
                         (leftRotate1(x3) ^ k[(round + 2) % 8]));
        x3 = leftRotate1((x3 ^ (round + 3)) +
                         (leftRotate8(x0) ^ k[(round + 3) % 8]));
    }

    /* Pack the state into the output block */
    le_store_word32(output,      x0);
    le_store_word32(output + 4,  x1);
    le_store_word32(output + 8,  x2);
    le_store_word32(output + 12, x3);
}

/* Load a little-endian 16-bit word from a byte buffer */
#define le_load_word16(ptr) \
    ((((uint16_t)((ptr)[1])) << 8) | \
      ((uint16_t)((ptr)[0])))

/* Store a little-endian 16-bit word into a byte buffer */
#define le_store_word16(ptr, x) \
    do { \
        uint16_t _x = (x); \
        (ptr)[0] = (uint8_t)_x; \
        (ptr)[1] = (uint8_t)(_x >> 8); \
    } while (0)

/* Rotate a 16-bit value left by a number of bits */
#define leftRotate_16(a, bits) \
    (__extension__ ({ \
        uint16_t _temp = (a); \
        (_temp << (bits)) | (_temp >> (16 - (bits))); \
    }))

void cham64_128_encrypt
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input)
{
    uint16_t x0, x1, x2, x3;
    uint16_t k[16];
    uint8_t round;

    /* Unpack the key and generate the key schedule */
    k[0]  = le_load_word16(key);
    k[1]  = le_load_word16(key + 2);
    k[2]  = le_load_word16(key + 4);
    k[3]  = le_load_word16(key + 6);
    k[4]  = le_load_word16(key + 8);
    k[5]  = le_load_word16(key + 10);
    k[6]  = le_load_word16(key + 12);
    k[7]  = le_load_word16(key + 14);
    k[8]  = k[1] ^ leftRotate_16(k[1], 1) ^ leftRotate_16(k[1], 11);
    k[9]  = k[0] ^ leftRotate_16(k[0], 1) ^ leftRotate_16(k[0], 11);
    k[10] = k[3] ^ leftRotate_16(k[3], 1) ^ leftRotate_16(k[3], 11);
    k[11] = k[2] ^ leftRotate_16(k[2], 1) ^ leftRotate_16(k[2], 11);
    k[12] = k[5] ^ leftRotate_16(k[5], 1) ^ leftRotate_16(k[5], 11);
    k[13] = k[4] ^ leftRotate_16(k[4], 1) ^ leftRotate_16(k[4], 11);
    k[14] = k[7] ^ leftRotate_16(k[7], 1) ^ leftRotate_16(k[7], 11);
    k[15] = k[6] ^ leftRotate_16(k[6], 1) ^ leftRotate_16(k[6], 11);
    k[0] ^= leftRotate_16(k[0], 1) ^ leftRotate_16(k[0], 8);
    k[1] ^= leftRotate_16(k[1], 1) ^ leftRotate_16(k[1], 8);
    k[2] ^= leftRotate_16(k[2], 1) ^ leftRotate_16(k[2], 8);
    k[3] ^= leftRotate_16(k[3], 1) ^ leftRotate_16(k[3], 8);
    k[4] ^= leftRotate_16(k[4], 1) ^ leftRotate_16(k[4], 8);
    k[5] ^= leftRotate_16(k[5], 1) ^ leftRotate_16(k[5], 8);
    k[6] ^= leftRotate_16(k[6], 1) ^ leftRotate_16(k[6], 8);
    k[7] ^= leftRotate_16(k[7], 1) ^ leftRotate_16(k[7], 8);

    /* Unpack the input block */
    x0 = le_load_word16(input);
    x1 = le_load_word16(input + 2);
    x2 = le_load_word16(input + 4);
    x3 = le_load_word16(input + 6);

    /* Perform the 80 rounds four at a time */
    for (round = 0; round < 80; round += 4) {
        x0 = leftRotate_16
            ((x0 ^ round) +
             (leftRotate_16(x1, 1) ^ k[round % 16]), 8);
        x1 = leftRotate_16
            ((x1 ^ (round + 1)) +
             (leftRotate_16(x2, 8) ^ k[(round + 1) % 16]), 1);
        x2 = leftRotate_16
            ((x2 ^ (round + 2)) +
             (leftRotate_16(x3, 1) ^ k[(round + 2) % 16]), 8);
        x3 = leftRotate_16
            ((x3 ^ (round + 3)) +
             (leftRotate_16(x0, 8) ^ k[(round + 3) % 16]), 1);
    }

    /* Pack the state into the output block */
    le_store_word16(output,     x0);
    le_store_word16(output + 2, x1);
    le_store_word16(output + 4, x2);
    le_store_word16(output + 6, x3);
}
