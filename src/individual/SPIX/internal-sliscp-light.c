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

#include "internal-sliscp-light.h"

/**
 * \brief Performs one round of the Simeck-64 block cipher.
 *
 * \param x Left half of the 64-bit block.
 * \param y Right half of the 64-bit block.
 */
#define simeck64_round(x, y) \
    do { \
        (y) ^= (leftRotate5((x)) & (x)) ^ leftRotate1((x)) ^ \
               0xFFFFFFFEU ^ (_rc & 1); \
        _rc >>= 1; \
    } while (0)

/**
 * \brief Encrypts a 64-bit block with the 8 round version of Simeck-64.
 *
 * \param x Left half of the 64-bit block.
 * \param y Right half of the 64-bit block.
 * \param rc Round constants for the 8 rounds, 1 bit per round.
 *
 * It is assumed that the two halves have already been converted from
 * big-endian to host byte order before calling this function.  The output
 * halves will also be in host byte order.
 */
#define simeck64_box(x, y, rc) \
    do { \
        unsigned char _rc = (rc); \
        simeck64_round(x, y);   /* Round 1 */ \
        simeck64_round(y, x);   /* Round 2 */ \
        simeck64_round(x, y);   /* Round 3 */ \
        simeck64_round(y, x);   /* Round 4 */ \
        simeck64_round(x, y);   /* Round 5 */ \
        simeck64_round(y, x);   /* Round 6 */ \
        simeck64_round(x, y);   /* Round 7 */ \
        simeck64_round(y, x);   /* Round 8 */ \
    } while (0)

/* Helper macros for 48-bit left rotations */
#define leftRotate5_48(x) (((x) << 5) | ((x) >> 19))
#define leftRotate1_48(x) (((x) << 1) | ((x) >> 23))

/**
 * \brief Performs one round of the Simeck-48 block cipher.
 *
 * \param x Left half of the 48-bit block.
 * \param y Right half of the 48-bit block.
 */
#define simeck48_round(x, y) \
    do { \
        (y) ^= (leftRotate5_48((x)) & (x)) ^ leftRotate1_48((x)) ^ \
               0x00FFFFFEU ^ (_rc & 1); \
        (y) &= 0x00FFFFFFU; \
        _rc >>= 1; \
    } while (0)

/**
 * \brief Encrypts a 48-bit block with the 6 round version of Simeck-48.
 *
 * \param x Left half of the 48-bit block.
 * \param y Right half of the 48-bit block.
 * \param rc Round constants for the 8 rounds, 1 bit per round.
 *
 * It is assumed that the two halves have already been converted from
 * big-endian to host byte order before calling this function.  The output
 * halves will also be in host byte order.
 */
#define simeck48_box(x, y, rc) \
    do { \
        unsigned char _rc = (rc); \
        simeck48_round(x, y);   /* Round 1 */ \
        simeck48_round(y, x);   /* Round 2 */ \
        simeck48_round(x, y);   /* Round 3 */ \
        simeck48_round(y, x);   /* Round 4 */ \
        simeck48_round(x, y);   /* Round 5 */ \
        simeck48_round(y, x);   /* Round 6 */ \
    } while (0)

void sliscp_light256_permute(unsigned char block[32], unsigned rounds)
{
    /* Interleaved rc0, rc1, sc0, and sc1 values for each round */
    static const unsigned char const RC[18 * 4] = {
        0x0f, 0x47, 0x08, 0x64, 0x04, 0xb2, 0x86, 0x6b,
        0x43, 0xb5, 0xe2, 0x6f, 0xf1, 0x37, 0x89, 0x2c,
        0x44, 0x96, 0xe6, 0xdd, 0x73, 0xee, 0xca, 0x99,
        0xe5, 0x4c, 0x17, 0xea, 0x0b, 0xf5, 0x8e, 0x0f,
        0x47, 0x07, 0x64, 0x04, 0xb2, 0x82, 0x6b, 0x43,
        0xb5, 0xa1, 0x6f, 0xf1, 0x37, 0x78, 0x2c, 0x44,
        0x96, 0xa2, 0xdd, 0x73, 0xee, 0xb9, 0x99, 0xe5,
        0x4c, 0xf2, 0xea, 0x0b, 0xf5, 0x85, 0x0f, 0x47,
        0x07, 0x23, 0x04, 0xb2, 0x82, 0xd9, 0x43, 0xb5
    };
    const unsigned char *rc = RC;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t t0, t1;

    /* Load the block into local state variables */
    x0 = be_load_word32(block);
    x1 = be_load_word32(block + 4);
    x2 = be_load_word32(block + 8);
    x3 = be_load_word32(block + 12);
    x4 = be_load_word32(block + 16);
    x5 = be_load_word32(block + 20);
    x6 = be_load_word32(block + 24);
    x7 = be_load_word32(block + 28);

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds, rc += 4) {
        /* Apply Simeck-64 to two of the 64-bit sub-blocks */
        simeck64_box(x2, x3, rc[0]);
        simeck64_box(x6, x7, rc[1]);

        /* Add step constants */
        x0 ^= 0xFFFFFFFFU;
        x1 ^= 0xFFFFFF00U ^ rc[2];
        x4 ^= 0xFFFFFFFFU;
        x5 ^= 0xFFFFFF00U ^ rc[3];

        /* Mix the sub-blocks */
        t0 = x0 ^ x2;
        t1 = x1 ^ x3;
        x0 = x2;
        x1 = x3;
        x2 = x4 ^ x6;
        x3 = x5 ^ x7;
        x4 = x6;
        x5 = x7;
        x6 = t0;
        x7 = t1;
    }

    /* Store the state back into the block */
    be_store_word32(block,      x0);
    be_store_word32(block +  4, x1);
    be_store_word32(block +  8, x2);
    be_store_word32(block + 12, x3);
    be_store_word32(block + 16, x4);
    be_store_word32(block + 20, x5);
    be_store_word32(block + 24, x6);
    be_store_word32(block + 28, x7);
}

/* Load a big-endian 24-bit word from a byte buffer */
#define be_load_word24(ptr) \
    ((((uint32_t)((ptr)[0])) << 16) | \
     (((uint32_t)((ptr)[1])) << 8) | \
      ((uint32_t)((ptr)[2])))

/* Store a big-endian 24-bit word into a byte buffer */
#define be_store_word24(ptr, x) \
    do { \
        uint32_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 16); \
        (ptr)[1] = (uint8_t)(_x >> 8); \
        (ptr)[2] = (uint8_t)_x; \
    } while (0)

void sliscp_light192_permute(unsigned char block[24], unsigned rounds)
{
    /* Interleaved rc0, rc1, sc0, and sc1 values for each round */
    static const unsigned char const RC[18 * 4] = {
        0x07, 0x27, 0x08, 0x29, 0x04, 0x34, 0x0c, 0x1d,
        0x06, 0x2e, 0x0a, 0x33, 0x25, 0x19, 0x2f, 0x2a,
        0x17, 0x35, 0x38, 0x1f, 0x1c, 0x0f, 0x24, 0x10,
        0x12, 0x08, 0x36, 0x18, 0x3b, 0x0c, 0x0d, 0x14,
        0x26, 0x0a, 0x2b, 0x1e, 0x15, 0x2f, 0x3e, 0x31,
        0x3f, 0x38, 0x01, 0x09, 0x20, 0x24, 0x21, 0x2d,
        0x30, 0x36, 0x11, 0x1b, 0x28, 0x0d, 0x39, 0x16,
        0x3c, 0x2b, 0x05, 0x3d, 0x22, 0x3e, 0x27, 0x03,
        0x13, 0x01, 0x34, 0x02, 0x1a, 0x21, 0x2e, 0x23
    };
    const unsigned char *rc = RC;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t t0, t1;

    /* Load the block into local state variables.  Each 24-bit block is
     * placed into a separate 32-bit word which improves efficiency below */
    x0 = be_load_word24(block);
    x1 = be_load_word24(block + 3);
    x2 = be_load_word24(block + 6);
    x3 = be_load_word24(block + 9);
    x4 = be_load_word24(block + 12);
    x5 = be_load_word24(block + 15);
    x6 = be_load_word24(block + 18);
    x7 = be_load_word24(block + 21);

    /* Perform all permutation rounds */
    for (; rounds > 0; --rounds, rc += 4) {
        /* Apply Simeck-48 to two of the 48-bit sub-blocks */
        simeck48_box(x2, x3, rc[0]);
        simeck48_box(x6, x7, rc[1]);

        /* Add step constants */
        x0 ^= 0x00FFFFFFU;
        x1 ^= 0x00FFFF00U ^ rc[2];
        x4 ^= 0x00FFFFFFU;
        x5 ^= 0x00FFFF00U ^ rc[3];

        /* Mix the sub-blocks */
        t0 = x0 ^ x2;
        t1 = x1 ^ x3;
        x0 = x2;
        x1 = x3;
        x2 = x4 ^ x6;
        x3 = x5 ^ x7;
        x4 = x6;
        x5 = x7;
        x6 = t0;
        x7 = t1;
    }

    /* Store the state back into the block */
    be_store_word24(block,      x0);
    be_store_word24(block +  3, x1);
    be_store_word24(block +  6, x2);
    be_store_word24(block +  9, x3);
    be_store_word24(block + 12, x4);
    be_store_word24(block + 15, x5);
    be_store_word24(block + 18, x6);
    be_store_word24(block + 21, x7);
}

void sliscp_light320_permute(unsigned char block[40])
{
    /* Interleaved rc0, rc1, rc2, sc0, sc1, and sc2 values for each round */
    static const unsigned char const RC[16 * 6] = {
        0x07, 0x53, 0x43, 0x50, 0x28, 0x14, 0x0a, 0x5d,
        0xe4, 0x5c, 0xae, 0x57, 0x9b, 0x49, 0x5e, 0x91,
        0x48, 0x24, 0xe0, 0x7f, 0xcc, 0x8d, 0xc6, 0x63,
        0xd1, 0xbe, 0x32, 0x53, 0xa9, 0x54, 0x1a, 0x1d,
        0x4e, 0x60, 0x30, 0x18, 0x22, 0x28, 0x75, 0x68,
        0x34, 0x9a, 0xf7, 0x6c, 0x25, 0xe1, 0x70, 0x38,
        0x62, 0x82, 0xfd, 0xf6, 0x7b, 0xbd, 0x96, 0x47,
        0xf9, 0x9d, 0xce, 0x67, 0x71, 0x6b, 0x76, 0x40,
        0x20, 0x10, 0xaa, 0x88, 0xa0, 0x4f, 0x27, 0x13,
        0x2b, 0xdc, 0xb0, 0xbe, 0x5f, 0x2f, 0xe9, 0x8b,
        0x09, 0x5b, 0xad, 0xd6, 0xcf, 0x59, 0x1e, 0xe9,
        0x74, 0xba, 0xb7, 0xc6, 0xad, 0x7f, 0x3f, 0x1f
    };
    const unsigned char *rc = RC;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7, x8, x9;
    uint32_t t0, t1;
    unsigned round;

    /* Load the block into local state variables */
    x0 = be_load_word32(block);
    x1 = be_load_word32(block + 4);
    x2 = be_load_word32(block + 8);
    x3 = be_load_word32(block + 12);
    x4 = be_load_word32(block + 16);
    x5 = be_load_word32(block + 20);
    x6 = be_load_word32(block + 24);
    x7 = be_load_word32(block + 28);
    x8 = be_load_word32(block + 32);
    x9 = be_load_word32(block + 36);

    /* Perform all permutation rounds */
    for (round = 0; round < 16; ++round, rc += 6) {
        /* Apply Simeck-64 to three of the 64-bit sub-blocks */
        simeck64_box(x0, x1, rc[0]);
        simeck64_box(x4, x5, rc[1]);
        simeck64_box(x8, x9, rc[2]);
        x6 ^= x8;
        x7 ^= x9;
        x2 ^= x4;
        x3 ^= x5;
        x8 ^= x0;
        x9 ^= x1;

        /* Add step constants */
        x2 ^= 0xFFFFFFFFU;
        x3 ^= 0xFFFFFF00U ^ rc[3];
        x6 ^= 0xFFFFFFFFU;
        x7 ^= 0xFFFFFF00U ^ rc[4];
        x8 ^= 0xFFFFFFFFU;
        x9 ^= 0xFFFFFF00U ^ rc[5];

        /* Rotate the sub-blocks */
        t0 = x8;
        t1 = x9;
        x8 = x2;
        x9 = x3;
        x2 = x4;
        x3 = x5;
        x4 = x0;
        x5 = x1;
        x0 = x6;
        x1 = x7;
        x6 = t0;
        x7 = t1;
    }

    /* Store the state back into the block */
    be_store_word32(block,      x0);
    be_store_word32(block +  4, x1);
    be_store_word32(block +  8, x2);
    be_store_word32(block + 12, x3);
    be_store_word32(block + 16, x4);
    be_store_word32(block + 20, x5);
    be_store_word32(block + 24, x6);
    be_store_word32(block + 28, x7);
    be_store_word32(block + 32, x8);
    be_store_word32(block + 36, x9);
}
