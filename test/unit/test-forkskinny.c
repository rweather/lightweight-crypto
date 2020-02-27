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

#include "internal-forkskinny.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors generated with the reference implementation of ForkAE */
static block_cipher_test_vector_128_t const forkskinny_128_256_1 = {
    "Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    32,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x32, 0x41, 0x1c, 0x5c, 0xa7, 0x0b, 0xaf, 0x92,    /* ciphertext */
     0x49, 0x51, 0x4b, 0x38, 0x93, 0x25, 0x42, 0x28}
};
static block_cipher_test_vector_128_t const forkskinny_128_256_2 = {
    "Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    32,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0xd6, 0xfd, 0x00, 0x8b, 0x1f, 0x5f, 0x14, 0xaa,    /* ciphertext */
     0xf1, 0x34, 0x1a, 0x5f, 0x76, 0xe5, 0xa3, 0x2f}
};
static block_cipher_test_vector_128_t const forkskinny_128_256_3 = {
    "Both Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    32,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x10, 0x78, 0xc5, 0x35, 0x97, 0xfc, 0x5e, 0x4c,    /* ciphertext */
     0x9d, 0x91, 0xa8, 0xea, 0xe8, 0xf5, 0xa8, 0x76}
};
static block_cipher_test_vector_128_t const forkskinny_128_256_4 = {
    "Both Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    32,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0xd6, 0xfd, 0x00, 0x8b, 0x1f, 0x5f, 0x14, 0xaa,    /* ciphertext */
     0xf1, 0x34, 0x1a, 0x5f, 0x76, 0xe5, 0xa3, 0x2f}
};
static block_cipher_test_vector_128_t const forkskinny_128_256_5 = {
    "Invert Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    32,                                                 /* key_len */
    {0x10, 0x78, 0xc5, 0x35, 0x97, 0xfc, 0x5e, 0x4c,    /* plaintext */
     0x9d, 0x91, 0xa8, 0xea, 0xe8, 0xf5, 0xa8, 0x76},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* ciphertext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
};
static block_cipher_test_vector_128_t const forkskinny_128_256_6 = {
    "Invert Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
    32,                                                 /* key_len */
    {0x10, 0x78, 0xc5, 0x35, 0x97, 0xfc, 0x5e, 0x4c,    /* plaintext */
     0x9d, 0x91, 0xa8, 0xea, 0xe8, 0xf5, 0xa8, 0x76},
    {0xd6, 0xfd, 0x00, 0x8b, 0x1f, 0x5f, 0x14, 0xaa,    /* ciphertext */
     0xf1, 0x34, 0x1a, 0x5f, 0x76, 0xe5, 0xa3, 0x2f}
};

static block_cipher_test_vector_128_t const forkskinny_128_384_1 = {
    "Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
    48,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x29, 0x26, 0x08, 0x66, 0xa8, 0x5f, 0xa1, 0x81,    /* ciphertext */
     0xf7, 0xc1, 0x39, 0x2f, 0xd7, 0x09, 0x29, 0x6c}
};
static block_cipher_test_vector_128_t const forkskinny_128_384_2 = {
    "Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
    48,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0xd0, 0x86, 0xcd, 0x29, 0x19, 0x96, 0x9e, 0xe6,    /* ciphertext */
     0xc3, 0x0a, 0xdb, 0xa2, 0x11, 0x94, 0xf8, 0x70}
};
static block_cipher_test_vector_128_t const forkskinny_128_384_3 = {
    "Both Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
    48,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0xa8, 0x42, 0xdc, 0xd5, 0x30, 0x62, 0x73, 0x0d,    /* ciphertext */
     0x8e, 0x29, 0x3c, 0xd9, 0x23, 0xef, 0x9a, 0xa9}
};
static block_cipher_test_vector_128_t const forkskinny_128_384_4 = {
    "Both Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
    48,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0xd0, 0x86, 0xcd, 0x29, 0x19, 0x96, 0x9e, 0xe6,    /* ciphertext */
     0xc3, 0x0a, 0xdb, 0xa2, 0x11, 0x94, 0xf8, 0x70}
};
static block_cipher_test_vector_128_t const forkskinny_128_384_5 = {
    "Invert Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
    48,                                                 /* key_len */
    {0xa8, 0x42, 0xdc, 0xd5, 0x30, 0x62, 0x73, 0x0d,    /* plaintext */
     0x8e, 0x29, 0x3c, 0xd9, 0x23, 0xef, 0x9a, 0xa9},
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* ciphertext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
};
static block_cipher_test_vector_128_t const forkskinny_128_384_6 = {
    "Invert Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
     0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
     0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
     0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f},
    48,                                                 /* key_len */
    {0xa8, 0x42, 0xdc, 0xd5, 0x30, 0x62, 0x73, 0x0d,    /* plaintext */
     0x8e, 0x29, 0x3c, 0xd9, 0x23, 0xef, 0x9a, 0xa9},
    {0xd0, 0x86, 0xcd, 0x29, 0x19, 0x96, 0x9e, 0xe6,    /* ciphertext */
     0xc3, 0x0a, 0xdb, 0xa2, 0x11, 0x94, 0xf8, 0x70}
};

static block_cipher_test_vector_128_t const forkskinny_64_192_1 = {
    "Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},   /* plaintext */
    {0x66, 0xca, 0x11, 0xab, 0x67, 0xf5, 0x9e, 0xd3}    /* ciphertext */
};
static block_cipher_test_vector_128_t const forkskinny_64_192_2 = {
    "Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},   /* plaintext */
    {0x10, 0xd0, 0xeb, 0x20, 0xe5, 0x98, 0x09, 0xfc}    /* ciphertext */
};
static block_cipher_test_vector_128_t const forkskinny_64_192_3 = {
    "Both Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},   /* plaintext */
    {0x91, 0xd0, 0x92, 0xd0, 0x6b, 0x39, 0xe6, 0x8f}    /* ciphertext */
};
static block_cipher_test_vector_128_t const forkskinny_64_192_4 = {
    "Both Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},   /* plaintext */
    {0x10, 0xd0, 0xeb, 0x20, 0xe5, 0x98, 0x09, 0xfc}    /* ciphertext */
};
static block_cipher_test_vector_128_t const forkskinny_64_192_5 = {
    "Invert Left",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x91, 0xd0, 0x92, 0xd0, 0x6b, 0x39, 0xe6, 0x8f},   /* plaintext */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}    /* ciphertext */
};
static block_cipher_test_vector_128_t const forkskinny_64_192_6 = {
    "Invert Right",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
     0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    24,                                                 /* key_len */
    {0x91, 0xd0, 0x92, 0xd0, 0x6b, 0x39, 0xe6, 0x8f},   /* plaintext */
    {0x10, 0xd0, 0xeb, 0x20, 0xe5, 0x98, 0x09, 0xfc}    /* ciphertext */
};

static int forkskinny_128_256_cipher_init
    (unsigned char *ks, const unsigned char *key, size_t key_len)
{
    if (key_len != 32)
        return 0;
    memcpy(ks, key, key_len);
    return 1;
}

static void forkskinny_128_256_encrypt_left_only
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    forkskinny_128_256_encrypt(ks, output, 0, input);
}

static void forkskinny_128_256_encrypt_right_only
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    forkskinny_128_256_encrypt(ks, 0, output, input);
}

static void forkskinny_128_256_encrypt_both_left
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_256_encrypt(ks, output, other, input);
}

static void forkskinny_128_256_encrypt_both_right
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_256_encrypt(ks, other, output, input);
}

static void forkskinny_128_256_decrypt_left
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_256_decrypt(ks, output, other, input);
}

static void forkskinny_128_256_decrypt_right
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_256_decrypt(ks, other, output, input);
}

/* Information blocks for the ForkSkinny-128-256 block cipher */
static block_cipher_t const forkskinny_128_256_left_only = {
    "ForkSkinny-128-256",
    32,
    (block_cipher_init_t)forkskinny_128_256_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_256_encrypt_left_only,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_256_right_only = {
    "ForkSkinny-128-256",
    32,
    (block_cipher_init_t)forkskinny_128_256_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_256_encrypt_right_only,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_256_both_left = {
    "ForkSkinny-128-256",
    32,
    (block_cipher_init_t)forkskinny_128_256_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_256_encrypt_both_left,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_256_both_right = {
    "ForkSkinny-128-256",
    32,
    (block_cipher_init_t)forkskinny_128_256_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_256_encrypt_both_right,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_256_invert_left = {
    "ForkSkinny-128-256",
    32,
    (block_cipher_init_t)forkskinny_128_256_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_256_decrypt_left,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_256_invert_right = {
    "ForkSkinny-128-256",
    32,
    (block_cipher_init_t)forkskinny_128_256_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_256_decrypt_right,
    (block_cipher_decrypt_t)0
};

static int forkskinny_128_384_cipher_init
    (unsigned char *ks, const unsigned char *key, size_t key_len)
{
    if (key_len != 48)
        return 0;
    memcpy(ks, key, key_len);
    return 1;
}

static void forkskinny_128_384_encrypt_left_only
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    forkskinny_128_384_encrypt(ks, output, 0, input);
}

static void forkskinny_128_384_encrypt_right_only
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    forkskinny_128_384_encrypt(ks, 0, output, input);
}

static void forkskinny_128_384_encrypt_both_left
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_384_encrypt(ks, output, other, input);
}

static void forkskinny_128_384_encrypt_both_right
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_384_encrypt(ks, other, output, input);
}

static void forkskinny_128_384_decrypt_left
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_384_decrypt(ks, output, other, input);
}

static void forkskinny_128_384_decrypt_right
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[16];
    forkskinny_128_384_decrypt(ks, other, output, input);
}

/* Information blocks for the ForkSkinny-128-384 block cipher */
static block_cipher_t const forkskinny_128_384_left_only = {
    "ForkSkinny-128-384",
    48,
    (block_cipher_init_t)forkskinny_128_384_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_384_encrypt_left_only,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_384_right_only = {
    "ForkSkinny-128-384",
    48,
    (block_cipher_init_t)forkskinny_128_384_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_384_encrypt_right_only,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_384_both_left = {
    "ForkSkinny-128-384",
    48,
    (block_cipher_init_t)forkskinny_128_384_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_384_encrypt_both_left,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_384_both_right = {
    "ForkSkinny-128-384",
    48,
    (block_cipher_init_t)forkskinny_128_384_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_384_encrypt_both_right,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_384_invert_left = {
    "ForkSkinny-128-384",
    48,
    (block_cipher_init_t)forkskinny_128_384_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_384_decrypt_left,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_128_384_invert_right = {
    "ForkSkinny-128-384",
    48,
    (block_cipher_init_t)forkskinny_128_384_cipher_init,
    (block_cipher_encrypt_t)forkskinny_128_384_decrypt_right,
    (block_cipher_decrypt_t)0
};

static int forkskinny_64_192_cipher_init
    (unsigned char *ks, const unsigned char *key, size_t key_len)
{
    if (key_len != 24)
        return 0;
    memcpy(ks, key, key_len);
    return 1;
}

static void forkskinny_64_192_encrypt_left_only
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    forkskinny_64_192_encrypt(ks, output, 0, input);
}

static void forkskinny_64_192_encrypt_right_only
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    forkskinny_64_192_encrypt(ks, 0, output, input);
}

static void forkskinny_64_192_encrypt_both_left
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[8];
    forkskinny_64_192_encrypt(ks, output, other, input);
}

static void forkskinny_64_192_encrypt_both_right
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[8];
    forkskinny_64_192_encrypt(ks, other, output, input);
}

static void forkskinny_64_192_decrypt_left
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[8];
    forkskinny_64_192_decrypt(ks, output, other, input);
}

static void forkskinny_64_192_decrypt_right
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    unsigned char other[8];
    forkskinny_64_192_decrypt(ks, other, output, input);
}

/* Information blocks for the ForkSkinny-64-192 block cipher */
static block_cipher_t const forkskinny_64_192_left_only = {
    "ForkSkinny-64-192",
    24,
    (block_cipher_init_t)forkskinny_64_192_cipher_init,
    (block_cipher_encrypt_t)forkskinny_64_192_encrypt_left_only,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_64_192_right_only = {
    "ForkSkinny-64-192",
    24,
    (block_cipher_init_t)forkskinny_64_192_cipher_init,
    (block_cipher_encrypt_t)forkskinny_64_192_encrypt_right_only,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_64_192_both_left = {
    "ForkSkinny-64-192",
    24,
    (block_cipher_init_t)forkskinny_64_192_cipher_init,
    (block_cipher_encrypt_t)forkskinny_64_192_encrypt_both_left,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_64_192_both_right = {
    "ForkSkinny-64-192",
    24,
    (block_cipher_init_t)forkskinny_64_192_cipher_init,
    (block_cipher_encrypt_t)forkskinny_64_192_encrypt_both_right,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_64_192_invert_left = {
    "ForkSkinny-64-192",
    24,
    (block_cipher_init_t)forkskinny_64_192_cipher_init,
    (block_cipher_encrypt_t)forkskinny_64_192_decrypt_left,
    (block_cipher_decrypt_t)0
};
static block_cipher_t const forkskinny_64_192_invert_right = {
    "ForkSkinny-64-192",
    24,
    (block_cipher_init_t)forkskinny_64_192_cipher_init,
    (block_cipher_encrypt_t)forkskinny_64_192_decrypt_right,
    (block_cipher_decrypt_t)0
};

void test_forkskinny(void)
{
    test_block_cipher_start(&forkskinny_128_256_left_only);
    test_block_cipher_128(&forkskinny_128_256_left_only, &forkskinny_128_256_1);
    test_block_cipher_128(&forkskinny_128_256_right_only, &forkskinny_128_256_2);
    test_block_cipher_128(&forkskinny_128_256_both_left, &forkskinny_128_256_3);
    test_block_cipher_128(&forkskinny_128_256_both_right, &forkskinny_128_256_4);
    test_block_cipher_128(&forkskinny_128_256_invert_left, &forkskinny_128_256_5);
    test_block_cipher_128(&forkskinny_128_256_invert_right, &forkskinny_128_256_6);
    test_block_cipher_end(&forkskinny_128_256_left_only);

    test_block_cipher_start(&forkskinny_128_384_left_only);
    test_block_cipher_128(&forkskinny_128_384_left_only, &forkskinny_128_384_1);
    test_block_cipher_128(&forkskinny_128_384_right_only, &forkskinny_128_384_2);
    test_block_cipher_128(&forkskinny_128_384_both_left, &forkskinny_128_384_3);
    test_block_cipher_128(&forkskinny_128_384_both_right, &forkskinny_128_384_4);
    test_block_cipher_128(&forkskinny_128_384_invert_left, &forkskinny_128_384_5);
    test_block_cipher_128(&forkskinny_128_384_invert_right, &forkskinny_128_384_6);
    test_block_cipher_end(&forkskinny_128_384_left_only);

    test_block_cipher_start(&forkskinny_64_192_left_only);
    test_block_cipher_other(&forkskinny_64_192_left_only, &forkskinny_64_192_1, 8);
    test_block_cipher_other(&forkskinny_64_192_right_only, &forkskinny_64_192_2, 8);
    test_block_cipher_other(&forkskinny_64_192_both_left, &forkskinny_64_192_3, 8);
    test_block_cipher_other(&forkskinny_64_192_both_right, &forkskinny_64_192_4, 8);
    test_block_cipher_other(&forkskinny_64_192_invert_left, &forkskinny_64_192_5, 8);
    test_block_cipher_other(&forkskinny_64_192_invert_right, &forkskinny_64_192_6, 8);
    test_block_cipher_end(&forkskinny_64_192_left_only);
}
