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

#include "internal-gift64.h"
#include "test-cipher.h"
#include <stdio.h>

/* Information block for the GIFT-64 block cipher (bit-sliced version) */
static block_cipher_t const gift64b = {
    "GIFT-64-b",
    sizeof(gift64n_key_schedule_t),
    (block_cipher_init_t)gift64b_init,
    (block_cipher_encrypt_t)gift64nb_encrypt,
    (block_cipher_decrypt_t)gift64nb_decrypt
};

/* Information block for the GIFT-64 block cipher (nibble-based version) */
static block_cipher_t const gift64n = {
    "GIFT-64-n",
    sizeof(gift64n_key_schedule_t),
    (block_cipher_init_t)gift64n_init,
    (block_cipher_encrypt_t)gift64n_encrypt,
    (block_cipher_decrypt_t)gift64n_decrypt
};

/* Test vectors for GIFT-64 (nibble-based version) that were generated
 * with the reference code for LOTUS/LOCUS.  This will indirectly test
 * that the bit-sliced version is working also. */
static block_cipher_test_vector_128_t const gift64n_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   /* plaintext */
    {0xac, 0x75, 0xf7, 0x34, 0xef, 0xc3, 0x2b, 0xf6}    /* ciphertext */
};
static block_cipher_test_vector_128_t const gift64n_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},   /* plaintext */
    {0x4b, 0x1f, 0xc1, 0xef, 0xfe, 0xe1, 0x87, 0x4e}    /* ciphertext */
};
static block_cipher_test_vector_128_t const gift64n_3 = {
    "Test Vector 3",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0x08, 0x2d, 0xad, 0xcc, 0x6a, 0xe6, 0x3c, 0x64}    /* ciphertext */
};

/* Test vectors for GIFT-64 (bit-sliced version) from the fixslicing
 * reference code at "https://github.com/aadomn/gift".  Note that
 * although the fixslicing implementation is bit-sliced, then input
 * plaintext and output ciphertext are actually in nibble form.
 * The fixslicing reference code rearranges the bits internally */
static block_cipher_test_vector_128_t const gift64b_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   /* plaintext */
    {0xf6, 0x2b, 0xc3, 0xef, 0x34, 0xf7, 0x75, 0xac}    /* ciphertext */
};
static block_cipher_test_vector_128_t const gift64b_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},   /* plaintext */
    {0xc1, 0xb7, 0x1f, 0x66, 0x16, 0x0f, 0xf5, 0x87}    /* ciphertext */
};
static block_cipher_test_vector_128_t const gift64b_3 = {
    "Test Vector 3",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0xe3, 0x27, 0x28, 0x85, 0xfa, 0x94, 0xba, 0x8b}    /* ciphertext */
};

static unsigned char gift64t_tweak_value = 0;

static void gift64t_encrypt_wrapper
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift64t_encrypt(ks, output, input, gift64t_tweak_value);
}

static void gift64t_decrypt_wrapper
    (const gift64n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift64t_decrypt(ks, output, input, gift64t_tweak_value);
}

/* Information block for the TweGIFT-64 block cipher (tweakable version) */
static block_cipher_t const gift64t = {
    "TweGIFT-64",
    sizeof(gift64n_key_schedule_t),
    (block_cipher_init_t)gift64n_init,
    (block_cipher_encrypt_t)gift64t_encrypt_wrapper,
    (block_cipher_decrypt_t)gift64t_decrypt_wrapper
};

/* Test vectors for TweGIFT-64 that were generated with the
 * reference code for LOTUS/LOCUS */
static block_cipher_test_vector_128_t const gift64t_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   /* plaintext */
    {0xb6, 0x6a, 0x7a, 0x0d, 0x14, 0xb1, 0x74, 0x0a}    /* ciphertext */
    /* tweak = 11 */
};
static block_cipher_test_vector_128_t const gift64t_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},   /* plaintext */
    {0x88, 0xb0, 0xf8, 0x78, 0xe0, 0x27, 0xe5, 0x8b}    /* ciphertext */
    /* tweak = 4 */
};
static block_cipher_test_vector_128_t const gift64t_3 = {
    "Test Vector 3",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0x55, 0x09, 0xa7, 0x40, 0x1b, 0x1e, 0x29, 0x61}    /* ciphertext */
    /* tweak = 9 */
};
static block_cipher_test_vector_128_t const gift64t_4 = {
    "Test Vector 4",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0x08, 0x2d, 0xad, 0xcc, 0x6a, 0xe6, 0x3c, 0x64}    /* ciphertext */
    /* tweak = 0 */
};

void test_gift64(void)
{
    test_block_cipher_start(&gift64b);
    test_block_cipher_other(&gift64b, &gift64b_1, 8);
    test_block_cipher_other(&gift64b, &gift64b_2, 8);
    test_block_cipher_other(&gift64b, &gift64b_3, 8);
    test_block_cipher_end(&gift64b);

    test_block_cipher_start(&gift64n);
    test_block_cipher_other(&gift64n, &gift64n_1, 8);
    test_block_cipher_other(&gift64n, &gift64n_2, 8);
    test_block_cipher_other(&gift64n, &gift64n_3, 8);
    test_block_cipher_end(&gift64n);

    test_block_cipher_start(&gift64t);
    gift64t_tweak_value = 11;
    test_block_cipher_other(&gift64t, &gift64t_1, 8);
    gift64t_tweak_value = 4;
    test_block_cipher_other(&gift64t, &gift64t_2, 8);
    gift64t_tweak_value = 9;
    test_block_cipher_other(&gift64t, &gift64t_3, 8);
    gift64t_tweak_value = 0;
    test_block_cipher_other(&gift64t, &gift64t_4, 8);
    test_block_cipher_end(&gift64t);
}
