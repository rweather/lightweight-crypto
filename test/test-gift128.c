/*
 * Copyright (C) 2019 Southern Storm Software, Pty Ltd.
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

#include "gift128.h"
#include "test-cipher.h"
#include <stdio.h>

/* Information block for the GIFT-128 block cipher (bit-sliced version) */
static block_cipher_t const gift128b = {
    "GIFT-128-b",
    sizeof(gift128b_key_schedule_t),
    (block_cipher_init_t)gift128b_init,
    (block_cipher_encrypt_t)gift128b_encrypt,
    (block_cipher_decrypt_t)gift128b_decrypt
};

/* Information block for the GIFT-128 block cipher (nibble-based version) */
static block_cipher_t const gift128n = {
    "GIFT-128-n",
    sizeof(gift128n_key_schedule_t),
    (block_cipher_init_t)gift128n_init,
    (block_cipher_encrypt_t)gift128n_encrypt,
    (block_cipher_decrypt_t)gift128n_decrypt
};

/* Test vectors for GIFT-128 (bit-sliced version) from the GIFT-COFB spec:
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gift-cofb-spec-round2.pdf */
static block_cipher_test_vector_128_t const gift128b_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* plaintext */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0xA9, 0x4A, 0xF7, 0xF9, 0xBA, 0x18, 0x1D, 0xF9,    /* ciphertext */
     0xB2, 0xB0, 0x0E, 0xB7, 0xDB, 0xFA, 0x93, 0xDF}
};
static block_cipher_test_vector_128_t const gift128b_2 = {
    "Test Vector 2",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x33, 0x31, 0xEF, 0xC3, 0xA6, 0x60, 0x4F, 0x95,    /* ciphertext */
     0x99, 0xED, 0x42, 0xB7, 0xDB, 0xC0, 0x2A, 0x38}
};

/* Test vectors for GIFT-128 (nibble-based version) from:
 * https://giftcipher.github.io/gift/ */
static block_cipher_test_vector_128_t const gift128n_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xcd, 0x0b, 0xd7, 0x38, 0x38, 0x8a, 0xd3, 0xf6,    /* ciphertext */
     0x68, 0xb1, 0x5a, 0x36, 0xce, 0xb6, 0xff, 0x92}
};
static block_cipher_test_vector_128_t const gift128n_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0x84, 0x22, 0x24, 0x1a, 0x6d, 0xbf, 0x5a, 0x93,    /* ciphertext */
     0x46, 0xaf, 0x46, 0x84, 0x09, 0xee, 0x01, 0x52}
};
static block_cipher_test_vector_128_t const gift128n_3 = {
    "Test Vector 3",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0x13, 0xed, 0xe6, 0x7c, 0xbd, 0xcc, 0x3d, 0xbf,    /* ciphertext */
     0x40, 0x0a, 0x62, 0xd6, 0x97, 0x72, 0x65, 0xea}
};

void test_gift128(void)
{
    test_block_cipher_start(&gift128b);
    test_block_cipher_128(&gift128b, &gift128b_1);
    test_block_cipher_128(&gift128b, &gift128b_2);
    test_block_cipher_end(&gift128b);

    test_block_cipher_start(&gift128n);
    test_block_cipher_128(&gift128n, &gift128n_1);
    test_block_cipher_128(&gift128n, &gift128n_2);
    test_block_cipher_128(&gift128n, &gift128n_3);
    test_block_cipher_end(&gift128n);
}
