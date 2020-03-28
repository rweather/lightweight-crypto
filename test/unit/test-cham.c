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
#include "test-cipher.h"
#include <string.h>

static void cham128_128_init(unsigned char *ks, const unsigned char *key)
{
    memcpy(ks, key, 16);
}

/* Information block for the CHAM-128-128 block cipher */
static block_cipher_t const cham_128_128 = {
    "CHAM-128-128",
    16,
    (block_cipher_init_t)cham128_128_init,
    (block_cipher_encrypt_t)cham128_128_encrypt,
    (block_cipher_decrypt_t)0
};

/* Information block for the CHAM-64-128 block cipher */
static block_cipher_t const cham_64_128 = {
    "CHAM-64-128",
    16,
    (block_cipher_init_t)cham128_128_init,
    (block_cipher_encrypt_t)cham64_128_encrypt,
    (block_cipher_decrypt_t)0
};

/* Test vector for CHAM-128-128 from the original CHAM paper */
static block_cipher_test_vector_128_t const cham128_128_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    16,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x34, 0x60, 0x74, 0xc3, 0xc5, 0x00, 0x57, 0xb5,    /* ciphertext */
     0x32, 0xec, 0x64, 0x8d, 0xf7, 0x32, 0x93, 0x48}
};

/* Test vector for CHAM-64-128 from the original CHAM paper */
static block_cipher_test_vector_128_t const cham64_128_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    16,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},   /* plaintext */
    {0x3c, 0x45, 0xbc, 0x63, 0xfa, 0xdc, 0x4e, 0xbf}    /* ciphertext */
};

void test_cham(void)
{
    test_block_cipher_start(&cham_128_128);
    test_block_cipher_128(&cham_128_128, &cham128_128_1);
    test_block_cipher_end(&cham_128_128);

    test_block_cipher_start(&cham_64_128);
    test_block_cipher_other(&cham_64_128, &cham64_128_1, 8);
    test_block_cipher_end(&cham_64_128);
}
