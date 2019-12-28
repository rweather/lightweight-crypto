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
#include "test-cipher.h"
#include <string.h>

static int speck64_128_init
    (unsigned char *ks, const unsigned char *key, size_t key_len)
{
    if (key_len != 16)
        return 0;
    memcpy(ks, key, 16);
    return 1;
}

/* Information block for the SPECK-64-128 block cipher */
static block_cipher_t const speck_64_128 = {
    "SPECK-64-128",
    16,
    (block_cipher_init_t)speck64_128_init,
    (block_cipher_encrypt_t)speck64_128_encrypt,
    (block_cipher_decrypt_t)0
};

/* Test vector for SPECK-64-128 from the original SPECK paper */
static block_cipher_test_vector_128_t const speck_64_128_1 = {
    "Test Vector 1",
    {0x1b, 0x1a, 0x19, 0x18, 0x13, 0x12, 0x11, 0x10,    /* key */
     0x0b, 0x0a, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00},
    16,                                                 /* key_len */
    {0x3b, 0x72, 0x65, 0x74, 0x74, 0x75, 0x43, 0x2d},   /* plaintext */
    {0x8c, 0x6f, 0xa5, 0x48, 0x45, 0x4e, 0x02, 0x8b}    /* ciphertext */
};

void test_speck64(void)
{
    test_block_cipher_start(&speck_64_128);
    test_block_cipher_64(&speck_64_128, &speck_64_128_1);
    test_block_cipher_end(&speck_64_128);
}
