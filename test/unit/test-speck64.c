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
#include <stdio.h>
#include <string.h>

static void speck64_128_init(unsigned char *ks, const unsigned char *key)
{
    memcpy(ks, key, 16);
}

/* Information block for the SPECK-64-128 block cipher */
static block_cipher_t const speck64_128 = {
    "SPECK-64-128",
    16,
    (block_cipher_init_t)speck64_128_init,
    (block_cipher_encrypt_t)speck64_128_encrypt,
    (block_cipher_decrypt_t)0
};

/* Test vector for SPECK-64-128 */
static block_cipher_test_vector_128_t const speck64_128_1 = {
    "Test Vector 1",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF},   /* plaintext */
    {0x71, 0xB0, 0x8A, 0xE3, 0xA2, 0x0A, 0x94, 0x96}    /* ciphertext */
};

void test_speck64(void)
{
    test_block_cipher_start(&speck64_128);
    test_block_cipher_other(&speck64_128, &speck64_128_1, 8);
    test_block_cipher_end(&speck64_128);
}
