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

#include "internal-pyjamask.h"
#include "internal-pyjamask-m.h"
#include "test-cipher.h"
#include <string.h>

/* Information block for the Pyjamask-128 block cipher */
static block_cipher_t const pyjamask_128 = {
    "Pyjamask-128",
    sizeof(pyjamask_128_key_schedule_t),
    (block_cipher_init_t)pyjamask_128_setup_key,
    (block_cipher_encrypt_t)pyjamask_128_encrypt,
    (block_cipher_decrypt_t)pyjamask_128_decrypt
};

/* Information block for the masked Pyjamask-128 block cipher */
static block_cipher_t const pyjamask_masked_128 = {
    "Pyjamask-128-Masked",
    sizeof(pyjamask_masked_128_key_schedule_t),
    (block_cipher_init_t)pyjamask_masked_128_setup_key,
    (block_cipher_encrypt_t)pyjamask_masked_128_encrypt,
    (block_cipher_decrypt_t)pyjamask_masked_128_decrypt
};

/* Information block for the Pyjamask-96 block cipher */
static block_cipher_t const pyjamask_96 = {
    "Pyjamask-96",
    sizeof(pyjamask_96_key_schedule_t),
    (block_cipher_init_t)pyjamask_96_setup_key,
    (block_cipher_encrypt_t)pyjamask_96_encrypt,
    (block_cipher_decrypt_t)pyjamask_96_decrypt
};

/* Information block for the masked Pyjamask-96 block cipher */
static block_cipher_t const pyjamask_masked_96 = {
    "Pyjamask-96-Masked",
    sizeof(pyjamask_masked_96_key_schedule_t),
    (block_cipher_init_t)pyjamask_masked_96_setup_key,
    (block_cipher_encrypt_t)pyjamask_masked_96_encrypt,
    (block_cipher_decrypt_t)pyjamask_masked_96_decrypt
};

/* Test vectors for the Pyjamask block cipher from the specification */
static block_cipher_test_vector_128_t const pyjamask_128_1 = {
    "Test Vector 1",
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* key */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    16,                                                 /* key_len */
    {0x50, 0x79, 0x6a, 0x61, 0x6d, 0x61, 0x73, 0x6b,    /* plaintext */
     0x2d, 0x31, 0x32, 0x38, 0x3a, 0x29, 0x3a, 0x29},
    {0x48, 0xf1, 0x39, 0xa1, 0x09, 0xbd, 0xd9, 0xc0,    /* ciphertext */
     0x72, 0x6e, 0x82, 0x61, 0xf8, 0xd6, 0x8e, 0x7d}
};
static block_cipher_test_vector_128_t const pyjamask_96_1 = {
    "Test Vector 1",
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* key */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    16,                                                 /* key_len */
    {0x50, 0x79, 0x6a, 0x61, 0x6d, 0x61, 0x73, 0x6b,    /* plaintext */
     0x39, 0x36, 0x3a, 0x29},
    {0xca, 0x9c, 0x6e, 0x1a, 0xbb, 0xde, 0x4e, 0xdc,    /* ciphertext */
     0x27, 0x07, 0x3d, 0xa6}
};

void test_pyjamask(void)
{
    test_block_cipher_start(&pyjamask_128);
    test_block_cipher_128(&pyjamask_128, &pyjamask_128_1);
    test_block_cipher_end(&pyjamask_128);

    test_block_cipher_start(&pyjamask_96);
    test_block_cipher_other(&pyjamask_96, &pyjamask_96_1, 12);
    test_block_cipher_end(&pyjamask_96);

    test_block_cipher_start(&pyjamask_masked_128);
    test_block_cipher_128(&pyjamask_masked_128, &pyjamask_128_1);
    test_block_cipher_end(&pyjamask_masked_128);

    test_block_cipher_start(&pyjamask_masked_96);
    test_block_cipher_other(&pyjamask_masked_96, &pyjamask_96_1, 12);
    test_block_cipher_end(&pyjamask_masked_96);
}
