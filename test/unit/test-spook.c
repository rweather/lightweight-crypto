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

#include "internal-spook.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

static void clyde128_test_init(unsigned char *ks, const unsigned char *key)
{
    memcpy(ks, key, 32);
}

static void clyde128_test_encrypt
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t k[4];
    uint32_t x[4];
    memcpy(k, ks + 16, sizeof(k));
    memcpy(x, input, sizeof(x));
    clyde128_encrypt(ks, x, x, k);
    memcpy(output, x, sizeof(x));
}

static void clyde128_test_decrypt
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t k[4];
    uint32_t x[4];
    memcpy(k, ks + 16, sizeof(k));
    clyde128_decrypt(ks, x, input, k);
    memcpy(output, x, sizeof(x));
}

static void clyde128_masked_test_encrypt
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t k[4];
    uint32_t x[4];
    memcpy(k, ks + 16, sizeof(k));
    memcpy(x, input, sizeof(x));
    clyde128_encrypt_masked(ks, x, x, k);
    memcpy(output, x, sizeof(x));
}

static void clyde128_masked_test_decrypt
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t k[4];
    uint32_t x[4];
    memcpy(k, ks + 16, sizeof(k));
    clyde128_decrypt_masked(ks, x, input, k);
    memcpy(output, x, sizeof(x));
}

/* Information block for the Clyde-128 block cipher */
static block_cipher_t const clyde128 = {
    "Clyde-128",
    32,
    (block_cipher_init_t)clyde128_test_init,
    (block_cipher_encrypt_t)clyde128_test_encrypt,
    (block_cipher_decrypt_t)clyde128_test_decrypt
};

/* Information block for the masked Clyde-128 block cipher */
static block_cipher_t const clyde128_masked = {
    "Clyde-128-Masked",
    32,
    (block_cipher_init_t)clyde128_test_init,
    (block_cipher_encrypt_t)clyde128_masked_test_encrypt,
    (block_cipher_decrypt_t)clyde128_masked_test_decrypt
};

/* Test vector for Clyde-128 generated with the reference implementation */
static block_cipher_test_vector_128_t const clyde128_1 = {
    "Test Vector 1",
    {0xc6, 0x5a, 0xf8, 0xdd, 0xcf, 0x9d, 0x4a, 0x70,    /* key + tweak */
     0xb7, 0x20, 0x2e, 0x95, 0x9b, 0x4b, 0xfd, 0xb7,
     0x9c, 0xc9, 0x76, 0xbd, 0x0c, 0x21, 0x48, 0x4c,
     0x9d, 0x19, 0xf9, 0x27, 0xb1, 0xaa, 0x3f, 0xe1},
    32,                                                 /* key_len */
    {0xd0, 0x84, 0x40, 0x22, 0x36, 0x80, 0x40, 0x4f,    /* plaintext */
     0xa2, 0x09, 0xb2, 0x1c, 0xf7, 0xff, 0x86, 0xa6},
    {0x6b, 0x73, 0xfa, 0x3e, 0x9a, 0x5a, 0x89, 0x95,    /* ciphertext */
     0x2c, 0xd2, 0x9d, 0x3e, 0xe2, 0x03, 0x85, 0x01},
};

void test_clyde128(void)
{
    test_block_cipher_start(&clyde128);
    test_block_cipher_128(&clyde128, &clyde128_1);
    test_block_cipher_end(&clyde128);

    test_block_cipher_start(&clyde128_masked);
    test_block_cipher_128(&clyde128_masked, &clyde128_1);
    test_block_cipher_end(&clyde128_masked);
}

/* Test vectors for Shadow-512/384 generated with reference implementation */
static unsigned char const shadow512_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static unsigned char const shadow512_output[] = {
    0x68, 0x3f, 0xa9, 0xf9, 0x00, 0xf6, 0x58, 0xa2,
    0x71, 0x66, 0xe2, 0xcc, 0x1b, 0xb4, 0x0d, 0xf8,
    0x32, 0xd2, 0x70, 0xf8, 0xc0, 0x10, 0x88, 0xbf,
    0xeb, 0x92, 0x43, 0x2f, 0x0d, 0xb2, 0xe6, 0x9c,
    0x73, 0xc6, 0x4d, 0x2a, 0x3c, 0xf3, 0x28, 0x49,
    0xbc, 0x6e, 0xe1, 0xbe, 0x09, 0x2a, 0x42, 0x68,
    0xad, 0x56, 0xf0, 0x78, 0xcb, 0x2b, 0x87, 0x92,
    0x44, 0x77, 0xcc, 0x15, 0xcd, 0x56, 0x52, 0x38,
};
static unsigned char const shadow384_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};
static unsigned char const shadow384_output[] = {
    0x28, 0x14, 0xfc, 0x1a, 0x79, 0xc9, 0x8e, 0x3d,
    0xcb, 0xb7, 0x11, 0xce, 0x0f, 0xce, 0xf8, 0xdb,
    0xfb, 0x3b, 0xd3, 0x45, 0xae, 0xac, 0x78, 0x43,
    0xeb, 0xcc, 0xb3, 0x1c, 0x41, 0xd9, 0x9d, 0x47,
    0xc6, 0xe7, 0xc6, 0xcc, 0x87, 0x82, 0xe3, 0x9c,
    0x4b, 0x40, 0xb1, 0xdf, 0xda, 0x96, 0x43, 0xb2,
};

void test_shadow(void)
{
    shadow512_state_t state512;
    shadow384_state_t state384;

    printf("Shadow Permutation:\n");

    printf("    Shadow-512 ... ");
    fflush(stdout);
    memcpy(state512.B, shadow512_input, sizeof(shadow512_input));
    shadow512(&state512);
    if (!test_memcmp(state512.B, shadow512_output, sizeof(shadow512_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Shadow-384 ... ");
    fflush(stdout);
    memcpy(state384.B, shadow384_input, sizeof(shadow384_input));
    shadow384(&state384);
    if (!test_memcmp(state384.B, shadow384_output, sizeof(shadow384_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
