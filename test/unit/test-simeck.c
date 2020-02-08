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

#include "internal-simeck.h"
#include "test-cipher.h"

static int simeck_init
    (unsigned char *ks, const unsigned char *key, size_t key_len)
{
    ks[0] = key[0]; /* Actually the round constant */
    return key_len == 1;
}

static void simeck64_encrypt
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t block[2];
    block[0] = be_load_word32(input);
    block[1] = be_load_word32(input + 4);
    simeck64_box(block, ks[0]);
    be_store_word32(output, block[0]);
    be_store_word32(output + 4, block[1]);
}

static void simeck48_encrypt
    (const unsigned char *ks, unsigned char *output,
     const unsigned char *input)
{
    uint32_t block[2];
    block[0] = (((uint32_t)(input[0])) << 16) |
               (((uint32_t)(input[1])) <<  8) |
                ((uint32_t)(input[2]));
    block[1] = (((uint32_t)(input[3])) << 16) |
               (((uint32_t)(input[4])) <<  8) |
                ((uint32_t)(input[5]));
    simeck48_box(block, ks[0]);
    output[0] = (uint8_t)(block[0] >> 16);
    output[1] = (uint8_t)(block[0] >> 8);
    output[2] = (uint8_t)(block[0]);
    output[3] = (uint8_t)(block[1] >> 16);
    output[4] = (uint8_t)(block[1] >> 8);
    output[5] = (uint8_t)(block[1]);
}

/* Information block for the Simeck-48 block cipher */
static block_cipher_t const simeck64 = {
    "Simeck-64",
    1,
    (block_cipher_init_t)simeck_init,
    (block_cipher_encrypt_t)simeck64_encrypt,
    (block_cipher_decrypt_t)0
};

/* Information block for the Simeck-64 block cipher */
static block_cipher_t const simeck48 = {
    "Simeck-48",
    1,
    (block_cipher_init_t)simeck_init,
    (block_cipher_encrypt_t)simeck48_encrypt,
    (block_cipher_decrypt_t)0
};

/* Test vector for Simeck-64 from the SPIX specification */
static block_cipher_test_vector_128_t const simeck64_1 = {
    "Test Vector 1",
    {0x07}, /* Simeck doesn't have keys; supply the round constant instead */
    1,                                                  /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   /* plaintext */
    {0x00, 0x00, 0x1c, 0x1e, 0x00, 0x00, 0x0c, 0x2d}    /* ciphertext */
};

/* Test vector for Simeck-64 generated with the SPIX reference code */
static block_cipher_test_vector_128_t const simeck64_2 = {
    "Test Vector 2",
    {0xff}, /* Simeck doesn't have keys; supply the round constant instead */
    1,                                                  /* key_len */
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},   /* plaintext */
    {0x88, 0x9c, 0x64, 0x82, 0x0e, 0x0f, 0xf7, 0x85}    /* ciphertext */
};

/* Test vectors for Simeck-48 generated with the SpoC reference code */
static block_cipher_test_vector_128_t const simeck48_1 = {
    "Test Vector 1",
    {0x07}, /* Simeck doesn't have keys; supply the round constant instead */
    1,                                                  /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},               /* plaintext */
    {0xff, 0xff, 0x9a, 0xff, 0xff, 0xfc}                /* ciphertext */
};
static block_cipher_test_vector_128_t const simeck48_2 = {
    "Test Vector 2",
    {0x3f}, /* Simeck doesn't have keys; supply the round constant instead */
    1,                                                  /* key_len */
    {0x01, 0x23, 0x45, 0x67, 0x89, 0xab},               /* plaintext */
    {0x37, 0x0f, 0x64, 0xea, 0x37, 0xea}                /* ciphertext */
};

void test_simeck(void)
{
    test_block_cipher_start(&simeck48);
    test_block_cipher_other(&simeck48, &simeck48_1, 6);
    test_block_cipher_other(&simeck48, &simeck48_2, 6);
    test_block_cipher_end(&simeck48);

    test_block_cipher_start(&simeck64);
    test_block_cipher_other(&simeck64, &simeck64_1, 8);
    test_block_cipher_other(&simeck64, &simeck64_2, 8);
    test_block_cipher_end(&simeck64);
}
