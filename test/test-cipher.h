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

#ifndef TEST_CIPHER_H
#define TEST_CIPHER_H

#include <stddef.h>

typedef int (*block_cipher_init_t)
    (void *ks, const unsigned char *key, size_t key_len);
typedef void (*block_cipher_encrypt_t)
    (const void *ks, unsigned char *output, const unsigned char *input);
typedef void (*block_cipher_decrypt_t)
    (const void *ks, unsigned char *output, const unsigned char *input);

/* Information about a block cipher for testing purposes */
typedef struct
{
    const char *name;
    size_t schedule_size;
    block_cipher_init_t init;
    block_cipher_encrypt_t encrypt;
    block_cipher_decrypt_t decrypt; /* May be NULL if no decrypt operation */

} block_cipher_t;

/* Information about a test vector for a 128-bit block cipher,
 * with variable key sizes up to 384-bit */
typedef struct
{
    const char *name;
    unsigned char key[48];
    unsigned key_len;
    unsigned char plaintext[16];
    unsigned char ciphertext[16];

} block_cipher_test_vector_128_t;

/* Value to return from the main() function for the test result */
extern int test_exit_result;

/* Start a batch of tests on a block cipher */
void test_block_cipher_start(const block_cipher_t *cipher);

/* Ends a batch of tests on a block cipher */
void test_block_cipher_end(const block_cipher_t *cipher);

/* Tests a block cipher with a 128-bit block */
void test_block_cipher_128
    (const block_cipher_t *cipher,
     const block_cipher_test_vector_128_t *test_vector);

#endif
