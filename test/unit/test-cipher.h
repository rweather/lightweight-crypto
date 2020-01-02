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

#ifndef TEST_CIPHER_H
#define TEST_CIPHER_H

#include "aead-common.h"
#include <stddef.h>
#include <stdint.h>

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

#define AEAD_MAX_KEY_LEN 32
#define AEAD_MAX_NONCE_LEN 16
#define AEAD_MAX_AD_LEN 32
#define AEAD_MAX_DATA_LEN 32
#define AEAD_MAX_TAG_LEN 16
#define AEAD_MAX_HASH_LEN 32

/* Information about a test vector for an AEAD algorithm */
typedef struct
{
    const char *name;
    unsigned char key[AEAD_MAX_KEY_LEN];
    unsigned char nonce[AEAD_MAX_NONCE_LEN];
    unsigned char ad[AEAD_MAX_AD_LEN];
    unsigned ad_len;
    unsigned char ciphertext[AEAD_MAX_DATA_LEN + AEAD_MAX_TAG_LEN];
    unsigned char plaintext[AEAD_MAX_DATA_LEN];
    unsigned plaintext_len;

} aead_cipher_test_vector_t;

/* Information about a test vector for a hash algorithm */
typedef struct
{
    const char *name;
    unsigned char hash[AEAD_MAX_HASH_LEN];
    unsigned char input[AEAD_MAX_DATA_LEN];
    unsigned input_len;

} aead_hash_test_vector_t;

/* Value to return from the main() function for the test result */
extern int test_exit_result;

/* Version of memcmp() that dumps its arguments on failure */
int test_memcmp
    (const unsigned char *actual, const unsigned char *expected,
     unsigned long long len);

/* Start a batch of tests on a block cipher */
void test_block_cipher_start(const block_cipher_t *cipher);

/* Ends a batch of tests on a block cipher */
void test_block_cipher_end(const block_cipher_t *cipher);

/* Tests a block cipher with a 128-bit block */
void test_block_cipher_128
    (const block_cipher_t *cipher,
     const block_cipher_test_vector_128_t *test_vector);

/* Tests a block cipher with a block size other than 128-bit */
void test_block_cipher_other
    (const block_cipher_t *cipher,
     const block_cipher_test_vector_128_t *test_vector,
     unsigned block_size);

/* Start a batch of tests on an AEAD cipher */
void test_aead_cipher_start(const aead_cipher_t *cipher);

/* Ends a batch of tests on an AEAD cipher */
void test_aead_cipher_end(const aead_cipher_t *cipher);

/* Tests an AEAD cipher */
void test_aead_cipher
    (const aead_cipher_t *cipher,
     const aead_cipher_test_vector_t *test_vector);

/* Start a batch of tests on a hash algorithm */
void test_hash_start(const aead_hash_algorithm_t *hash);

/* Ends a batch of tests on a hash algorithm */
void test_hash_end(const aead_hash_algorithm_t *hash);

/* Tests a hash algorithm */
void test_hash
    (const aead_hash_algorithm_t *hash,
     const aead_hash_test_vector_t *test_vector);

#endif
