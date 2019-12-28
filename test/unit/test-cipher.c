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

#include "test-cipher.h"
#include "aead-common.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int first_test = 1;
int test_exit_result = 0;

static void test_print_hex
    (const char *tag, const unsigned char *data, unsigned long long len)
{
    printf("%s =", tag);
    while (len > 0) {
        printf(" %02x", data[0]);
        ++data;
        --len;
    }
    printf("\n");
}

int test_memcmp
    (const unsigned char *actual, const unsigned char *expected,
     unsigned long long len)
{
    int cmp = memcmp(actual, expected, (size_t)len);
    if (cmp == 0)
        return 0;
    printf("\n");
    test_print_hex("actual  ", actual, len);
    test_print_hex("expected", expected, len);
    return cmp;
}

void test_block_cipher_start(const block_cipher_t *cipher)
{
    if (first_test) {
        printf("\n");
        first_test = 0;
    }
    printf("%s:\n", cipher->name);
}

void test_block_cipher_end(const block_cipher_t *cipher)
{
    printf("\n");
}

static int test_block_cipher_128_inner
    (const block_cipher_t *cipher,
     const block_cipher_test_vector_128_t *test_vector, void *ks,
     size_t block_size)
{
    unsigned char temp[block_size];

    /* Set the encryption key */
    if (!(*(cipher->init))(ks, test_vector->key, test_vector->key_len)) {
        printf("cannot set key ... ");
        return 0;
    }

    /* Test encryption */
    memset(temp, 0xAA, sizeof(temp));
    (*(cipher->encrypt))(ks, temp, test_vector->plaintext);
    if (test_memcmp(temp, test_vector->ciphertext, block_size) != 0) {
        printf("encryption ... ");
        return 0;
    }

    /* Test in-place encryption */
    memcpy(temp, test_vector->plaintext, block_size);
    (*(cipher->encrypt))(ks, temp, temp);
    if (test_memcmp(temp, test_vector->ciphertext, block_size) != 0) {
        printf("in-place encryption ... ");
        return 0;
    }

    /* Test decryption if the operation is supported */
    if (cipher->decrypt) {
        /* Test decryption */
        memset(temp, 0xBB, sizeof(temp));
        (*(cipher->decrypt))(ks, temp, test_vector->ciphertext);
        if (test_memcmp(temp, test_vector->plaintext, block_size) != 0) {
            printf("decryption ... ");
            return 0;
        }

        /* Test in-place decryption */
        memcpy(temp, test_vector->ciphertext, block_size);
        (*(cipher->decrypt))(ks, temp, temp);
        if (test_memcmp(temp, test_vector->plaintext, block_size) != 0) {
            printf("in-place decryption ... ");
            return 0;
        }
    }

    return 1;
}

void test_block_cipher_128
    (const block_cipher_t *cipher,
     const block_cipher_test_vector_128_t *test_vector)
{
    char *ks;

    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    ks = calloc(1, cipher->schedule_size);
    if (!ks) {
        printf("out of memory\n");
        test_exit_result = 1;
        return;
    }

    if (test_block_cipher_128_inner(cipher, test_vector, ks, 16)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
    free(ks);
}

void test_block_cipher_64
    (const block_cipher_t *cipher,
     const block_cipher_test_vector_128_t *test_vector)
{
    char *ks;

    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    ks = calloc(1, cipher->schedule_size);
    if (!ks) {
        printf("out of memory\n");
        test_exit_result = 1;
        return;
    }

    if (test_block_cipher_128_inner(cipher, test_vector, ks, 8)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
    free(ks);
}

void test_aead_cipher_start(const aead_cipher_t *cipher)
{
    if (first_test) {
        printf("\n");
        first_test = 0;
    }
    printf("%s:\n", cipher->name);
}

void test_aead_cipher_end(const aead_cipher_t *cipher)
{
    printf("\n");
}

static int test_aead_cipher_inner
    (const aead_cipher_t *cipher,
     const aead_cipher_test_vector_t *test_vector)
{
    unsigned char temp[AEAD_MAX_DATA_LEN + AEAD_MAX_TAG_LEN];
    unsigned char temp2[AEAD_MAX_DATA_LEN + AEAD_MAX_TAG_LEN];
    unsigned ciphertext_len = test_vector->plaintext_len + cipher->tag_len;
    unsigned long long len;
    int result;

    /* Test encryption */
    memset(temp, 0xAA, sizeof(temp));
    len = 0xBADBEEF;
    result = (*(cipher->encrypt))
        (temp, &len, test_vector->plaintext, test_vector->plaintext_len,
         test_vector->ad, test_vector->ad_len, 0, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != ciphertext_len ||
            test_memcmp(temp, test_vector->ciphertext, len) != 0) {
        printf("encryption ... ");
        return 0;
    }

    /* Test in-place encryption */
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp, test_vector->plaintext, test_vector->plaintext_len);
    len = 0xBADBEEF;
    result = (*(cipher->encrypt))
        (temp, &len, temp, test_vector->plaintext_len,
         test_vector->ad, test_vector->ad_len, 0, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != ciphertext_len ||
            test_memcmp(temp, test_vector->ciphertext, len) != 0) {
        printf("in-place encryption ... ");
        return 0;
    }

    /* Test decryption */
    memset(temp, 0xAA, sizeof(temp));
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, test_vector->ciphertext, ciphertext_len,
         test_vector->ad, test_vector->ad_len, test_vector->nonce,
         test_vector->key);
    if (result != 0 || len != test_vector->plaintext_len ||
            test_memcmp(temp, test_vector->plaintext, len) != 0) {
        printf("decryption ... ");
        return 0;
    }

    /* Test in-place decryption */
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp, test_vector->ciphertext, ciphertext_len);
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, temp, ciphertext_len,
         test_vector->ad, test_vector->ad_len, test_vector->nonce,
         test_vector->key);
    if (result != 0 ||
            len != test_vector->plaintext_len ||
            test_memcmp(temp, test_vector->plaintext, len) != 0) {
        printf("in-place decryption ... ");
        return 0;
    }

    /* Test decryption with a failed tag check */
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp2, test_vector->ciphertext, ciphertext_len);
    temp2[0] ^= 0x01; // Corrupt the first byte of the ciphertext.
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, temp2, ciphertext_len,
         test_vector->ad, test_vector->ad_len, test_vector->nonce,
         test_vector->key);
    if (result != -1) {
        printf("corrupt data ... ");
        return 0;
    }
    memset(temp, 0xAA, sizeof(temp));
    memcpy(temp2, test_vector->ciphertext, ciphertext_len);
    temp2[test_vector->plaintext_len] ^= 0x01; // Corrupt first byte of the tag.
    len = 0xBADBEEF;
    result = (*(cipher->decrypt))
        (temp, &len, 0, temp2, ciphertext_len,
         test_vector->ad, test_vector->ad_len, test_vector->nonce,
         test_vector->key);
    if (result != -1) {
        printf("corrupt tag ... ");
        return 0;
    }

    return 1;
}

void test_aead_cipher
    (const aead_cipher_t *cipher,
     const aead_cipher_test_vector_t *test_vector)
{
    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    if (test_aead_cipher_inner(cipher, test_vector)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_hash_start(const aead_hash_algorithm_t *hash)
{
    if (first_test) {
        printf("\n");
        first_test = 0;
    }
    printf("%s:\n", hash->name);
}

void test_hash_end(const aead_hash_algorithm_t *hash)
{
    printf("\n");
}

void test_hash
    (const aead_hash_algorithm_t *hash,
     const aead_hash_test_vector_t *test_vector)
{
    unsigned char output[AEAD_MAX_HASH_LEN];

    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    (*hash->hash)(output, test_vector->input, test_vector->input_len);
    if (test_memcmp(output, test_vector->hash, hash->hash_len) == 0) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}
