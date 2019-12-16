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

#include "test-cipher.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int first_test = 1;
int test_exit_result = 0;

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
     const block_cipher_test_vector_128_t *test_vector, void *ks)
{
    unsigned char temp[16];

    /* Set the encryption key */
    if (!(*(cipher->init))(ks, test_vector->key, test_vector->key_len)) {
        printf("cannot set key ... ");
        return 0;
    }

    /* Test encryption */
    memset(temp, 0xAA, sizeof(temp));
    (*(cipher->encrypt))(ks, temp, test_vector->plaintext);
    if (memcmp(temp, test_vector->ciphertext, 16) != 0) {
        printf("encryption ... ");
        return 0;
    }

    /* Test in-place encryption */
    memcpy(temp, test_vector->plaintext, 16);
    (*(cipher->encrypt))(ks, temp, temp);
    if (memcmp(temp, test_vector->ciphertext, 16) != 0) {
        printf("in-place encryption ... ");
        return 0;
    }

    /* Test decryption if the operation is supported */
    if (cipher->decrypt) {
        /* Test decryption */
        memset(temp, 0xBB, sizeof(temp));
        (*(cipher->decrypt))(ks, temp, test_vector->ciphertext);
        if (memcmp(temp, test_vector->plaintext, 16) != 0) {
            printf("decryption ... ");
            return 0;
        }

        /* Test in-place decryption */
        memcpy(temp, test_vector->ciphertext, 16);
        (*(cipher->decrypt))(ks, temp, temp);
        if (memcmp(temp, test_vector->plaintext, 16) != 0) {
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

    if (test_block_cipher_128_inner(cipher, test_vector, ks)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
    free(ks);
}
