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

#include "internal-saturnin.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for Saturnin created with the reference code */
static unsigned char const saturnin_test_key[32] = {
    /* Generated randomly */
    0x44, 0x79, 0x65, 0x0b, 0x43, 0xa0, 0x4b, 0xc0,
    0x9d, 0xae, 0x85, 0x8b, 0xd2, 0xd9, 0x70, 0x1c,
    0x9f, 0xb6, 0xfb, 0x15, 0xb6, 0x0b, 0x47, 0xce,
    0xb3, 0x92, 0xf9, 0xb2, 0x3d, 0x72, 0x8d, 0x1e
};
static unsigned char const saturnin_test_plaintext[SATURNIN_BLOCK_SIZE] = {
    /* Generated randomly */
    0x11, 0x91, 0x38, 0x67, 0x48, 0x4e, 0x4b, 0x8e,
    0xa7, 0x59, 0xf1, 0x9d, 0xbc, 0xf4, 0x24, 0x1b,
    0x0f, 0x65, 0x9d, 0x00, 0xa8, 0x8a, 0x41, 0xba,
    0xb6, 0x78, 0x0f, 0x9a, 0x57, 0xd7, 0x94, 0x92
};
static unsigned char const saturnin_test_ciphertext[SATURNIN_BLOCK_SIZE] = {
    /* Ciphertext output with rounds = 10 and domain separator = 3 */
    0xa8, 0x7c, 0x31, 0x8d, 0xb5, 0x66, 0x8e, 0x84,
    0x0e, 0xbd, 0x66, 0xb9, 0x72, 0x0a, 0x78, 0x1d,
    0xb4, 0x06, 0x07, 0x12, 0xb2, 0xe6, 0x94, 0x5d,
    0xe0, 0x67, 0xac, 0xf4, 0x91, 0xf6, 0xba, 0xfd
};

void test_saturnin(void)
{
    saturnin_key_schedule_t ks;
    unsigned char output[SATURNIN_BLOCK_SIZE];
    int ok = 1;

    printf("Saturnin:\n");
    printf("    Test Vector 1 ... ");
    fflush(stdout);

    saturnin_setup_key(&ks, saturnin_test_key);
    saturnin_encrypt_block
        (&ks, output, saturnin_test_plaintext, SATURNIN_DOMAIN_10_3);

    if (memcmp(output, saturnin_test_ciphertext, 32) != 0) {
        printf("encryption failed\n");
        test_exit_result = 1;
        ok = 0;
    }

    if (ok) {
        saturnin_decrypt_block
            (&ks, output, saturnin_test_ciphertext, SATURNIN_DOMAIN_10_3);
        if (memcmp(output, saturnin_test_plaintext, 32) != 0) {
            printf("decryption failed\n");
            test_exit_result = 1;
            ok = 0;
        }
    }

    if (ok) {
        printf("ok\n");
    }

    printf("\n");
}
