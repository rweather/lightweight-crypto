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

#include "gimli24.h"
#include "internal-gimli24.h"
#include "internal-gimli24-m.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors from https://gimli.cr.yp.to/impl.html for the permutation */
static uint8_t const gimli24_input[48] = {
    0x00, 0x00, 0x00, 0x00, 0xba, 0x79, 0x37, 0x9e,
    0x7a, 0xf3, 0x6e, 0x3c, 0x46, 0x6d, 0xa6, 0xda,
    0x24, 0xe7, 0xdd, 0x78, 0x1a, 0x61, 0x15, 0x17,
    0x2e, 0xdb, 0x4c, 0xb5, 0x66, 0x55, 0x84, 0x53,
    0xc8, 0xcf, 0xbb, 0xf1, 0x5a, 0x4a, 0xf3, 0x8f,
    0x22, 0xc5, 0x2a, 0x2e, 0x26, 0x40, 0x62, 0xcc
};
static uint8_t const gimli24_output[48] = {
    0x5a, 0xc8, 0x11, 0xba, 0x19, 0xd1, 0xba, 0x91,
    0x80, 0xe8, 0x0c, 0x38, 0x68, 0x2c, 0x4c, 0xd2,
    0xea, 0xff, 0xce, 0x3e, 0x1c, 0x92, 0x7a, 0x27,
    0xbd, 0xa0, 0x73, 0x4f, 0xd8, 0x9c, 0x5a, 0xda,
    0xf0, 0x73, 0xb6, 0x84, 0xf7, 0x2f, 0xe5, 0x34,
    0x49, 0xef, 0x2b, 0x9e, 0xd6, 0xb8, 0x1b, 0xf4
};

static void test_gimli24_permutation(void)
{
    uint32_t state[12];

    printf("    Permutation ... ");
    fflush(stdout);

    memcpy(state, gimli24_input, sizeof(gimli24_input));
    gimli24_permute(state);
    if (memcmp(state, gimli24_output, sizeof(gimli24_output)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

static void test_gimli24_masked(void)
{
    mask_uint32_t state[12];
    uint32_t unmasked[12];
    int index;

    printf("    Masked Permutation ... ");
    fflush(stdout);

    for (index = 0; index < 12; ++index)
        mask_input(state[index], le_load_word32(gimli24_input + index * 4));

    gimli24_permute_masked(state);
    gimli24_unmask(unmasked, state);

    if (memcmp(unmasked, gimli24_output, sizeof(gimli24_output)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

void test_gimli24(void)
{
    test_aead_cipher_start(&gimli24_cipher);
    test_gimli24_permutation();
    test_gimli24_masked();
    test_aead_cipher_end(&gimli24_cipher);
}
