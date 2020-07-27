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

#include "ascon128.h"
#include "internal-ascon.h"
#include "internal-ascon-m.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors generated with the reference code */
static uint8_t const ascon_input[40] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};
static uint8_t const ascon_output_12[40] = {
    /* Output after 12 rounds */
    0x06, 0x05, 0x87, 0xe2, 0xd4, 0x89, 0xdd, 0x43,
    0x1c, 0xc2, 0xb1, 0x7b, 0x0e, 0x3c, 0x17, 0x64,
    0x95, 0x73, 0x42, 0x53, 0x18, 0x44, 0xa6, 0x74,
    0x96, 0xb1, 0x71, 0x75, 0xb4, 0xcb, 0x68, 0x63,
    0x29, 0xb5, 0x12, 0xd6, 0x27, 0xd9, 0x06, 0xe5
};
static uint8_t const ascon_output_8[40] = {
    /* Output after 8 rounds */
    0x83, 0x0d, 0x26, 0x0d, 0x33, 0x5f, 0x3b, 0xed,
    0xda, 0x0b, 0xba, 0x91, 0x7b, 0xcf, 0xca, 0xd7,
    0xdd, 0x0d, 0x88, 0xe7, 0xdc, 0xb5, 0xec, 0xd0,
    0x89, 0x2a, 0x02, 0x15, 0x1f, 0x95, 0x94, 0x6e,
    0x3a, 0x69, 0xcb, 0x3c, 0xf9, 0x82, 0xf6, 0xf7
};

static void test_ascon_permutation(void)
{
    ascon_state_t state;

    printf("    Permutation 12 ... ");
    fflush(stdout);
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_permute(&state, 0);
    if (memcmp(state.B, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("    Permutation 8 ... ");
    fflush(stdout);
    memcpy(state.B, ascon_input, sizeof(ascon_input));
    ascon_permute(&state, 4);
    if (memcmp(state.B, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

static void test_ascon_masked(void)
{
    mask_uint64_t state[5];
    uint64_t unmasked[5];

    printf("    Masked Permutation 12 ... ");
    fflush(stdout);
    memcpy(unmasked, ascon_input, sizeof(ascon_input));
    ascon_mask(state, unmasked);
    ascon_permute_masked(state, 0);
    ascon_unmask(unmasked, state);
    if (memcmp(unmasked, ascon_output_12, sizeof(ascon_output_12)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }

    printf("    Masked Permutation 8 ... ");
    fflush(stdout);
    memcpy(unmasked, ascon_input, sizeof(ascon_input));
    ascon_mask(state, unmasked);
    ascon_permute_masked(state, 4);
    ascon_unmask(unmasked, state);
    if (memcmp(unmasked, ascon_output_8, sizeof(ascon_output_8)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

void test_ascon(void)
{
    test_aead_cipher_start(&ascon128_cipher);
    test_ascon_permutation();
    test_ascon_masked();
    test_aead_cipher_end(&ascon128_cipher);
}
