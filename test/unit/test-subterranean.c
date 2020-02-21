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

#include "internal-subterranean.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for Subterranean generated with the reference code */
static unsigned char const subterranean_input[] = {
    0x81, 0xbb, 0xd3, 0xe3, 0xa1, 0x9d, 0x4e, 0x80, /* randomly generated */
    0xac, 0x00, 0xfe, 0xf5, 0x8f, 0x22, 0x0f, 0xbc,
    0x1c, 0x84, 0x40, 0x37, 0x8f, 0x49, 0x43, 0x71,
    0x84, 0x69, 0x48, 0x31, 0x0b, 0xf0, 0xa5, 0x71,
    0x01
};
static unsigned char const subterranean_output_1[] = {
    /* Execute the round function once with no absorb or squeeze */
    0xb5, 0x7c, 0x2a, 0x14, 0xe0, 0xa8, 0x02, 0x44,
    0x11, 0x3d, 0x31, 0xaf, 0x4b, 0x91, 0xd0, 0xe2,
    0x7c, 0x80, 0x9d, 0x13, 0xd9, 0x33, 0x67, 0x18,
    0xce, 0x84, 0xa1, 0x03, 0xf0, 0x07, 0x65, 0x9c,
    0x00
};
static unsigned char const subterranean_output_2[] = {
    /* Execute 8 rounds in "blank" mode */
    0xdb, 0xd1, 0x37, 0xe4, 0xaa, 0x4c, 0x09, 0x8d,
    0x5f, 0x85, 0x57, 0x2d, 0x72, 0x6c, 0x12, 0xd2,
    0x69, 0x52, 0xf0, 0x61, 0x47, 0x7e, 0x72, 0x1c,
    0x6b, 0x8a, 0xab, 0x94, 0x41, 0x56, 0xf0, 0x18,
    0x01
};
static unsigned char const subterranean_output_3[] = {
    /* One round and then absorb 4 bytes with subterranean_absorb() */
    0xbd, 0x8f, 0x16, 0x5d, 0x72, 0x80, 0x9e, 0xf3,
    0x60, 0x6e, 0xe7, 0x0d, 0x1c, 0x4d, 0xe6, 0xe8,
    0x06, 0x0c, 0x7a, 0x7e, 0x21, 0x2d, 0x5a, 0x6e,
    0x53, 0x7f, 0x71, 0x76, 0x49, 0x65, 0x3d, 0x4c,
    0x01
};
static unsigned char const subterranean_absorb_data[] = {
    0xa8, 0xb8, 0xf9, 0xc2
};
static unsigned char const subterranean_output_4[] = {
    /* State after 16 bytes have been squeezed out of the state */
    0x9d, 0x28, 0x3d, 0x9f, 0x2d, 0x50, 0x47, 0xe0,
    0x7e, 0x6c, 0xb2, 0x2b, 0x04, 0x4f, 0x60, 0x3b,
    0xaa, 0xcd, 0x68, 0xa7, 0x3c, 0x22, 0xd5, 0xa8,
    0x82, 0x80, 0x95, 0xff, 0x9c, 0x14, 0x48, 0x5a,
    0x00
};
static unsigned char const subterranean_squeezed_data[] = {
    0xfb, 0x1b, 0x72, 0x8b, 0x2a, 0x31, 0x73, 0xf0,
    0x46, 0xff, 0xcb, 0x12, 0xb0, 0x33, 0x1d, 0x9f
};

static void subterranean_load
    (subterranean_state_t *state, const unsigned char input[33])
{
    unsigned index;
    for (index = 0; index < 8; ++index)
        state->x[index] = le_load_word32(input + index * 4);
    state->x[8] = input[32] & 1;
}

static void subterranean_store
    (unsigned char output[33], const subterranean_state_t *state)
{
    unsigned index;
    for (index = 0; index < 8; ++index)
        le_store_word32(output + index * 4, state->x[index]);
    output[32] = (unsigned char)(state->x[8] & 1);
}

void test_subterranean(void)
{
    subterranean_state_t state;
    unsigned char buffer[33];
    unsigned char squeezed[16];

    printf("Subterranean:\n");

    printf("    Test Vector 1 ... ");
    fflush(stdout);
    subterranean_load(&state, subterranean_input);
    subterranean_round(&state);
    subterranean_store(buffer, &state);
    if (!test_memcmp(buffer, subterranean_output_1, sizeof(subterranean_output_1))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 2 ... ");
    fflush(stdout);
    subterranean_load(&state, subterranean_input);
    subterranean_blank(&state);
    subterranean_store(buffer, &state);
    if (!test_memcmp(buffer, subterranean_output_2, sizeof(subterranean_output_2))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 3 ... ");
    fflush(stdout);
    subterranean_load(&state, subterranean_input);
    subterranean_absorb(&state, subterranean_absorb_data, sizeof(subterranean_absorb_data));
    subterranean_store(buffer, &state);
    if (!test_memcmp(buffer, subterranean_output_3, sizeof(subterranean_output_3))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 4 ... ");
    fflush(stdout);
    subterranean_load(&state, subterranean_input);
    subterranean_absorb(&state, subterranean_absorb_data, sizeof(subterranean_absorb_data));
    subterranean_squeeze(&state, squeezed, sizeof(squeezed));
    subterranean_store(buffer, &state);
    if (!test_memcmp(buffer, subterranean_output_4, sizeof(subterranean_output_4)) &&
        !test_memcmp(squeezed, subterranean_squeezed_data, sizeof(subterranean_squeezed_data))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
