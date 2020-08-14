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

#include "internal-knot.h"
#include "internal-knot-m.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* KNOT permutation test vectors generated with the reference implementation */
#define knot256_rounds 52
static unsigned char knot256_in[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char knot256_out[32] = {
    0x0c, 0x86, 0x01, 0xe9, 0x7f, 0x59, 0x30, 0xfd,
    0xe2, 0x3c, 0x45, 0xa6, 0x03, 0x05, 0x7f, 0x85,
    0x0e, 0xa5, 0x6d, 0x6e, 0xc5, 0x84, 0x67, 0xd3,
    0xa4, 0x25, 0xe7, 0x35, 0xa3, 0x85, 0x66, 0x09
};
#define knot384_rounds 76
static unsigned char knot384_in[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static unsigned char knot384_out[48] = {
    0xca, 0x10, 0x72, 0x70, 0xbd, 0x88, 0x9f, 0xa0,
    0x89, 0xd2, 0xd1, 0x09, 0xf7, 0x65, 0x8e, 0xe1,
    0x0d, 0x2a, 0xd7, 0xc8, 0x79, 0x4f, 0x59, 0xb9,
    0x16, 0x87, 0x64, 0xba, 0x1a, 0xed, 0x86, 0x83,
    0xf2, 0x9b, 0x82, 0x80, 0x9e, 0x83, 0x2e, 0xf2,
    0xca, 0x1c, 0x93, 0xe9, 0xf6, 0xf7, 0x52, 0x40
};
#define knot512_rounds 140
static unsigned char knot512_in[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static unsigned char knot512_out[64] = {
    0x03, 0xbb, 0x5f, 0x54, 0xea, 0x9b, 0x15, 0x76,
    0xef, 0x12, 0xdd, 0x18, 0x52, 0x1a, 0x9d, 0x89,
    0xd6, 0x5d, 0xd3, 0x7d, 0xec, 0xb7, 0x47, 0xc7,
    0x4a, 0x67, 0xfe, 0x31, 0x13, 0x9d, 0x0c, 0x54,
    0x00, 0x72, 0x4e, 0xba, 0x05, 0x34, 0x3b, 0x3f,
    0x1e, 0xb2, 0x79, 0x66, 0x73, 0x33, 0x32, 0x35,
    0x8a, 0x61, 0xba, 0xd9, 0x62, 0x72, 0xf9, 0xb7,
    0xb3, 0x43, 0xdd, 0xc7, 0x66, 0x59, 0xee, 0x7d
};

static void test_knot256(void)
{
    knot256_state_t state;
    printf("    KNOT-256 ... ");
    memcpy(state.B, knot256_in, sizeof(knot256_in));
    knot256_permute_6(&state, knot256_rounds);
    if (test_memcmp(state.B, knot256_out, sizeof(knot256_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

static void test_knot384(void)
{
    knot384_state_t state;
    printf("    KNOT-384 ... ");
    memcpy(state.B, knot384_in, sizeof(knot384_in));
    knot384_permute_7(&state, knot384_rounds);
    if (test_memcmp(state.B, knot384_out, sizeof(knot384_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

static void test_knot512(void)
{
    knot512_state_t state;
    printf("    KNOT-512 ... ");
    memcpy(state.B, knot512_in, sizeof(knot512_in));
    knot512_permute_8(&state, knot512_rounds);
    if (test_memcmp(state.B, knot512_out, sizeof(knot512_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

static void test_knot256_masked(void)
{
    uint64_t temp[4];
    knot256_masked_state_t state;
    printf("    KNOT-256-Masked ... ");
    memcpy(temp, knot256_in, sizeof(knot256_in));
    knot256_mask(&state, temp);
    knot256_masked_permute_6(&state, knot256_rounds);
    knot256_unmask(temp, &state);
    if (test_memcmp((const unsigned char *)temp, knot256_out,
                    sizeof(knot256_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

static void test_knot384_masked(void)
{
    uint32_t temp[16];
    knot384_masked_state_t state;
    printf("    KNOT-384-Masked ... ");
    memcpy(temp, knot384_in, sizeof(knot384_in));
    knot384_mask(&state, temp);
    knot384_masked_permute_7(&state, knot384_rounds);
    knot384_unmask(temp, &state);
    if (test_memcmp((const unsigned char *)temp,
                    knot384_out, sizeof(knot384_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

static void test_knot512_masked(void)
{
    uint64_t temp[8];
    knot512_masked_state_t state;
    printf("    KNOT-512-Masked ... ");
    memcpy(temp, knot512_in, sizeof(knot512_in));
    knot512_mask(&state, temp);
    knot512_masked_permute_8(&state, knot512_rounds);
    knot512_unmask(temp, &state);
    if (test_memcmp((const unsigned char *)temp, knot512_out,
                    sizeof(knot512_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

void test_knot(void)
{
    printf("KNOT Permutation:\n");
    test_knot256();
    test_knot384();
    test_knot512();
    test_knot256_masked();
    test_knot384_masked();
    test_knot512_masked();
    printf("\n");
}
