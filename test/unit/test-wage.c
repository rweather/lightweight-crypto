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

#include "internal-wage.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors generated with the WAGE reference code */
static unsigned char const wage_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24
};
static unsigned char const wage_output[] = {
    0x44, 0x78, 0x43, 0x21, 0x25, 0x6f, 0x30, 0x64,
    0x00, 0x27, 0x00, 0x76, 0x27, 0x4b, 0x73, 0x25,
    0x33, 0x43, 0x6c, 0x0e, 0x76, 0x17, 0x35, 0x49,
    0x0a, 0x16, 0x69, 0x23, 0x1d, 0x39, 0x64, 0x36,
    0x5f, 0x72, 0x18, 0x61, 0x01
};
static unsigned char const wage_absorb_data[] = {
    0xe8, 0xf2, 0x37, 0x38, 0xf5, 0x70, 0x4c, 0x8b /* randomly generated */
};
static unsigned char const wage_output_2[] = {
    0x35, 0x31, 0x3f, 0x44, 0x71, 0x2e, 0x79, 0x0c,
    0x19, 0x00, 0x6b, 0x6f, 0x39, 0x24, 0x15, 0x38,
    0x21, 0x2a, 0x1d, 0x69, 0x1e, 0x2c, 0x57, 0x35,
    0x65, 0x21, 0x18, 0x1c, 0x07, 0x2d, 0x06, 0x35,
    0x00, 0x4a, 0x7d, 0x66, 0x6c
};
static unsigned char const wage_key[16] = {
    0x20, 0x21, 0xd5, 0x37, 0xf4, 0x50, 0x45, 0xcd, /* randomly generated */
    0xb4, 0x45, 0x73, 0x32, 0x16, 0x3c, 0x60, 0x03
};
static unsigned char const wage_nonce[16] = {
    0x7d, 0x26, 0x29, 0x38, 0xbf, 0xd9, 0x4c, 0xc9, /* randomly generated */
    0x94, 0x56, 0x6f, 0x05, 0x35, 0xf2, 0x83, 0x1c
};
static unsigned char const wage_output_3[] = {
    0x51, 0x72, 0x7b, 0x78, 0x7e, 0x31, 0x62, 0x6e,
    0x4a, 0x08, 0x6a, 0x03, 0x66, 0x6c, 0x06, 0x54,
    0x1b, 0x48, 0x3a, 0x6f, 0x3b, 0x23, 0x47, 0x5f,
    0x5a, 0x2a, 0x5b, 0x5b, 0x71, 0x27, 0x66, 0x5f,
    0x53, 0x34, 0x08, 0x58, 0x0e
};

void test_wage(void)
{
    unsigned char state[WAGE_STATE_SIZE];

    printf("WAGE:\n");

    printf("    Test Vector 1 ... ");
    fflush(stdout);
    memcpy(state, wage_input, sizeof(wage_input));
    wage_permute(state);
    if (!test_memcmp(state, wage_output, sizeof(wage_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 2 ... ");
    fflush(stdout);
    wage_absorb(state, wage_absorb_data, 0);
    wage_permute(state);
    if (!test_memcmp(state, wage_output_2, sizeof(wage_output_2))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Test Vector 3 ... ");
    fflush(stdout);
    wage_init(state, wage_key, wage_nonce);
    if (!test_memcmp(state, wage_output_3, sizeof(wage_output_3))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
