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

#include "internal-simp.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for SimP generated with the Oribatida reference code */
static unsigned char const simp_192_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};
static unsigned char const simp_192_output[] = {
    0xd8, 0x01, 0x34, 0xd1, 0xb6, 0xc1, 0xf9, 0xfc,
    0x05, 0x73, 0xa5, 0x1f, 0x01, 0xfe, 0x06, 0x8b,
    0xa3, 0xd2, 0xf7, 0xd3, 0x61, 0x7b, 0x87, 0x29
};
static unsigned char const simp_256_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char const simp_256_output[] = {
    0x5a, 0xb3, 0x47, 0xab, 0x9a, 0x01, 0x6f, 0xe0,
    0x3b, 0xad, 0x26, 0xb4, 0x5b, 0x43, 0xa1, 0xb0,
    0x67, 0x1d, 0xe4, 0x17, 0x6e, 0x2a, 0x33, 0x07,
    0x93, 0x81, 0xae, 0xca, 0xae, 0x63, 0xda, 0x3d
};

void test_simp(void)
{
    unsigned char state[32];

    printf("SimP Permutation:\n");

    printf("    SimP[192] ... ");
    fflush(stdout);
    memcpy(state, simp_192_input, sizeof(simp_192_input));
    simp_192_permute(state, 4);
    if (!test_memcmp(state, simp_192_output, sizeof(simp_192_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    SimP[256] ... ");
    fflush(stdout);
    memcpy(state, simp_256_input, sizeof(simp_256_input));
    simp_256_permute(state, 4);
    if (!test_memcmp(state, simp_256_output, sizeof(simp_256_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
