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

#include "internal-spongent.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for Spongent-pi generated with the Elephant reference code */
static unsigned char const spongent160_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};
static unsigned char const spongent160_output[] = {
    0x7c, 0x80, 0x0e, 0xdf, 0x9a, 0x56, 0x0d, 0xf7,
    0xcc, 0x19, 0xf1, 0xa2, 0x26, 0x2c, 0x7d, 0x73,
    0x26, 0x7b, 0xf7, 0x7b
};
static unsigned char const spongent176_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x00, 0x00 /* 2 bytes of zero padding */
};
static unsigned char const spongent176_output[] = {
    0xd2, 0x69, 0x76, 0xeb, 0x35, 0x34, 0xb5, 0x85,
    0xcd, 0xd0, 0x61, 0xe7, 0xc6, 0xe4, 0x9b, 0x5b,
    0xee, 0xd9, 0xe8, 0xd8, 0x66, 0x26
};

void test_spongent(void)
{
    spongent160_state_t state160;
    spongent176_state_t state176;

    printf("Spongent:\n");

    printf("    Spongent-pi[160] ... ");
    fflush(stdout);
    memcpy(state160.B, spongent160_input, sizeof(spongent160_input));
    spongent160_permute(&state160);
    if (!test_memcmp(state160.B, spongent160_output, sizeof(spongent160_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    Spongent-pi[176] ... ");
    fflush(stdout);
    memcpy(state176.B, spongent176_input, sizeof(spongent176_input));
    spongent176_permute(&state176);
    if (!test_memcmp(state176.B, spongent176_output, sizeof(spongent176_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
