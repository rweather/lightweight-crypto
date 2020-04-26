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

#include "internal-xoodoo.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors generated with the Xoodyak reference implementation */
static uint8_t const xoodoo_input[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static uint8_t const xoodoo_output[48] = {
    0x76, 0x33, 0xae, 0xb5, 0x5d, 0xcc, 0xbf, 0x60,
    0xd4, 0xa6, 0xdf, 0xd7, 0x50, 0x6d, 0x06, 0xbf,
    0xb2, 0xac, 0x97, 0xae, 0x97, 0x0d, 0x8a, 0xd3,
    0x13, 0x85, 0x11, 0x7b, 0xb7, 0x75, 0xa7, 0x41,
    0xb3, 0xb1, 0x54, 0x0b, 0xb5, 0x3b, 0xe9, 0x6f,
    0x3b, 0x2b, 0x8f, 0xaf, 0xa6, 0x76, 0xa3, 0xb6
};

static void test_xoodoo_permutation(void)
{
    xoodoo_state_t state;

    printf("    Permutation ... ");
    fflush(stdout);

    memcpy(state.B, xoodoo_input, sizeof(xoodoo_input));
    xoodoo_permute(&state);
    if (memcmp(state.B, xoodoo_output, sizeof(xoodoo_output)) != 0) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
}

void test_xoodoo(void)
{
    printf("Xoodoo:\n");
    test_xoodoo_permutation();
    printf("\n");
}
