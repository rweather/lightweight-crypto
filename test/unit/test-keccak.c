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

#include "internal-keccak.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Keccak-p[200] test vectors generated with the reference implementation */
static unsigned char keccakp_200_in[25] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18
};
static unsigned char keccakp_200_out[25] = {
    0x7f, 0x03, 0x40, 0xbd, 0x5e, 0xf9, 0xa9, 0xce,
    0x6c, 0x77, 0xd1, 0x41, 0xea, 0x91, 0x23, 0x77,
    0x2d, 0x83, 0xf0, 0x40, 0xbf, 0x23, 0x1c, 0xa5,
    0x1c
};

/* Keccak-p[400] test vectors generated with the reference implementation */
#define keccakp_400_rounds 20
static unsigned char keccakp_400_in[50] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31
};
static unsigned char keccakp_400_out[50] = {
    0x4f, 0x12, 0x06, 0x0e, 0x11, 0x27, 0x48, 0x1e,
    0x58, 0xdf, 0x3c, 0x9f, 0xef, 0x2e, 0x02, 0xaf,
    0xf4, 0xfc, 0x03, 0xd8, 0x32, 0x95, 0x7a, 0x54,
    0xac, 0xbc, 0xbe, 0x22, 0x51, 0x4e, 0x5c, 0xcb,
    0x0f, 0x58, 0x95, 0xdd, 0x1f, 0x37, 0xe8, 0x3a,
    0x23, 0x49, 0x82, 0x2c, 0xde, 0x5c, 0xaa, 0x77,
    0x7d, 0x54
};

static void test_keccakp_200(void)
{
    keccakp_200_state_t state;
    printf("    Keccak-p[200] ... ");
    memcpy(state.B, keccakp_200_in, sizeof(keccakp_200_in));
    keccakp_200_permute(&state);
    if (test_memcmp(state.B, keccakp_200_out, sizeof(keccakp_200_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

static void test_keccakp_400(void)
{
    keccakp_400_state_t state;
    printf("    Keccak-p[400] ... ");
    memcpy(state.B, keccakp_400_in, sizeof(keccakp_400_in));
    keccakp_400_permute(&state, keccakp_400_rounds);
    if (test_memcmp(state.B, keccakp_400_out, sizeof(keccakp_400_out))) {
        printf("failed\n");
        test_exit_result = 1;
    } else {
        printf("ok\n");
    }
    fflush(stdout);
}

void test_keccak(void)
{
    printf("Keccak:\n");
    test_keccakp_200();
    test_keccakp_400();
    printf("\n");
}
