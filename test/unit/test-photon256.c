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

#include "internal-photon256.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vector for PHOTON-256 generated with the PHOTON-Beetle reference code */
static unsigned char const photon256_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char const photon256_output[] = {
    0x25, 0x5e, 0x27, 0x0d, 0x37, 0xe9, 0x0d, 0x76,
    0xbc, 0xa8, 0x38, 0x53, 0x65, 0xba, 0xae, 0x7d,
    0x4a, 0xcc, 0x71, 0x33, 0x8f, 0x26, 0x5b, 0x0c,
    0x1b, 0x52, 0x09, 0x3f, 0x4d, 0x48, 0xee, 0xf9
};

void test_photon256(void)
{
    unsigned char state[32];

    printf("PHOTON-256 Permutation:\n");

    printf("    Test Vector ... ");
    fflush(stdout);
    memcpy(state, photon256_input, sizeof(photon256_input));
    photon256_permute(state);
    if (!test_memcmp(state, photon256_output, sizeof(photon256_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
