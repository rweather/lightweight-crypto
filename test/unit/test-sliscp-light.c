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

#include "internal-sliscp-light.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

/* Test vectors for sLiSCP-light from the SpoC specification */
static unsigned char const sliscp192_output[] = {
    0x2d, 0xca, 0xca, 0x34, 0x66, 0xfa, 0x12, 0x6d,
    0x47, 0xf0, 0xe1, 0x42, 0x29, 0xa1, 0x1a, 0x0b,
    0x5d, 0x4c, 0x7f, 0x70, 0x2d, 0x8a, 0x46, 0x4d
};
static unsigned char const sliscp256_output[] = {
    0xc1, 0x4f, 0xd3, 0x2f, 0xdd, 0x8c, 0x4f, 0x91,
    0x3d, 0x7c, 0xd3, 0x7c, 0xe4, 0xc0, 0xfc, 0x40,
    0x47, 0x57, 0x72, 0x47, 0xa9, 0x07, 0xf4, 0x6a,
    0xb9, 0x29, 0x67, 0x03, 0xc6, 0x78, 0x8a, 0x4c
};

/* Test vector for sLiSCP-light-320 from the ACE specification */
static unsigned char const sliscp320_output[] = {
    0x5c, 0x93, 0x69, 0x1a, 0xd5, 0x06, 0x09, 0x35,
    0xdc, 0x19, 0xce, 0x94, 0x7e, 0xad, 0x55, 0x0d,
    0xac, 0x12, 0xbe, 0xe1, 0xa6, 0x4b, 0x67, 0x0e,
    0xf5, 0x16, 0xe8, 0xbe, 0x1d, 0xfa, 0x60, 0xda,
    0x40, 0x98, 0x92, 0xa4, 0xe4, 0xcc, 0xbc, 0x15
};

void test_sliscp_light(void)
{
    unsigned char state[40];

    printf("sLiSCP-light Permutation:\n");

    printf("    SLiSCP-light[192] ... ");
    fflush(stdout);
    memset(state, 0, sizeof(state));
    sliscp_light192_permute(state);
    if (!test_memcmp(state, sliscp192_output, sizeof(sliscp192_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    SLiSCP-light-SPIX[256] ... ");
    fflush(stdout);
    memset(state, 0, sizeof(state));
    sliscp_light256_swap_spix(state);
    sliscp_light256_permute_spix(state, 18);
    sliscp_light256_swap_spix(state);
    if (!test_memcmp(state, sliscp256_output, sizeof(sliscp256_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    SLiSCP-light-SpoC[256] ... ");
    fflush(stdout);
    memset(state, 0, sizeof(state));
    sliscp_light256_swap_spoc(state);
    sliscp_light256_permute_spoc(state, 18);
    sliscp_light256_swap_spoc(state);
    if (!test_memcmp(state, sliscp256_output, sizeof(sliscp256_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("    SLiSCP-light-ACE[320] ... ");
    fflush(stdout);
    memset(state, 0, sizeof(state));
    sliscp_light320_swap(state);
    sliscp_light320_permute(state);
    sliscp_light320_swap(state);
    if (!test_memcmp(state, sliscp320_output, sizeof(sliscp320_output))) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }

    printf("\n");
}
