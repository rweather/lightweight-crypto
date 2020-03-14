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

#include "internal-blake2s.h"
#include "test-cipher.h"
#include <stdio.h>
#include <string.h>

#define HASH_SIZE 32
#define BLOCK_SIZE 64

typedef struct
{
    const char *name;
    const char *data;
    uint8_t hash[HASH_SIZE];

} TestHashVector;

// Test vectors generated with the reference implementation of BLAKE2s.
static TestHashVector const testVectorBLAKE2s_1 = {
    "Test Vector 1",
    "",
    {0x69, 0x21, 0x7a, 0x30, 0x79, 0x90, 0x80, 0x94,
     0xe1, 0x11, 0x21, 0xd0, 0x42, 0x35, 0x4a, 0x7c,
     0x1f, 0x55, 0xb6, 0x48, 0x2c, 0xa1, 0xa5, 0x1e,
     0x1b, 0x25, 0x0d, 0xfd, 0x1e, 0xd0, 0xee, 0xf9}
};
static TestHashVector const testVectorBLAKE2s_2 = {
    "Test Vector 2",
    "abc",
    {0x50, 0x8c, 0x5e, 0x8c, 0x32, 0x7c, 0x14, 0xe2,
     0xe1, 0xa7, 0x2b, 0xa3, 0x4e, 0xeb, 0x45, 0x2f,
     0x37, 0x45, 0x8b, 0x20, 0x9e, 0xd6, 0x3a, 0x29,
     0x4d, 0x99, 0x9b, 0x4c, 0x86, 0x67, 0x59, 0x82}
};
static TestHashVector const testVectorBLAKE2s_3 = {
    "Test Vector 3",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    {0x6f, 0x4d, 0xf5, 0x11, 0x6a, 0x6f, 0x33, 0x2e,
     0xda, 0xb1, 0xd9, 0xe1, 0x0e, 0xe8, 0x7d, 0xf6,
     0x55, 0x7b, 0xea, 0xb6, 0x25, 0x9d, 0x76, 0x63,
     0xf3, 0xbc, 0xd5, 0x72, 0x2c, 0x13, 0xf1, 0x89}
};
static TestHashVector const testVectorBLAKE2s_4 = {
    "Test Vector 4",
    "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn"
    "hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
    {0x35, 0x8d, 0xd2, 0xed, 0x07, 0x80, 0xd4, 0x05,
     0x4e, 0x76, 0xcb, 0x6f, 0x3a, 0x5b, 0xce, 0x28,
     0x41, 0xe8, 0xe2, 0xf5, 0x47, 0x43, 0x1d, 0x4d,
     0x09, 0xdb, 0x21, 0xb6, 0x6d, 0x94, 0x1f, 0xc7}
};

static int test_blake2s_vector_inner(const TestHashVector *test_vector)
{
    unsigned char out[HASH_SIZE];
    int result;
    memset(out, 0xAA, sizeof(out));
    result = internal_blake2s_hash
        (out, (unsigned char *)(test_vector->data),
         strlen(test_vector->data));
    if (result != 0 || test_memcmp(out, test_vector->hash, HASH_SIZE) != 0)
        return 0;
    return 1;
}

static void test_blake2s_vector(const TestHashVector *test_vector)
{
    printf("    %s ... ", test_vector->name);
    fflush(stdout);

    if (test_blake2s_vector_inner(test_vector)) {
        printf("ok\n");
    } else {
        printf("failed\n");
        test_exit_result = 1;
    }
}

void test_blake2s(void)
{
    printf("BLAKE2s:\n");
    test_blake2s_vector(&testVectorBLAKE2s_1);
    test_blake2s_vector(&testVectorBLAKE2s_2);
    test_blake2s_vector(&testVectorBLAKE2s_3);
    test_blake2s_vector(&testVectorBLAKE2s_4);
    printf("\n");
}
