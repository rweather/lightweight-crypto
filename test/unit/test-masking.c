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

#include "internal-masking.h"
#include "test-cipher.h"
#include <stdio.h>

/* Test the 2-share version of masked words */
#define MASK_NAME(a, b) a##_x2_##b
#define mask_test_uint16_t mask_x2_uint16_t
#define mask_test_uint32_t mask_x2_uint32_t
#define mask_test_uint64_t mask_x2_uint64_t
#define mask_test_input(a, b) mask_x2_input((a), (b))
#define mask_test_output(a) mask_x2_output((a))
#define mask_test_xor_const(a, b) mask_x2_xor_const((a), (b))
#define mask_test_xor(a, b) mask_x2_xor((a), (b))
#define mask_test_not(a) mask_x2_not((a))
#define mask_test_and(a, b, c) mask_x2_and((a), (b), (c))
#define mask_test_or(a, b, c) mask_x2_or((a), (b), (c))
#define mask_test_shl(a, b, c) mask_x2_shl((a), (b), (c))
#define mask_test_shr(a, b, c) mask_x2_shr((a), (b), (c))
#define mask_test_rol(a, b, c) mask_x2_rol((a), (b), (c))
#define mask_test_ror(a, b, c) mask_x2_ror((a), (b), (c))
#include "test-masking-common.c"
#undef MASK_NAME
#undef mask_test_uint16_t
#undef mask_test_uint32_t
#undef mask_test_uint64_t
#undef mask_test_input
#undef mask_test_output
#undef mask_test_xor_const
#undef mask_test_xor
#undef mask_test_not
#undef mask_test_and
#undef mask_test_or
#undef mask_test_shl
#undef mask_test_shr
#undef mask_test_rol
#undef mask_test_ror

/* Test the 3-share version of masked words */
#define MASK_NAME(a, b) a##_x3_##b
#define mask_test_uint16_t mask_x3_uint16_t
#define mask_test_uint32_t mask_x3_uint32_t
#define mask_test_uint64_t mask_x3_uint64_t
#define mask_test_input(a, b) mask_x3_input((a), (b))
#define mask_test_output(a) mask_x3_output((a))
#define mask_test_xor_const(a, b) mask_x3_xor_const((a), (b))
#define mask_test_xor(a, b) mask_x3_xor((a), (b))
#define mask_test_not(a) mask_x3_not((a))
#define mask_test_and(a, b, c) mask_x3_and((a), (b), (c))
#define mask_test_or(a, b, c) mask_x3_or((a), (b), (c))
#define mask_test_shl(a, b, c) mask_x3_shl((a), (b), (c))
#define mask_test_shr(a, b, c) mask_x3_shr((a), (b), (c))
#define mask_test_rol(a, b, c) mask_x3_rol((a), (b), (c))
#define mask_test_ror(a, b, c) mask_x3_ror((a), (b), (c))
#include "test-masking-common.c"
#undef MASK_NAME
#undef mask_test_uint16_t
#undef mask_test_uint32_t
#undef mask_test_uint64_t
#undef mask_test_input
#undef mask_test_output
#undef mask_test_xor_const
#undef mask_test_xor
#undef mask_test_not
#undef mask_test_and
#undef mask_test_or
#undef mask_test_shl
#undef mask_test_shr
#undef mask_test_rol
#undef mask_test_ror

/* Test the 4-share version of masked words */
#define MASK_NAME(a, b) a##_x4_##b
#define mask_test_uint16_t mask_x4_uint16_t
#define mask_test_uint32_t mask_x4_uint32_t
#define mask_test_uint64_t mask_x4_uint64_t
#define mask_test_input(a, b) mask_x4_input((a), (b))
#define mask_test_output(a) mask_x4_output((a))
#define mask_test_xor_const(a, b) mask_x4_xor_const((a), (b))
#define mask_test_xor(a, b) mask_x4_xor((a), (b))
#define mask_test_not(a) mask_x4_not((a))
#define mask_test_and(a, b, c) mask_x4_and((a), (b), (c))
#define mask_test_or(a, b, c) mask_x4_or((a), (b), (c))
#define mask_test_shl(a, b, c) mask_x4_shl((a), (b), (c))
#define mask_test_shr(a, b, c) mask_x4_shr((a), (b), (c))
#define mask_test_rol(a, b, c) mask_x4_rol((a), (b), (c))
#define mask_test_ror(a, b, c) mask_x4_ror((a), (b), (c))
#include "test-masking-common.c"
#undef MASK_NAME
#undef mask_test_uint16_t
#undef mask_test_uint32_t
#undef mask_test_uint64_t
#undef mask_test_input
#undef mask_test_output
#undef mask_test_xor_const
#undef mask_test_xor
#undef mask_test_not
#undef mask_test_and
#undef mask_test_or
#undef mask_test_shl
#undef mask_test_shr
#undef mask_test_rol
#undef mask_test_ror

/* Test the 5-share version of masked words */
#define MASK_NAME(a, b) a##_x5_##b
#define mask_test_uint16_t mask_x5_uint16_t
#define mask_test_uint32_t mask_x5_uint32_t
#define mask_test_uint64_t mask_x5_uint64_t
#define mask_test_input(a, b) mask_x5_input((a), (b))
#define mask_test_output(a) mask_x5_output((a))
#define mask_test_xor_const(a, b) mask_x5_xor_const((a), (b))
#define mask_test_xor(a, b) mask_x5_xor((a), (b))
#define mask_test_not(a) mask_x5_not((a))
#define mask_test_and(a, b, c) mask_x5_and((a), (b), (c))
#define mask_test_or(a, b, c) mask_x5_or((a), (b), (c))
#define mask_test_shl(a, b, c) mask_x5_shl((a), (b), (c))
#define mask_test_shr(a, b, c) mask_x5_shr((a), (b), (c))
#define mask_test_rol(a, b, c) mask_x5_rol((a), (b), (c))
#define mask_test_ror(a, b, c) mask_x5_ror((a), (b), (c))
#include "test-masking-common.c"
#undef MASK_NAME
#undef mask_test_uint16_t
#undef mask_test_uint32_t
#undef mask_test_uint64_t
#undef mask_test_input
#undef mask_test_output
#undef mask_test_xor_const
#undef mask_test_xor
#undef mask_test_not
#undef mask_test_and
#undef mask_test_or
#undef mask_test_shl
#undef mask_test_shr
#undef mask_test_rol
#undef mask_test_ror

/* Test the 6-share version of masked words */
#define MASK_NAME(a, b) a##_x6_##b
#define mask_test_uint16_t mask_x6_uint16_t
#define mask_test_uint32_t mask_x6_uint32_t
#define mask_test_uint64_t mask_x6_uint64_t
#define mask_test_input(a, b) mask_x6_input((a), (b))
#define mask_test_output(a) mask_x6_output((a))
#define mask_test_xor_const(a, b) mask_x6_xor_const((a), (b))
#define mask_test_xor(a, b) mask_x6_xor((a), (b))
#define mask_test_not(a) mask_x6_not((a))
#define mask_test_and(a, b, c) mask_x6_and((a), (b), (c))
#define mask_test_or(a, b, c) mask_x6_or((a), (b), (c))
#define mask_test_shl(a, b, c) mask_x6_shl((a), (b), (c))
#define mask_test_shr(a, b, c) mask_x6_shr((a), (b), (c))
#define mask_test_rol(a, b, c) mask_x6_rol((a), (b), (c))
#define mask_test_ror(a, b, c) mask_x6_ror((a), (b), (c))
#include "test-masking-common.c"
#undef MASK_NAME
#undef mask_test_uint16_t
#undef mask_test_uint32_t
#undef mask_test_uint64_t
#undef mask_test_input
#undef mask_test_output
#undef mask_test_xor_const
#undef mask_test_xor
#undef mask_test_not
#undef mask_test_and
#undef mask_test_or
#undef mask_test_shl
#undef mask_test_shr
#undef mask_test_rol
#undef mask_test_ror

/* Test the generic-share version of masked words */
#define MASK_NAME(a, b) a##_generic_##b
#define mask_test_uint16_t mask_uint16_t
#define mask_test_uint32_t mask_uint32_t
#define mask_test_uint64_t mask_uint64_t
#define mask_test_input(a, b) mask_input((a), (b))
#define mask_test_output(a) mask_output((a))
#define mask_test_xor_const(a, b) mask_xor_const((a), (b))
#define mask_test_xor(a, b) mask_xor((a), (b))
#define mask_test_not(a) mask_not((a))
#define mask_test_and(a, b, c) mask_and((a), (b), (c))
#define mask_test_or(a, b, c) mask_or((a), (b), (c))
#define mask_test_shl(a, b, c) mask_shl((a), (b), (c))
#define mask_test_shr(a, b, c) mask_shr((a), (b), (c))
#define mask_test_rol(a, b, c) mask_rol((a), (b), (c))
#define mask_test_ror(a, b, c) mask_ror((a), (b), (c))
#include "test-masking-common.c"
#undef MASK_NAME
#undef mask_test_uint16_t
#undef mask_test_uint32_t
#undef mask_test_uint64_t
#undef mask_test_input
#undef mask_test_output
#undef mask_test_xor_const
#undef mask_test_xor
#undef mask_test_not
#undef mask_test_and
#undef mask_test_or
#undef mask_test_shl
#undef mask_test_shr
#undef mask_test_rol
#undef mask_test_ror

/* ------------------ high-level test harness ------------------ */

/* Runs a masking test function multiple times because we'll get
 * different random numbers each time.  This should expose any
 * issues in the implementation over repeated test runs. */
static void test_masking_run(const char *name, int (*func)(void))
{
    int count;
    printf("    %s ... ", name);
    fflush(stdout);
    for (count = 0; count < 100; ++count) {
        if (!(*func)()) {
            printf("failed\n");
            test_exit_result = 1;
            return;
        }
    }
    printf("ok\n");
}

void test_masking(void)
{
    printf("Masking Utilities:\n");
    aead_masking_init();

    test_masking_run("uint16-x2-load", test_uint16_x2_load);
    test_masking_run("uint32-x2-load", test_uint32_x2_load);
    test_masking_run("uint64-x2-load", test_uint64_x2_load);
    test_masking_run("uint16-x2-add-const", test_uint16_x2_xor_const);
    test_masking_run("uint32-x2-add-const", test_uint32_x2_xor_const);
    test_masking_run("uint64-x2-add-const", test_uint64_x2_xor_const);
    test_masking_run("uint16-x2-xor", test_uint16_x2_xor);
    test_masking_run("uint32-x2-xor", test_uint32_x2_xor);
    test_masking_run("uint64-x2-xor", test_uint64_x2_xor);
    test_masking_run("uint16-x2-not", test_uint16_x2_not);
    test_masking_run("uint32-x2-not", test_uint32_x2_not);
    test_masking_run("uint64-x2-not", test_uint64_x2_not);
    test_masking_run("uint16-x2-and", test_uint16_x2_and);
    test_masking_run("uint32-x2-and", test_uint32_x2_and);
    test_masking_run("uint64-x2-and", test_uint64_x2_and);
    test_masking_run("uint16-x2-or", test_uint16_x2_or);
    test_masking_run("uint32-x2-or", test_uint32_x2_or);
    test_masking_run("uint64-x2-or", test_uint64_x2_or);
    test_masking_run("uint16-x2-shl", test_uint16_x2_shl);
    test_masking_run("uint32-x2-shl", test_uint32_x2_shl);
    test_masking_run("uint64-x2-shl", test_uint64_x2_shl);
    test_masking_run("uint16-x2-shr", test_uint16_x2_shr);
    test_masking_run("uint32-x2-shr", test_uint32_x2_shr);
    test_masking_run("uint64-x2-shr", test_uint64_x2_shr);
    test_masking_run("uint16-x2-rol", test_uint16_x2_rol);
    test_masking_run("uint32-x2-rol", test_uint32_x2_rol);
    test_masking_run("uint64-x2-rol", test_uint64_x2_rol);
    test_masking_run("uint16-x2-ror", test_uint16_x2_ror);
    test_masking_run("uint32-x2-ror", test_uint32_x2_ror);
    test_masking_run("uint64-x2-ror", test_uint64_x2_ror);

    test_masking_run("uint16-x3-load", test_uint16_x3_load);
    test_masking_run("uint32-x3-load", test_uint32_x3_load);
    test_masking_run("uint64-x3-load", test_uint64_x3_load);
    test_masking_run("uint16-x3-add-const", test_uint16_x3_xor_const);
    test_masking_run("uint32-x3-add-const", test_uint32_x3_xor_const);
    test_masking_run("uint64-x3-add-const", test_uint64_x3_xor_const);
    test_masking_run("uint16-x3-xor", test_uint16_x3_xor);
    test_masking_run("uint32-x3-xor", test_uint32_x3_xor);
    test_masking_run("uint64-x3-xor", test_uint64_x3_xor);
    test_masking_run("uint16-x3-not", test_uint16_x3_not);
    test_masking_run("uint32-x3-not", test_uint32_x3_not);
    test_masking_run("uint64-x3-not", test_uint64_x3_not);
    test_masking_run("uint16-x3-and", test_uint16_x3_and);
    test_masking_run("uint32-x3-and", test_uint32_x3_and);
    test_masking_run("uint64-x3-and", test_uint64_x3_and);
    test_masking_run("uint16-x3-or", test_uint16_x3_or);
    test_masking_run("uint32-x3-or", test_uint32_x3_or);
    test_masking_run("uint64-x3-or", test_uint64_x3_or);
    test_masking_run("uint16-x3-shl", test_uint16_x3_shl);
    test_masking_run("uint32-x3-shl", test_uint32_x3_shl);
    test_masking_run("uint64-x3-shl", test_uint64_x3_shl);
    test_masking_run("uint16-x3-shr", test_uint16_x3_shr);
    test_masking_run("uint32-x3-shr", test_uint32_x3_shr);
    test_masking_run("uint64-x3-shr", test_uint64_x3_shr);
    test_masking_run("uint16-x3-rol", test_uint16_x3_rol);
    test_masking_run("uint32-x3-rol", test_uint32_x3_rol);
    test_masking_run("uint64-x3-rol", test_uint64_x3_rol);
    test_masking_run("uint16-x3-ror", test_uint16_x3_ror);
    test_masking_run("uint32-x3-ror", test_uint32_x3_ror);
    test_masking_run("uint64-x3-ror", test_uint64_x3_ror);

    test_masking_run("uint16-x4-load", test_uint16_x4_load);
    test_masking_run("uint32-x4-load", test_uint32_x4_load);
    test_masking_run("uint64-x4-load", test_uint64_x4_load);
    test_masking_run("uint16-x4-add-const", test_uint16_x4_xor_const);
    test_masking_run("uint32-x4-add-const", test_uint32_x4_xor_const);
    test_masking_run("uint64-x4-add-const", test_uint64_x4_xor_const);
    test_masking_run("uint16-x4-xor", test_uint16_x4_xor);
    test_masking_run("uint32-x4-xor", test_uint32_x4_xor);
    test_masking_run("uint64-x4-xor", test_uint64_x4_xor);
    test_masking_run("uint16-x4-not", test_uint16_x4_not);
    test_masking_run("uint32-x4-not", test_uint32_x4_not);
    test_masking_run("uint64-x4-not", test_uint64_x4_not);
    test_masking_run("uint16-x4-and", test_uint16_x4_and);
    test_masking_run("uint32-x4-and", test_uint32_x4_and);
    test_masking_run("uint64-x4-and", test_uint64_x4_and);
    test_masking_run("uint16-x4-or", test_uint16_x4_or);
    test_masking_run("uint32-x4-or", test_uint32_x4_or);
    test_masking_run("uint64-x4-or", test_uint64_x4_or);
    test_masking_run("uint16-x4-shl", test_uint16_x4_shl);
    test_masking_run("uint32-x4-shl", test_uint32_x4_shl);
    test_masking_run("uint64-x4-shl", test_uint64_x4_shl);
    test_masking_run("uint16-x4-shr", test_uint16_x4_shr);
    test_masking_run("uint32-x4-shr", test_uint32_x4_shr);
    test_masking_run("uint64-x4-shr", test_uint64_x4_shr);
    test_masking_run("uint16-x4-rol", test_uint16_x4_rol);
    test_masking_run("uint32-x4-rol", test_uint32_x4_rol);
    test_masking_run("uint64-x4-rol", test_uint64_x4_rol);
    test_masking_run("uint16-x4-ror", test_uint16_x4_ror);
    test_masking_run("uint32-x4-ror", test_uint32_x4_ror);
    test_masking_run("uint64-x4-ror", test_uint64_x4_ror);

    test_masking_run("uint16-x5-load", test_uint16_x5_load);
    test_masking_run("uint32-x5-load", test_uint32_x5_load);
    test_masking_run("uint64-x5-load", test_uint64_x5_load);
    test_masking_run("uint16-x5-add-const", test_uint16_x5_xor_const);
    test_masking_run("uint32-x5-add-const", test_uint32_x5_xor_const);
    test_masking_run("uint64-x5-add-const", test_uint64_x5_xor_const);
    test_masking_run("uint16-x5-xor", test_uint16_x5_xor);
    test_masking_run("uint32-x5-xor", test_uint32_x5_xor);
    test_masking_run("uint64-x5-xor", test_uint64_x5_xor);
    test_masking_run("uint16-x5-not", test_uint16_x5_not);
    test_masking_run("uint32-x5-not", test_uint32_x5_not);
    test_masking_run("uint64-x5-not", test_uint64_x5_not);
    test_masking_run("uint16-x5-and", test_uint16_x5_and);
    test_masking_run("uint32-x5-and", test_uint32_x5_and);
    test_masking_run("uint64-x5-and", test_uint64_x5_and);
    test_masking_run("uint16-x5-or", test_uint16_x5_or);
    test_masking_run("uint32-x5-or", test_uint32_x5_or);
    test_masking_run("uint64-x5-or", test_uint64_x5_or);
    test_masking_run("uint16-x5-shl", test_uint16_x5_shl);
    test_masking_run("uint32-x5-shl", test_uint32_x5_shl);
    test_masking_run("uint64-x5-shl", test_uint64_x5_shl);
    test_masking_run("uint16-x5-shr", test_uint16_x5_shr);
    test_masking_run("uint32-x5-shr", test_uint32_x5_shr);
    test_masking_run("uint64-x5-shr", test_uint64_x5_shr);
    test_masking_run("uint16-x5-rol", test_uint16_x5_rol);
    test_masking_run("uint32-x5-rol", test_uint32_x5_rol);
    test_masking_run("uint64-x5-rol", test_uint64_x5_rol);
    test_masking_run("uint16-x5-ror", test_uint16_x5_ror);
    test_masking_run("uint32-x5-ror", test_uint32_x5_ror);
    test_masking_run("uint64-x5-ror", test_uint64_x5_ror);

    test_masking_run("uint16-x6-load", test_uint16_x6_load);
    test_masking_run("uint32-x6-load", test_uint32_x6_load);
    test_masking_run("uint64-x6-load", test_uint64_x6_load);
    test_masking_run("uint16-x6-add-const", test_uint16_x6_xor_const);
    test_masking_run("uint32-x6-add-const", test_uint32_x6_xor_const);
    test_masking_run("uint64-x6-add-const", test_uint64_x6_xor_const);
    test_masking_run("uint16-x6-xor", test_uint16_x6_xor);
    test_masking_run("uint32-x6-xor", test_uint32_x6_xor);
    test_masking_run("uint64-x6-xor", test_uint64_x6_xor);
    test_masking_run("uint16-x6-not", test_uint16_x6_not);
    test_masking_run("uint32-x6-not", test_uint32_x6_not);
    test_masking_run("uint64-x6-not", test_uint64_x6_not);
    test_masking_run("uint16-x6-and", test_uint16_x6_and);
    test_masking_run("uint32-x6-and", test_uint32_x6_and);
    test_masking_run("uint64-x6-and", test_uint64_x6_and);
    test_masking_run("uint16-x6-or", test_uint16_x6_or);
    test_masking_run("uint32-x6-or", test_uint32_x6_or);
    test_masking_run("uint64-x6-or", test_uint64_x6_or);
    test_masking_run("uint16-x6-shl", test_uint16_x6_shl);
    test_masking_run("uint32-x6-shl", test_uint32_x6_shl);
    test_masking_run("uint64-x6-shl", test_uint64_x6_shl);
    test_masking_run("uint16-x6-shr", test_uint16_x6_shr);
    test_masking_run("uint32-x6-shr", test_uint32_x6_shr);
    test_masking_run("uint64-x6-shr", test_uint64_x6_shr);
    test_masking_run("uint16-x6-rol", test_uint16_x6_rol);
    test_masking_run("uint32-x6-rol", test_uint32_x6_rol);
    test_masking_run("uint64-x6-rol", test_uint64_x6_rol);
    test_masking_run("uint16-x6-ror", test_uint16_x6_ror);
    test_masking_run("uint32-x6-ror", test_uint32_x6_ror);
    test_masking_run("uint64-x6-ror", test_uint64_x6_ror);

    test_masking_run("uint16-generic-load", test_uint16_generic_load);
    test_masking_run("uint32-generic-load", test_uint32_generic_load);
    test_masking_run("uint64-generic-load", test_uint64_generic_load);
    test_masking_run("uint16-generic-add-const", test_uint16_generic_xor_const);
    test_masking_run("uint32-generic-add-const", test_uint32_generic_xor_const);
    test_masking_run("uint64-generic-add-const", test_uint64_generic_xor_const);
    test_masking_run("uint16-generic-xor", test_uint16_generic_xor);
    test_masking_run("uint32-generic-xor", test_uint32_generic_xor);
    test_masking_run("uint64-generic-xor", test_uint64_generic_xor);
    test_masking_run("uint16-generic-not", test_uint16_generic_not);
    test_masking_run("uint32-generic-not", test_uint32_generic_not);
    test_masking_run("uint64-generic-not", test_uint64_generic_not);
    test_masking_run("uint16-generic-and", test_uint16_generic_and);
    test_masking_run("uint32-generic-and", test_uint32_generic_and);
    test_masking_run("uint64-generic-and", test_uint64_generic_and);
    test_masking_run("uint16-generic-or", test_uint16_generic_or);
    test_masking_run("uint32-generic-or", test_uint32_generic_or);
    test_masking_run("uint64-generic-or", test_uint64_generic_or);
    test_masking_run("uint16-generic-shl", test_uint16_generic_shl);
    test_masking_run("uint32-generic-shl", test_uint32_generic_shl);
    test_masking_run("uint64-generic-shl", test_uint64_generic_shl);
    test_masking_run("uint16-generic-shr", test_uint16_generic_shr);
    test_masking_run("uint32-generic-shr", test_uint32_generic_shr);
    test_masking_run("uint64-generic-shr", test_uint64_generic_shr);
    test_masking_run("uint16-generic-rol", test_uint16_generic_rol);
    test_masking_run("uint32-generic-rol", test_uint32_generic_rol);
    test_masking_run("uint64-generic-rol", test_uint64_generic_rol);
    test_masking_run("uint16-generic-ror", test_uint16_generic_ror);
    test_masking_run("uint32-generic-ror", test_uint32_generic_ror);
    test_masking_run("uint64-generic-ror", test_uint64_generic_ror);

    printf("\n");
}
