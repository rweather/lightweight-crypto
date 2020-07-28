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

/* This file is included multiple times from test-masking.c to test all
 * of the sharing variants from internal-masking.h (x2, x4, ...) */

#if defined(mask_test_uint16_t)

/* ---------- tests for masked 16-bit words ---------- */

/* Test loading and unloading a masked 16-bit word */
static int MASK_NAME(test_uint16, load)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w;
    mask_test_input(w, x);
    return mask_test_output(w) == x;
}

/* Test adding a constant to a masked 16-bit word */
static int MASK_NAME(test_uint16, xor_const)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w;
    mask_test_input(w, x);
    mask_test_xor_const(w, y);
    return mask_test_output(w) == (x ^ y);
}

/* Test XOR'ing two masked 16-bit words */
static int MASK_NAME(test_uint16, xor)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_xor(w1, w2);
    return mask_test_output(w1) == (x ^ y) && mask_test_output(w2) == y;
}

/* Test XOR'ing three masked 16-bit words */
static int MASK_NAME(test_uint16, xor3)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    uint16_t z = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_uint16_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_xor3(w1, w2, w3);
    return mask_test_output(w1) == (x ^ y ^ z) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test NOT'ing a masked 16-bit word */
static int MASK_NAME(test_uint16, not)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w;
    mask_test_input(w, x);
    mask_test_not(w);
    return mask_test_output(w) == (uint16_t)(~x);
}

/* Test AND'ing two masked 16-bit words */
static int MASK_NAME(test_uint16, and)(void)
{
    uint16_t temp;
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    uint16_t z = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_uint16_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_and(w1, w2, w3);
    return mask_test_output(w1) == (x ^ (y & z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test AND'ing two masked 16-bit words where one of them is NOT'ed */
static int MASK_NAME(test_uint16, and_not)(void)
{
    uint16_t temp;
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    uint16_t z = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_uint16_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_and_not(w1, w2, w3);
    return mask_test_output(w1) == (x ^ ((~y) & z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test OR'ing two masked 16-bit words */
static int MASK_NAME(test_uint16, or)(void)
{
    uint16_t temp;
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    uint16_t z = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_uint16_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_or(w1, w2, w3);
    return mask_test_output(w1) == (x ^ (y | z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test left shifting a masked 16-bit word */
static int MASK_NAME(test_uint16, shl)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w2, x);
    mask_test_shl(w1, w2, 5);
    if (mask_test_output(w1) != (uint16_t)(x << 5))
        return 0;
    mask_test_input(w2, x);
    mask_test_shl(w2, w2, 1);
    return mask_test_output(w2) == (uint16_t)(x << 1);
}

/* Test right shifting a masked 16-bit word */
static int MASK_NAME(test_uint16, shr)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w2, x);
    mask_test_shr(w1, w2, 5);
    if (mask_test_output(w1) != (uint16_t)(x >> 5))
        return 0;
    mask_test_input(w2, x);
    mask_test_shr(w2, w2, 1);
    return mask_test_output(w2) == (uint16_t)(x >> 1);
}

/* Test left rotating a masked 16-bit word */
static int MASK_NAME(test_uint16, rol)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w2, x);
    mask_test_rol(w1, w2, 5);
    if (mask_test_output(w1) != (uint16_t)((x << 5) | (x >> 11)))
        return 0;
    mask_test_input(w2, x);
    mask_test_rol(w2, w2, 1);
    return mask_test_output(w2) == (uint16_t)((x << 1) | (x >> 15));
}

/* Test right rotating a masked 16-bit word */
static int MASK_NAME(test_uint16, ror)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w2, x);
    mask_test_ror(w1, w2, 5);
    if (mask_test_output(w1) != (uint16_t)((x >> 5) | (x << 11)))
        return 0;
    mask_test_input(w2, x);
    mask_test_ror(w2, w2, 1);
    return mask_test_output(w2) == (uint16_t)((x >> 1) | (x << 15));
}

/* Test swapping two masked 16-bit words */
static int MASK_NAME(test_uint16, swap)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_swap(w1, w2);
    return mask_test_output(w1) == y && mask_test_output(w2) == x;
}

/* Test a swap and move on two masked 16-bit words */
static int MASK_NAME(test_uint16, swap_move)(void)
{
    uint16_t x = (uint16_t)aead_masking_generate_32();
    uint16_t y = (uint16_t)aead_masking_generate_32();
    uint16_t temp;
    mask_test_uint16_t w1;
    mask_test_uint16_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_swap_move(w1, w2, 0x5555, 1);
    mask_swap_move_internal(x, y, 0x5555, 1);
    return mask_test_output(w1) == x && mask_test_output(w2) == y;
}

/* ---------- tests for masked 32-bit words ---------- */

/* Test loading and unloading a masked 32-bit word */
static int MASK_NAME(test_uint32, load)(void)
{
    uint32_t x = aead_masking_generate_32();
    mask_test_uint32_t w;
    mask_test_input(w, x);
    return mask_test_output(w) == x;
}

/* Test adding a constant to a masked 32-bit word */
static int MASK_NAME(test_uint32, xor_const)(void)
{
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    mask_test_uint32_t w;
    mask_test_input(w, x);
    mask_test_xor_const(w, y);
    return mask_test_output(w) == (x ^ y);
}

/* Test XOR'ing two masked 32-bit words */
static int MASK_NAME(test_uint32, xor)(void)
{
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_xor(w1, w2);
    return mask_test_output(w1) == (x ^ y) && mask_test_output(w2) == y;
}

/* Test XOR'ing three masked 32-bit words */
static int MASK_NAME(test_uint32, xor3)(void)
{
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    uint32_t z = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_uint32_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_xor3(w1, w2, w3);
    return mask_test_output(w1) == (x ^ y ^ z) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test NOT'ing a masked 32-bit word */
static int MASK_NAME(test_uint32, not)(void)
{
    uint32_t x = aead_masking_generate_32();
    mask_test_uint32_t w;
    mask_test_input(w, x);
    mask_test_not(w);
    return mask_test_output(w) == (~x);
}

/* Test AND'ing two masked 32-bit words */
static int MASK_NAME(test_uint32, and)(void)
{
    uint32_t temp;
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    uint32_t z = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_uint32_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_and(w1, w2, w3);
    return mask_test_output(w1) == (x ^ (y & z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test AND'ing two masked 32-bit words where one of them is NOT'ed */
static int MASK_NAME(test_uint32, and_not)(void)
{
    uint32_t temp;
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    uint32_t z = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_uint32_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_and_not(w1, w2, w3);
    return mask_test_output(w1) == (x ^ ((~y) & z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test OR'ing two masked 32-bit words */
static int MASK_NAME(test_uint32, or)(void)
{
    uint32_t temp;
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    uint32_t z = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_uint32_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_or(w1, w2, w3);
    return mask_test_output(w1) == (x ^ (y | z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test left shifting a masked 32-bit word */
static int MASK_NAME(test_uint32, shl)(void)
{
    uint32_t x = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w2, x);
    mask_test_shl(w1, w2, 5);
    if (mask_test_output(w1) != (x << 5))
        return 0;
    mask_test_input(w2, x);
    mask_test_shl(w2, w2, 1);
    return mask_test_output(w2) == (x << 1);
}

/* Test right shifting a masked 32-bit word */
static int MASK_NAME(test_uint32, shr)(void)
{
    uint32_t x = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w2, x);
    mask_test_shr(w1, w2, 5);
    if (mask_test_output(w1) != (x >> 5))
        return 0;
    mask_test_input(w2, x);
    mask_test_shr(w2, w2, 1);
    return mask_test_output(w2) == (x >> 1);
}

/* Test left rotating a masked 32-bit word */
static int MASK_NAME(test_uint32, rol)(void)
{
    uint32_t x = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w2, x);
    mask_test_rol(w1, w2, 5);
    if (mask_test_output(w1) != ((x << 5) | (x >> 27)))
        return 0;
    mask_test_input(w2, x);
    mask_test_rol(w2, w2, 1);
    return mask_test_output(w2) == ((x << 1) | (x >> 31));
}

/* Test right rotating a masked 32-bit word */
static int MASK_NAME(test_uint32, ror)(void)
{
    uint32_t x = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w2, x);
    mask_test_ror(w1, w2, 5);
    if (mask_test_output(w1) != ((x >> 5) | (x << 27)))
        return 0;
    mask_test_input(w2, x);
    mask_test_ror(w2, w2, 1);
    return mask_test_output(w2) == ((x >> 1) | (x << 31));
}

/* Test swapping two masked 32-bit words */
static int MASK_NAME(test_uint32, swap)(void)
{
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_swap(w1, w2);
    return mask_test_output(w1) == y && mask_test_output(w2) == x;
}

/* Test a swap and move on two masked 32-bit words */
static int MASK_NAME(test_uint32, swap_move)(void)
{
    uint32_t x = aead_masking_generate_32();
    uint32_t y = aead_masking_generate_32();
    uint32_t temp;
    mask_test_uint32_t w1;
    mask_test_uint32_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_swap_move(w1, w2, 0x55555555, 1);
    mask_swap_move_internal(x, y, 0x55555555, 1);
    return mask_test_output(w1) == x && mask_test_output(w2) == y;
}

/* ---------- tests for masked 64-bit words ---------- */

/* Test loading and unloading a masked 64-bit word */
static int MASK_NAME(test_uint64, load)(void)
{
    uint64_t x = aead_masking_generate_64();
    mask_test_uint64_t w;
    mask_test_input(w, x);
    return mask_test_output(w) == x;
}

/* Test adding a constant to a masked 64-bit word */
static int MASK_NAME(test_uint64, xor_const)(void)
{
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    mask_test_uint64_t w;
    mask_test_input(w, x);
    mask_test_xor_const(w, y);
    return mask_test_output(w) == (x ^ y);
}

/* Test XOR'ing two masked 64-bit words */
static int MASK_NAME(test_uint64, xor)(void)
{
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_xor(w1, w2);
    return mask_test_output(w1) == (x ^ y) && mask_test_output(w2) == y;
}

/* Test XOR'ing three masked 64-bit words */
static int MASK_NAME(test_uint64, xor3)(void)
{
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    uint64_t z = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_uint64_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_xor3(w1, w2, w3);
    return mask_test_output(w1) == (x ^ y ^ z) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test NOT'ing a masked 64-bit word */
static int MASK_NAME(test_uint64, not)(void)
{
    uint64_t x = aead_masking_generate_64();
    mask_test_uint64_t w;
    mask_test_input(w, x);
    mask_test_not(w);
    return mask_test_output(w) == (~x);
}

/* Test AND'ing two masked 64-bit words */
static int MASK_NAME(test_uint64, and)(void)
{
    uint64_t temp;
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    uint64_t z = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_uint64_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_and(w1, w2, w3);
    return mask_test_output(w1) == (x ^ (y & z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test AND'ing two masked 64-bit words where one of them is NOT'ed */
static int MASK_NAME(test_uint64, and_not)(void)
{
    uint64_t temp;
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    uint64_t z = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_uint64_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_and_not(w1, w2, w3);
    return mask_test_output(w1) == (x ^ ((~y) & z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test OR'ing two masked 64-bit words */
static int MASK_NAME(test_uint64, or)(void)
{
    uint64_t temp;
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    uint64_t z = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_uint64_t w3;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_input(w3, z);
    mask_test_or(w1, w2, w3);
    return mask_test_output(w1) == (x ^ (y | z)) &&
           mask_test_output(w2) == y &&
           mask_test_output(w3) == z;
}

/* Test left shifting a masked 64-bit word */
static int MASK_NAME(test_uint64, shl)(void)
{
    uint64_t x = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w2, x);
    mask_test_shl(w1, w2, 5);
    if (mask_test_output(w1) != (x << 5))
        return 0;
    mask_test_input(w2, x);
    mask_test_shl(w2, w2, 1);
    return mask_test_output(w2) == (x << 1);
}

/* Test right shifting a masked 64-bit word */
static int MASK_NAME(test_uint64, shr)(void)
{
    uint64_t x = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w2, x);
    mask_test_shr(w1, w2, 5);
    if (mask_test_output(w1) != (x >> 5))
        return 0;
    mask_test_input(w2, x);
    mask_test_shr(w2, w2, 1);
    return mask_test_output(w2) == (x >> 1);
}

/* Test left rotating a masked 64-bit word */
static int MASK_NAME(test_uint64, rol)(void)
{
    uint64_t x = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w2, x);
    mask_test_rol(w1, w2, 5);
    if (mask_test_output(w1) != ((x << 5) | (x >> 59)))
        return 0;
    mask_test_input(w2, x);
    mask_test_rol(w2, w2, 1);
    return mask_test_output(w2) == ((x << 1) | (x >> 63));
}

/* Test right rotating a masked 64-bit word */
static int MASK_NAME(test_uint64, ror)(void)
{
    uint64_t x = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w2, x);
    mask_test_ror(w1, w2, 5);
    if (mask_test_output(w1) != ((x >> 5) | (x << 59)))
        return 0;
    mask_test_input(w2, x);
    mask_test_ror(w2, w2, 1);
    return mask_test_output(w2) == ((x >> 1) | (x << 63));
}

/* Test swapping two masked 64-bit words */
static int MASK_NAME(test_uint64, swap)(void)
{
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_swap(w1, w2);
    return mask_test_output(w1) == y && mask_test_output(w2) == x;
}

/* Test a swap and move on two masked 64-bit words */
static int MASK_NAME(test_uint64, swap_move)(void)
{
    uint64_t x = aead_masking_generate_64();
    uint64_t y = aead_masking_generate_64();
    uint64_t temp;
    mask_test_uint64_t w1;
    mask_test_uint64_t w2;
    mask_test_input(w1, x);
    mask_test_input(w2, y);
    mask_test_swap_move(w1, w2, 0x5555555555555555ULL, 1);
    mask_swap_move_internal(x, y, 0x5555555555555555ULL, 1);
    return mask_test_output(w1) == x && mask_test_output(w2) == y;
}

#endif
