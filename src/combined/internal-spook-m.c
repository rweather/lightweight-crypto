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

#include "internal-spook.h"
#include "internal-masking.h"

/**
 * \brief Round constants for the steps of Clyde-128.
 */
static uint8_t const rc[CLYDE128_STEPS][8] = {
    {1, 0, 0, 0, 0, 1, 0, 0},
    {0, 0, 1, 0, 0, 0, 0, 1},
    {1, 1, 0, 0, 0, 1, 1, 0},
    {0, 0, 1, 1, 1, 1, 0, 1},
    {1, 0, 1, 0, 0, 1, 0, 1},
    {1, 1, 1, 0, 0, 1, 1, 1}
};

/** @cond clyde128_masked_util */

#define clyde128_sbox_masked(s0, s1, s2, s3) \
    do { \
        c = s2; \
        mask_and(c, s0, s1); \
        d = s1; \
        mask_and(d, s3, s0); \
        s2 = s3; \
        mask_and(s2, c, d); \
        mask_and(s0, c, s3); \
        s3 = s0; \
        s0 = d; \
        s1 = c; \
    } while (0)

#define clyde128_lbox_masked(x, y) \
    do { \
        mask_ror(c, x, 12); \
        mask_xor(c, x); \
        mask_ror(d, y, 12); \
        mask_xor(d, y); \
        mask_ror(t, c, 3); \
        mask_xor(c, t); \
        mask_ror(t, d, 3); \
        mask_xor(d, t); \
        mask_rol(x, x, 15); \
        mask_xor(x, c); \
        mask_rol(y, y, 15); \
        mask_xor(y, d); \
        mask_rol(c, x, 1); \
        mask_xor(c, x); \
        mask_rol(d, y, 1); \
        mask_xor(d, y); \
        mask_rol(t, d, 6); \
        mask_xor(x, t); \
        mask_rol(t, c, 7); \
        mask_xor(y, t); \
        mask_ror(c, c, 15); \
        mask_xor(x, c); \
        mask_ror(d, d, 15); \
        mask_xor(y, d); \
    } while (0)

#define clyde128_inv_sbox_masked(s0, s1, s2, s3) \
    do { \
        d = s2; \
        mask_and(d, s0, s1); \
        a = s3; \
        mask_and(a, s1, d); \
        b = s0; \
        mask_and(b, d, a); \
        s2 = s1; \
        mask_and(s2, a, b); \
        s0 = a; \
        s1 = b; \
        s3 = d; \
    } while (0)

#define clyde128_inv_lbox_masked(x, y) \
    do { \
        mask_rol(a, x, 7); \
        mask_xor(a, x); \
        mask_rol(b, y, 7); \
        mask_xor(b, y); \
        mask_rol(d, a, 1); \
        mask_xor(x, d); \
        mask_rol(d, b, 1); \
        mask_xor(y, d); \
        mask_rol(a, a, 12); \
        mask_xor(x, a); \
        mask_rol(b, b, 12); \
        mask_xor(y, b); \
        mask_rol(a, x, 1); \
        mask_xor(a, x); \
        mask_rol(b, y, 1); \
        mask_xor(b, y); \
        mask_rol(d, b, 6); \
        mask_xor(x, d); \
        mask_rol(d, a, 7); \
        mask_xor(y, d); \
        mask_rol(x, x, 15); \
        mask_xor(a, x); \
        mask_rol(y, y, 15); \
        mask_xor(b, y); \
        mask_ror(x, a, 16); \
        mask_ror(y, b, 16); \
    } while (0)

/** @endcond */

void clyde128_encrypt_masked(const unsigned char key[CLYDE128_KEY_SIZE],
                             uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                             const uint32_t input[CLYDE128_BLOCK_SIZE / 4],
                             const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4])
{
    mask_uint32_t k0, k1, k2, k3;
    mask_uint32_t t0, t1, t2, t3;
    mask_uint32_t s0, s1, s2, s3;
    mask_uint32_t c, d, t;
    uint32_t temp;
    int step;

    /* Make sure that the system random number generator is initialized */
    aead_masking_init();

    /* Unpack the key, tweak, and state */
    mask_input(k0, le_load_word32(key));
    mask_input(k1, le_load_word32(key + 4));
    mask_input(k2, le_load_word32(key + 8));
    mask_input(k3, le_load_word32(key + 12));
#if defined(LW_UTIL_LITTLE_ENDIAN)
    mask_input(t0, tweak[0]);
    mask_input(t1, tweak[1]);
    mask_input(t2, tweak[2]);
    mask_input(t3, tweak[3]);
    mask_input(s0, input[0]);
    mask_input(s1, input[1]);
    mask_input(s2, input[2]);
    mask_input(s3, input[3]);
#else
    mask_input(t0, le_load_word32((const unsigned char *)&(tweak[0])));
    mask_input(t1, le_load_word32((const unsigned char *)&(tweak[1])));
    mask_input(t2, le_load_word32((const unsigned char *)&(tweak[2])));
    mask_input(t3, le_load_word32((const unsigned char *)&(tweak[3])));
    mask_input(s0, le_load_word32((const unsigned char *)&(input[0])));
    mask_input(s1, le_load_word32((const unsigned char *)&(input[1])));
    mask_input(s2, le_load_word32((const unsigned char *)&(input[2])));
    mask_input(s3, le_load_word32((const unsigned char *)&(input[3])));
#endif

    /* Add the initial tweakey to the state */
    mask_xor(s0, k0);
    mask_xor(s0, t0);
    mask_xor(s1, k1);
    mask_xor(s1, t1);
    mask_xor(s2, k2);
    mask_xor(s2, t2);
    mask_xor(s3, k3);
    mask_xor(s3, t3);

    /* Perform all rounds in pairs */
    for (step = 0; step < CLYDE128_STEPS; ++step) {
        /* Perform the two rounds of this step */
        clyde128_sbox_masked(s0, s1, s2, s3);
        clyde128_lbox_masked(s0, s1);
        clyde128_lbox_masked(s2, s3);
        mask_xor_const(s0, rc[step][0]);
        mask_xor_const(s1, rc[step][1]);
        mask_xor_const(s2, rc[step][2]);
        mask_xor_const(s3, rc[step][3]);
        clyde128_sbox_masked(s0, s1, s2, s3);
        clyde128_lbox_masked(s0, s1);
        clyde128_lbox_masked(s2, s3);
        mask_xor_const(s0, rc[step][4]);
        mask_xor_const(s1, rc[step][5]);
        mask_xor_const(s2, rc[step][6]);
        mask_xor_const(s3, rc[step][7]);

        /* Update the tweakey on the fly and add it to the state */
        c = t2;
        d = t3;
        mask_xor(c, t0);
        mask_xor(d, t1);
        t2 = t0;
        t3 = t1;
        t0 = c;
        t1 = d;
        mask_xor(s0, k0);
        mask_xor(s0, t0);
        mask_xor(s1, k1);
        mask_xor(s1, t1);
        mask_xor(s2, k2);
        mask_xor(s2, t2);
        mask_xor(s3, k3);
        mask_xor(s3, t3);
    }

    /* Pack the state into the output buffer */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    output[0] = mask_output(s0);
    output[1] = mask_output(s1);
    output[2] = mask_output(s2);
    output[3] = mask_output(s3);
#else
    le_store_word32((unsigned char *)&(output[0]), mask_output(s0));
    le_store_word32((unsigned char *)&(output[1]), mask_output(s1));
    le_store_word32((unsigned char *)&(output[2]), mask_output(s2));
    le_store_word32((unsigned char *)&(output[3]), mask_output(s3));
#endif
}

void clyde128_decrypt_masked(const unsigned char key[CLYDE128_KEY_SIZE],
                             uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                             const unsigned char input[CLYDE128_BLOCK_SIZE],
                             const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4])
{
    mask_uint32_t k0, k1, k2, k3;
    mask_uint32_t t0, t1, t2, t3;
    mask_uint32_t s0, s1, s2, s3;
    mask_uint32_t a, b, d;
    uint32_t temp;
    int step;

    /* Unpack the key, tweak, and state */
    mask_input(k0, le_load_word32(key));
    mask_input(k1, le_load_word32(key + 4));
    mask_input(k2, le_load_word32(key + 8));
    mask_input(k3, le_load_word32(key + 12));
#if defined(LW_UTIL_LITTLE_ENDIAN)
    mask_input(t0, tweak[0]);
    mask_input(t1, tweak[1]);
    mask_input(t2, tweak[2]);
    mask_input(t3, tweak[3]);
#else
    mask_input(t0, le_load_word32((const unsigned char *)&(tweak[0])));
    mask_input(t1, le_load_word32((const unsigned char *)&(tweak[1])));
    mask_input(t2, le_load_word32((const unsigned char *)&(tweak[2])));
    mask_input(t3, le_load_word32((const unsigned char *)&(tweak[3])));
#endif
    mask_input(s0, le_load_word32(input));
    mask_input(s1, le_load_word32(input + 4));
    mask_input(s2, le_load_word32(input + 8));
    mask_input(s3, le_load_word32(input + 12));

    /* Perform all rounds in pairs */
    for (step = CLYDE128_STEPS - 1; step >= 0; --step) {
        /* Add the tweakey to the state and update the tweakey */
        mask_xor(s0, k0);
        mask_xor(s0, t0);
        mask_xor(s1, k1);
        mask_xor(s1, t1);
        mask_xor(s2, k2);
        mask_xor(s2, t2);
        mask_xor(s3, k3);
        mask_xor(s3, t3);
        a = t2;
        b = t3;
        mask_xor(a, t0);
        mask_xor(b, t1);
        t0 = t2;
        t1 = t3;
        t2 = a;
        t3 = b;

        /* Perform the two rounds of this step */
        mask_xor_const(s0, rc[step][4]);
        mask_xor_const(s1, rc[step][5]);
        mask_xor_const(s2, rc[step][6]);
        mask_xor_const(s3, rc[step][7]);
        clyde128_inv_lbox_masked(s0, s1);
        clyde128_inv_lbox_masked(s2, s3);
        clyde128_inv_sbox_masked(s0, s1, s2, s3);
        mask_xor_const(s0, rc[step][0]);
        mask_xor_const(s1, rc[step][1]);
        mask_xor_const(s2, rc[step][2]);
        mask_xor_const(s3, rc[step][3]);
        clyde128_inv_lbox_masked(s0, s1);
        clyde128_inv_lbox_masked(s2, s3);
        clyde128_inv_sbox_masked(s0, s1, s2, s3);
    }

    /* Add the tweakey to the state one last time */
    mask_xor(s0, k0);
    mask_xor(s0, t0);
    mask_xor(s1, k1);
    mask_xor(s1, t1);
    mask_xor(s2, k2);
    mask_xor(s2, t2);
    mask_xor(s3, k3);
    mask_xor(s3, t3);

    /* Pack the state into the output buffer */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    output[0] = mask_output(s0);
    output[1] = mask_output(s1);
    output[2] = mask_output(s2);
    output[3] = mask_output(s3);
#else
    le_store_word32((unsigned char *)&(output[0]), mask_output(s0));
    le_store_word32((unsigned char *)&(output[1]), mask_output(s1));
    le_store_word32((unsigned char *)&(output[2]), mask_output(s2));
    le_store_word32((unsigned char *)&(output[3]), mask_output(s3));
#endif
}
