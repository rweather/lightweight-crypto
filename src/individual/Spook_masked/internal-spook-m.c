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

#define clyde128_lbox_limb(x, y, c, d) \
    do { \
        c = x ^ rightRotate12(x); \
        d = y ^ rightRotate12(y); \
        c ^= rightRotate3(c); \
        d ^= rightRotate3(d); \
        x = c ^ leftRotate15(x); \
        y = d ^ leftRotate15(y); \
        c = x ^ leftRotate1(x); \
        d = y ^ leftRotate1(y); \
        x ^= leftRotate6(d); \
        y ^= leftRotate7(c); \
        x ^= rightRotate15(c); \
        y ^= rightRotate15(d); \
    } while (0)

#define clyde128_inv_lbox_limb(x, y, a, b) \
    do { \
        a = x ^ leftRotate7(x); \
        b = y ^ leftRotate7(y); \
        x ^= leftRotate1(a); \
        y ^= leftRotate1(b); \
        x ^= leftRotate12(a); \
        y ^= leftRotate12(b); \
        a = x ^ leftRotate1(x); \
        b = y ^ leftRotate1(y); \
        x ^= leftRotate6(b); \
        y ^= leftRotate7(a); \
        a ^= leftRotate15(x); \
        b ^= leftRotate15(y); \
        x = rightRotate16(a); \
        y = rightRotate16(b); \
    } while (0)

/* We can reduce the number of register spills in the lbox by
 * processing the shares one at a time rather than interleaving.
 * This gives roughly a 5% improvement on runtime performance. */
#if AEAD_MASKING_SHARES == 2
#define clyde128_lbox_masked(x, y) \
    do { \
        clyde128_lbox_limb((x).a, (y).a, c.a, d.a); \
        clyde128_lbox_limb((x).b, (y).b, c.b, d.b); \
    } while (0)
#define clyde128_inv_lbox_masked(x, y) \
    do { \
        clyde128_inv_lbox_limb((x).a, (y).a, a.a, b.a); \
        clyde128_inv_lbox_limb((x).b, (y).b, a.b, b.b); \
    } while (0)
#elif AEAD_MASKING_SHARES == 3
#define clyde128_lbox_masked(x, y) \
    do { \
        clyde128_lbox_limb((x).a, (y).a, c.a, d.a); \
        clyde128_lbox_limb((x).b, (y).b, c.b, d.b); \
        clyde128_lbox_limb((x).c, (y).c, c.c, d.c); \
    } while (0)
#define clyde128_inv_lbox_masked(x, y) \
    do { \
        clyde128_inv_lbox_limb((x).a, (y).a, a.a, b.a); \
        clyde128_inv_lbox_limb((x).b, (y).b, a.b, b.b); \
        clyde128_inv_lbox_limb((x).c, (y).c, a.c, b.c); \
    } while (0)
#elif AEAD_MASKING_SHARES == 4
#define clyde128_lbox_masked(x, y) \
    do { \
        clyde128_lbox_limb((x).a, (y).a, c.a, d.a); \
        clyde128_lbox_limb((x).b, (y).b, c.b, d.b); \
        clyde128_lbox_limb((x).c, (y).c, c.c, d.c); \
        clyde128_lbox_limb((x).d, (y).d, c.d, d.d); \
    } while (0)
#define clyde128_inv_lbox_masked(x, y) \
    do { \
        clyde128_inv_lbox_limb((x).a, (y).a, a.a, b.a); \
        clyde128_inv_lbox_limb((x).b, (y).b, a.b, b.b); \
        clyde128_inv_lbox_limb((x).c, (y).c, a.c, b.c); \
        clyde128_inv_lbox_limb((x).d, (y).d, a.d, b.d); \
    } while (0)
#elif AEAD_MASKING_SHARES == 5
#define clyde128_lbox_masked(x, y) \
    do { \
        clyde128_lbox_limb((x).a, (y).a, c.a, d.a); \
        clyde128_lbox_limb((x).b, (y).b, c.b, d.b); \
        clyde128_lbox_limb((x).c, (y).c, c.c, d.c); \
        clyde128_lbox_limb((x).d, (y).d, c.d, d.d); \
        clyde128_lbox_limb((x).e, (y).e, c.e, d.e); \
    } while (0)
#define clyde128_inv_lbox_masked(x, y) \
    do { \
        clyde128_inv_lbox_limb((x).a, (y).a, a.a, b.a); \
        clyde128_inv_lbox_limb((x).b, (y).b, a.b, b.b); \
        clyde128_inv_lbox_limb((x).c, (y).c, a.c, b.c); \
        clyde128_inv_lbox_limb((x).d, (y).d, a.d, b.d); \
        clyde128_inv_lbox_limb((x).e, (y).e, a.e, b.e); \
    } while (0)
#elif AEAD_MASKING_SHARES == 6
#define clyde128_lbox_masked(x, y) \
    do { \
        clyde128_lbox_limb((x).a, (y).a, c.a, d.a); \
        clyde128_lbox_limb((x).b, (y).b, c.b, d.b); \
        clyde128_lbox_limb((x).c, (y).c, c.c, d.c); \
        clyde128_lbox_limb((x).d, (y).d, c.d, d.d); \
        clyde128_lbox_limb((x).e, (y).e, c.e, d.e); \
        clyde128_lbox_limb((x).f, (y).f, c.f, d.f); \
    } while (0)
#define clyde128_inv_lbox_masked(x, y) \
    do { \
        clyde128_inv_lbox_limb((x).a, (y).a, a.a, b.a); \
        clyde128_inv_lbox_limb((x).b, (y).b, a.b, b.b); \
        clyde128_inv_lbox_limb((x).c, (y).c, a.c, b.c); \
        clyde128_inv_lbox_limb((x).d, (y).d, a.d, b.d); \
        clyde128_inv_lbox_limb((x).e, (y).e, a.e, b.e); \
        clyde128_inv_lbox_limb((x).f, (y).f, a.f, b.f); \
    } while (0)
#else
#error "Unknown number of shares"
#endif

/** @endcond */

void clyde128_encrypt_masked(const unsigned char key[CLYDE128_KEY_SIZE],
                             uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                             const uint32_t input[CLYDE128_BLOCK_SIZE / 4],
                             const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4])
{
    mask_uint32_t k0, k1, k2, k3;
    mask_uint32_t t0, t1, t2, t3;
    mask_uint32_t s0, s1, s2, s3;
    mask_uint32_t c, d;
    uint32_t temp;
    int step;

    /* Make sure that the system random number generator is initialized */
    aead_random_init();

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
    mask_xor3(s0, k0, t0);
    mask_xor3(s1, k1, t1);
    mask_xor3(s2, k2, t2);
    mask_xor3(s3, k3, t3);

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
        mask_xor3(s0, k0, t0);
        mask_xor3(s1, k1, t1);
        mask_xor3(s2, k2, t2);
        mask_xor3(s3, k3, t3);
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
        mask_xor3(s0, k0, t0);
        mask_xor3(s1, k1, t1);
        mask_xor3(s2, k2, t2);
        mask_xor3(s3, k3, t3);
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
    mask_xor3(s0, k0, t0);
    mask_xor3(s1, k1, t1);
    mask_xor3(s2, k2, t2);
    mask_xor3(s3, k3, t3);

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
