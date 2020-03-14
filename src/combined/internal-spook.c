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

/**
 * \brief Number of steps in the Clyde-128 block cipher.
 *
 * This is also the number of steps in the Shadow-512 and Shadow-384
 * permutations.
 */
#define CLYDE128_STEPS 6

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

void clyde128_encrypt(const unsigned char key[CLYDE128_KEY_SIZE],
                      const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4],
                      uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                      const uint32_t input[CLYDE128_BLOCK_SIZE / 4])
{
    uint32_t k0, k1, k2, k3;
    uint32_t t0, t1, t2, t3;
    uint32_t s0, s1, s2, s3;
    uint32_t c, d;
    int step;

    /* Unpack the key, tweak, and state */
    k0 = le_load_word32(key);
    k1 = le_load_word32(key + 4);
    k2 = le_load_word32(key + 8);
    k3 = le_load_word32(key + 12);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    t0 = tweak[0];
    t1 = tweak[1];
    t2 = tweak[2];
    t3 = tweak[3];
    s0 = input[0];
    s1 = input[1];
    s2 = input[2];
    s3 = input[3];
#else
    t0 = le_load_word32((const unsigned char *)&(tweak[0]));
    t1 = le_load_word32((const unsigned char *)&(tweak[1]));
    t2 = le_load_word32((const unsigned char *)&(tweak[2]));
    t3 = le_load_word32((const unsigned char *)&(tweak[3]));
    s0 = le_load_word32((const unsigned char *)&(input[0]));
    s1 = le_load_word32((const unsigned char *)&(input[1]));
    s2 = le_load_word32((const unsigned char *)&(input[2]));
    s3 = le_load_word32((const unsigned char *)&(input[3]));
#endif

    /* Add the initial tweakey to the state */
    s0 ^= k0 ^ t0;
    s1 ^= k1 ^ t1;
    s2 ^= k2 ^ t2;
    s3 ^= k3 ^ t3;

    /* Perform all rounds in pairs */
    for (step = 0; step < CLYDE128_STEPS; ++step) {
        /* Perform the two rounds of this step */
        #define clyde128_sbox(s0, s1, s2, s3) \
            do { \
                c = (s0 & s1) ^ s2; \
                d = (s3 & s0) ^ s1; \
                s2 = (c & d) ^ s3; \
                s3 = (c & s3) ^ s0; \
                s0 = d; \
                s1 = c; \
            } while (0)
        #define clyde128_lbox(x, y) \
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
        clyde128_sbox(s0, s1, s2, s3);
        clyde128_lbox(s0, s1);
        clyde128_lbox(s2, s3);
        s0 ^= rc[step][0];
        s1 ^= rc[step][1];
        s2 ^= rc[step][2];
        s3 ^= rc[step][3];
        clyde128_sbox(s0, s1, s2, s3);
        clyde128_lbox(s0, s1);
        clyde128_lbox(s2, s3);
        s0 ^= rc[step][4];
        s1 ^= rc[step][5];
        s2 ^= rc[step][6];
        s3 ^= rc[step][7];

        /* Update the tweakey on the fly and add it to the state */
        c = t2 ^ t0;
        d = t3 ^ t1;
        t2 = t0;
        t3 = t1;
        t0 = c;
        t1 = d;
        s0 ^= k0 ^ t0;
        s1 ^= k1 ^ t1;
        s2 ^= k2 ^ t2;
        s3 ^= k3 ^ t3;
    }

    /* Pack the state into the output buffer */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    output[0] = s0;
    output[1] = s1;
    output[2] = s2;
    output[3] = s3;
#else
    le_store_word32((unsigned char *)&(output[0]), s0);
    le_store_word32((unsigned char *)&(output[1]), s1);
    le_store_word32((unsigned char *)&(output[2]), s2);
    le_store_word32((unsigned char *)&(output[3]), s3);
#endif
}

void clyde128_decrypt(const unsigned char key[CLYDE128_KEY_SIZE],
                      const uint32_t tweak[CLYDE128_TWEAK_SIZE / 4],
                      uint32_t output[CLYDE128_BLOCK_SIZE / 4],
                      const unsigned char input[CLYDE128_BLOCK_SIZE])
{
    uint32_t k0, k1, k2, k3;
    uint32_t t0, t1, t2, t3;
    uint32_t s0, s1, s2, s3;
    uint32_t a, b, d;
    int step;

    /* Unpack the key, tweak, and state */
    k0 = le_load_word32(key);
    k1 = le_load_word32(key + 4);
    k2 = le_load_word32(key + 8);
    k3 = le_load_word32(key + 12);
#if defined(LW_UTIL_LITTLE_ENDIAN)
    t0 = tweak[0];
    t1 = tweak[1];
    t2 = tweak[2];
    t3 = tweak[3];
#else
    t0 = le_load_word32((const unsigned char *)&(tweak[0]));
    t1 = le_load_word32((const unsigned char *)&(tweak[1]));
    t2 = le_load_word32((const unsigned char *)&(tweak[2]));
    t3 = le_load_word32((const unsigned char *)&(tweak[3]));
#endif
    s0 = le_load_word32(input);
    s1 = le_load_word32(input + 4);
    s2 = le_load_word32(input + 8);
    s3 = le_load_word32(input + 12);

    /* Perform all rounds in pairs */
    for (step = CLYDE128_STEPS - 1; step >= 0; --step) {
        /* Add the tweakey to the state and update the tweakey */
        s0 ^= k0 ^ t0;
        s1 ^= k1 ^ t1;
        s2 ^= k2 ^ t2;
        s3 ^= k3 ^ t3;
        a = t2 ^ t0;
        b = t3 ^ t1;
        t0 = t2;
        t1 = t3;
        t2 = a;
        t3 = b;

        /* Perform the two rounds of this step */
        #define clyde128_inv_sbox(s0, s1, s2, s3) \
            do { \
                d = (s0 & s1) ^ s2; \
                a = (s1 & d) ^ s3; \
                b = (d & a) ^ s0; \
                s2 = (a & b) ^ s1; \
                s0 = a; \
                s1 = b; \
                s3 = d; \
            } while (0)
        #define clyde128_inv_lbox(x, y) \
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
        s0 ^= rc[step][4];
        s1 ^= rc[step][5];
        s2 ^= rc[step][6];
        s3 ^= rc[step][7];
        clyde128_inv_lbox(s0, s1);
        clyde128_inv_lbox(s2, s3);
        clyde128_inv_sbox(s0, s1, s2, s3);
        s0 ^= rc[step][0];
        s1 ^= rc[step][1];
        s2 ^= rc[step][2];
        s3 ^= rc[step][3];
        clyde128_inv_lbox(s0, s1);
        clyde128_inv_lbox(s2, s3);
        clyde128_inv_sbox(s0, s1, s2, s3);
    }

    /* Add the tweakey to the state one last time */
    s0 ^= k0 ^ t0;
    s1 ^= k1 ^ t1;
    s2 ^= k2 ^ t2;
    s3 ^= k3 ^ t3;

    /* Pack the state into the output buffer */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    output[0] = s0;
    output[1] = s1;
    output[2] = s2;
    output[3] = s3;
#else
    le_store_word32((unsigned char *)&(output[0]), s0);
    le_store_word32((unsigned char *)&(output[1]), s1);
    le_store_word32((unsigned char *)&(output[2]), s2);
    le_store_word32((unsigned char *)&(output[3]), s3);
#endif
}

void shadow512(shadow512_state_t *state)
{
    uint32_t s00, s01, s02, s03;
    uint32_t s10, s11, s12, s13;
    uint32_t s20, s21, s22, s23;
    uint32_t s30, s31, s32, s33;
    uint32_t c, d, w, x, y, z;
    int step;

    /* Unpack the state into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s00 = state->W[0];
    s01 = state->W[1];
    s02 = state->W[2];
    s03 = state->W[3];
    s10 = state->W[4];
    s11 = state->W[5];
    s12 = state->W[6];
    s13 = state->W[7];
    s20 = state->W[8];
    s21 = state->W[9];
    s22 = state->W[10];
    s23 = state->W[11];
    s30 = state->W[12];
    s31 = state->W[13];
    s32 = state->W[14];
    s33 = state->W[15];
#else
    s00 = le_load_word32(state->B);
    s01 = le_load_word32(state->B + 4);
    s02 = le_load_word32(state->B + 8);
    s03 = le_load_word32(state->B + 12);
    s10 = le_load_word32(state->B + 16);
    s11 = le_load_word32(state->B + 20);
    s12 = le_load_word32(state->B + 24);
    s13 = le_load_word32(state->B + 28);
    s20 = le_load_word32(state->B + 32);
    s21 = le_load_word32(state->B + 36);
    s22 = le_load_word32(state->B + 40);
    s23 = le_load_word32(state->B + 44);
    s30 = le_load_word32(state->B + 48);
    s31 = le_load_word32(state->B + 52);
    s32 = le_load_word32(state->B + 56);
    s33 = le_load_word32(state->B + 60);
#endif

    /* Perform all rounds in pairs */
    for (step = 0; step < CLYDE128_STEPS; ++step) {
        /* Apply the S-box and L-box to bundle 0 */
        clyde128_sbox(s00, s01, s02, s03);
        clyde128_lbox(s00, s01);
        clyde128_lbox(s02, s03);
        s00 ^= rc[step][0];
        s01 ^= rc[step][1];
        s02 ^= rc[step][2];
        s03 ^= rc[step][3];
        clyde128_sbox(s00, s01, s02, s03);

        /* Apply the S-box and L-box to bundle 1 */
        clyde128_sbox(s10, s11, s12, s13);
        clyde128_lbox(s10, s11);
        clyde128_lbox(s12, s13);
        s10 ^= rc[step][0] << 1;
        s11 ^= rc[step][1] << 1;
        s12 ^= rc[step][2] << 1;
        s13 ^= rc[step][3] << 1;
        clyde128_sbox(s10, s11, s12, s13);

        /* Apply the S-box and L-box to bundle 2 */
        clyde128_sbox(s20, s21, s22, s23);
        clyde128_lbox(s20, s21);
        clyde128_lbox(s22, s23);
        s20 ^= rc[step][0] << 2;
        s21 ^= rc[step][1] << 2;
        s22 ^= rc[step][2] << 2;
        s23 ^= rc[step][3] << 2;
        clyde128_sbox(s20, s21, s22, s23);

        /* Apply the S-box and L-box to bundle 3 */
        clyde128_sbox(s30, s31, s32, s33);
        clyde128_lbox(s30, s31);
        clyde128_lbox(s32, s33);
        s30 ^= rc[step][0] << 3;
        s31 ^= rc[step][1] << 3;
        s32 ^= rc[step][2] << 3;
        s33 ^= rc[step][3] << 3;
        clyde128_sbox(s30, s31, s32, s33);

        /* Apply the diffusion layer to the rows of the state */
        #define shadow512_diffusion_layer(row) \
            do { \
                w = s0##row; \
                x = s1##row; \
                y = s2##row; \
                z = s3##row; \
                c = w ^ x; \
                d = y ^ z; \
                s0##row = x ^ d; \
                s1##row = w ^ d; \
                s2##row = c ^ z; \
                s3##row = c ^ y; \
            } while (0)
        shadow512_diffusion_layer(0);
        shadow512_diffusion_layer(1);
        shadow512_diffusion_layer(2);
        shadow512_diffusion_layer(3);

        /* Add round constants to all bundles again */
        s00 ^= rc[step][4];
        s01 ^= rc[step][5];
        s02 ^= rc[step][6];
        s03 ^= rc[step][7];
        s10 ^= rc[step][4] << 1;
        s11 ^= rc[step][5] << 1;
        s12 ^= rc[step][6] << 1;
        s13 ^= rc[step][7] << 1;
        s20 ^= rc[step][4] << 2;
        s21 ^= rc[step][5] << 2;
        s22 ^= rc[step][6] << 2;
        s23 ^= rc[step][7] << 2;
        s30 ^= rc[step][4] << 3;
        s31 ^= rc[step][5] << 3;
        s32 ^= rc[step][6] << 3;
        s33 ^= rc[step][7] << 3;
    }

    /* Pack the local variables back into the state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0]  = s00;
    state->W[1]  = s01;
    state->W[2]  = s02;
    state->W[3]  = s03;
    state->W[4]  = s10;
    state->W[5]  = s11;
    state->W[6]  = s12;
    state->W[7]  = s13;
    state->W[8]  = s20;
    state->W[9]  = s21;
    state->W[10] = s22;
    state->W[11] = s23;
    state->W[12] = s30;
    state->W[13] = s31;
    state->W[14] = s32;
    state->W[15] = s33;
#else
    le_store_word32(state->B,      s00);
    le_store_word32(state->B + 4,  s01);
    le_store_word32(state->B + 8,  s02);
    le_store_word32(state->B + 12, s03);
    le_store_word32(state->B + 16, s10);
    le_store_word32(state->B + 20, s11);
    le_store_word32(state->B + 24, s12);
    le_store_word32(state->B + 28, s13);
    le_store_word32(state->B + 32, s20);
    le_store_word32(state->B + 36, s21);
    le_store_word32(state->B + 40, s22);
    le_store_word32(state->B + 44, s23);
    le_store_word32(state->B + 48, s30);
    le_store_word32(state->B + 52, s31);
    le_store_word32(state->B + 56, s32);
    le_store_word32(state->B + 60, s33);
#endif
}

void shadow384(shadow384_state_t *state)
{
    uint32_t s00, s01, s02, s03;
    uint32_t s10, s11, s12, s13;
    uint32_t s20, s21, s22, s23;
    uint32_t c, d, x, y, z;
    int step;

    /* Unpack the state into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s00 = state->W[0];
    s01 = state->W[1];
    s02 = state->W[2];
    s03 = state->W[3];
    s10 = state->W[4];
    s11 = state->W[5];
    s12 = state->W[6];
    s13 = state->W[7];
    s20 = state->W[8];
    s21 = state->W[9];
    s22 = state->W[10];
    s23 = state->W[11];
#else
    s00 = le_load_word32(state->B);
    s01 = le_load_word32(state->B + 4);
    s02 = le_load_word32(state->B + 8);
    s03 = le_load_word32(state->B + 12);
    s10 = le_load_word32(state->B + 16);
    s11 = le_load_word32(state->B + 20);
    s12 = le_load_word32(state->B + 24);
    s13 = le_load_word32(state->B + 28);
    s20 = le_load_word32(state->B + 32);
    s21 = le_load_word32(state->B + 36);
    s22 = le_load_word32(state->B + 40);
    s23 = le_load_word32(state->B + 44);
#endif

    /* Perform all rounds in pairs */
    for (step = 0; step < CLYDE128_STEPS; ++step) {
        /* Apply the S-box and L-box to bundle 0 */
        clyde128_sbox(s00, s01, s02, s03);
        clyde128_lbox(s00, s01);
        clyde128_lbox(s02, s03);
        s00 ^= rc[step][0];
        s01 ^= rc[step][1];
        s02 ^= rc[step][2];
        s03 ^= rc[step][3];
        clyde128_sbox(s00, s01, s02, s03);

        /* Apply the S-box and L-box to bundle 1 */
        clyde128_sbox(s10, s11, s12, s13);
        clyde128_lbox(s10, s11);
        clyde128_lbox(s12, s13);
        s10 ^= rc[step][0] << 1;
        s11 ^= rc[step][1] << 1;
        s12 ^= rc[step][2] << 1;
        s13 ^= rc[step][3] << 1;
        clyde128_sbox(s10, s11, s12, s13);

        /* Apply the S-box and L-box to bundle 2 */
        clyde128_sbox(s20, s21, s22, s23);
        clyde128_lbox(s20, s21);
        clyde128_lbox(s22, s23);
        s20 ^= rc[step][0] << 2;
        s21 ^= rc[step][1] << 2;
        s22 ^= rc[step][2] << 2;
        s23 ^= rc[step][3] << 2;
        clyde128_sbox(s20, s21, s22, s23);

        /* Apply the diffusion layer to the rows of the state */
        #define shadow384_diffusion_layer(row) \
            do { \
                x = s0##row; \
                y = s1##row; \
                z = s2##row; \
                s0##row = x ^ y ^ z; \
                s1##row = x ^ z; \
                s2##row = x ^ y; \
            } while (0)
        shadow384_diffusion_layer(0);
        shadow384_diffusion_layer(1);
        shadow384_diffusion_layer(2);
        shadow384_diffusion_layer(3);

        /* Add round constants to all bundles again */
        s00 ^= rc[step][4];
        s01 ^= rc[step][5];
        s02 ^= rc[step][6];
        s03 ^= rc[step][7];
        s10 ^= rc[step][4] << 1;
        s11 ^= rc[step][5] << 1;
        s12 ^= rc[step][6] << 1;
        s13 ^= rc[step][7] << 1;
        s20 ^= rc[step][4] << 2;
        s21 ^= rc[step][5] << 2;
        s22 ^= rc[step][6] << 2;
        s23 ^= rc[step][7] << 2;
    }

    /* Pack the local variables back into the state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->W[0]  = s00;
    state->W[1]  = s01;
    state->W[2]  = s02;
    state->W[3]  = s03;
    state->W[4]  = s10;
    state->W[5]  = s11;
    state->W[6]  = s12;
    state->W[7]  = s13;
    state->W[8]  = s20;
    state->W[9]  = s21;
    state->W[10] = s22;
    state->W[11] = s23;
#else
    le_store_word32(state->B,      s00);
    le_store_word32(state->B + 4,  s01);
    le_store_word32(state->B + 8,  s02);
    le_store_word32(state->B + 12, s03);
    le_store_word32(state->B + 16, s10);
    le_store_word32(state->B + 20, s11);
    le_store_word32(state->B + 24, s12);
    le_store_word32(state->B + 28, s13);
    le_store_word32(state->B + 32, s20);
    le_store_word32(state->B + 36, s21);
    le_store_word32(state->B + 40, s22);
    le_store_word32(state->B + 44, s23);
#endif
}
