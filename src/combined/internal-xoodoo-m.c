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

#include "internal-xoodoo-m.h"
#include "internal-util.h"

/**
 * \brief Number of rounds for the Xoodoo permutation.
 */
#define XOODOO_MASKED_ROUNDS 12

/* Apply the theta and rho-west steps to one share in the masked state */
#define theta_rho_west_share(share) \
    do { \
        /* Step theta: Mix column parity */ \
        t1 = x03.share ^ x13.share ^ x23.share; \
        t2 = x00.share ^ x10.share ^ x20.share; \
        t1 = leftRotate5(t1) ^ leftRotate14(t1); \
        t2 = leftRotate5(t2) ^ leftRotate14(t2); \
        x00.share ^= t1; \
        x10.share ^= t1; \
        x20.share ^= t1; \
        t1 = x01.share ^ x11.share ^ x21.share; \
        t1 = leftRotate5(t1) ^ leftRotate14(t1); \
        x01.share ^= t2; \
        x11.share ^= t2; \
        x21.share ^= t2; \
        t2 = x02.share ^ x12.share ^ x22.share; \
        t2 = leftRotate5(t2) ^ leftRotate14(t2); \
        x02.share ^= t1; \
        x12.share ^= t1; \
        x22.share ^= t1; \
        x03.share ^= t2; \
        x13.share ^= t2; \
        x23.share ^= t2; \
        \
        /* Step rho-west: Plane shift */ \
        t1 = x13.share; \
        x13.share = x12.share; \
        x12.share = x11.share; \
        x11.share = x10.share; \
        x10.share = t1; \
        x20.share = leftRotate11(x20.share); \
        x21.share = leftRotate11(x21.share); \
        x22.share = leftRotate11(x22.share); \
        x23.share = leftRotate11(x23.share); \
    } while (0)

/* Apply the rho-east step to one share in the masked state */
#define rho_east_share(share) \
    do { \
        x10.share = leftRotate1(x10.share); \
        x11.share = leftRotate1(x11.share); \
        x12.share = leftRotate1(x12.share); \
        x13.share = leftRotate1(x13.share); \
        t1 = leftRotate8(x22.share); \
        t2 = leftRotate8(x23.share); \
        x22.share = leftRotate8(x20.share); \
        x23.share = leftRotate8(x21.share); \
        x20.share = t1; \
        x21.share = t2; \
    } while (0)

/* Apply the Xoodoo steps to all shares in the masked state */
#if AEAD_MASKING_SHARES == 2
#define theta_rho_west() \
    do { \
        theta_rho_west_share(a); \
        theta_rho_west_share(b); \
    } while (0)
#define rho_east() \
    do { \
        rho_east_share(a); \
        rho_east_share(b); \
    } while (0)
#elif AEAD_MASKING_SHARES == 3
#define theta_rho_west() \
    do { \
        theta_rho_west_share(a); \
        theta_rho_west_share(b); \
        theta_rho_west_share(c); \
    } while (0)
#define rho_east() \
    do { \
        rho_east_share(a); \
        rho_east_share(b); \
        rho_east_share(c); \
    } while (0)
#elif AEAD_MASKING_SHARES == 4
#define theta_rho_west() \
    do { \
        theta_rho_west_share(a); \
        theta_rho_west_share(b); \
        theta_rho_west_share(c); \
        theta_rho_west_share(d); \
    } while (0)
#define rho_east() \
    do { \
        rho_east_share(a); \
        rho_east_share(b); \
        rho_east_share(c); \
        rho_east_share(d); \
    } while (0)
#elif AEAD_MASKING_SHARES == 5
#define theta_rho_west() \
    do { \
        theta_rho_west_share(a); \
        theta_rho_west_share(b); \
        theta_rho_west_share(c); \
        theta_rho_west_share(d); \
        theta_rho_west_share(e); \
    } while (0)
#define rho_east() \
    do { \
        rho_east_share(a); \
        rho_east_share(b); \
        rho_east_share(c); \
        rho_east_share(d); \
        rho_east_share(e); \
    } while (0)
#elif AEAD_MASKING_SHARES == 6
#define theta_rho_west() \
    do { \
        theta_rho_west_share(a); \
        theta_rho_west_share(b); \
        theta_rho_west_share(c); \
        theta_rho_west_share(d); \
        theta_rho_west_share(e); \
        theta_rho_west_share(f); \
    } while (0)
#define rho_east() \
    do { \
        rho_east_share(a); \
        rho_east_share(b); \
        rho_east_share(c); \
        rho_east_share(d); \
        rho_east_share(e); \
        rho_east_share(f); \
    } while (0)
#else
#error "Unknown number of shares"
#endif

void xoodoo_permute_masked(mask_uint32_t state[12])
{
    static uint16_t const rc[XOODOO_MASKED_ROUNDS] = {
        0x0058, 0x0038, 0x03C0, 0x00D0, 0x0120, 0x0014,
        0x0060, 0x002C, 0x0380, 0x00F0, 0x01A0, 0x0012
    };
    uint32_t t1, t2, temp;
    uint8_t round;

    /* Create aliases for the masked state words */
    #define XD(row,col) ((row) * 4 + (col))
    #define x00 (state[XD(0, 0)])
    #define x01 (state[XD(0, 1)])
    #define x02 (state[XD(0, 2)])
    #define x03 (state[XD(0, 3)])
    #define x10 (state[XD(1, 0)])
    #define x11 (state[XD(1, 1)])
    #define x12 (state[XD(1, 2)])
    #define x13 (state[XD(1, 3)])
    #define x20 (state[XD(2, 0)])
    #define x21 (state[XD(2, 1)])
    #define x22 (state[XD(2, 2)])
    #define x23 (state[XD(2, 3)])

    /* Perform all permutation rounds */
    for (round = 0; round < XOODOO_MASKED_ROUNDS; ++round) {
        /* Optimization ideas from the Xoodoo implementation here:
         * https://github.com/XKCP/XKCP/tree/master/lib/low/Xoodoo/Optimized */

        /* Step theta and rho-west */
        theta_rho_west();

        /* Step iota: Add the round constant to the state */
        mask_xor_const(x00, rc[round]); /* x00 ^= rc[round] */

        /* Step chi: Non-linear layer */
        mask_and_not(x00, x10, x20);    /* x00 ^= (~x10) & x20 */
        mask_and_not(x10, x20, x00);    /* x10 ^= (~x20) & x00 */
        mask_and_not(x20, x00, x10);    /* x20 ^= (~x00) & x10 */
        mask_and_not(x01, x11, x21);    /* x01 ^= (~x11) & x21 */
        mask_and_not(x11, x21, x01);    /* x11 ^= (~x21) & x01 */
        mask_and_not(x21, x01, x11);    /* x21 ^= (~x01) & x11 */
        mask_and_not(x02, x12, x22);    /* x02 ^= (~x12) & x22 */
        mask_and_not(x12, x22, x02);    /* x12 ^= (~x22) & x02 */
        mask_and_not(x22, x02, x12);    /* x22 ^= (~x02) & x12 */
        mask_and_not(x03, x13, x23);    /* x03 ^= (~x13) & x23 */
        mask_and_not(x13, x23, x03);    /* x13 ^= (~x23) & x03 */
        mask_and_not(x23, x03, x13);    /* x23 ^= (~x03) & x13 */

        /* Step rho-east: Plane shift */
        rho_east();
    }
}

void xoodoo_mask(mask_uint32_t output[12], const uint32_t input[12])
{
    int index;
    for (index = 0; index < 12; ++index) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        mask_input(output[index], input[index]);
#else
        mask_input(output[index],
                   le_load_word32((const unsigned char *)(&(input[index]))));
#endif
    }
}

void xoodoo_unmask(uint32_t output[12], const mask_uint32_t input[12])
{
    int index;
    for (index = 0; index < 12; ++index) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        output[index] = mask_output(input[index]);
#else
        le_store_word32(((unsigned char *)(&(output[index]))),
                        mask_output(input[index]));
#endif
    }
}
