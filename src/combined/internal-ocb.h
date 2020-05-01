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

#ifndef LW_INTERNAL_OCB_H
#define LW_INTERNAL_OCB_H

#include "internal-util.h"
#include <string.h>

/* We expect a number of macros to be defined before this file
 * is included to configure the underlying block cipher:
 *
 * OCB_ALG_NAME         Name of the algorithm that is using OCB mode.
 * OCB_BLOCK_SIZE       Size of the block for the underlying cipher in bytes.
 * OCB_NONCE_SIZE       Size of the nonce which must be < OCB_BLOCK_SIZE.
 * OCB_TAG_SIZE         Size of the authentication tag.
 * OCB_KEY_SCHEDULE     Type for the key schedule.
 * OCB_SETUP_KEY        Name of the key schedule setup function.
 * OCB_ENCRYPT_BLOCK    Name of the block cipher ECB encrypt function.
 * OCB_DECRYPT_BLOCK    Name of the block cipher ECB decrypt function.
 * OCB_DOUBLE_L         Name of the function to double L (optional).
 */
#if defined(OCB_ENCRYPT_BLOCK)

/**
 * \file internal-ocb.h
 * \brief Internal implementation of the OCB block cipher mode.
 *
 * Note that OCB is covered by patents so it may not be usable in all
 * applications.  Open source applications should be covered, but for
 * others you will need to contact the patent authors to find out
 * if you can use it or if a paid license is required.
 *
 * License information: https://web.cs.ucdavis.edu/~rogaway/ocb/license.htm
 *
 * References: https://tools.ietf.org/html/rfc7253
 */

#define OCB_CONCAT_INNER(name,suffix) name##suffix
#define OCB_CONCAT(name,suffix) OCB_CONCAT_INNER(name,suffix)

#if !defined(OCB_DOUBLE_L)

#define OCB_DOUBLE_L OCB_CONCAT(OCB_ALG_NAME,_double_l)

#if OCB_BLOCK_SIZE == 16

/* Double a value in GF(128) */
static void OCB_DOUBLE_L(unsigned char out[16], const unsigned char in[16])
{
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)in[0]) >> 7);
    for (index = 0; index < 15; ++index)
        out[index] = (in[index] << 1) | (in[index + 1] >> 7);
    out[15] = (in[15] << 1) ^ (mask & 0x87);
}

#elif OCB_BLOCK_SIZE == 12

/* Double a value in GF(96) */
static void OCB_DOUBLE_L
    (unsigned char out[12], const unsigned char in[12])
{
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)in[0]) >> 7);
    for (index = 0; index < 11; ++index)
        out[index] = (in[index] << 1) | (in[index + 1] >> 7);
    out[11] = (in[11] << 1) ^ (mask & 0x41);
    out[10] ^= (mask & 0x06);
}

#else
#error "Unknown block size for OCB"
#endif

#endif

/* State information for OCB functions */
#define OCB_STATE OCB_CONCAT(OCB_ALG_NAME,_state_t)
typedef struct
{
    OCB_KEY_SCHEDULE ks;
    unsigned char Lstar[OCB_BLOCK_SIZE];
    unsigned char Ldollar[OCB_BLOCK_SIZE];
    unsigned char L0[OCB_BLOCK_SIZE];
    unsigned char L1[OCB_BLOCK_SIZE];

} OCB_STATE;

/* Initializes the OCB state from the key and nonce */
static void OCB_CONCAT(OCB_ALG_NAME,_init)
    (OCB_STATE *state, const unsigned char *k, const unsigned char *nonce,
     unsigned char offset[OCB_BLOCK_SIZE])
{
    unsigned bottom;

    /* Set up the key schedule */
    OCB_SETUP_KEY(&(state->ks), k);

    /* Derive the values of L*, L$, L0, and L1 */
    memset(state->Lstar, 0, sizeof(state->Lstar));
    OCB_ENCRYPT_BLOCK(&(state->ks), state->Lstar, state->Lstar);
    OCB_DOUBLE_L(state->Ldollar, state->Lstar);
    OCB_DOUBLE_L(state->L0, state->Ldollar);
    OCB_DOUBLE_L(state->L1, state->L0);

    /* Derive the initial offset from the nonce */
    memset(offset, 0, OCB_BLOCK_SIZE);
    memcpy(offset + OCB_BLOCK_SIZE - OCB_NONCE_SIZE, nonce, OCB_NONCE_SIZE);
    offset[0] = ((OCB_TAG_SIZE * 8) & 0x7F) << 1;
    offset[OCB_BLOCK_SIZE - OCB_NONCE_SIZE - 1] |= 0x01;
    bottom = offset[OCB_BLOCK_SIZE - 1] & 0x3F;
    offset[OCB_BLOCK_SIZE - 1] &= 0xC0;
    {
        unsigned index;
        unsigned byte_posn = bottom / 8;
#if OCB_BLOCK_SIZE == 16
        /* Standard OCB with a 128-bit block */
        unsigned char stretch[24];
        OCB_ENCRYPT_BLOCK(&(state->ks), stretch, offset);
        memcpy(stretch + 16, stretch + 1, 8);
        lw_xor_block(stretch + 16, stretch, 8);
#elif OCB_BLOCK_SIZE == 12
        /* 96-bit block handling from the Pyjamask specification */
        unsigned char stretch[20];
        OCB_ENCRYPT_BLOCK(&(state->ks), stretch, offset);
        for (index = 0; index < 8; ++index) {
            stretch[index + 12] =
                (stretch[index + 1] << 1) | (stretch[index + 2] >> 7);
        }
        lw_xor_block(stretch + 12, stretch, 8);
#else
        unsigned char stretch[OCB_BLOCK_SIZE + 8] = {0};
        #error "unsupported block size for OCB mode"
#endif
        bottom %= 8;
        if (bottom != 0) {
            for (index = 0; index < OCB_BLOCK_SIZE; ++index) {
                offset[index] =
                    (stretch[index + byte_posn] << bottom) |
                    (stretch[index + byte_posn + 1] >> (8 - bottom));
            }
        } else {
            memcpy(offset, stretch + byte_posn, OCB_BLOCK_SIZE);
        }
    }
}

/* Calculate L_{ntz(i)} when the last two bits of i are zero */
static void OCB_CONCAT(OCB_ALG_NAME,_calculate_L)
    (OCB_STATE *state, unsigned char L[OCB_BLOCK_SIZE], unsigned long long i)
{
    OCB_DOUBLE_L(L, state->L1);
    i >>= 2;
    while ((i & 1) == 0) {
        OCB_DOUBLE_L(L, L);
        i >>= 1;
    }
}

/* Process associated data with OCB */
static void OCB_CONCAT(OCB_ALG_NAME,_process_ad)
    (OCB_STATE *state, unsigned char tag[OCB_BLOCK_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char offset[OCB_BLOCK_SIZE];
    unsigned char block[OCB_BLOCK_SIZE];
    unsigned long long block_number;

    /* Process all full blocks */
    memset(offset, 0, sizeof(offset));
    block_number = 1;
    while (adlen >= OCB_BLOCK_SIZE) {
        if (block_number & 1) {
            lw_xor_block(offset, state->L0, OCB_BLOCK_SIZE);
        } else if ((block_number & 3) == 2) {
            lw_xor_block(offset, state->L1, OCB_BLOCK_SIZE);
        } else {
            OCB_CONCAT(OCB_ALG_NAME,_calculate_L)(state, block, block_number);
            lw_xor_block(offset, block, OCB_BLOCK_SIZE);
        }
        lw_xor_block_2_src(block, offset, ad, OCB_BLOCK_SIZE);
        OCB_ENCRYPT_BLOCK(&(state->ks), block, block);
        lw_xor_block(tag, block, OCB_BLOCK_SIZE);
        ad += OCB_BLOCK_SIZE;
        adlen -= OCB_BLOCK_SIZE;
        ++block_number;
    }

    /* Pad and process the last partial block */
    if (adlen > 0) {
        unsigned temp = (unsigned)adlen;
        lw_xor_block(offset, state->Lstar, OCB_BLOCK_SIZE);
        lw_xor_block(offset, ad, temp);
        offset[temp] ^= 0x80;
        OCB_ENCRYPT_BLOCK(&(state->ks), block, offset);
        lw_xor_block(tag, block, OCB_BLOCK_SIZE);
    }
}

int OCB_CONCAT(OCB_ALG_NAME,_aead_encrypt)
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    OCB_STATE state;
    unsigned char offset[OCB_BLOCK_SIZE];
    unsigned char sum[OCB_BLOCK_SIZE];
    unsigned char block[OCB_BLOCK_SIZE];
    unsigned long long block_number;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + OCB_TAG_SIZE;

    /* Initialize the OCB state */
    OCB_CONCAT(OCB_ALG_NAME,_init)(&state, k, npub, offset);

    /* Process all plaintext blocks except the last */
    memset(sum, 0, sizeof(sum));
    block_number = 1;
    while (mlen >= OCB_BLOCK_SIZE) {
        if (block_number & 1) {
            lw_xor_block(offset, state.L0, OCB_BLOCK_SIZE);
        } else if ((block_number & 3) == 2) {
            lw_xor_block(offset, state.L1, OCB_BLOCK_SIZE);
        } else {
            OCB_CONCAT(OCB_ALG_NAME,_calculate_L)(&state, block, block_number);
            lw_xor_block(offset, block, OCB_BLOCK_SIZE);
        }
        lw_xor_block(sum, m, OCB_BLOCK_SIZE);
        lw_xor_block_2_src(block, offset, m, OCB_BLOCK_SIZE);
        OCB_ENCRYPT_BLOCK(&(state.ks), block, block);
        lw_xor_block_2_src(c, block, offset, OCB_BLOCK_SIZE);
        c += OCB_BLOCK_SIZE;
        m += OCB_BLOCK_SIZE;
        mlen -= OCB_BLOCK_SIZE;
        ++block_number;
    }

    /* Pad and process the last plaintext block */
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        lw_xor_block(sum, m, temp);
        sum[temp] ^= 0x80;
        lw_xor_block(offset, state.Lstar, OCB_BLOCK_SIZE);
        OCB_ENCRYPT_BLOCK(&(state.ks), block, offset);
        lw_xor_block_2_src(c, block, m, temp);
        c += temp;
    }

    /* Finalize the encryption phase */
    lw_xor_block(sum, offset, OCB_BLOCK_SIZE);
    lw_xor_block(sum, state.Ldollar, OCB_BLOCK_SIZE);
    OCB_ENCRYPT_BLOCK(&(state.ks), sum, sum);

    /* Process the associated data and compute the final authentication tag */
    OCB_CONCAT(OCB_ALG_NAME,_process_ad)(&state, sum, ad, adlen);
    memcpy(c, sum, OCB_TAG_SIZE);
    return 0;
}

int OCB_CONCAT(OCB_ALG_NAME,_aead_decrypt)
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    OCB_STATE state;
    unsigned char *mtemp = m;
    unsigned char offset[OCB_BLOCK_SIZE];
    unsigned char sum[OCB_BLOCK_SIZE];
    unsigned char block[OCB_BLOCK_SIZE];
    unsigned long long block_number;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < OCB_TAG_SIZE)
        return -1;
    *mlen = clen - OCB_TAG_SIZE;

    /* Initialize the OCB state */
    OCB_CONCAT(OCB_ALG_NAME,_init)(&state, k, npub, offset);

    /* Process all ciphertext blocks except the last */
    memset(sum, 0, sizeof(sum));
    block_number = 1;
    clen -= OCB_TAG_SIZE;
    while (clen >= OCB_BLOCK_SIZE) {
        if (block_number & 1) {
            lw_xor_block(offset, state.L0, OCB_BLOCK_SIZE);
        } else if ((block_number & 3) == 2) {
            lw_xor_block(offset, state.L1, OCB_BLOCK_SIZE);
        } else {
            OCB_CONCAT(OCB_ALG_NAME,_calculate_L)(&state, block, block_number);
            lw_xor_block(offset, block, OCB_BLOCK_SIZE);
        }
        lw_xor_block_2_src(block, offset, c, OCB_BLOCK_SIZE);
        OCB_DECRYPT_BLOCK(&(state.ks), block, block);
        lw_xor_block_2_src(m, block, offset, OCB_BLOCK_SIZE);
        lw_xor_block(sum, m, OCB_BLOCK_SIZE);
        c += OCB_BLOCK_SIZE;
        m += OCB_BLOCK_SIZE;
        clen -= OCB_BLOCK_SIZE;
        ++block_number;
    }

    /* Pad and process the last ciphertext block */
    if (clen > 0) {
        unsigned temp = (unsigned)clen;
        lw_xor_block(offset, state.Lstar, OCB_BLOCK_SIZE);
        OCB_ENCRYPT_BLOCK(&(state.ks), block, offset);
        lw_xor_block_2_src(m, block, c, temp);
        lw_xor_block(sum, m, temp);
        sum[temp] ^= 0x80;
        c += temp;
    }

    /* Finalize the decryption phase */
    lw_xor_block(sum, offset, OCB_BLOCK_SIZE);
    lw_xor_block(sum, state.Ldollar, OCB_BLOCK_SIZE);
    OCB_ENCRYPT_BLOCK(&(state.ks), sum, sum);

    /* Process the associated data and check the final authentication tag */
    OCB_CONCAT(OCB_ALG_NAME,_process_ad)(&state, sum, ad, adlen);
    return aead_check_tag(mtemp, *mlen, sum, c, OCB_TAG_SIZE);
}

#endif /* OCB_ENCRYPT_BLOCK */

#endif /* LW_INTERNAL_OCB_H */
