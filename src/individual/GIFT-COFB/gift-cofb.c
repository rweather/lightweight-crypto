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

#include "gift-cofb.h"
#include "internal-gift128.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const gift_cofb_cipher = {
    "GIFT-COFB",
    GIFT_COFB_KEY_SIZE,
    GIFT_COFB_NONCE_SIZE,
    GIFT_COFB_TAG_SIZE,
    AEAD_FLAG_NONE,
    gift_cofb_aead_encrypt,
    gift_cofb_aead_decrypt
};

/**
 * \brief Doubles an L value in the F(2^64) field.
 *
 * \param L The value to be doubled.
 *
 * L = L << 1 if the top-most bit is 0, or L = (L << 1) ^ 0x1B otherwise.
 */
static void gift_cofb_double_L(unsigned char L[8])
{
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)(L[0])) >> 7);
    for (index = 0; index < 7; ++index)
        L[index] = (L[index] << 1) | (L[index + 1] >> 7);
    L[7] = (L[7] << 1) ^ (mask & 0x1B);
}

/**
 * \brief Triples an L value in the F(2^64) field.
 *
 * \param L The value to be tripled.
 *
 * L = double(L) ^ L
 */
static void gift_cofb_triple_L(unsigned char L[8])
{
    unsigned char temp[8];
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)(L[0])) >> 7);
    for (index = 0; index < 7; ++index)
        temp[index] = (L[index] << 1) | (L[index + 1] >> 7);
    temp[7] = (L[7] << 1) ^ (mask & 0x1B);
    lw_xor_block(L, temp, 8);
}

/**
 * \brief Applies the GIFT-COFB feedback function to Y.
 *
 * \param Y The value to be modified with the feedback function.
 *
 * Y is divided into L and R halves and then (R, L <<< 1) is returned.
 */
static void gift_cofb_feedback(unsigned char Y[16])
{
    unsigned char temp[8];
    unsigned index;
    for (index = 0; index < 8; ++index) {
        temp[index] = Y[index];
        Y[index] = Y[index + 8];
    }
    for (index = 0; index < 7; ++index) {
        Y[index + 8] = (temp[index] << 1) | (temp[index + 1] >> 7);
    }
    Y[15] = (temp[7] << 1) | (temp[0] >> 7);
}

/**
 * \brief Process the associated data for GIFT-COFB encryption or decryption.
 *
 * \param ks The GIFT-128 key schedule to use.
 * \param Y GIFT-COFB internal state.
 * \param L GIFT-COFB internal state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 * \param mlen Length of the plaintext in bytes.
 */
static void gift_cofb_assoc_data
    (gift128b_key_schedule_t *ks, unsigned char Y[16], unsigned char L[8],
     const unsigned char *ad, unsigned long long adlen, unsigned long long mlen)
{
    /* Deal with all associated data blocks except the last */
    while (adlen > 16) {
        gift_cofb_double_L(L);
        gift_cofb_feedback(Y);
        lw_xor_block(Y, L, 8);
        lw_xor_block(Y, ad, 16);
        gift128b_encrypt(ks, Y, Y);
        ad += 16;
        adlen -= 16;
    }

    /* Pad and deal with the last block */
    gift_cofb_feedback(Y);
    if (adlen == 16) {
        lw_xor_block(Y, ad, 16);
        gift_cofb_triple_L(L);
    } else {
        unsigned temp = (unsigned)adlen;
        lw_xor_block(Y, ad, temp);
        Y[temp] ^= 0x80;
        gift_cofb_triple_L(L);
        gift_cofb_triple_L(L);
    }
    if (mlen == 0) {
        gift_cofb_triple_L(L);
        gift_cofb_triple_L(L);
    }
    lw_xor_block(Y, L, 8);
    gift128b_encrypt(ks, Y, Y);
}

int gift_cofb_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128b_key_schedule_t ks;
    unsigned char Y[16];
    unsigned char L[8];
    unsigned char P[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GIFT_COFB_TAG_SIZE;

    /* Set up the key schedule and use it to encrypt the nonce */
    if (!gift128b_init(&ks, k, GIFT_COFB_KEY_SIZE))
        return -1;
    gift128b_encrypt(&ks, Y, npub);
    memcpy(L, Y, sizeof(L));

    /* Authenticate the associated data */
    gift_cofb_assoc_data(&ks, Y, L, ad, adlen, mlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        /* Deal with all plaintext blocks except the last */
        while (mlen > 16) {
            lw_xor_block_copy_src(P, c, Y, m, 16);
            gift_cofb_double_L(L);
            gift_cofb_feedback(Y);
            lw_xor_block(Y, L, 8);
            lw_xor_block(Y, P, 16);
            gift128b_encrypt(&ks, Y, Y);
            c += 16;
            m += 16;
            mlen -= 16;
        }

        /* Pad and deal with the last plaintext block */
        if (mlen == 16) {
            lw_xor_block_copy_src(P, c, Y, m, 16);
            gift_cofb_feedback(Y);
            lw_xor_block(Y, P, 16);
            gift_cofb_triple_L(L);
            c += 16;
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_copy_src(P, c, Y, m, temp);
            gift_cofb_feedback(Y);
            lw_xor_block(Y, P, temp);
            Y[temp] ^= 0x80;
            gift_cofb_triple_L(L);
            gift_cofb_triple_L(L);
            c += temp;
        }
        lw_xor_block(Y, L, 8);
        gift128b_encrypt(&ks, Y, Y);
    }

    /* Generate the final authentication tag */
    memcpy(c, Y, GIFT_COFB_TAG_SIZE);
    return 0;
}

int gift_cofb_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128b_key_schedule_t ks;
    unsigned char Y[16];
    unsigned char L[8];
    unsigned char *mtemp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < GIFT_COFB_TAG_SIZE)
        return -1;
    *mlen = clen - GIFT_COFB_TAG_SIZE;

    /* Set up the key schedule and use it to encrypt the nonce */
    if (!gift128b_init(&ks, k, GIFT_COFB_KEY_SIZE))
        return -1;
    gift128b_encrypt(&ks, Y, npub);
    memcpy(L, Y, sizeof(L));

    /* Authenticate the associated data */
    gift_cofb_assoc_data(&ks, Y, L, ad, adlen, *mlen);

    /* Decrypt the ciphertext to produce the plaintext */
    mtemp = m;
    clen -= GIFT_COFB_TAG_SIZE;
    if (clen > 0) {
        /* Deal with all ciphertext blocks except the last */
        while (clen > 16) {
            lw_xor_block_2_src(m, c, Y, 16);
            gift_cofb_double_L(L);
            gift_cofb_feedback(Y);
            lw_xor_block(Y, L, 8);
            lw_xor_block(Y, m, 16);
            gift128b_encrypt(&ks, Y, Y);
            c += 16;
            m += 16;
            clen -= 16;
        }

        /* Pad and deal with the last ciphertext block */
        if (clen == 16) {
            lw_xor_block_2_src(m, c, Y, 16);
            gift_cofb_feedback(Y);
            lw_xor_block(Y, m, 16);
            gift_cofb_triple_L(L);
            c += 16;
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, c, Y, temp);
            gift_cofb_feedback(Y);
            lw_xor_block(Y, m, temp);
            Y[temp] ^= 0x80;
            gift_cofb_triple_L(L);
            gift_cofb_triple_L(L);
            c += temp;
        }
        lw_xor_block(Y, L, 8);
        gift128b_encrypt(&ks, Y, Y);
    }

    /* Check the authentication tag at the end of the packet */
    return aead_check_tag(mtemp, *mlen, Y, c, GIFT_COFB_TAG_SIZE, 0);
}
