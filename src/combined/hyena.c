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

#include "hyena.h"
#include "internal-gift128.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const hyena_cipher = {
    "HYENA",
    HYENA_KEY_SIZE,
    HYENA_NONCE_SIZE,
    HYENA_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    hyena_aead_encrypt,
    hyena_aead_decrypt
};

/**
 * \brief Doubles a delta value in the F(2^64) field.
 *
 * \param D The delta value to be doubled.
 *
 * D = D << 1 if the top-most bit is 0, or D = (D << 1) ^ 0x1B otherwise.
 */
static void hyena_double_delta(unsigned char D[8])
{
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)(D[0])) >> 7);
    for (index = 0; index < 7; ++index)
        D[index] = (D[index] << 1) | (D[index + 1] >> 7);
    D[7] = (D[7] << 1) ^ (mask & 0x1B);
}

/**
 * \brief Process the associated data for HYENA.
 *
 * \param ks Key schedule for the GIFT-128 cipher.
 * \param Y Internal hash state of HYENA.
 * \param D Internal hash state of HYENA.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void hyena_process_ad
    (const gift128n_key_schedule_t *ks, unsigned char Y[16],
     unsigned char D[8], const unsigned char *ad,
     unsigned long long adlen)
{
    unsigned char feedback[16];
    hyena_double_delta(D);
    while (adlen > 16) {
        memcpy(feedback, ad, 16);
        lw_xor_block(feedback + 8, Y + 8, 8);
        lw_xor_block(feedback + 8, D, 8);
        lw_xor_block(Y, feedback, 16);
        gift128n_encrypt(ks, Y, Y);
        hyena_double_delta(D);
        ad += 16;
        adlen -= 16;
    }
    if (adlen == 16) {
        hyena_double_delta(D);
        memcpy(feedback, ad, 16);
        lw_xor_block(feedback + 8, Y + 8, 8);
        lw_xor_block(feedback + 8, D, 8);
        lw_xor_block(Y, feedback, 16);
    } else {
        unsigned temp = (unsigned)adlen;
        hyena_double_delta(D);
        hyena_double_delta(D);
        memcpy(feedback, ad, temp);
        feedback[temp] = 0x01;
        memset(feedback + temp + 1, 0, 15 - temp);
        if (temp > 8)
            lw_xor_block(feedback + 8, Y + 8, temp - 8);
        lw_xor_block(feedback + 8, D, 8);
        lw_xor_block(Y, feedback, 16);
    }
}

int hyena_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128n_key_schedule_t ks;
    unsigned char Y[16];
    unsigned char D[8];
    unsigned char feedback[16];
    unsigned index;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + HYENA_TAG_SIZE;

    /* Set up the key schedule and use it to encrypt the nonce */
    gift128n_init(&ks, k);
    Y[0] = 0;
    if (adlen == 0)
        Y[0] |= 0x01;
    if (adlen == 0 && mlen == 0)
        Y[0] |= 0x02;
    Y[1] = 0;
    Y[2] = 0;
    Y[3] = 0;
    memcpy(Y + 4, npub, HYENA_NONCE_SIZE);
    gift128n_encrypt(&ks, Y, Y);
    memcpy(D, Y + 8, 8);

    /* Process the associated data */
    hyena_process_ad(&ks, Y, D, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > 16) {
            gift128n_encrypt(&ks, Y, Y);
            hyena_double_delta(D);
            memcpy(feedback, m, 16);
            lw_xor_block(feedback + 8, Y + 8, 8);
            lw_xor_block(feedback + 8, D, 8);
            lw_xor_block_2_src(c, m, Y, 16);
            lw_xor_block(Y, feedback, 16);
            c += 16;
            m += 16;
            mlen -= 16;
        }
        gift128n_encrypt(&ks, Y, Y);
        if (mlen == 16) {
            hyena_double_delta(D);
            hyena_double_delta(D);
            memcpy(feedback, m, 16);
            lw_xor_block(feedback + 8, Y + 8, 8);
            lw_xor_block(feedback + 8, D, 8);
            lw_xor_block_2_src(c, m, Y, 16);
            lw_xor_block(Y, feedback, 16);
            c += 16;
        } else {
            unsigned temp = (unsigned)mlen;
            hyena_double_delta(D);
            hyena_double_delta(D);
            hyena_double_delta(D);
            memcpy(feedback, m, temp);
            feedback[temp] = 0x01;
            memset(feedback + temp + 1, 0, 15 - temp);
            if (temp > 8)
                lw_xor_block(feedback + 8, Y + 8, temp - 8);
            lw_xor_block(feedback + 8, D, 8);
            lw_xor_block_2_src(c, m, Y, temp);
            lw_xor_block(Y, feedback, 16);
            c += temp;
        }
    }

    /* Swap the two halves of Y and generate the authentication tag */
    for (index = 0; index < 8; ++index) {
        unsigned char temp1 = Y[index];
        unsigned char temp2 = Y[index + 8];
        Y[index] = temp2;
        Y[index + 8] = temp1;
    }
    gift128n_encrypt(&ks, c, Y);
    return 0;
}

int hyena_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128n_key_schedule_t ks;
    unsigned char Y[16];
    unsigned char D[8];
    unsigned char feedback[16];
    unsigned char *mtemp;
    unsigned index;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < HYENA_TAG_SIZE)
        return -1;
    *mlen = clen - HYENA_TAG_SIZE;

    /* Set up the key schedule and use it to encrypt the nonce */
    gift128n_init(&ks, k);
    Y[0] = 0;
    if (adlen == 0)
        Y[0] |= 0x01;
    if (adlen == 0 && clen == HYENA_TAG_SIZE)
        Y[0] |= 0x02;
    Y[1] = 0;
    Y[2] = 0;
    Y[3] = 0;
    memcpy(Y + 4, npub, HYENA_NONCE_SIZE);
    gift128n_encrypt(&ks, Y, Y);
    memcpy(D, Y + 8, 8);

    /* Process the associated data */
    hyena_process_ad(&ks, Y, D, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= HYENA_TAG_SIZE;
    mtemp = m;
    if (clen > 0) {
        while (clen > 16) {
            gift128n_encrypt(&ks, Y, Y);
            hyena_double_delta(D);
            memcpy(feedback + 8, c + 8, 8);
            lw_xor_block_2_src(m, c, Y, 16);
            memcpy(feedback, m, 8);
            lw_xor_block(feedback + 8, D, 8);
            lw_xor_block(Y, feedback, 16);
            c += 16;
            m += 16;
            clen -= 16;
        }
        gift128n_encrypt(&ks, Y, Y);
        if (clen == 16) {
            hyena_double_delta(D);
            hyena_double_delta(D);
            memcpy(feedback + 8, c + 8, 8);
            lw_xor_block_2_src(m, c, Y, 16);
            memcpy(feedback, m, 8);
            lw_xor_block(feedback + 8, D, 8);
            lw_xor_block(Y, feedback, 16);
            c += 16;
        } else {
            unsigned temp = (unsigned)clen;
            hyena_double_delta(D);
            hyena_double_delta(D);
            hyena_double_delta(D);
            if (temp > 8) {
                memcpy(feedback + 8, c + 8, temp - 8);
                lw_xor_block_2_src(m, c, Y, temp);
                memcpy(feedback, m, 8);
            } else {
                lw_xor_block_2_src(m, c, Y, temp);
                memcpy(feedback, m, temp);
            }
            feedback[temp] = 0x01;
            memset(feedback + temp + 1, 0, 15 - temp);
            lw_xor_block(feedback + 8, D, 8);
            lw_xor_block(Y, feedback, 16);
            c += temp;
        }
    }

    /* Swap the two halves of Y and check the authentication tag */
    for (index = 0; index < 8; ++index) {
        unsigned char temp1 = Y[index];
        unsigned char temp2 = Y[index + 8];
        Y[index] = temp2;
        Y[index + 8] = temp1;
    }
    gift128n_encrypt(&ks, Y, Y);
    return aead_check_tag(mtemp, *mlen, Y, c, HYENA_TAG_SIZE);
}
