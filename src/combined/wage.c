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

#include "wage.h"
#include "internal-wage.h"
#include <string.h>

aead_cipher_t const wage_cipher = {
    "WAGE",
    WAGE_KEY_SIZE,
    WAGE_NONCE_SIZE,
    WAGE_TAG_SIZE,
    AEAD_FLAG_NONE,
    wage_aead_encrypt,
    wage_aead_decrypt
};

/**
 * \brief Rate of absorbing data into the WAGE state in sponge mode.
 */
#define WAGE_RATE 8

/**
 * \brief Processes associated data for WAGE.
 *
 * \param state Points to the WAGE state.
 * \param pad Points to an 8-byte temporary buffer for handling padding.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data.
 */
static void wage_process_ad
    (unsigned char state[WAGE_STATE_SIZE], unsigned char pad[WAGE_RATE],
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Process as many full blocks as possible */
    while (adlen >= WAGE_RATE) {
        wage_absorb(state, ad);
        state[0] ^= 0x40;
        wage_permute(state);
        ad += WAGE_RATE;
        adlen -= WAGE_RATE;
    }

    /* Pad and absorb the final block */
    temp = (unsigned)adlen;
    memcpy(pad, ad, temp);
    pad[temp] = 0x80;
    memset(pad + temp + 1, 0, WAGE_RATE - temp - 1);
    wage_absorb(state, pad);
    state[0] ^= 0x40;
    wage_permute(state);
}

int wage_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[WAGE_STATE_SIZE];
    unsigned char block[WAGE_RATE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + WAGE_TAG_SIZE;

    /* Initialize the state and absorb the associated data */
    wage_init(state, k, npub);
    if (adlen != 0)
        wage_process_ad(state, block, ad, adlen);

    /* Encrypts the plaintext to produce the ciphertext */
    while (mlen >= WAGE_RATE) {
        wage_get_rate(state, block);
        lw_xor_block(block, m, WAGE_RATE);
        wage_set_rate(state, block);
        state[0] ^= 0x20;
        wage_permute(state);
        memcpy(c, block, WAGE_RATE);
        c += WAGE_RATE;
        m += WAGE_RATE;
        mlen -= WAGE_RATE;
    }
    temp = (unsigned)mlen;
    wage_get_rate(state, block);
    lw_xor_block(block, m, temp);
    block[temp] ^= 0x80;
    wage_set_rate(state, block);
    state[0] ^= 0x20;
    wage_permute(state);
    memcpy(c, block, temp);

    /* Generate and extract the authentication tag */
    wage_absorb_key(state, k);
    wage_extract_tag(state, c + temp);
    return 0;
}

int wage_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[WAGE_STATE_SIZE];
    unsigned char block[WAGE_TAG_SIZE];
    unsigned char *mtemp = m;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < WAGE_TAG_SIZE)
        return -1;
    *mlen = clen - WAGE_TAG_SIZE;

    /* Initialize the state and absorb the associated data */
    wage_init(state, k, npub);
    if (adlen != 0)
        wage_process_ad(state, block, ad, adlen);

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= WAGE_TAG_SIZE;
    while (clen >= WAGE_RATE) {
        wage_get_rate(state, block);
        lw_xor_block(block, c, WAGE_RATE);
        wage_set_rate(state, c);
        state[0] ^= 0x20;
        wage_permute(state);
        memcpy(m, block, WAGE_RATE);
        c += WAGE_RATE;
        m += WAGE_RATE;
        clen -= WAGE_RATE;
    }
    temp = (unsigned)clen;
    wage_get_rate(state, block);
    lw_xor_block_2_src(block + 8, block, c, temp);
    memcpy(block, c, temp);
    block[temp] ^= 0x80;
    wage_set_rate(state, block);
    state[0] ^= 0x20;
    wage_permute(state);
    memcpy(m, block + 8, temp);

    /* Generate and check the authentication tag */
    wage_absorb_key(state, k);
    wage_extract_tag(state, block);
    return aead_check_tag(mtemp, *mlen, block, c + temp, WAGE_TAG_SIZE);
}
