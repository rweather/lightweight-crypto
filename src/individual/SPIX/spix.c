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

#include "spix.h"
#include "internal-sliscp-light.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Size of the state for the internal sLiSCP-light permutation.
 */
#define SPIX_STATE_SIZE SLISCP_LIGHT256_STATE_SIZE

/**
 * \brief Rate for absorbing data into the sLiSCP-light state and for
 * squeezing data out again.
 */
#define SPIX_RATE 8

aead_cipher_t const spix_cipher = {
    "SPIX",
    SPIX_KEY_SIZE,
    SPIX_NONCE_SIZE,
    SPIX_TAG_SIZE,
    AEAD_FLAG_NONE,
    spix_aead_encrypt,
    spix_aead_decrypt
};

/* Indices of where a rate byte is located to help with padding */
static unsigned char const spix_rate_posn[8] = {
    8, 9, 10, 11, 24, 25, 26, 27
};

/**
 * \brief Initializes the SPIX state.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spix_init
    (unsigned char state[SPIX_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    memcpy(state, npub, 8);
    memcpy(state + 8, k, 8);
    memcpy(state + 16, npub + 8, 8);
    memcpy(state + 24, k + 8, 8);

    /* Run the permutation to scramble the initial state */
    sliscp_light256_permute(state, 18);

    /* Absorb the key in two further permutation operations */
    lw_xor_block(state + 8, k, 4);
    lw_xor_block(state + 24, k + 4, 4);
    sliscp_light256_permute(state, 18);
    lw_xor_block(state + 8, k + 8, 4);
    lw_xor_block(state + 24, k + 12, 4);
    sliscp_light256_permute(state, 18);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPIX_RATE) {
            lw_xor_block(state + 8, ad, 4);
            lw_xor_block(state + 24, ad + 4, 4);
            state[SPIX_STATE_SIZE - 1] ^= 0x01; /* domain separation */
            sliscp_light256_permute(state, 9);
            ad += SPIX_RATE;
            adlen -= SPIX_RATE;
        }
        temp = (unsigned)adlen;
        state[spix_rate_posn[temp]] ^= 0x80; /* padding */
        state[SPIX_STATE_SIZE - 1] ^= 0x01; /* domain separation */
        while (temp > 0) {
            --temp;
            state[spix_rate_posn[temp]] ^= ad[temp];
        }
        sliscp_light256_permute(state, 9);
    }
}

/**
 * \brief Finalizes the SPIX encryption or decryption operation.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spix_finalize
    (unsigned char state[SPIX_STATE_SIZE], const unsigned char *k,
     unsigned char *tag)
{
    /* Absorb the key into the state again */
    lw_xor_block(state + 8, k, 4);
    lw_xor_block(state + 24, k + 4, 4);
    sliscp_light256_permute(state, 18);
    lw_xor_block(state + 8, k + 8, 4);
    lw_xor_block(state + 24, k + 12, 4);
    sliscp_light256_permute(state, 18);

    /* Copy out the authentication tag */
    memcpy(tag, state + 8, 8);
    memcpy(tag + 8, state + 24, 8);
}

int spix_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPIX_STATE_SIZE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPIX_TAG_SIZE;

    /* Initialize the SPIX state and absorb the associated data */
    spix_init(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= SPIX_RATE) {
        lw_xor_block_2_dest(c, state + 8, m, 4);
        lw_xor_block_2_dest(c + 4, state + 24, m + 4, 4);
        state[SPIX_STATE_SIZE - 1] ^= 0x02; /* domain separation */
        sliscp_light256_permute(state, 9);
        c += SPIX_RATE;
        m += SPIX_RATE;
        mlen -= SPIX_RATE;
    }
    temp = (unsigned)mlen;
    state[spix_rate_posn[temp]] ^= 0x80; /* padding */
    state[SPIX_STATE_SIZE - 1] ^= 0x02; /* domain separation */
    while (temp > 0) {
        --temp;
        state[spix_rate_posn[temp]] ^= m[temp];
        c[temp] = state[spix_rate_posn[temp]];
    }
    sliscp_light256_permute(state, 9);
    c += mlen;

    /* Generate the authentication tag */
    spix_finalize(state, k, c);
    return 0;
}

int spix_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPIX_STATE_SIZE];
    unsigned char *mtemp = m;
    unsigned char cbyte;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPIX_TAG_SIZE)
        return -1;
    *mlen = clen - SPIX_TAG_SIZE;

    /* Initialize the SPIX state and absorb the associated data */
    spix_init(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPIX_TAG_SIZE;
    while (clen >= SPIX_RATE) {
        lw_xor_block_swap(m, state + 8, c, 4);
        lw_xor_block_swap(m + 4, state + 24, c + 4, 4);
        state[SPIX_STATE_SIZE - 1] ^= 0x02; /* domain separation */
        sliscp_light256_permute(state, 9);
        c += SPIX_RATE;
        m += SPIX_RATE;
        clen -= SPIX_RATE;
    }
    temp = (unsigned)clen;
    state[spix_rate_posn[temp]] ^= 0x80; /* padding */
    state[SPIX_STATE_SIZE - 1] ^= 0x02; /* domain separation */
    while (temp > 0) {
        --temp;
        cbyte = c[temp];
        m[temp] = cbyte ^ state[spix_rate_posn[temp]];
        state[spix_rate_posn[temp]] = cbyte;
    }
    sliscp_light256_permute(state, 9);
    c += clen;

    /* Finalize the SPIX state and compare against the authentication tag */
    spix_finalize(state, k, state);
    return aead_check_tag(mtemp, *mlen, state, c, SPIX_TAG_SIZE);
}
