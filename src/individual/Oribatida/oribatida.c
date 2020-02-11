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

#include "oribatida.h"
#include "internal-simp.h"
#include <string.h>

/**
 * \brief Rate for processing data for the Oribatida-256-64 state.
 */
#define ORIBATIDA_256_RATE 16

/**
 * \brief Size of the masking value for Oribatida-256-64.
 */
#define ORIBATIDA_256_MASK_SIZE 8

/**
 * \brief Rate for processing data for the Oribatida-192-96 state.
 */
#define ORIBATIDA_192_RATE 12

/**
 * \brief Size of the masking value for Oribatida-192-96.
 */
#define ORIBATIDA_192_MASK_SIZE 12

aead_cipher_t const oribatida_256_cipher = {
    "Oribatida-256-64",
    ORIBATIDA_256_KEY_SIZE,
    ORIBATIDA_256_NONCE_SIZE,
    ORIBATIDA_256_TAG_SIZE,
    AEAD_FLAG_NONE,
    oribatida_256_aead_encrypt,
    oribatida_256_aead_decrypt
};

aead_cipher_t const oribatida_192_cipher = {
    "Oribatida-192-96",
    ORIBATIDA_192_KEY_SIZE,
    ORIBATIDA_192_NONCE_SIZE,
    ORIBATIDA_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    oribatida_192_aead_encrypt,
    oribatida_192_aead_decrypt
};

/* Definitions for domain separation values */
#define ORIBATIDA_NUM_DOMAINS 3
#define ORIBATIDA_DOMAIN_NONCE 0
#define ORIBATIDA_DOMAIN_AD 1
#define ORIBATIDA_DOMAIN_MSG 2

/**
 * \brief Gets the domain separation values to use for different phases
 * of the Oribatida encryption process.
 *
 * \param domains Returns the domain separation values to use.
 * \param adlen Length of the associated data.
 * \param mlen Length of the plaintext message.
 * \param rate Rate of processing message blocks, 12 or 16.
 */
static void oribatida_get_domains
    (unsigned char domains[ORIBATIDA_NUM_DOMAINS],
     unsigned long long adlen, unsigned long long mlen, unsigned rate)
{
    /* Domain separation value for the nonce */
    if (adlen == 0 && mlen == 0) {
        domains[ORIBATIDA_DOMAIN_NONCE] = 9;
    } else {
        domains[ORIBATIDA_DOMAIN_NONCE] = 5;
    }

    /* Domain separation value for associated data processing */
    if (mlen == 0) {
        if ((adlen % rate) == 0)
            domains[ORIBATIDA_DOMAIN_AD] = 12;
        else
            domains[ORIBATIDA_DOMAIN_AD] = 14;
    } else {
        if ((adlen % rate) == 0)
            domains[ORIBATIDA_DOMAIN_AD] = 4;
        else
            domains[ORIBATIDA_DOMAIN_AD] = 6;
    }

    /* Domain separation value for message processing */
    if ((mlen % rate) == 0) {
        domains[ORIBATIDA_DOMAIN_MSG] = 13;
    } else {
        domains[ORIBATIDA_DOMAIN_MSG] = 15;
    }
}

/**
 * \brief Initializes the Oribatida-256-64 state.
 *
 * \param state Oribatida-256-64 permutation state.
 * \param mask Oribatida-256-64 masking state.
 * \param domains Precomputed domain separation values.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data.
 */
static void oribatida_256_init
    (unsigned char state[SIMP_256_STATE_SIZE],
     unsigned char mask[ORIBATIDA_256_MASK_SIZE],
     const unsigned char domains[ORIBATIDA_NUM_DOMAINS],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state with the key and nonce */
    memcpy(state, npub, ORIBATIDA_256_NONCE_SIZE);
    memcpy(state + ORIBATIDA_256_NONCE_SIZE, k, ORIBATIDA_256_KEY_SIZE);

    /* Use the current state as the mask for zero-length associated data */
    if (adlen == 0) {
        memcpy(mask, state + SIMP_256_STATE_SIZE - ORIBATIDA_256_MASK_SIZE,
               ORIBATIDA_256_MASK_SIZE);
    }

    /* Add the domain separation value for the nonce */
    state[SIMP_256_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_NONCE];

    /* Run the permutation for the first time */
    simp_256_permute(state, 4);

    /* If there is no associated data, then we are done */
    if (adlen == 0)
        return;

    /* Use the current state as the mask for non-zero length associated data */
    memcpy(mask, state + SIMP_256_STATE_SIZE - ORIBATIDA_256_MASK_SIZE,
           ORIBATIDA_256_MASK_SIZE);

    /* Process all associated data blocks except the last */
    while (adlen > ORIBATIDA_256_RATE) {
        lw_xor_block(state, ad, ORIBATIDA_256_RATE);
        simp_256_permute(state, 2);
        ad += ORIBATIDA_256_RATE;
        adlen -= ORIBATIDA_256_RATE;
    }

    /* Process the final associated data block */
    temp = (unsigned)adlen;
    if (temp == ORIBATIDA_256_RATE) {
        lw_xor_block(state, ad, ORIBATIDA_256_RATE);
    } else {
        lw_xor_block(state, ad, temp);
        state[temp] ^= 0x80; /* padding */
    }
    state[SIMP_256_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_AD];
    simp_256_permute(state, 4);
}

/**
 * \brief Initializes the Oribatida-192-96 state.
 *
 * \param state Oribatida-192-96 permutation state.
 * \param mask Oribatida-192-96 masking state.
 * \param domains Precomputed domain separation values.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data.
 */
static void oribatida_192_init
    (unsigned char state[SIMP_192_STATE_SIZE],
     unsigned char mask[ORIBATIDA_192_MASK_SIZE],
     const unsigned char domains[ORIBATIDA_NUM_DOMAINS],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state with the key and nonce */
    memcpy(state, npub, ORIBATIDA_192_NONCE_SIZE);
    memcpy(state + ORIBATIDA_192_NONCE_SIZE, k, ORIBATIDA_256_KEY_SIZE);

    /* Use the current state as the mask for zero-length associated data */
    if (adlen == 0) {
        memcpy(mask, state + SIMP_192_STATE_SIZE - ORIBATIDA_192_MASK_SIZE,
               ORIBATIDA_192_MASK_SIZE);
    }

    /* Add the domain separation value for the nonce */
    state[SIMP_192_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_NONCE];

    /* Run the permutation for the first time */
    simp_192_permute(state, 4);

    /* If there is no associated data, then we are done */
    if (adlen == 0)
        return;

    /* Use the current state as the mask for non-zero length associated data */
    memcpy(mask, state + SIMP_192_STATE_SIZE - ORIBATIDA_192_MASK_SIZE,
           ORIBATIDA_192_MASK_SIZE);

    /* Process all associated data blocks except the last */
    while (adlen > ORIBATIDA_192_RATE) {
        lw_xor_block(state, ad, ORIBATIDA_192_RATE);
        simp_192_permute(state, 2);
        ad += ORIBATIDA_192_RATE;
        adlen -= ORIBATIDA_192_RATE;
    }

    /* Process the final associated data block */
    temp = (unsigned)adlen;
    if (temp == ORIBATIDA_192_RATE) {
        lw_xor_block(state, ad, ORIBATIDA_192_RATE);
    } else {
        lw_xor_block(state, ad, temp);
        state[temp] ^= 0x80; /* padding */
    }
    state[SIMP_192_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_AD];
    simp_192_permute(state, 4);
}

int oribatida_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SIMP_256_STATE_SIZE];
    unsigned char mask[ORIBATIDA_256_MASK_SIZE];
    unsigned char domains[ORIBATIDA_NUM_DOMAINS];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ORIBATIDA_256_TAG_SIZE;

    /* Initialize the state and absorb the associated data */
    oribatida_get_domains(domains, adlen, mlen, ORIBATIDA_256_RATE);
    oribatida_256_init(state, mask, domains, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen > ORIBATIDA_256_RATE) {
        lw_xor_block_2_dest(c, state, m, ORIBATIDA_256_RATE);
        lw_xor_block(c + ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE,
                     mask, ORIBATIDA_256_MASK_SIZE);
        memcpy(mask, state + SIMP_256_STATE_SIZE - ORIBATIDA_256_MASK_SIZE,
               ORIBATIDA_256_MASK_SIZE);
        simp_256_permute(state, 4);
        c += ORIBATIDA_256_RATE;
        m += ORIBATIDA_256_RATE;
        mlen -= ORIBATIDA_256_RATE;
    }
    if (mlen == ORIBATIDA_256_RATE) {
        lw_xor_block_2_dest(c, state, m, ORIBATIDA_256_RATE);
        lw_xor_block(c + ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE,
                     mask, ORIBATIDA_256_MASK_SIZE);
        state[SIMP_256_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_256_permute(state, 4);
    } else if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        lw_xor_block_2_dest(c, state, m, temp);
        if (temp > (ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE)) {
            lw_xor_block
                (c + ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE, mask,
                 temp - (ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE));
        }
        state[temp] ^= 0x80; /* padding */
        state[SIMP_256_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_256_permute(state, 4);
    }

    /* Generate the authentication tag */
    memcpy(c + mlen, state, ORIBATIDA_256_TAG_SIZE);
    return 0;
}

int oribatida_256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SIMP_256_STATE_SIZE];
    unsigned char mask[ORIBATIDA_256_MASK_SIZE];
    unsigned char domains[ORIBATIDA_NUM_DOMAINS];
    unsigned char block[ORIBATIDA_256_RATE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ORIBATIDA_256_TAG_SIZE)
        return -1;
    *mlen = clen - ORIBATIDA_256_TAG_SIZE;

    /* Initialize the state and absorb the associated data */
    clen -= ORIBATIDA_256_TAG_SIZE;
    oribatida_get_domains(domains, adlen, clen, ORIBATIDA_256_RATE);
    oribatida_256_init(state, mask, domains, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    while (clen > ORIBATIDA_256_RATE) {
        memcpy(block, c, ORIBATIDA_256_RATE);
        lw_xor_block(block + ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE,
                     mask, ORIBATIDA_256_MASK_SIZE);
        lw_xor_block_swap(m, state, block, ORIBATIDA_256_RATE);
        memcpy(mask, state + SIMP_256_STATE_SIZE - ORIBATIDA_256_MASK_SIZE,
               ORIBATIDA_256_MASK_SIZE);
        simp_256_permute(state, 4);
        c += ORIBATIDA_256_RATE;
        m += ORIBATIDA_256_RATE;
        clen -= ORIBATIDA_256_RATE;
    }
    if (clen == ORIBATIDA_256_RATE) {
        memcpy(block, c, ORIBATIDA_256_RATE);
        lw_xor_block(block + ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE,
                     mask, ORIBATIDA_256_MASK_SIZE);
        lw_xor_block_swap(m, state, block, ORIBATIDA_256_RATE);
        state[SIMP_256_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_256_permute(state, 4);
    } else if (clen > 0) {
        unsigned temp = (unsigned)clen;
        memcpy(block, c, temp);
        if (temp > (ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE)) {
            lw_xor_block
                (block + ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE, mask,
                 temp - (ORIBATIDA_256_RATE - ORIBATIDA_256_MASK_SIZE));
        }
        lw_xor_block_swap(m, state, block, temp);
        state[temp] ^= 0x80; /* padding */
        state[SIMP_256_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_256_permute(state, 4);
    }
    c += clen;

    /* Check the authentication tag */
    return aead_check_tag(mtemp, *mlen, state, c, ORIBATIDA_256_TAG_SIZE);
}

int oribatida_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SIMP_192_STATE_SIZE];
    unsigned char mask[ORIBATIDA_192_MASK_SIZE];
    unsigned char domains[ORIBATIDA_NUM_DOMAINS];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ORIBATIDA_192_TAG_SIZE;

    /* Initialize the state and absorb the associated data */
    oribatida_get_domains(domains, adlen, mlen, ORIBATIDA_192_RATE);
    oribatida_192_init(state, mask, domains, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen > ORIBATIDA_192_RATE) {
        lw_xor_block_2_dest(c, state, m, ORIBATIDA_192_RATE);
        lw_xor_block(c + ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE,
                     mask, ORIBATIDA_192_MASK_SIZE);
        memcpy(mask, state + SIMP_192_STATE_SIZE - ORIBATIDA_192_MASK_SIZE,
               ORIBATIDA_192_MASK_SIZE);
        simp_192_permute(state, 4);
        c += ORIBATIDA_192_RATE;
        m += ORIBATIDA_192_RATE;
        mlen -= ORIBATIDA_192_RATE;
    }
    if (mlen == ORIBATIDA_192_RATE) {
        lw_xor_block_2_dest(c, state, m, ORIBATIDA_192_RATE);
        lw_xor_block(c + ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE,
                     mask, ORIBATIDA_192_MASK_SIZE);
        state[SIMP_192_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_192_permute(state, 4);
    } else if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        lw_xor_block_2_dest(c, state, m, temp);
        if (temp > (ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE)) {
            lw_xor_block
                (c + ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE, mask,
                 temp - (ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE));
        }
        state[temp] ^= 0x80; /* padding */
        state[SIMP_192_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_192_permute(state, 4);
    }

    /* Generate the authentication tag */
    memcpy(c + mlen, state, ORIBATIDA_192_TAG_SIZE);
    return 0;
}

int oribatida_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SIMP_192_STATE_SIZE];
    unsigned char mask[ORIBATIDA_192_MASK_SIZE];
    unsigned char domains[ORIBATIDA_NUM_DOMAINS];
    unsigned char block[ORIBATIDA_192_RATE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ORIBATIDA_192_TAG_SIZE)
        return -1;
    *mlen = clen - ORIBATIDA_192_TAG_SIZE;

    /* Initialize the state and absorb the associated data */
    clen -= ORIBATIDA_192_TAG_SIZE;
    oribatida_get_domains(domains, adlen, clen, ORIBATIDA_192_RATE);
    oribatida_192_init(state, mask, domains, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    while (clen > ORIBATIDA_192_RATE) {
        memcpy(block, c, ORIBATIDA_192_RATE);
        lw_xor_block(block + ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE,
                     mask, ORIBATIDA_192_MASK_SIZE);
        lw_xor_block_swap(m, state, block, ORIBATIDA_192_RATE);
        memcpy(mask, state + SIMP_192_STATE_SIZE - ORIBATIDA_192_MASK_SIZE,
               ORIBATIDA_192_MASK_SIZE);
        simp_192_permute(state, 4);
        c += ORIBATIDA_192_RATE;
        m += ORIBATIDA_192_RATE;
        clen -= ORIBATIDA_192_RATE;
    }
    if (clen == ORIBATIDA_192_RATE) {
        memcpy(block, c, ORIBATIDA_192_RATE);
        lw_xor_block(block + ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE,
                     mask, ORIBATIDA_192_MASK_SIZE);
        lw_xor_block_swap(m, state, block, ORIBATIDA_192_RATE);
        state[SIMP_192_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_192_permute(state, 4);
    } else if (clen > 0) {
        unsigned temp = (unsigned)clen;
        memcpy(block, c, temp);
        if (temp > (ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE)) {
            lw_xor_block
                (block + ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE, mask,
                 temp - (ORIBATIDA_192_RATE - ORIBATIDA_192_MASK_SIZE));
        }
        lw_xor_block_swap(m, state, block, temp);
        state[temp] ^= 0x80; /* padding */
        state[SIMP_192_STATE_SIZE - 1] ^= domains[ORIBATIDA_DOMAIN_MSG];
        simp_192_permute(state, 4);
    }
    c += clen;

    /* Check the authentication tag */
    return aead_check_tag(mtemp, *mlen, state, c, ORIBATIDA_192_TAG_SIZE);
}
