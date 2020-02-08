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

#include "spoc.h"
#include "internal-sliscp-light.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Size of the state for the internal sLiSCP-light-256 permutation.
 */
#define SPOC_128_STATE_SIZE SLISCP_LIGHT256_STATE_SIZE

/**
 * \brief Rate for absorbing data into the sLiSCP-light-256 state and for
 * squeezing data out again.
 */
#define SPOC_128_RATE 16

/**
 * \brief Size of the state for the internal sLiSCP-light-192 permutation.
 */
#define SPOC_64_STATE_SIZE SLISCP_LIGHT192_STATE_SIZE

/**
 * \brief Rate for absorbing data into the sLiSCP-light-192 state and for
 * squeezing data out again.
 */
#define SPOC_64_RATE 8

aead_cipher_t const spoc_128_cipher = {
    "SpoC-128",
    SPOC_KEY_SIZE,
    SPOC_NONCE_SIZE,
    SPOC_128_TAG_SIZE,
    AEAD_FLAG_NONE,
    spoc_128_aead_encrypt,
    spoc_128_aead_decrypt
};

aead_cipher_t const spoc_64_cipher = {
    "SpoC-64",
    SPOC_KEY_SIZE,
    SPOC_NONCE_SIZE,
    SPOC_64_TAG_SIZE,
    AEAD_FLAG_NONE,
    spoc_64_aead_encrypt,
    spoc_64_aead_decrypt
};

/* Indices of where a rate byte is located to help with padding */
static unsigned char const spoc_128_rate_posn[16] = {
    0, 1, 2, 3, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23
};
static unsigned char const spoc_128_mask_posn[16] = {
    8, 9, 10, 11, 12, 13, 14, 15, 24, 25, 26, 27, 28, 29, 30, 31
};
static unsigned char const spoc_64_rate_posn[8] = {
    0, 1, 2, 3, 12, 13, 14, 15
};
static unsigned char const spoc_64_mask_posn[8] = {
    6, 7, 8, 9, 18, 19, 20, 21
};

/**
 * \brief Initializes the SpoC-128 state.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spoc_128_init
    (unsigned char state[SPOC_128_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    memcpy(state, npub, 8);
    memcpy(state + 8, k, 8);
    memcpy(state + 16, npub + 8, 8);
    memcpy(state + 24, k + 8, 8);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPOC_128_RATE) {
            sliscp_light256_permute(state, 18);
            lw_xor_block(state + 8, ad, 8);
            lw_xor_block(state + 24, ad + 8, 8);
            state[0] ^= 0x20; /* domain separation */
            ad += SPOC_128_RATE;
            adlen -= SPOC_128_RATE;
        }
        temp = (unsigned)adlen;
        if (temp > 0) {
            sliscp_light256_permute(state, 18);
            state[spoc_128_mask_posn[temp]] ^= 0x80; /* padding */
            state[0] ^= 0x30; /* domain separation */
            while (temp > 0) {
                --temp;
                state[spoc_128_mask_posn[temp]] ^= ad[temp];
            }
        }
    }
}

/**
 * \brief Initializes the SpoC-64 state.
 *
 * \param state sLiSCP-light-192 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spoc_64_init
    (unsigned char state[SPOC_64_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    memcpy(state, npub, 4);
    state[4] = k[6];
    state[5] = k[7];
    memcpy(state + 6, k, 6);
    memcpy(state + 12, npub + 4, 4);
    state[16] = k[14];
    state[17] = k[15];
    memcpy(state + 18, k + 8, 6);
    sliscp_light192_permute(state);
    lw_xor_block(state + 6, npub + 8, 4);
    lw_xor_block(state + 18, npub + 12, 4);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPOC_64_RATE) {
            sliscp_light192_permute(state);
            lw_xor_block(state + 6, ad, 4);
            lw_xor_block(state + 18, ad + 4, 4);
            state[0] ^= 0x20; /* domain separation */
            ad += SPOC_64_RATE;
            adlen -= SPOC_64_RATE;
        }
        temp = (unsigned)adlen;
        if (temp > 0) {
            sliscp_light192_permute(state);
            state[spoc_64_mask_posn[temp]] ^= 0x80; /* padding */
            state[0] ^= 0x30; /* domain separation */
            while (temp > 0) {
                --temp;
                state[spoc_64_mask_posn[temp]] ^= ad[temp];
            }
        }
    }
}

/**
 * \brief Finalizes the SpoC-128 encryption or decryption operation.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spoc_128_finalize
    (unsigned char state[SPOC_128_STATE_SIZE], unsigned char *tag)
{
    /* Pad and permute the state one more time */
    state[0] ^= 0x80;
    sliscp_light256_permute(state, 18);

    /* Copy out the authentication tag */
    memcpy(tag, state + 8, 8);
    memcpy(tag + 8, state + 24, 8);
}

/**
 * \brief Finalizes the SpoC-64 encryption or decryption operation.
 *
 * \param state sLiSCP-light-192 permutation state.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spoc_64_finalize
    (unsigned char state[SPOC_64_STATE_SIZE], unsigned char *tag)
{
    /* Pad and permute the state one more time */
    state[0] ^= 0x80;
    sliscp_light192_permute(state);

    /* Copy out the authentication tag */
    memcpy(tag, state + 6, 4);
    memcpy(tag + 4, state + 18, 4);
}

int spoc_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPOC_128_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOC_128_TAG_SIZE;

    /* Initialize the SpoC-128 state and absorb the associated data */
    spoc_128_init(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen != 0) {
        while (mlen >= SPOC_128_RATE) {
            sliscp_light256_permute(state, 18);
            lw_xor_block(state + 8, m, 8);
            lw_xor_block(state + 24, m + 8, 8);
            lw_xor_block_2_src(c, m, state, 8);
            lw_xor_block_2_src(c + 8, m + 8, state + 16, 8);
            state[0] ^= 0x40; /* domain separation */
            c += SPOC_128_RATE;
            m += SPOC_128_RATE;
            mlen -= SPOC_128_RATE;
        }
        if (mlen != 0) {
            unsigned temp = (unsigned)mlen;
            sliscp_light256_permute(state, 18);
            state[spoc_128_mask_posn[temp]] ^= 0x80; /* padding */
            while (temp > 0) {
                --temp;
                unsigned char mbyte = m[temp];
                state[spoc_128_mask_posn[temp]] ^= mbyte;
                c[temp] = mbyte ^ state[spoc_128_rate_posn[temp]];
            }
            state[0] ^= 0x50; /* domain separation */
            c += mlen;
        }
    }

    /* Finalize and generate the authentication tag */
    spoc_128_finalize(state, c);
    return 0;
}

int spoc_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPOC_128_STATE_SIZE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOC_128_TAG_SIZE)
        return -1;
    *mlen = clen - SPOC_128_TAG_SIZE;

    /* Initialize the Spoc-128 state and absorb the associated data */
    spoc_128_init(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOC_128_TAG_SIZE;
    if (clen != 0) {
        while (clen >= SPOC_128_RATE) {
            sliscp_light256_permute(state, 18);
            lw_xor_block_2_src(m, c, state, 8);
            lw_xor_block_2_src(m + 8, c + 8, state + 16, 8);
            lw_xor_block(state + 8, m, 8);
            lw_xor_block(state + 24, m + 8, 8);
            state[0] ^= 0x40; /* domain separation */
            c += SPOC_128_RATE;
            m += SPOC_128_RATE;
            clen -= SPOC_128_RATE;
        }
        if (clen != 0) {
            unsigned temp = (unsigned)clen;
            sliscp_light256_permute(state, 18);
            state[spoc_128_mask_posn[temp]] ^= 0x80; /* padding */
            while (temp > 0) {
                --temp;
                unsigned char mbyte = c[temp] ^ state[spoc_128_rate_posn[temp]];
                state[spoc_128_mask_posn[temp]] ^= mbyte;
                m[temp] = mbyte;
            }
            state[0] ^= 0x50; /* domain separation */
            c += clen;
        }
    }

    /* Finalize and check the authentication tag */
    spoc_128_finalize(state, state);
    return aead_check_tag(mtemp, *mlen, state, c, SPOC_128_TAG_SIZE);
}

int spoc_64_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPOC_64_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOC_64_TAG_SIZE;

    /* Initialize the SpoC-64 state and absorb the associated data */
    spoc_64_init(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen != 0) {
        while (mlen >= SPOC_64_RATE) {
            sliscp_light192_permute(state);
            lw_xor_block(state + 6, m, 4);
            lw_xor_block(state + 18, m + 4, 4);
            lw_xor_block_2_src(c, m, state, 4);
            lw_xor_block_2_src(c + 4, m + 4, state + 12, 4);
            state[0] ^= 0x40; /* domain separation */
            c += SPOC_64_RATE;
            m += SPOC_64_RATE;
            mlen -= SPOC_64_RATE;
        }
        if (mlen != 0) {
            unsigned temp = (unsigned)mlen;
            sliscp_light192_permute(state);
            state[spoc_64_mask_posn[temp]] ^= 0x80; /* padding */
            while (temp > 0) {
                --temp;
                unsigned char mbyte = m[temp];
                state[spoc_64_mask_posn[temp]] ^= mbyte;
                c[temp] = mbyte ^ state[spoc_64_rate_posn[temp]];
            }
            state[0] ^= 0x50; /* domain separation */
            c += mlen;
        }
    }

    /* Finalize and generate the authentication tag */
    spoc_64_finalize(state, c);
    return 0;
}

int spoc_64_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPOC_64_STATE_SIZE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOC_64_TAG_SIZE)
        return -1;
    *mlen = clen - SPOC_64_TAG_SIZE;

    /* Initialize the Spoc-64 state and absorb the associated data */
    spoc_64_init(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOC_64_TAG_SIZE;
    if (clen != 0) {
        while (clen >= SPOC_64_RATE) {
            sliscp_light192_permute(state);
            lw_xor_block_2_src(m, c, state, 4);
            lw_xor_block_2_src(m + 4, c + 4, state + 12, 4);
            lw_xor_block(state + 6, m, 4);
            lw_xor_block(state + 18, m + 4, 4);
            state[0] ^= 0x40; /* domain separation */
            c += SPOC_64_RATE;
            m += SPOC_64_RATE;
            clen -= SPOC_64_RATE;
        }
        if (clen != 0) {
            unsigned temp = (unsigned)clen;
            sliscp_light192_permute(state);
            state[spoc_64_mask_posn[temp]] ^= 0x80; /* padding */
            while (temp > 0) {
                --temp;
                unsigned char mbyte = c[temp] ^ state[spoc_64_rate_posn[temp]];
                state[spoc_64_mask_posn[temp]] ^= mbyte;
                m[temp] = mbyte;
            }
            state[0] ^= 0x50; /* domain separation */
            c += clen;
        }
    }

    /* Finalize and check the authentication tag */
    spoc_64_finalize(state, state);
    return aead_check_tag(mtemp, *mlen, state, c, SPOC_64_TAG_SIZE);
}
