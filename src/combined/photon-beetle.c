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

#include "photon-beetle.h"
#include "internal-photon256.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const photon_beetle_128_cipher = {
    "PHOTON-Beetle-AEAD-ENC-128",
    PHOTON_BEETLE_KEY_SIZE,
    PHOTON_BEETLE_NONCE_SIZE,
    PHOTON_BEETLE_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    photon_beetle_128_aead_encrypt,
    photon_beetle_128_aead_decrypt
};

aead_cipher_t const photon_beetle_32_cipher = {
    "PHOTON-Beetle-AEAD-ENC-32",
    PHOTON_BEETLE_KEY_SIZE,
    PHOTON_BEETLE_NONCE_SIZE,
    PHOTON_BEETLE_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    photon_beetle_32_aead_encrypt,
    photon_beetle_32_aead_decrypt
};

aead_hash_algorithm_t const photon_beetle_hash_algorithm = {
    "PHOTON-Beetle-HASH",
    sizeof(int),
    PHOTON_BEETLE_HASH_SIZE,
    AEAD_FLAG_NONE,
    photon_beetle_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \brief Rate of operation for PHOTON-Beetle-AEAD-ENC-128.
 */
#define PHOTON_BEETLE_128_RATE 16

/**
 * \brief Rate of operation for PHOTON-Beetle-AEAD-ENC-32.
 */
#define PHOTON_BEETLE_32_RATE 4

/* Shifts a domain constant from the spec to the correct bit position */
#define DOMAIN(c) ((c) << 5)

/**
 * \brief Processes the associated data for PHOTON-Beetle.
 *
 * \param state PHOTON-256 permutation state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be non-zero.
 * \param rate Rate of absorption for the data.
 * \param mempty Non-zero if the message is empty.
 */
static void photon_beetle_process_ad
    (unsigned char state[PHOTON256_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen,
     unsigned rate, int mempty)
{
    unsigned temp;

    /* Absorb as many full rate blocks as possible */
    while (adlen > rate) {
        photon256_permute(state);
        lw_xor_block(state, ad, rate);
        ad += rate;
        adlen -= rate;
    }

    /* Pad and absorb the last block */
    temp = (unsigned)adlen;
    photon256_permute(state);
    lw_xor_block(state, ad, temp);
    if (temp < rate)
        state[temp] ^= 0x01; /* padding */

    /* Add the domain constant to finalize associated data processing */
    if (mempty && temp == rate)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(3);
    else if (mempty)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(4);
    else if (temp == rate)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    else
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
}

/**
 * \brief Rotates part of the PHOTON-256 state right by one bit.
 *
 * \param out Output state buffer.
 * \param in Input state buffer, must not overlap with \a out.
 * \param len Length of the state buffer.
 */
static void photon_beetle_rotate1
    (unsigned char *out, const unsigned char *in, unsigned len)
{
    unsigned posn;
    for (posn = 0; posn < (len - 1); ++posn)
        out[posn] = (in[posn] >> 1) | (in[posn + 1] << 7);
    out[len - 1] = (in[len - 1] >> 1) | (in[0] << 7);
}

/**
 * \brief Encrypts a plaintext block with PHOTON-Beetle.
 *
 * \param state PHOTON-256 permutation state.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param mlen Length of the message, must be non-zero.
 * \param rate Rate of absorption for the data.
 * \param adempty Non-zero if the associated data is empty.
 */
static void photon_beetle_encrypt
    (unsigned char state[PHOTON256_STATE_SIZE],
     unsigned char *c, const unsigned char *m, unsigned long long mlen,
     unsigned rate, int adempty)
{
    unsigned char shuffle[PHOTON_BEETLE_128_RATE]; /* Block of max rate size */
    unsigned temp;

    /* Process all plaintext blocks except the last */
    while (mlen > rate) {
        photon256_permute(state);
        memcpy(shuffle, state + rate / 2, rate / 2);
        photon_beetle_rotate1(shuffle + rate / 2, state, rate / 2);
        lw_xor_block(state, m, rate);
        lw_xor_block_2_src(c, m, shuffle, rate);
        c += rate;
        m += rate;
        mlen -= rate;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    photon256_permute(state);
    memcpy(shuffle, state + rate / 2, rate / 2);
    photon_beetle_rotate1(shuffle + rate / 2, state, rate / 2);
    if (temp == rate) {
        lw_xor_block(state, m, rate);
        lw_xor_block_2_src(c, m, shuffle, rate);
    } else {
        lw_xor_block(state, m, temp);
        state[temp] ^= 0x01; /* padding */
        lw_xor_block_2_src(c, m, shuffle, temp);
    }

    /* Add the domain constant to finalize message processing */
    if (adempty && temp == rate)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(5);
    else if (adempty)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(6);
    else if (temp == rate)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    else
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
}

/**
 * \brief Decrypts a ciphertext block with PHOTON-Beetle.
 *
 * \param state PHOTON-256 permutation state.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param mlen Length of the message, must be non-zero.
 * \param rate Rate of absorption for the data.
 * \param adempty Non-zero if the associated data is empty.
 */
static void photon_beetle_decrypt
    (unsigned char state[PHOTON256_STATE_SIZE],
     unsigned char *m, const unsigned char *c, unsigned long long mlen,
     unsigned rate, int adempty)
{
    unsigned char shuffle[PHOTON_BEETLE_128_RATE]; /* Block of max rate size */
    unsigned temp;

    /* Process all plaintext blocks except the last */
    while (mlen > rate) {
        photon256_permute(state);
        memcpy(shuffle, state + rate / 2, rate / 2);
        photon_beetle_rotate1(shuffle + rate / 2, state, rate / 2);
        lw_xor_block_2_src(m, c, shuffle, rate);
        lw_xor_block(state, m, rate);
        c += rate;
        m += rate;
        mlen -= rate;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    photon256_permute(state);
    memcpy(shuffle, state + rate / 2, rate / 2);
    photon_beetle_rotate1(shuffle + rate / 2, state, rate / 2);
    if (temp == rate) {
        lw_xor_block_2_src(m, c, shuffle, rate);
        lw_xor_block(state, m, rate);
    } else {
        lw_xor_block_2_src(m, c, shuffle, temp);
        lw_xor_block(state, m, temp);
        state[temp] ^= 0x01; /* padding */
    }

    /* Add the domain constant to finalize message processing */
    if (adempty && temp == rate)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(5);
    else if (adempty)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(6);
    else if (temp == rate)
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    else
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
}

int photon_beetle_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state, npub, 16);
    memcpy(state + 16, k, 16);

    /* Process the associated data */
    if (adlen > 0) {
        photon_beetle_process_ad
            (state, ad, adlen, PHOTON_BEETLE_128_RATE, mlen == 0);
    } else if (mlen == 0) {
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        photon_beetle_encrypt
            (state, c, m, mlen, PHOTON_BEETLE_128_RATE, adlen == 0);
    }

    /* Generate the authentication tag */
    photon256_permute(state);
    memcpy(c + mlen, state, PHOTON_BEETLE_TAG_SIZE);
    return 0;
}

int photon_beetle_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < PHOTON_BEETLE_TAG_SIZE)
        return -1;
    *mlen = clen - PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state, npub, 16);
    memcpy(state + 16, k, 16);

    /* Process the associated data */
    clen -= PHOTON_BEETLE_TAG_SIZE;
    if (adlen > 0) {
        photon_beetle_process_ad
            (state, ad, adlen, PHOTON_BEETLE_128_RATE, clen == 0);
    } else if (clen == 0) {
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > 0) {
        photon_beetle_decrypt
            (state, m, c, clen, PHOTON_BEETLE_128_RATE, adlen == 0);
    }

    /* Check the authentication tag */
    photon256_permute(state);
    return aead_check_tag(m, clen, state, c + clen, PHOTON_BEETLE_TAG_SIZE);
}

int photon_beetle_32_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state, npub, 16);
    memcpy(state + 16, k, 16);

    /* Process the associated data */
    if (adlen > 0) {
        photon_beetle_process_ad
            (state, ad, adlen, PHOTON_BEETLE_32_RATE, mlen == 0);
    } else if (mlen == 0) {
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        photon_beetle_encrypt
            (state, c, m, mlen, PHOTON_BEETLE_32_RATE, adlen == 0);
    }

    /* Generate the authentication tag */
    photon256_permute(state);
    memcpy(c + mlen, state, PHOTON_BEETLE_TAG_SIZE);
    return 0;
}

int photon_beetle_32_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < PHOTON_BEETLE_TAG_SIZE)
        return -1;
    *mlen = clen - PHOTON_BEETLE_TAG_SIZE;

    /* Initialize the state by concatenating the nonce and the key */
    memcpy(state, npub, 16);
    memcpy(state + 16, k, 16);

    /* Process the associated data */
    clen -= PHOTON_BEETLE_TAG_SIZE;
    if (adlen > 0) {
        photon_beetle_process_ad
            (state, ad, adlen, PHOTON_BEETLE_32_RATE, clen == 0);
    } else if (clen == 0) {
        state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
    }

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > 0) {
        photon_beetle_decrypt
            (state, m, c, clen, PHOTON_BEETLE_32_RATE, adlen == 0);
    }

    /* Check the authentication tag */
    photon256_permute(state);
    return aead_check_tag(m, clen, state, c + clen, PHOTON_BEETLE_TAG_SIZE);
}

int photon_beetle_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    unsigned temp;

    /* Absorb the input data */
    if (inlen == 0) {
        /* No input data at all */
        memset(state, 0, sizeof(state) - 1);
        state[PHOTON256_STATE_SIZE - 1] = DOMAIN(1);
    } else if (inlen <= PHOTON_BEETLE_128_RATE) {
        /* Only one block of input data, which may require padding */
        temp = (unsigned)inlen;
        memcpy(state, in, temp);
        memset(state + temp, 0, sizeof(state) - temp - 1);
        if (temp < PHOTON_BEETLE_128_RATE) {
            state[temp] = 0x01;
            state[PHOTON256_STATE_SIZE - 1] = DOMAIN(1);
        } else {
            state[PHOTON256_STATE_SIZE - 1] = DOMAIN(2);
        }
    } else {
        /* Initialize the state with the first block, then absorb the rest */
        memcpy(state, in, PHOTON_BEETLE_128_RATE);
        memset(state + PHOTON_BEETLE_128_RATE, 0,
               sizeof(state) - PHOTON_BEETLE_128_RATE);
        in += PHOTON_BEETLE_128_RATE;
        inlen -= PHOTON_BEETLE_128_RATE;
        while (inlen > PHOTON_BEETLE_32_RATE) {
            photon256_permute(state);
            lw_xor_block(state, in, PHOTON_BEETLE_32_RATE);
            in += PHOTON_BEETLE_32_RATE;
            inlen -= PHOTON_BEETLE_32_RATE;
        }
        photon256_permute(state);
        temp = (unsigned)inlen;
        if (temp == PHOTON_BEETLE_32_RATE) {
            lw_xor_block(state, in, PHOTON_BEETLE_32_RATE);
            state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(1);
        } else {
            lw_xor_block(state, in, temp);
            state[temp] ^= 0x01;
            state[PHOTON256_STATE_SIZE - 1] ^= DOMAIN(2);
        }
    }

    /* Generate the output hash */
    photon256_permute(state);
    memcpy(out, state, 16);
    photon256_permute(state);
    memcpy(out + 16, state, 16);
    return 0;
}
