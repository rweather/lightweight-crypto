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

#include "knot.h"
#include "internal-knot.h"
#include <string.h>

aead_cipher_t const knot_aead_128_256_cipher = {
    "KNOT-AEAD-128-256",
    KNOT_AEAD_128_KEY_SIZE,
    KNOT_AEAD_128_NONCE_SIZE,
    KNOT_AEAD_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_aead_128_256_encrypt,
    knot_aead_128_256_decrypt
};

aead_cipher_t const knot_aead_128_384_cipher = {
    "KNOT-AEAD-128-384",
    KNOT_AEAD_128_KEY_SIZE,
    KNOT_AEAD_128_NONCE_SIZE,
    KNOT_AEAD_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_aead_128_384_encrypt,
    knot_aead_128_384_decrypt
};

aead_cipher_t const knot_aead_192_384_cipher = {
    "KNOT-AEAD-192-384",
    KNOT_AEAD_192_KEY_SIZE,
    KNOT_AEAD_192_NONCE_SIZE,
    KNOT_AEAD_192_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_aead_192_384_encrypt,
    knot_aead_192_384_decrypt
};

aead_cipher_t const knot_aead_256_512_cipher = {
    "KNOT-AEAD-256-512",
    KNOT_AEAD_256_KEY_SIZE,
    KNOT_AEAD_256_NONCE_SIZE,
    KNOT_AEAD_256_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    knot_aead_256_512_encrypt,
    knot_aead_256_512_decrypt
};

/**
 * \brief Rate for KNOT-AEAD-128-256.
 */
#define KNOT_AEAD_128_256_RATE 8

/**
 * \brief Rate for KNOT-AEAD-128-384.
 */
#define KNOT_AEAD_128_384_RATE 24

/**
 * \brief Rate for KNOT-AEAD-192-384.
 */
#define KNOT_AEAD_192_384_RATE 12

/**
 * \brief Rate for KNOT-AEAD-256-512.
 */
#define KNOT_AEAD_256_512_RATE 16

/**
 * \brief Absorbs the associated data into a KNOT permutation state.
 *
 * \param state Points to the KNOT permutation state.
 * \param permute Points to the function to perform the KNOT permutation.
 * \param rounds Number of rounds to perform.
 * \param rate Rate of absorption to use with the permutation.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be at least 1.
 */
static void knot_aead_absorb_ad
    (void *state, knot_permute_t permute, uint8_t rounds, unsigned rate,
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen >= rate) {
        lw_xor_block((unsigned char *)state, ad, rate);
        permute(state, rounds);
        ad += rate;
        adlen -= rate;
    }
    rate = (unsigned)adlen;
    lw_xor_block((unsigned char *)state, ad, rate);
    ((unsigned char *)state)[rate] ^= 0x01;
    permute(state, rounds);
}

/**
 * \brief Encrypts plaintext data with a KNOT permutation state.
 *
 * \param state Points to the KNOT permutation state.
 * \param permute Points to the function to perform the KNOT permutation.
 * \param rounds Number of rounds to perform.
 * \param rate Rate of absorption to use with the permutation.
 * \param c Buffer to receive the ciphertext.
 * \param m Buffer containing the plaintext.
 * \param len Length of the plaintext data, must be at least 1.
 */
static void knot_aead_encrypt
    (void *state, knot_permute_t permute, uint8_t rounds, unsigned rate,
     unsigned char *c, const unsigned char *m, unsigned long long len)
{
    while (len >= rate) {
        lw_xor_block_2_dest(c, (unsigned char *)state, m, rate);
        permute(state, rounds);
        c += rate;
        m += rate;
        len -= rate;
    }
    rate = (unsigned)len;
    lw_xor_block_2_dest(c, (unsigned char *)state, m, rate);
    ((unsigned char *)state)[rate] ^= 0x01;
}

/**
 * \brief Decrypts ciphertext data with a KNOT permutation state.
 *
 * \param state Points to the KNOT permutation state.
 * \param permute Points to the function to perform the KNOT permutation.
 * \param rounds Number of rounds to perform.
 * \param rate Rate of absorption to use with the permutation.
 * \param m Buffer to receive the plaintext.
 * \param c Buffer containing the ciphertext.
 * \param len Length of the plaintext data, must be at least 1.
 */
static void knot_aead_decrypt
    (void *state, knot_permute_t permute, uint8_t rounds, unsigned rate,
     unsigned char *m, const unsigned char *c, unsigned long long len)
{
    while (len >= rate) {
        lw_xor_block_swap(m, (unsigned char *)state, c, rate);
        permute(state, rounds);
        c += rate;
        m += rate;
        len -= rate;
    }
    rate = (unsigned)len;
    lw_xor_block_swap(m, (unsigned char *)state, c, rate);
    ((unsigned char *)state)[rate] ^= 0x01;
}

int knot_aead_128_256_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot256_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_128_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_128_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_128_NONCE_SIZE, k, KNOT_AEAD_128_KEY_SIZE);
    knot256_permute_6(&state, 52);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_128_256_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_128_256_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot256_permute_6(&state, 32);
    memcpy(c + mlen, state.B, KNOT_AEAD_128_TAG_SIZE);
    return 0;
}

int knot_aead_128_256_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot256_state_t state;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_128_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_128_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_128_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_128_NONCE_SIZE, k, KNOT_AEAD_128_KEY_SIZE);
    knot256_permute_6(&state, 52);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_128_256_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_128_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_128_256_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot256_permute_6(&state, 32);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_128_TAG_SIZE);
}

int knot_aead_128_384_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_128_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_128_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_128_NONCE_SIZE, k, KNOT_AEAD_128_KEY_SIZE);
    memset(state.B + KNOT_AEAD_128_NONCE_SIZE + KNOT_AEAD_128_KEY_SIZE,
           0, 47 - (KNOT_AEAD_128_NONCE_SIZE + KNOT_AEAD_128_KEY_SIZE));
    state.B[47] = 0x80;
    knot384_permute_7(&state, 76);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_128_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_128_384_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot384_permute_7(&state, 32);
    memcpy(c + mlen, state.B, KNOT_AEAD_128_TAG_SIZE);
    return 0;
}

int knot_aead_128_384_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_state_t state;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_128_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_128_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_128_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_128_NONCE_SIZE, k, KNOT_AEAD_128_KEY_SIZE);
    memset(state.B + KNOT_AEAD_128_NONCE_SIZE + KNOT_AEAD_128_KEY_SIZE,
           0, 47 - (KNOT_AEAD_128_NONCE_SIZE + KNOT_AEAD_128_KEY_SIZE));
    state.B[47] = 0x80;
    knot384_permute_7(&state, 76);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_128_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_128_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_128_384_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot384_permute_7(&state, 32);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_128_TAG_SIZE);
}

int knot_aead_192_384_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_192_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_192_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_192_NONCE_SIZE, k, KNOT_AEAD_192_KEY_SIZE);
    knot384_permute_7(&state, 76);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_192_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_192_384_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot384_permute_7(&state, 44);
    memcpy(c + mlen, state.B, KNOT_AEAD_192_TAG_SIZE);
    return 0;
}

int knot_aead_192_384_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_state_t state;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_192_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_192_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_192_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_192_NONCE_SIZE, k, KNOT_AEAD_192_KEY_SIZE);
    knot384_permute_7(&state, 76);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_192_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_192_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_192_384_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot384_permute_7(&state, 44);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_192_TAG_SIZE);
}

int knot_aead_256_512_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot512_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_256_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_256_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_256_NONCE_SIZE, k, KNOT_AEAD_256_KEY_SIZE);
    knot512_permute_7(&state, 100);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_256_512_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_256_512_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot512_permute_7(&state, 56);
    memcpy(c + mlen, state.B, KNOT_AEAD_256_TAG_SIZE);
    return 0;
}

int knot_aead_256_512_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot512_state_t state;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_256_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_256_TAG_SIZE;

    /* Initialize the permutation state to the nonce and the key */
    memcpy(state.B, npub, KNOT_AEAD_256_NONCE_SIZE);
    memcpy(state.B + KNOT_AEAD_256_NONCE_SIZE, k, KNOT_AEAD_256_KEY_SIZE);
    knot512_permute_7(&state, 100);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_256_512_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_256_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_256_512_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot512_permute_7(&state, 56);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_256_TAG_SIZE);
}
