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

#include "knot-masked.h"
#include "internal-knot.h"
#include "internal-knot-m.h"
#include <string.h>

aead_cipher_t const knot_aead_128_256_masked_cipher = {
    "KNOT-AEAD-128-256-Masked",
    KNOT_AEAD_MASKED_128_KEY_SIZE,
    KNOT_AEAD_MASKED_128_NONCE_SIZE,
    KNOT_AEAD_MASKED_128_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
#endif
    knot_masked_128_256_aead_encrypt,
    knot_masked_128_256_aead_decrypt
};

aead_cipher_t const knot_aead_128_384_masked_cipher = {
    "KNOT-AEAD-128-384-Masked",
    KNOT_AEAD_MASKED_128_KEY_SIZE,
    KNOT_AEAD_MASKED_128_NONCE_SIZE,
    KNOT_AEAD_MASKED_128_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
#endif
    knot_masked_128_384_aead_encrypt,
    knot_masked_128_384_aead_decrypt
};

aead_cipher_t const knot_aead_192_384_masked_cipher = {
    "KNOT-AEAD-192-384-Masked",
    KNOT_AEAD_MASKED_192_KEY_SIZE,
    KNOT_AEAD_MASKED_192_NONCE_SIZE,
    KNOT_AEAD_MASKED_192_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
#endif
    knot_masked_192_384_aead_encrypt,
    knot_masked_192_384_aead_decrypt
};

aead_cipher_t const knot_aead_256_512_masked_cipher = {
    "KNOT-AEAD-256-512-Masked",
    KNOT_AEAD_MASKED_256_KEY_SIZE,
    KNOT_AEAD_MASKED_256_NONCE_SIZE,
    KNOT_AEAD_MASKED_256_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
#endif
    knot_masked_256_512_aead_encrypt,
    knot_masked_256_512_aead_decrypt
};

/**
 * \brief Rate for KNOT-AEAD-128-256.
 */
#define KNOT_AEAD_MASKED_128_256_RATE 8

/**
 * \brief Rate for KNOT-AEAD-128-384.
 */
#define KNOT_AEAD_MASKED_128_384_RATE 24

/**
 * \brief Rate for KNOT-AEAD-192-384.
 */
#define KNOT_AEAD_MASKED_192_384_RATE 12

/**
 * \brief Rate for KNOT-AEAD-256-512.
 */
#define KNOT_AEAD_MASKED_256_512_RATE 16

#if AEAD_MASKING_KEY_ONLY

/**
 * \brief Initializes KNOT-AEAD-128-256 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_128_256_init_masked
    (knot256_state_t *state, const unsigned char *k, const unsigned char *npub)
{
    knot256_masked_state_t masked_state;
    aead_random_init();
    mask_input(masked_state.S[0], le_load_word64(npub));
    mask_input(masked_state.S[1], le_load_word64(npub + 8));
    mask_input(masked_state.S[2], le_load_word64(k));
    mask_input(masked_state.S[3], le_load_word64(k + 8));
    knot256_masked_permute_6(&masked_state, 52);
    knot256_unmask(state->S, &masked_state);
}

/**
 * \brief Initializes KNOT-AEAD-128-384 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_128_384_init_masked
    (knot384_state_t *state, const unsigned char *k, const unsigned char *npub)
{
    knot384_masked_state_t masked_state;
    aead_random_init();
    mask_input(masked_state.L[0], le_load_word64(npub));
    mask_input(masked_state.H[0], le_load_word32(npub + 8));
    mask_input(masked_state.L[1],
               le_load_word32(npub + 12) |
               (((uint64_t)le_load_word32(k)) << 32));
    mask_input(masked_state.H[1], le_load_word32(k + 4));
    mask_input(masked_state.L[2], le_load_word64(k + 8));
    mask_input(masked_state.H[2], 0);
    mask_input(masked_state.L[3], 0);
    mask_input(masked_state.H[3], 0x80000000U);
    knot384_masked_permute_7(&masked_state, 76);
    knot384_unmask(state->W, &masked_state);
}

/**
 * \brief Initializes KNOT-AEAD-192-384 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_192_384_init_masked
    (knot384_state_t *state, const unsigned char *k, const unsigned char *npub)
{
    knot384_masked_state_t masked_state;
    aead_random_init();
    mask_input(masked_state.L[0], le_load_word64(npub));
    mask_input(masked_state.H[0], le_load_word32(npub + 8));
    mask_input(masked_state.L[1], le_load_word64(npub + 12));
    mask_input(masked_state.H[1], le_load_word32(npub + 20));
    mask_input(masked_state.L[2], le_load_word64(k));
    mask_input(masked_state.H[2], le_load_word32(k + 8));
    mask_input(masked_state.L[3], le_load_word64(k + 12));
    mask_input(masked_state.H[3], le_load_word32(k + 20));
    knot384_masked_permute_7(&masked_state, 76);
    knot384_unmask(state->W, &masked_state);
}

/**
 * \brief Initializes KNOT-AEAD-256-512 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_256_512_init_masked
    (knot512_state_t *state, const unsigned char *k, const unsigned char *npub)
{
    knot512_masked_state_t masked_state;
    aead_random_init();
    mask_input(masked_state.S[0], le_load_word64(npub));
    mask_input(masked_state.S[1], le_load_word64(npub + 8));
    mask_input(masked_state.S[2], le_load_word64(npub + 16));
    mask_input(masked_state.S[3], le_load_word64(npub + 24));
    mask_input(masked_state.S[4], le_load_word64(k));
    mask_input(masked_state.S[5], le_load_word64(k + 8));
    mask_input(masked_state.S[6], le_load_word64(k + 16));
    mask_input(masked_state.S[7], le_load_word64(k + 24));
    knot512_masked_permute_7(&masked_state, 100);
    knot512_unmask(state->S, &masked_state);
}

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
static void knot_aead_absorb_ad_masked
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
static void knot_aead_encrypt_masked
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
static void knot_aead_decrypt_masked
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

int knot_masked_128_256_aead_encrypt
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
    *clen = mlen + KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_256_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_MASKED_128_256_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt_masked
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_MASKED_128_256_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot256_permute_6(&state, 32);
    memcpy(c + mlen, state.B, KNOT_AEAD_MASKED_128_TAG_SIZE);
    return 0;
}

int knot_masked_128_256_aead_decrypt
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
    if (clen < KNOT_AEAD_MASKED_128_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_256_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_MASKED_128_256_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_128_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt_masked
            (&state, (knot_permute_t)knot256_permute_6,
             28, KNOT_AEAD_MASKED_128_256_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot256_permute_6(&state, 32);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_MASKED_128_TAG_SIZE);
}

int knot_masked_128_384_aead_encrypt
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
    *clen = mlen + KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_MASKED_128_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt_masked
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_MASKED_128_384_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot384_permute_7(&state, 32);
    memcpy(c + mlen, state.B, KNOT_AEAD_MASKED_128_TAG_SIZE);
    return 0;
}

int knot_masked_128_384_aead_decrypt
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
    if (clen < KNOT_AEAD_MASKED_128_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_MASKED_128_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_128_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt_masked
            (&state, (knot_permute_t)knot384_permute_7,
             28, KNOT_AEAD_MASKED_128_384_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot384_permute_7(&state, 32);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_MASKED_128_TAG_SIZE);
}

int knot_masked_192_384_aead_encrypt
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
    *clen = mlen + KNOT_AEAD_MASKED_192_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_192_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_MASKED_192_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt_masked
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_MASKED_192_384_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot384_permute_7(&state, 44);
    memcpy(c + mlen, state.B, KNOT_AEAD_MASKED_192_TAG_SIZE);
    return 0;
}

int knot_masked_192_384_aead_decrypt
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
    if (clen < KNOT_AEAD_MASKED_192_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_192_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_192_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_MASKED_192_384_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_192_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt_masked
            (&state, (knot_permute_t)knot384_permute_7,
             40, KNOT_AEAD_MASKED_192_384_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot384_permute_7(&state, 44);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_MASKED_192_TAG_SIZE);
}

int knot_masked_256_512_aead_encrypt
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
    *clen = mlen + KNOT_AEAD_MASKED_256_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_256_512_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_MASKED_256_512_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        knot_aead_encrypt_masked
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_MASKED_256_512_RATE, c, m, mlen);
    }

    /* Compute the authentication tag */
    knot512_permute_7(&state, 56);
    memcpy(c + mlen, state.B, KNOT_AEAD_MASKED_256_TAG_SIZE);
    return 0;
}

int knot_masked_256_512_aead_decrypt
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
    if (clen < KNOT_AEAD_MASKED_256_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_256_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_256_512_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0) {
        knot_aead_absorb_ad_masked
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_MASKED_256_512_RATE, ad, adlen);
    }
    state.B[sizeof(state.B) - 1] ^= 0x80; /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_256_TAG_SIZE;
    if (clen > 0) {
        knot_aead_decrypt_masked
            (&state, (knot_permute_t)knot512_permute_7,
             52, KNOT_AEAD_MASKED_256_512_RATE, m, c, clen);
    }

    /* Check the authentication tag */
    knot512_permute_7(&state, 56);
    return aead_check_tag
        (m, clen, state.B, c + clen, KNOT_AEAD_MASKED_256_TAG_SIZE);
}

#else /* !AEAD_MASKING_KEY_ONLY */

/**
 * \brief Initializes KNOT-AEAD-128-256 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_128_256_init_masked
    (knot256_masked_state_t *state, const unsigned char *k,
     const unsigned char *npub)
{
    aead_random_init();
    mask_input(state->S[0], le_load_word64(npub));
    mask_input(state->S[1], le_load_word64(npub + 8));
    mask_input(state->S[2], le_load_word64(k));
    mask_input(state->S[3], le_load_word64(k + 8));
    knot256_masked_permute_6(state, 52);
}

/**
 * \brief Initializes KNOT-AEAD-128-384 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_128_384_init_masked
    (knot384_masked_state_t *state, const unsigned char *k,
     const unsigned char *npub)
{
    aead_random_init();
    mask_input(state->L[0], le_load_word64(npub));
    mask_input(state->H[0], le_load_word32(npub + 8));
    mask_input(state->L[1],
               le_load_word32(npub + 12) |
               (((uint64_t)le_load_word32(k)) << 32));
    mask_input(state->H[1], le_load_word32(k + 4));
    mask_input(state->L[2], le_load_word64(k + 8));
    mask_input(state->H[2], 0);
    mask_input(state->L[3], 0);
    mask_input(state->H[3], 0x80000000U);
    knot384_masked_permute_7(state, 76);
}

/**
 * \brief Initializes KNOT-AEAD-192-384 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_192_384_init_masked
    (knot384_masked_state_t *state, const unsigned char *k,
     const unsigned char *npub)
{
    aead_random_init();
    mask_input(state->L[0], le_load_word64(npub));
    mask_input(state->H[0], le_load_word32(npub + 8));
    mask_input(state->L[1], le_load_word64(npub + 12));
    mask_input(state->H[1], le_load_word32(npub + 20));
    mask_input(state->L[2], le_load_word64(k));
    mask_input(state->H[2], le_load_word32(k + 8));
    mask_input(state->L[3], le_load_word64(k + 12));
    mask_input(state->H[3], le_load_word32(k + 20));
    knot384_masked_permute_7(state, 76);
}

/**
 * \brief Initializes KNOT-AEAD-256-512 in masked mode.
 *
 * \param state KNOT state to be initialized.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void knot_aead_256_512_init_masked
    (knot512_masked_state_t *state, const unsigned char *k,
     const unsigned char *npub)
{
    aead_random_init();
    mask_input(state->S[0], le_load_word64(npub));
    mask_input(state->S[1], le_load_word64(npub + 8));
    mask_input(state->S[2], le_load_word64(npub + 16));
    mask_input(state->S[3], le_load_word64(npub + 24));
    mask_input(state->S[4], le_load_word64(k));
    mask_input(state->S[5], le_load_word64(k + 8));
    mask_input(state->S[6], le_load_word64(k + 16));
    mask_input(state->S[7], le_load_word64(k + 24));
    knot512_masked_permute_7(state, 100);
}

/**
 * \brief Absorbs the associated data for masked KNOT-AEAD-128-256.
 *
 * \param state Points to the permutation state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be at least 1.
 */
static void knot_aead_128_256_absorb_ad_masked
    (knot256_masked_state_t *state, const unsigned char *ad,
     unsigned long long adlen)
{
    unsigned char padded[KNOT_AEAD_MASKED_128_256_RATE];
    unsigned temp;
    while (adlen >= KNOT_AEAD_MASKED_128_256_RATE) {
        mask_xor_const(state->S[0], le_load_word64(ad));
        knot256_masked_permute_6(state, 28);
        ad += KNOT_AEAD_MASKED_128_256_RATE;
        adlen -= KNOT_AEAD_MASKED_128_256_RATE;
    }
    temp = (unsigned)adlen;
    memcpy(padded, ad, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], le_load_word64(padded));
    knot256_masked_permute_6(state, 28);
}

/**
 * \brief Absorbs the associated data for masked KNOT-AEAD-128-384.
 *
 * \param state Points to the permutation state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be at least 1.
 */
static void knot_aead_128_384_absorb_ad_masked
    (knot384_masked_state_t *state, const unsigned char *ad,
     unsigned long long adlen)
{
    unsigned char padded[KNOT_AEAD_MASKED_128_384_RATE];
    unsigned temp;
    while (adlen >= KNOT_AEAD_MASKED_128_384_RATE) {
        mask_xor_const(state->L[0], le_load_word64(ad));
        mask_xor_const(state->H[0], le_load_word32(ad + 8));
        mask_xor_const(state->L[1], le_load_word64(ad + 12));
        mask_xor_const(state->H[1], le_load_word32(ad + 20));
        knot384_masked_permute_7(state, 28);
        ad += KNOT_AEAD_MASKED_128_384_RATE;
        adlen -= KNOT_AEAD_MASKED_128_384_RATE;
    }
    temp = (unsigned)adlen;
    memcpy(padded, ad, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->L[0], le_load_word64(padded));
    mask_xor_const(state->H[0], le_load_word32(padded + 8));
    mask_xor_const(state->L[1], le_load_word64(padded + 12));
    mask_xor_const(state->H[1], le_load_word32(padded + 20));
    knot384_masked_permute_7(state, 28);
}

/**
 * \brief Absorbs the associated data for masked KNOT-AEAD-192-384.
 *
 * \param state Points to the permutation state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be at least 1.
 */
static void knot_aead_192_384_absorb_ad_masked
    (knot384_masked_state_t *state, const unsigned char *ad,
     unsigned long long adlen)
{
    unsigned char padded[KNOT_AEAD_MASKED_192_384_RATE];
    unsigned temp;
    while (adlen >= KNOT_AEAD_MASKED_192_384_RATE) {
        mask_xor_const(state->L[0], le_load_word64(ad));
        mask_xor_const(state->H[0], le_load_word32(ad + 8));
        knot384_masked_permute_7(state, 40);
        ad += KNOT_AEAD_MASKED_192_384_RATE;
        adlen -= KNOT_AEAD_MASKED_192_384_RATE;
    }
    temp = (unsigned)adlen;
    memcpy(padded, ad, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->L[0], le_load_word64(padded));
    mask_xor_const(state->H[0], le_load_word32(padded + 8));
    knot384_masked_permute_7(state, 40);
}

/**
 * \brief Absorbs the associated data for masked KNOT-AEAD-256-512.
 *
 * \param state Points to the permutation state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must be at least 1.
 */
static void knot_aead_256_512_absorb_ad_masked
    (knot512_masked_state_t *state, const unsigned char *ad,
     unsigned long long adlen)
{
    unsigned char padded[KNOT_AEAD_MASKED_256_512_RATE];
    unsigned temp;
    while (adlen >= KNOT_AEAD_MASKED_256_512_RATE) {
        mask_xor_const(state->S[0], le_load_word64(ad));
        mask_xor_const(state->S[1], le_load_word64(ad + 8));
        knot512_masked_permute_7(state, 52);
        ad += KNOT_AEAD_MASKED_256_512_RATE;
        adlen -= KNOT_AEAD_MASKED_256_512_RATE;
    }
    temp = (unsigned)adlen;
    memcpy(padded, ad, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], le_load_word64(padded));
    mask_xor_const(state->S[1], le_load_word64(padded + 8));
    knot512_masked_permute_7(state, 52);
}

int knot_masked_128_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot256_masked_state_t state;
    unsigned char padded[KNOT_AEAD_MASKED_128_256_RATE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_256_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_128_256_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.S[3], 0x8000000000000000ULL); /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen >= KNOT_AEAD_MASKED_128_256_RATE) {
            mask_xor_const(state.S[0], le_load_word64(m));
            le_store_word64(c, mask_output(state.S[0]));
            knot256_masked_permute_6(&state, 28);
            c += KNOT_AEAD_MASKED_128_256_RATE;
            m += KNOT_AEAD_MASKED_128_256_RATE;
            mlen -= KNOT_AEAD_MASKED_128_256_RATE;
        }
        temp = (unsigned)mlen;
        memcpy(padded, m, temp);
        padded[temp] = 0x01; /* Padding */
        memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
        mask_xor_const(state.S[0], le_load_word64(padded));
        le_store_word64(padded, mask_output(state.S[0]));
        memcpy(c, padded, temp);
    }

    /* Compute the authentication tag */
    knot256_masked_permute_6(&state, 32);
    c += mlen;
    le_store_word64(c,     mask_output(state.S[0]));
    le_store_word64(c + 8, mask_output(state.S[1]));
    return 0;
}

int knot_masked_128_256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot256_masked_state_t state;
    unsigned char tag[KNOT_AEAD_MASKED_128_TAG_SIZE];
    unsigned temp;
    uint64_t mword;
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_MASKED_128_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_256_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_128_256_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.S[3], 0x8000000000000000ULL); /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_128_TAG_SIZE;
    if (clen > 0) {
        while (clen >= KNOT_AEAD_MASKED_128_256_RATE) {
            mword = mask_output(state.S[0]) ^ le_load_word64(c);
            mask_xor_const(state.S[0], mword);
            le_store_word64(m, mword);
            knot256_masked_permute_6(&state, 28);
            c += KNOT_AEAD_MASKED_128_256_RATE;
            m += KNOT_AEAD_MASKED_128_256_RATE;
            clen -= KNOT_AEAD_MASKED_128_256_RATE;
        }
        temp = (unsigned)clen;
        le_store_word64(tag, mask_output(state.S[0]));
        lw_xor_block_2_dest(m, tag, c, temp);
        tag[temp] = 0x01; /* Padding */
        memset(tag + temp + 1, 0, KNOT_AEAD_MASKED_128_256_RATE - (temp + 1));
        mask_xor_const(state.S[0], le_load_word64(tag));
    }

    /* Check the authentication tag */
    knot256_masked_permute_6(&state, 32);
    le_store_word64(tag,     mask_output(state.S[0]));
    le_store_word64(tag + 8, mask_output(state.S[1]));
    return aead_check_tag
        (mtemp, *mlen, tag, c + clen, KNOT_AEAD_MASKED_128_TAG_SIZE);
}

int knot_masked_128_384_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_masked_state_t state;
    unsigned char padded[KNOT_AEAD_MASKED_128_384_RATE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_128_384_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.H[3], 0x80000000U); /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen >= KNOT_AEAD_MASKED_128_384_RATE) {
            mask_xor_const(state.L[0], le_load_word64(m));
            mask_xor_const(state.H[0], le_load_word32(m + 8));
            mask_xor_const(state.L[1], le_load_word64(m + 12));
            mask_xor_const(state.H[1], le_load_word32(m + 20));
            le_store_word64(c,      mask_output(state.L[0]));
            le_store_word32(c + 8,  mask_output(state.H[0]));
            le_store_word64(c + 12, mask_output(state.L[1]));
            le_store_word32(c + 20, mask_output(state.H[1]));
            knot384_masked_permute_7(&state, 28);
            c += KNOT_AEAD_MASKED_128_384_RATE;
            m += KNOT_AEAD_MASKED_128_384_RATE;
            mlen -= KNOT_AEAD_MASKED_128_384_RATE;
        }
        temp = (unsigned)mlen;
        memcpy(padded, m, temp);
        padded[temp] = 0x01; /* Padding */
        memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
        mask_xor_const(state.L[0], le_load_word64(padded));
        mask_xor_const(state.H[0], le_load_word32(padded + 8));
        mask_xor_const(state.L[1], le_load_word64(padded + 12));
        mask_xor_const(state.H[1], le_load_word32(padded + 20));
        le_store_word64(padded,      mask_output(state.L[0]));
        le_store_word32(padded + 8,  mask_output(state.H[0]));
        le_store_word64(padded + 12, mask_output(state.L[1]));
        le_store_word32(padded + 20, mask_output(state.H[1]));
        memcpy(c, padded, temp);
        c += mlen;
    }

    /* Compute the authentication tag */
    knot384_masked_permute_7(&state, 32);
    le_store_word64(c,      mask_output(state.L[0]));
    le_store_word32(c + 8,  mask_output(state.H[0]));
    le_store_word32(c + 12, (uint32_t)mask_output(state.L[1]));
    return 0;
}

int knot_masked_128_384_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_masked_state_t state;
    unsigned char padded[KNOT_AEAD_MASKED_128_384_RATE];
    unsigned char *mtemp = m;
    uint64_t mword64;
    uint32_t mword32;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_MASKED_128_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_128_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_128_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_128_384_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.H[3], 0x80000000U); /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_128_TAG_SIZE;
    if (clen > 0) {
        while (clen >= KNOT_AEAD_MASKED_128_384_RATE) {
            mword64 = mask_output(state.L[0]) ^ le_load_word64(c);
            mword32 = mask_output(state.H[0]) ^ le_load_word64(c + 8);
            mask_xor_const(state.L[0], mword64);
            mask_xor_const(state.H[0], mword32);
            le_store_word64(m, mword64);
            le_store_word32(m + 8, mword32);
            mword64 = mask_output(state.L[1]) ^ le_load_word64(c + 12);
            mword32 = mask_output(state.H[1]) ^ le_load_word64(c + 20);
            mask_xor_const(state.L[1], mword64);
            mask_xor_const(state.H[1], mword32);
            le_store_word64(m + 12, mword64);
            le_store_word32(m + 20, mword32);
            knot384_masked_permute_7(&state, 28);
            c += KNOT_AEAD_MASKED_128_384_RATE;
            m += KNOT_AEAD_MASKED_128_384_RATE;
            clen -= KNOT_AEAD_MASKED_128_384_RATE;
        }
        temp = (unsigned)clen;
        le_store_word64(padded,      mask_output(state.L[0]));
        le_store_word32(padded + 8,  mask_output(state.H[0]));
        le_store_word64(padded + 12, mask_output(state.L[1]));
        le_store_word32(padded + 20, mask_output(state.H[1]));
        lw_xor_block_2_dest(m, padded, c, temp);
        padded[temp] = 0x01; /* Padding */
        memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
        mask_xor_const(state.L[0], le_load_word64(padded));
        mask_xor_const(state.H[0], le_load_word32(padded + 8));
        mask_xor_const(state.L[1], le_load_word64(padded + 12));
        mask_xor_const(state.H[1], le_load_word32(padded + 20));
    }

    /* Check the authentication tag */
    knot384_masked_permute_7(&state, 32);
    le_store_word64(padded,      mask_output(state.L[0]));
    le_store_word32(padded + 8,  mask_output(state.H[0]));
    le_store_word32(padded + 12, (uint32_t)mask_output(state.L[1]));
    return aead_check_tag
        (mtemp, *mlen, padded, c + clen, KNOT_AEAD_MASKED_128_TAG_SIZE);
}

int knot_masked_192_384_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_masked_state_t state;
    unsigned char padded[KNOT_AEAD_MASKED_192_384_RATE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_MASKED_192_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_192_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_192_384_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.H[3], 0x80000000U); /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen >= KNOT_AEAD_MASKED_192_384_RATE) {
            mask_xor_const(state.L[0], le_load_word64(m));
            mask_xor_const(state.H[0], le_load_word32(m + 8));
            le_store_word64(c,      mask_output(state.L[0]));
            le_store_word32(c + 8,  mask_output(state.H[0]));
            knot384_masked_permute_7(&state, 40);
            c += KNOT_AEAD_MASKED_192_384_RATE;
            m += KNOT_AEAD_MASKED_192_384_RATE;
            mlen -= KNOT_AEAD_MASKED_192_384_RATE;
        }
        temp = (unsigned)mlen;
        memcpy(padded, m, temp);
        padded[temp] = 0x01; /* Padding */
        memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
        mask_xor_const(state.L[0], le_load_word64(padded));
        mask_xor_const(state.H[0], le_load_word32(padded + 8));
        le_store_word64(padded,      mask_output(state.L[0]));
        le_store_word32(padded + 8,  mask_output(state.H[0]));
        memcpy(c, padded, temp);
        c += mlen;
    }

    /* Compute the authentication tag */
    knot384_masked_permute_7(&state, 44);
    le_store_word64(c,      mask_output(state.L[0]));
    le_store_word32(c + 8,  mask_output(state.H[0]));
    le_store_word64(c + 12, mask_output(state.L[1]));
    le_store_word32(c + 20, mask_output(state.H[1]));
    return 0;
}

int knot_masked_192_384_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot384_masked_state_t state;
    unsigned char tag[KNOT_AEAD_MASKED_192_TAG_SIZE];
    unsigned char *mtemp = m;
    uint64_t mword64;
    uint32_t mword32;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_MASKED_192_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_192_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_192_384_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_192_384_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.H[3], 0x80000000U); /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_192_TAG_SIZE;
    if (clen > 0) {
        while (clen >= KNOT_AEAD_MASKED_192_384_RATE) {
            mword64 = mask_output(state.L[0]) ^ le_load_word64(c);
            mword32 = mask_output(state.H[0]) ^ le_load_word64(c + 8);
            mask_xor_const(state.L[0], mword64);
            mask_xor_const(state.H[0], mword32);
            le_store_word64(m, mword64);
            le_store_word32(m + 8, mword32);
            knot384_masked_permute_7(&state, 40);
            c += KNOT_AEAD_MASKED_192_384_RATE;
            m += KNOT_AEAD_MASKED_192_384_RATE;
            clen -= KNOT_AEAD_MASKED_192_384_RATE;
        }
        temp = (unsigned)clen;
        le_store_word64(tag,      mask_output(state.L[0]));
        le_store_word32(tag + 8,  mask_output(state.H[0]));
        lw_xor_block_2_dest(m, tag, c, temp);
        tag[temp] = 0x01; /* Padding */
        memset(tag + temp + 1, 0, KNOT_AEAD_MASKED_192_384_RATE - (temp + 1));
        mask_xor_const(state.L[0], le_load_word64(tag));
        mask_xor_const(state.H[0], le_load_word32(tag + 8));
    }

    /* Check the authentication tag */
    knot384_masked_permute_7(&state, 44);
    le_store_word64(tag,      mask_output(state.L[0]));
    le_store_word32(tag + 8,  mask_output(state.H[0]));
    le_store_word64(tag + 12, mask_output(state.L[1]));
    le_store_word32(tag + 20, mask_output(state.H[1]));
    return aead_check_tag
        (mtemp, *mlen, tag, c + clen, KNOT_AEAD_MASKED_192_TAG_SIZE);
}

int knot_masked_256_512_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot512_masked_state_t state;
    unsigned char padded[KNOT_AEAD_MASKED_256_512_RATE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + KNOT_AEAD_MASKED_256_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_256_512_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_256_512_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.S[7], 0x8000000000000000ULL); /* Domain separation */

    /* Encrypts the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen >= KNOT_AEAD_MASKED_256_512_RATE) {
            mask_xor_const(state.S[0], le_load_word64(m));
            mask_xor_const(state.S[1], le_load_word64(m + 8));
            le_store_word64(c,     mask_output(state.S[0]));
            le_store_word64(c + 8, mask_output(state.S[1]));
            knot512_masked_permute_7(&state, 52);
            c += KNOT_AEAD_MASKED_256_512_RATE;
            m += KNOT_AEAD_MASKED_256_512_RATE;
            mlen -= KNOT_AEAD_MASKED_256_512_RATE;
        }
        temp = (unsigned)mlen;
        memcpy(padded, m, temp);
        padded[temp] = 0x01; /* Padding */
        memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
        mask_xor_const(state.S[0], le_load_word64(padded));
        mask_xor_const(state.S[1], le_load_word64(padded + 8));
        le_store_word64(padded,     mask_output(state.S[0]));
        le_store_word64(padded + 8, mask_output(state.S[1]));
        memcpy(c, padded, temp);
        c += mlen;
    }

    /* Compute the authentication tag */
    knot512_masked_permute_7(&state, 56);
    le_store_word64(c,      mask_output(state.S[0]));
    le_store_word64(c + 8,  mask_output(state.S[1]));
    le_store_word64(c + 16, mask_output(state.S[2]));
    le_store_word64(c + 24, mask_output(state.S[3]));
    return 0;
}

int knot_masked_256_512_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    knot512_masked_state_t state;
    unsigned char tag[KNOT_AEAD_MASKED_256_TAG_SIZE];
    unsigned char *mtemp = m;
    uint64_t mword;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < KNOT_AEAD_MASKED_256_TAG_SIZE)
        return -1;
    *mlen = clen - KNOT_AEAD_MASKED_256_TAG_SIZE;

    /* Initialize the permutation state with the nonce and the key */
    knot_aead_256_512_init_masked(&state, k, npub);

    /* Absorb the associated data */
    if (adlen > 0)
        knot_aead_256_512_absorb_ad_masked(&state, ad, adlen);
    mask_xor_const(state.S[7], 0x8000000000000000ULL); /* Domain separation */

    /* Decrypts the ciphertext to produce the plaintext */
    clen -= KNOT_AEAD_MASKED_256_TAG_SIZE;
    if (clen > 0) {
        while (clen >= KNOT_AEAD_MASKED_256_512_RATE) {
            mword = mask_output(state.S[0]) ^ le_load_word64(c);
            mask_xor_const(state.S[0], mword);
            le_store_word64(m, mword);
            mword = mask_output(state.S[1]) ^ le_load_word64(c + 8);
            mask_xor_const(state.S[1], mword);
            le_store_word64(m + 8, mword);
            knot512_masked_permute_7(&state, 52);
            c += KNOT_AEAD_MASKED_256_512_RATE;
            m += KNOT_AEAD_MASKED_256_512_RATE;
            clen -= KNOT_AEAD_MASKED_256_512_RATE;
        }
        temp = (unsigned)clen;
        le_store_word64(tag,      mask_output(state.S[0]));
        le_store_word64(tag + 8,  mask_output(state.S[1]));
        lw_xor_block_2_dest(m, tag, c, temp);
        tag[temp] = 0x01; /* Padding */
        memset(tag + temp + 1, 0, KNOT_AEAD_MASKED_256_512_RATE - (temp + 1));
        mask_xor_const(state.S[0], le_load_word64(tag));
        mask_xor_const(state.S[1], le_load_word64(tag + 8));
    }

    /* Check the authentication tag */
    knot512_masked_permute_7(&state, 56);
    le_store_word64(tag,      mask_output(state.S[0]));
    le_store_word64(tag + 8,  mask_output(state.S[1]));
    le_store_word64(tag + 16, mask_output(state.S[2]));
    le_store_word64(tag + 24, mask_output(state.S[3]));
    return aead_check_tag
        (mtemp, *mlen, tag, c + clen, KNOT_AEAD_MASKED_256_TAG_SIZE);
}

#endif /* !AEAD_MASKING_KEY_ONLY */
