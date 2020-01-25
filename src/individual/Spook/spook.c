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

#include "spook.h"
#include "internal-spook.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const spook_128_512_su_cipher = {
    "Spook-128-512-su",
    SPOOK_SU_KEY_SIZE,
    SPOOK_NONCE_SIZE,
    SPOOK_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    spook_128_512_su_aead_encrypt,
    spook_128_512_su_aead_decrypt
};

aead_cipher_t const spook_128_384_su_cipher = {
    "Spook-128-384-su",
    SPOOK_SU_KEY_SIZE,
    SPOOK_NONCE_SIZE,
    SPOOK_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    spook_128_384_su_aead_encrypt,
    spook_128_384_su_aead_decrypt
};

aead_cipher_t const spook_128_512_mu_cipher = {
    "Spook-128-512-mu",
    SPOOK_MU_KEY_SIZE,
    SPOOK_NONCE_SIZE,
    SPOOK_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    spook_128_512_mu_aead_encrypt,
    spook_128_512_mu_aead_decrypt
};

aead_cipher_t const spook_128_384_mu_cipher = {
    "Spook-128-384-mu",
    SPOOK_MU_KEY_SIZE,
    SPOOK_NONCE_SIZE,
    SPOOK_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    spook_128_384_mu_aead_encrypt,
    spook_128_384_mu_aead_decrypt
};

/**
 * \brief Initializes the Shadow-512 sponge state.
 *
 * \param state The sponge state.
 * \param k Points to the key.
 * \param klen Length of the key in bytes, either 16 or 32.
 * \param npub Public nonce for the state.
 */
static void spook_128_512_init
    (unsigned char state[SHADOW512_STATE_SIZE],
     const unsigned char *k, unsigned klen,
     const unsigned char *npub)
{
    memset(state, 0, SHADOW512_STATE_SIZE);
    if (klen == SPOOK_MU_KEY_SIZE) {
        /* The public tweak is 126 bits in size followed by a 1 bit */
        memcpy(state, k + CLYDE128_BLOCK_SIZE, CLYDE128_BLOCK_SIZE);
        state[CLYDE128_BLOCK_SIZE - 1] &= 0x7F;
        state[CLYDE128_BLOCK_SIZE - 1] |= 0x40;
    }
    memcpy(state + CLYDE128_BLOCK_SIZE, npub, CLYDE128_BLOCK_SIZE);
    clyde128_encrypt
        (k, state, state + SHADOW512_STATE_SIZE - CLYDE128_BLOCK_SIZE, npub);
    shadow512(state);
}

/**
 * \brief Initializes the Shadow-384 sponge state.
 *
 * \param state The sponge state.
 * \param k Points to the key.
 * \param klen Length of the key in bytes, either 16 or 32.
 * \param npub Public nonce for the state.
 */
static void spook_128_384_init
    (unsigned char state[SHADOW384_STATE_SIZE],
     const unsigned char *k, unsigned klen,
     const unsigned char *npub)
{
    memset(state, 0, SHADOW384_STATE_SIZE);
    if (klen == SPOOK_MU_KEY_SIZE) {
        /* The public tweak is 126 bits in size followed by a 1 bit */
        memcpy(state, k + CLYDE128_BLOCK_SIZE, CLYDE128_BLOCK_SIZE);
        state[CLYDE128_BLOCK_SIZE - 1] &= 0x7F;
        state[CLYDE128_BLOCK_SIZE - 1] |= 0x40;
    }
    memcpy(state + CLYDE128_BLOCK_SIZE, npub, CLYDE128_BLOCK_SIZE);
    clyde128_encrypt
        (k, state, state + SHADOW384_STATE_SIZE - CLYDE128_BLOCK_SIZE, npub);
    shadow384(state);
}

/**
 * \brief Absorbs associated data into the Shadow-512 sponge state.
 *
 * \param state The sponge state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes, must be non-zero.
 */
static void spook_128_512_absorb
    (unsigned char state[SHADOW512_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen >= SHADOW512_RATE) {
        lw_xor_block(state, ad, SHADOW512_RATE);
        shadow512(state);
        ad += SHADOW512_RATE;
        adlen -= SHADOW512_RATE;
    }
    if (adlen > 0) {
        unsigned temp = (unsigned)adlen;
        lw_xor_block(state, ad, temp);
        state[temp] ^= 0x01;
        state[SHADOW512_RATE] ^= 0x02;
        shadow512(state);
    }
}

/**
 * \brief Absorbs associated data into the Shadow-384 sponge state.
 *
 * \param state The sponge state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes, must be non-zero.
 */
static void spook_128_384_absorb
    (unsigned char state[SHADOW384_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen >= SHADOW384_RATE) {
        lw_xor_block(state, ad, SHADOW384_RATE);
        shadow384(state);
        ad += SHADOW384_RATE;
        adlen -= SHADOW384_RATE;
    }
    if (adlen > 0) {
        unsigned temp = (unsigned)adlen;
        lw_xor_block(state, ad, temp);
        state[temp] ^= 0x01;
        state[SHADOW384_RATE] ^= 0x02;
        shadow384(state);
    }
}

/**
 * \brief Encrypts the plaintext with the Shadow-512 sponge state.
 *
 * \param state The sponge state.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param mlen Number of bytes of plaintext to be encrypted.
 */
static void spook_128_512_encrypt
    (unsigned char state[SHADOW512_STATE_SIZE], unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    state[SHADOW512_RATE] ^= 0x01;
    while (mlen >= SHADOW512_RATE) {
        lw_xor_block_2_dest(c, state, m, SHADOW512_RATE);
        shadow512(state);
        c += SHADOW512_RATE;
        m += SHADOW512_RATE;
        mlen -= SHADOW512_RATE;
    }
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        lw_xor_block_2_dest(c, state, m, temp);
        state[temp] ^= 0x01;
        state[SHADOW512_RATE] ^= 0x02;
        shadow512(state);
    }
}

/**
 * \brief Encrypts the plaintext with the Shadow-384 sponge state.
 *
 * \param state The sponge state.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param mlen Number of bytes of plaintext to be encrypted.
 */
static void spook_128_384_encrypt
    (unsigned char state[SHADOW384_STATE_SIZE], unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    state[SHADOW384_RATE] ^= 0x01;
    while (mlen >= SHADOW384_RATE) {
        lw_xor_block_2_dest(c, state, m, SHADOW384_RATE);
        shadow384(state);
        c += SHADOW384_RATE;
        m += SHADOW384_RATE;
        mlen -= SHADOW384_RATE;
    }
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        lw_xor_block_2_dest(c, state, m, temp);
        state[temp] ^= 0x01;
        state[SHADOW384_RATE] ^= 0x02;
        shadow384(state);
    }
}

/**
 * \brief Decrypts the ciphertext with the Shadow-512 sponge state.
 *
 * \param state The sponge state.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param clen Number of bytes of ciphertext to be decrypted.
 */
static void spook_128_512_decrypt
    (unsigned char state[SHADOW512_STATE_SIZE], unsigned char *m,
     const unsigned char *c, unsigned long long clen)
{
    state[SHADOW512_RATE] ^= 0x01;
    while (clen >= SHADOW512_RATE) {
        lw_xor_block_swap(m, state, c, SHADOW512_RATE);
        shadow512(state);
        c += SHADOW512_RATE;
        m += SHADOW512_RATE;
        clen -= SHADOW512_RATE;
    }
    if (clen > 0) {
        unsigned temp = (unsigned)clen;
        lw_xor_block_swap(m, state, c, temp);
        state[temp] ^= 0x01;
        state[SHADOW512_RATE] ^= 0x02;
        shadow512(state);
    }
}

/**
 * \brief Decrypts the ciphertext with the Shadow-384 sponge state.
 *
 * \param state The sponge state.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param clen Number of bytes of ciphertext to be decrypted.
 */
static void spook_128_384_decrypt
    (unsigned char state[SHADOW384_STATE_SIZE], unsigned char *m,
     const unsigned char *c, unsigned long long clen)
{
    state[SHADOW384_RATE] ^= 0x01;
    while (clen >= SHADOW384_RATE) {
        lw_xor_block_swap(m, state, c, SHADOW384_RATE);
        shadow384(state);
        c += SHADOW384_RATE;
        m += SHADOW384_RATE;
        clen -= SHADOW384_RATE;
    }
    if (clen > 0) {
        unsigned temp = (unsigned)clen;
        lw_xor_block_swap(m, state, c, temp);
        state[temp] ^= 0x01;
        state[SHADOW384_RATE] ^= 0x02;
        shadow384(state);
    }
}

int spook_128_512_su_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW512_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOOK_TAG_SIZE;

    /* Initialize the Shadow-512 sponge state */
    spook_128_512_init(state, k, SPOOK_SU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_512_absorb(state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        spook_128_512_encrypt(state, c, m, mlen);

    /* Compute the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_encrypt(k, state + CLYDE128_BLOCK_SIZE, c + mlen, state);
    return 0;
}

int spook_128_512_su_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW512_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOOK_TAG_SIZE)
        return -1;
    *mlen = clen - SPOOK_TAG_SIZE;

    /* Initialize the Shadow-512 sponge state */
    spook_128_512_init(state, k, SPOOK_SU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_512_absorb(state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOOK_TAG_SIZE;
    if (clen > 0)
        spook_128_512_decrypt(state, m, c, clen);

    /* Check the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_decrypt
        (k, state + CLYDE128_BLOCK_SIZE,
         state + CLYDE128_BLOCK_SIZE, c + clen);
    return aead_check_tag
        (m, clen, state, state + CLYDE128_BLOCK_SIZE, SPOOK_TAG_SIZE);
}

int spook_128_384_su_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW384_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOOK_TAG_SIZE;

    /* Initialize the Shadow-384 sponge state */
    spook_128_384_init(state, k, SPOOK_SU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_384_absorb(state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        spook_128_384_encrypt(state, c, m, mlen);

    /* Compute the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_encrypt(k, state + CLYDE128_BLOCK_SIZE, c + mlen, state);
    return 0;
}

int spook_128_384_su_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW384_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOOK_TAG_SIZE)
        return -1;
    *mlen = clen - SPOOK_TAG_SIZE;

    /* Initialize the Shadow-384 sponge state */
    spook_128_384_init(state, k, SPOOK_SU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_384_absorb(state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOOK_TAG_SIZE;
    if (clen > 0)
        spook_128_384_decrypt(state, m, c, clen);

    /* Check the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_decrypt
        (k, state + CLYDE128_BLOCK_SIZE,
         state + CLYDE128_BLOCK_SIZE, c + clen);
    return aead_check_tag
        (m, clen, state, state + CLYDE128_BLOCK_SIZE, SPOOK_TAG_SIZE);
}

int spook_128_512_mu_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW512_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOOK_TAG_SIZE;

    /* Initialize the Shadow-512 sponge state */
    spook_128_512_init(state, k, SPOOK_MU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_512_absorb(state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        spook_128_512_encrypt(state, c, m, mlen);

    /* Compute the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_encrypt(k, state + CLYDE128_BLOCK_SIZE, c + mlen, state);
    return 0;
}

int spook_128_512_mu_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW512_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOOK_TAG_SIZE)
        return -1;
    *mlen = clen - SPOOK_TAG_SIZE;

    /* Initialize the Shadow-512 sponge state */
    spook_128_512_init(state, k, SPOOK_MU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_512_absorb(state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOOK_TAG_SIZE;
    if (clen > 0)
        spook_128_512_decrypt(state, m, c, clen);

    /* Check the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_decrypt
        (k, state + CLYDE128_BLOCK_SIZE,
         state + CLYDE128_BLOCK_SIZE, c + clen);
    return aead_check_tag
        (m, clen, state, state + CLYDE128_BLOCK_SIZE, SPOOK_TAG_SIZE);
}

int spook_128_384_mu_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW384_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOOK_TAG_SIZE;

    /* Initialize the Shadow-384 sponge state */
    spook_128_384_init(state, k, SPOOK_MU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_384_absorb(state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        spook_128_384_encrypt(state, c, m, mlen);

    /* Compute the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_encrypt(k, state + CLYDE128_BLOCK_SIZE, c + mlen, state);
    return 0;
}

int spook_128_384_mu_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SHADOW384_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOOK_TAG_SIZE)
        return -1;
    *mlen = clen - SPOOK_TAG_SIZE;

    /* Initialize the Shadow-384 sponge state */
    spook_128_384_init(state, k, SPOOK_MU_KEY_SIZE, npub);

    /* Process the associated data */
    if (adlen > 0)
        spook_128_384_absorb(state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOOK_TAG_SIZE;
    if (clen > 0)
        spook_128_384_decrypt(state, m, c, clen);

    /* Check the authentication tag */
    state[CLYDE128_BLOCK_SIZE * 2 - 1] |= 0x80;
    clyde128_decrypt
        (k, state + CLYDE128_BLOCK_SIZE,
         state + CLYDE128_BLOCK_SIZE, c + clen);
    return aead_check_tag
        (m, clen, state, state + CLYDE128_BLOCK_SIZE, SPOOK_TAG_SIZE);
}
