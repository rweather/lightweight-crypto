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

#include "ascon128.h"
#include "internal-ascon.h"
#include <string.h>

/**
 * \brief Initialization vector for ASCON-128.
 */
#define ASCON128_IV     0x80400c0600000000ULL

/**
 * \brief Initialization vector for ASCON-128a.
 */
#define ASCON128a_IV    0x80800c0800000000ULL

/**
 * \brief Initialization vector for ASCON-80pq.
 */
#define ASCON80PQ_IV    0xa0400c06U

aead_cipher_t const ascon128_cipher = {
    "ASCON-128",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128_aead_encrypt,
    ascon128_aead_decrypt
};

aead_cipher_t const ascon128a_cipher = {
    "ASCON-128a",
    ASCON128_KEY_SIZE,
    ASCON128_NONCE_SIZE,
    ASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon128a_aead_encrypt,
    ascon128a_aead_decrypt
};

aead_cipher_t const ascon80pq_cipher = {
    "ASCON-80pq",
    ASCON80PQ_KEY_SIZE,
    ASCON80PQ_NONCE_SIZE,
    ASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    ascon80pq_aead_encrypt,
    ascon80pq_aead_decrypt
};

/**
 * \brief Absorbs data into an ASCON state.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param rate Block rate, which is either 8 or 16.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_absorb
    (ascon_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t rate, uint8_t first_round)
{
    while (len >= rate) {
        lw_xor_block(state->B, data, rate);
        ascon_permute(state, first_round);
        data += rate;
        len -= rate;
    }
    lw_xor_block(state->B, data, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
    ascon_permute(state, first_round);
}

/**
 * \brief Encrypts a block of data with an ASCON state.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param rate Block rate, which is either 8 or 16.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_encrypt
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len,
     uint8_t rate, uint8_t first_round)
{
    while (len >= rate) {
        lw_xor_block_2_dest(dest, state->B, src, rate);
        ascon_permute(state, first_round);
        dest += rate;
        src += rate;
        len -= rate;
    }
    lw_xor_block_2_dest(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
}

/**
 * \brief Decrypts a block of data with an ASCON state.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param rate Block rate, which is either 8 or 16.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_decrypt
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len,
     uint8_t rate, uint8_t first_round)
{
    while (len >= rate) {
        lw_xor_block_swap(dest, state->B, src, rate);
        ascon_permute(state, first_round);
        dest += rate;
        src += rate;
        len -= rate;
    }
    lw_xor_block_swap(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
}

int ascon128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    be_store_word64(state.B, ASCON128_IV);
    memcpy(state.B + 8, k, ASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb(&state, ad, adlen, 8, 6);

    /* Separator between the associated data and the payload */
    state.B[39] ^= 0x01;

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt(&state, c, m, mlen, 8, 6);

    /* Finalize and compute the authentication tag */
    lw_xor_block(state.B + 8, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block_2_src(c + mlen, state.B + 24, k, 16);
    return 0;
}

int ascon128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    be_store_word64(state.B, ASCON128_IV);
    memcpy(state.B + 8, k, ASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb(&state, ad, adlen, 8, 6);

    /* Separator between the associated data and the payload */
    state.B[39] ^= 0x01;

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt(&state, m, c, *mlen, 8, 6);

    /* Finalize and check the authentication tag */
    lw_xor_block(state.B + 8, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, 16);
    return lw_check_tag(state.B + 24, c + *mlen, ASCON128_TAG_SIZE, 0);
}

int ascon128a_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    be_store_word64(state.B, ASCON128a_IV);
    memcpy(state.B + 8, k, ASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb(&state, ad, adlen, 16, 4);

    /* Separator between the associated data and the payload */
    state.B[39] ^= 0x01;

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt(&state, c, m, mlen, 16, 4);

    /* Finalize and compute the authentication tag */
    lw_xor_block(state.B + 16, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block_2_src(c + mlen, state.B + 24, k, 16);
    return 0;
}

int ascon128a_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_TAG_SIZE;

    /* Initialize the ASCON state */
    be_store_word64(state.B, ASCON128a_IV);
    memcpy(state.B + 8, k, ASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON128_NONCE_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb(&state, ad, adlen, 16, 4);

    /* Separator between the associated data and the payload */
    state.B[39] ^= 0x01;

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt(&state, m, c, *mlen, 16, 4);

    /* Finalize and check the authentication tag */
    lw_xor_block(state.B + 16, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, 16);
    return lw_check_tag(state.B + 24, c + *mlen, ASCON128_TAG_SIZE, 0);
}

int ascon80pq_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON80PQ_TAG_SIZE;

    /* Initialize the ASCON state */
    be_store_word32(state.B, ASCON80PQ_IV);
    memcpy(state.B + 4, k, ASCON80PQ_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON80PQ_NONCE_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 20, k, ASCON80PQ_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb(&state, ad, adlen, 8, 6);

    /* Separator between the associated data and the payload */
    state.B[39] ^= 0x01;

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt(&state, c, m, mlen, 8, 6);

    /* Finalize and compute the authentication tag */
    lw_xor_block(state.B + 8, k, ASCON80PQ_KEY_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block_2_src(c + mlen, state.B + 24, k + 4, 16);
    return 0;
}

int ascon80pq_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON80PQ_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON80PQ_TAG_SIZE;

    /* Initialize the ASCON state */
    be_store_word32(state.B, ASCON80PQ_IV);
    memcpy(state.B + 4, k, ASCON80PQ_KEY_SIZE);
    memcpy(state.B + 24, npub, ASCON80PQ_NONCE_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 20, k, ASCON80PQ_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb(&state, ad, adlen, 8, 6);

    /* Separator between the associated data and the payload */
    state.B[39] ^= 0x01;

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt(&state, m, c, *mlen, 8, 6);

    /* Finalize and check the authentication tag */
    lw_xor_block(state.B + 8, k, ASCON80PQ_KEY_SIZE);
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k + 4, 16);
    return lw_check_tag(state.B + 24, c + *mlen, ASCON80PQ_TAG_SIZE, 0);
}
