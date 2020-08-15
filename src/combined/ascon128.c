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
 * \brief Absorbs data into an ASCON state with an 8-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_absorb_8
    (ascon_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t first_round)
{
#if ASCON_SLICED
    unsigned char padded[8];
    unsigned temp;
    while (len >= 8) {
        ascon_absorb_sliced(state, data, 0);
        ascon_permute_sliced(state, first_round);
        data += 8;
        len -= 8;
    }
    temp = (unsigned)len;
    memcpy(padded, data, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    ascon_absorb_sliced(state, padded, 0);
    ascon_permute_sliced(state, first_round);
#else
    while (len >= 8) {
        lw_xor_block(state->B, data, 8);
        ascon_permute(state, first_round);
        data += 8;
        len -= 8;
    }
    lw_xor_block(state->B, data, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
    ascon_permute(state, first_round);
#endif
}

/**
 * \brief Absorbs data into an ASCON state with a 16-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_absorb_16
    (ascon_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t first_round)
{
#if ASCON_SLICED
    unsigned char padded[16];
    unsigned temp;
    while (len >= 16) {
        ascon_absorb_sliced(state, data, 0);
        ascon_absorb_sliced(state, data + 8, 1);
        ascon_permute_sliced(state, first_round);
        data += 16;
        len -= 16;
    }
    temp = (unsigned)len;
    memcpy(padded, data, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    ascon_absorb_sliced(state, padded, 0);
    ascon_absorb_sliced(state, padded + 8, 1);
    ascon_permute_sliced(state, first_round);
#else
    while (len >= 16) {
        lw_xor_block(state->B, data, 16);
        ascon_permute(state, first_round);
        data += 16;
        len -= 16;
    }
    lw_xor_block(state->B, data, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
    ascon_permute(state, first_round);
#endif
}

/**
 * \brief Encrypts a block of data with an ASCON state and an 8-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_encrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
#if ASCON_SLICED
    unsigned char padded[8];
    unsigned temp;
    while (len >= 8) {
        ascon_encrypt_sliced(state, dest, src, 0);
        ascon_permute_sliced(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    temp = (unsigned)len;
    memcpy(padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    ascon_encrypt_sliced(state, padded, padded, 0);
    memcpy(dest, padded, temp);
#else
    while (len >= 8) {
        lw_xor_block_2_dest(dest, state->B, src, 8);
        ascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    lw_xor_block_2_dest(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
#endif
}

/**
 * \brief Encrypts a block of data with an ASCON state and a 16-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_encrypt_16
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
#if ASCON_SLICED
    unsigned char padded[16];
    unsigned temp;
    while (len >= 16) {
        ascon_encrypt_sliced(state, dest, src, 0);
        ascon_encrypt_sliced(state, dest + 8, src + 8, 1);
        ascon_permute_sliced(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    temp = (unsigned)len;
    memcpy(padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    ascon_encrypt_sliced(state, padded, padded, 0);
    ascon_encrypt_sliced(state, padded + 8, padded + 8, 1);
    memcpy(dest, padded, temp);
#else
    while (len >= 16) {
        lw_xor_block_2_dest(dest, state->B, src, 16);
        ascon_permute(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    lw_xor_block_2_dest(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
#endif
}

/**
 * \brief Decrypts a block of data with an ASCON state and an 8-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_decrypt_8
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
#if ASCON_SLICED
    unsigned char padded[8];
    unsigned temp;
    while (len >= 8) {
        ascon_decrypt_sliced(state, dest, src, 0);
        ascon_permute_sliced(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    temp = (unsigned)len;
    ascon_squeeze_sliced(state, padded, 0);
    lw_xor_block_2_dest(dest, padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    ascon_absorb_sliced(state, padded, 0);
#else
    while (len >= 8) {
        lw_xor_block_swap(dest, state->B, src, 8);
        ascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    lw_xor_block_swap(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
#endif
}

/**
 * \brief Decrypts a block of data with an ASCON state and a 16-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_decrypt_16
    (ascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
#if ASCON_SLICED
    unsigned char padded[16];
    unsigned temp;
    while (len >= 16) {
        ascon_decrypt_sliced(state, dest, src, 0);
        ascon_decrypt_sliced(state, dest + 8, src + 8, 1);
        ascon_permute_sliced(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    temp = (unsigned)len;
    ascon_squeeze_sliced(state, padded, 0);
    ascon_squeeze_sliced(state, padded + 8, 1);
    lw_xor_block_2_dest(dest, padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    ascon_absorb_sliced(state, padded, 0);
    ascon_absorb_sliced(state, padded + 8, 1);
#else
    while (len >= 16) {
        lw_xor_block_swap(dest, state->B, src, 16);
        ascon_permute(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    lw_xor_block_swap(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
#endif
}

#if ASCON_SLICED
#define ascon_separator() (state.W[8] ^= 0x01)
#else
#define ascon_separator() (state.B[39] ^= 0x01)
#endif

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
#if ASCON_SLICED
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_absorb_sliced(&state, k, 3);
    ascon_absorb_sliced(&state, k + 8, 4);
#else
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
#if ASCON_SLICED
    ascon_absorb_sliced(&state, k, 1);
    ascon_absorb_sliced(&state, k + 8, 2);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
#else
    lw_xor_block(state.B + 8, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
#endif
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
#if ASCON_SLICED
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_absorb_sliced(&state, k, 3);
    ascon_absorb_sliced(&state, k + 8, 4);
#else
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag */
#if ASCON_SLICED
    ascon_absorb_sliced(&state, k, 1);
    ascon_absorb_sliced(&state, k + 8, 2);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
#else
    lw_xor_block(state.B + 8, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
#endif
    lw_xor_block(state.B + 24, k, 16);
    return aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, ASCON128_TAG_SIZE);
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
#if ASCON_SLICED
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_absorb_sliced(&state, k, 3);
    ascon_absorb_sliced(&state, k + 8, 4);
#else
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_16(&state, c, m, mlen, 4);

    /* Finalize and compute the authentication tag */
#if ASCON_SLICED
    ascon_absorb_sliced(&state, k, 2);
    ascon_absorb_sliced(&state, k + 8, 3);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
#else
    lw_xor_block(state.B + 16, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
#endif
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
#if ASCON_SLICED
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_absorb_sliced(&state, k, 3);
    ascon_absorb_sliced(&state, k + 8, 4);
#else
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, ASCON128_KEY_SIZE);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_16(&state, m, c, *mlen, 4);

    /* Finalize and check the authentication tag */
#if ASCON_SLICED
    ascon_absorb_sliced(&state, k, 2);
    ascon_absorb_sliced(&state, k + 8, 3);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
#else
    lw_xor_block(state.B + 16, k, ASCON128_KEY_SIZE);
    ascon_permute(&state, 0);
#endif
    lw_xor_block(state.B + 24, k, 16);
    return aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, ASCON128_TAG_SIZE);
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
#if ASCON_SLICED
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_absorb32_low_sliced(&state, k, 2);
    ascon_absorb_sliced(&state, k + 4, 3);
    ascon_absorb_sliced(&state, k + 12, 4);
#else
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 20, k, ASCON80PQ_KEY_SIZE);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
#if ASCON_SLICED
    ascon_absorb_sliced(&state, k, 1);
    ascon_absorb_sliced(&state, k + 8, 2);
    ascon_absorb32_high_sliced(&state, k + 16, 3);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
#else
    lw_xor_block(state.B + 8, k, ASCON80PQ_KEY_SIZE);
    ascon_permute(&state, 0);
#endif
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
#if ASCON_SLICED
    ascon_to_sliced(&state);
    ascon_permute_sliced(&state, 0);
    ascon_absorb32_low_sliced(&state, k, 2);
    ascon_absorb_sliced(&state, k + 4, 3);
    ascon_absorb_sliced(&state, k + 12, 4);
#else
    ascon_permute(&state, 0);
    lw_xor_block(state.B + 20, k, ASCON80PQ_KEY_SIZE);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag */
#if ASCON_SLICED
    ascon_absorb_sliced(&state, k, 1);
    ascon_absorb_sliced(&state, k + 8, 2);
    ascon_absorb32_high_sliced(&state, k + 16, 3);
    ascon_permute_sliced(&state, 0);
    ascon_from_sliced(&state);
#else
    lw_xor_block(state.B + 8, k, ASCON80PQ_KEY_SIZE);
    ascon_permute(&state, 0);
#endif
    lw_xor_block(state.B + 24, k + 4, 16);
    return aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, ASCON80PQ_TAG_SIZE);
}
