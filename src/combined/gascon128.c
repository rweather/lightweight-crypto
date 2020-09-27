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

#include "gascon128.h"
#include "internal-gascon.h"
#include <string.h>

/**
 * \brief Initialization vector for GASCON-128.
 */
#define GASCON128_IV     0x80400c0600000000ULL

/**
 * \brief Initialization vector for GASCON-128a.
 */
#define GASCON128a_IV    0x80800c0800000000ULL

/**
 * \brief Initialization vector for GASCON-80pq.
 */
#define GASCON80PQ_IV    0xa0400c06U

aead_cipher_t const gascon128_cipher = {
    "GASCON-128",
    GASCON128_KEY_SIZE,
    GASCON128_NONCE_SIZE,
    GASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    gascon128_aead_encrypt,
    gascon128_aead_decrypt
};

aead_cipher_t const gascon128a_cipher = {
    "GASCON-128a",
    GASCON128_KEY_SIZE,
    GASCON128_NONCE_SIZE,
    GASCON128_TAG_SIZE,
    AEAD_FLAG_NONE,
    gascon128a_aead_encrypt,
    gascon128a_aead_decrypt
};

aead_cipher_t const gascon80pq_cipher = {
    "GASCON-80pq",
    GASCON80PQ_KEY_SIZE,
    GASCON80PQ_NONCE_SIZE,
    GASCON80PQ_TAG_SIZE,
    AEAD_FLAG_NONE,
    gascon80pq_aead_encrypt,
    gascon80pq_aead_decrypt
};

/**
 * \brief Absorbs data into an GASCON state with an 8-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void gascon_absorb_8
    (gascon_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t first_round)
{
    while (len >= 8) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        state->W[0] ^= le_load_word32(data);
        state->W[1] ^= le_load_word32(data + 4);
#else
        lw_xor_block(state->B, data, 8);
#endif
        gascon_permute(state, first_round);
        data += 8;
        len -= 8;
    }
    lw_xor_block(state->B, data, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
    gascon_permute(state, first_round);
}

/**
 * \brief Absorbs data into an GASCON state with a 16-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void gascon_absorb_16
    (gascon_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t first_round)
{
    while (len >= 16) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        state->W[0] ^= le_load_word32(data);
        state->W[1] ^= le_load_word32(data + 4);
        state->W[2] ^= le_load_word32(data + 8);
        state->W[3] ^= le_load_word32(data + 12);
#else
        lw_xor_block(state->B, data, 16);
#endif
        gascon_permute(state, first_round);
        data += 16;
        len -= 16;
    }
    lw_xor_block(state->B, data, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
    gascon_permute(state, first_round);
}

/**
 * \brief Encrypts a block of data with an GASCON state and an 8-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void gascon_encrypt_8
    (gascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
    while (len >= 8) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        state->W[0] ^= le_load_word32(src);
        state->W[1] ^= le_load_word32(src + 4);
        le_store_word32(dest, state->W[0]);
        le_store_word32(dest + 4, state->W[1]);
#else
        lw_xor_block_2_dest(dest, state->B, src, 8);
#endif
        gascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    lw_xor_block_2_dest(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
}

/**
 * \brief Encrypts a block of data with an GASCON state and a 16-byte rate.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void gascon_encrypt_16
    (gascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
    while (len >= 16) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        state->W[0] ^= le_load_word32(src);
        state->W[1] ^= le_load_word32(src + 4);
        state->W[2] ^= le_load_word32(src + 8);
        state->W[3] ^= le_load_word32(src + 12);
        le_store_word32(dest, state->W[0]);
        le_store_word32(dest + 4, state->W[1]);
        le_store_word32(dest + 8, state->W[2]);
        le_store_word32(dest + 12, state->W[3]);
#else
        lw_xor_block_2_dest(dest, state->B, src, 16);
#endif
        gascon_permute(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    lw_xor_block_2_dest(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
}

/**
 * \brief Decrypts a block of data with an GASCON state and an 8-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void gascon_decrypt_8
    (gascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
    while (len >= 8) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        uint32_t m = state->W[0] ^ le_load_word32(src);
        le_store_word32(dest, m);
        state->W[0] ^= m;
        m = state->W[1] ^ le_load_word32(src + 4);
        le_store_word32(dest + 4, m);
        state->W[1] ^= m;
#else
        lw_xor_block_swap(dest, state->B, src, 8);
#endif
        gascon_permute(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    lw_xor_block_swap(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
}

/**
 * \brief Decrypts a block of data with an GASCON state and a 16-byte rate.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 * \param first_round First round of the permutation to apply each block.
 */
static void gascon_decrypt_16
    (gascon_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len, uint8_t first_round)
{
    while (len >= 16) {
#if defined(LW_UTIL_LITTLE_ENDIAN)
        uint32_t m = state->W[0] ^ le_load_word32(src);
        le_store_word32(dest, m);
        state->W[0] ^= m;
        m = state->W[1] ^ le_load_word32(src + 4);
        le_store_word32(dest + 4, m);
        state->W[1] ^= m;
        m = state->W[2] ^ le_load_word32(src + 8);
        le_store_word32(dest + 8, m);
        state->W[2] ^= m;
        m = state->W[3] ^ le_load_word32(src + 12);
        le_store_word32(dest + 12, m);
        state->W[3] ^= m;
#else
        lw_xor_block_swap(dest, state->B, src, 16);
#endif
        gascon_permute(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    lw_xor_block_swap(dest, state->B, src, (unsigned)len);
    state->B[(unsigned)len] ^= 0x80;
}


#define gascon_separator() (state.B[39] ^= 0x01)

int gascon128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GASCON128_TAG_SIZE;

    /* Initialize the GASCON state */
    le_store_word64(state.B, GASCON128_IV);
    memcpy(state.B + 8, k, GASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, GASCON128_NONCE_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, GASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        gascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    gascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    gascon_encrypt_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
    lw_xor_block(state.B + 8, k, GASCON128_KEY_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block_2_src(c + mlen, state.B + 24, k, 16);
    return 0;
}

int gascon128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < GASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - GASCON128_TAG_SIZE;

    /* Initialize the GASCON state */
    le_store_word64(state.B, GASCON128_IV);
    memcpy(state.B + 8, k, GASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, GASCON128_NONCE_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, GASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        gascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    gascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    gascon_decrypt_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag */
    lw_xor_block(state.B + 8, k, GASCON128_KEY_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, 16);
    return aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, GASCON128_TAG_SIZE);
}

int gascon128a_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GASCON128_TAG_SIZE;

    /* Initialize the GASCON state */
    le_store_word64(state.B, GASCON128a_IV);
    memcpy(state.B + 8, k, GASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, GASCON128_NONCE_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, GASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        gascon_absorb_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    gascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    gascon_encrypt_16(&state, c, m, mlen, 4);

    /* Finalize and compute the authentication tag */
    lw_xor_block(state.B + 16, k, GASCON128_KEY_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block_2_src(c + mlen, state.B + 24, k, 16);
    return 0;
}

int gascon128a_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < GASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - GASCON128_TAG_SIZE;

    /* Initialize the GASCON state */
    le_store_word64(state.B, GASCON128a_IV);
    memcpy(state.B + 8, k, GASCON128_KEY_SIZE);
    memcpy(state.B + 24, npub, GASCON128_NONCE_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, GASCON128_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        gascon_absorb_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    gascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    gascon_decrypt_16(&state, m, c, *mlen, 4);

    /* Finalize and check the authentication tag */
    lw_xor_block(state.B + 16, k, GASCON128_KEY_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k, 16);
    return aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, GASCON128_TAG_SIZE);
}

int gascon80pq_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GASCON80PQ_TAG_SIZE;

    /* Initialize the GASCON state */
    le_store_word32(state.B, GASCON80PQ_IV);
    memcpy(state.B + 4, k, GASCON80PQ_KEY_SIZE);
    memcpy(state.B + 24, npub, GASCON80PQ_NONCE_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 20, k, GASCON80PQ_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        gascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    gascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    gascon_encrypt_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
    lw_xor_block(state.B + 8, k, GASCON80PQ_KEY_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block_2_src(c + mlen, state.B + 24, k + 4, 16);
    return 0;
}

int gascon80pq_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < GASCON80PQ_TAG_SIZE)
        return -1;
    *mlen = clen - GASCON80PQ_TAG_SIZE;

    /* Initialize the GASCON state */
    le_store_word32(state.B, GASCON80PQ_IV);
    memcpy(state.B + 4, k, GASCON80PQ_KEY_SIZE);
    memcpy(state.B + 24, npub, GASCON80PQ_NONCE_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 20, k, GASCON80PQ_KEY_SIZE);

    /* Absorb the associated data into the state */
    if (adlen > 0)
        gascon_absorb_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    gascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    gascon_decrypt_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag */
    lw_xor_block(state.B + 8, k, GASCON80PQ_KEY_SIZE);
    gascon_permute(&state, 0);
    lw_xor_block(state.B + 24, k + 4, 16);
    return aead_check_tag
        (m, *mlen, state.B + 24, c + *mlen, GASCON80PQ_TAG_SIZE);
}
