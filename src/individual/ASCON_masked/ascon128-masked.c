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

#include "ascon128-masked.h"
#include "internal-ascon.h"
#include "internal-ascon-m.h"
#include <string.h>

/**
 * \brief Initialization vector for masked ASCON-128.
 */
#define ASCON128_MASKED_IV  0x80400c0600000000ULL

/**
 * \brief Initialization vector for masked ASCON-128a.
 */
#define ASCON128a_MASKED_IV 0x80800c0800000000ULL

/**
 * \brief Initialization vector for masked ASCON-80pq.
 */
#define ASCON80PQ_MASKED_IV 0xa0400c0600000000ULL

aead_cipher_t const ascon128_masked_cipher = {
    "ASCON-128-Masked",
    ASCON128_MASKED_KEY_SIZE,
    ASCON128_MASKED_NONCE_SIZE,
    ASCON128_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_SC_PROTECT_ALL,
#endif
    ascon128_masked_aead_encrypt,
    ascon128_masked_aead_decrypt
};

aead_cipher_t const ascon128a_masked_cipher = {
    "ASCON-128a-Masked",
    ASCON128_MASKED_KEY_SIZE,
    ASCON128_MASKED_NONCE_SIZE,
    ASCON128_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_SC_PROTECT_ALL,
#endif
    ascon128a_masked_aead_encrypt,
    ascon128a_masked_aead_decrypt
};

aead_cipher_t const ascon80pq_masked_cipher = {
    "ASCON-80pq-Masked",
    ASCON80PQ_MASKED_KEY_SIZE,
    ASCON80PQ_MASKED_NONCE_SIZE,
    ASCON80PQ_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_SC_PROTECT_ALL,
#endif
    ascon80pq_masked_aead_encrypt,
    ascon80pq_masked_aead_decrypt
};

#if AEAD_MASKING_KEY_ONLY

/**
 * \brief Absorbs data into an ASCON state with an 8-byte rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_absorb_masked_8
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
static void ascon_absorb_masked_16
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
static void ascon_encrypt_masked_8
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
static void ascon_encrypt_masked_16
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
static void ascon_decrypt_masked_8
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
static void ascon_decrypt_masked_16
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

int ascon128_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t masked_state;
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(masked_state.S[0], ASCON128_MASKED_IV);
    mask_input(masked_state.S[1], be_load_word64(k));
    mask_input(masked_state.S[2], be_load_word64(k + 8));
    mask_input(masked_state.S[3], be_load_word64(npub));
    mask_input(masked_state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
#if ASCON_SLICED
    ascon_unmask_sliced(&state, &masked_state);
#else
    ascon_unmask(&state, &masked_state);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_masked_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag in masked form */
#if ASCON_SLICED
    ascon_mask_sliced(&masked_state, &state);
#else
    ascon_mask(&masked_state, &state);
#endif
    mask_xor_const(masked_state.S[1], be_load_word64(k));
    mask_xor_const(masked_state.S[2], be_load_word64(k + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
    be_store_word64(c + mlen, mask_output(masked_state.S[3]));
    be_store_word64(c + mlen + 8, mask_output(masked_state.S[4]));
    aead_random_finish();
    return 0;
}

int ascon128_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t masked_state;
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(masked_state.S[0], ASCON128_MASKED_IV);
    mask_input(masked_state.S[1], be_load_word64(k));
    mask_input(masked_state.S[2], be_load_word64(k + 8));
    mask_input(masked_state.S[3], be_load_word64(npub));
    mask_input(masked_state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
#if ASCON_SLICED
    ascon_unmask_sliced(&state, &masked_state);
#else
    ascon_unmask(&state, &masked_state);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_masked_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag in masked form */
#if ASCON_SLICED
    ascon_mask_sliced(&masked_state, &state);
#else
    ascon_mask(&masked_state, &state);
#endif
    mask_xor_const(masked_state.S[1], be_load_word64(k));
    mask_xor_const(masked_state.S[2], be_load_word64(k + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
    be_store_word64(state.B, mask_output(masked_state.S[3]));
    be_store_word64(state.B + 8, mask_output(masked_state.S[4]));
    aead_random_finish();
    return aead_check_tag
        (m, *mlen, state.B, c + *mlen, ASCON128_MASKED_TAG_SIZE);
}

int ascon128a_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t masked_state;
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(masked_state.S[0], ASCON128a_MASKED_IV);
    mask_input(masked_state.S[1], be_load_word64(k));
    mask_input(masked_state.S[2], be_load_word64(k + 8));
    mask_input(masked_state.S[3], be_load_word64(npub));
    mask_input(masked_state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
#if ASCON_SLICED
    ascon_unmask_sliced(&state, &masked_state);
#else
    ascon_unmask(&state, &masked_state);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_masked_16(&state, c, m, mlen, 4);

    /* Finalize and compute the authentication tag in masked form */
#if ASCON_SLICED
    ascon_mask_sliced(&masked_state, &state);
#else
    ascon_mask(&masked_state, &state);
#endif
    mask_xor_const(masked_state.S[2], be_load_word64(k));
    mask_xor_const(masked_state.S[3], be_load_word64(k + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
    be_store_word64(c + mlen, mask_output(masked_state.S[3]));
    be_store_word64(c + mlen + 8, mask_output(masked_state.S[4]));
    aead_random_finish();
    return 0;
}

int ascon128a_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t masked_state;
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(masked_state.S[0], ASCON128a_MASKED_IV);
    mask_input(masked_state.S[1], be_load_word64(k));
    mask_input(masked_state.S[2], be_load_word64(k + 8));
    mask_input(masked_state.S[3], be_load_word64(npub));
    mask_input(masked_state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
#if ASCON_SLICED
    ascon_unmask_sliced(&state, &masked_state);
#else
    ascon_unmask(&state, &masked_state);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_masked_16(&state, m, c, *mlen, 4);

    /* Finalize and check the authentication tag in masked form */
#if ASCON_SLICED
    ascon_mask_sliced(&masked_state, &state);
#else
    ascon_mask(&masked_state, &state);
#endif
    mask_xor_const(masked_state.S[2], be_load_word64(k));
    mask_xor_const(masked_state.S[3], be_load_word64(k + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 8));
    be_store_word64(state.B, mask_output(masked_state.S[3]));
    be_store_word64(state.B + 8, mask_output(masked_state.S[4]));
    aead_random_finish();
    return aead_check_tag
        (m, *mlen, state.B, c + *mlen, ASCON128_MASKED_TAG_SIZE);
}

int ascon80pq_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t masked_state;
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON80PQ_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(masked_state.S[0], ASCON80PQ_MASKED_IV | be_load_word32(k));
    mask_input(masked_state.S[1], be_load_word64(k + 4));
    mask_input(masked_state.S[2], be_load_word64(k + 12));
    mask_input(masked_state.S[3], be_load_word64(npub));
    mask_input(masked_state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[2], be_load_word32(k));
    mask_xor_const(masked_state.S[3], be_load_word64(k + 4));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 12));
#if ASCON_SLICED
    ascon_unmask_sliced(&state, &masked_state);
#else
    ascon_unmask(&state, &masked_state);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_masked_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
#if ASCON_SLICED
    ascon_mask_sliced(&masked_state, &state);
#else
    ascon_mask(&masked_state, &state);
#endif
    mask_xor_const(masked_state.S[1], be_load_word64(k));
    mask_xor_const(masked_state.S[2], be_load_word64(k + 8));
    mask_xor_const(masked_state.S[3], ((uint64_t)(be_load_word32(k + 16))) << 32);
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k + 4));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 12));
    be_store_word64(c + mlen, mask_output(masked_state.S[3]));
    be_store_word64(c + mlen + 8, mask_output(masked_state.S[4]));
    aead_random_finish();
    return 0;
}

int ascon80pq_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t masked_state;
    ascon_state_t state;
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON80PQ_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON80PQ_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(masked_state.S[0], ASCON80PQ_MASKED_IV | be_load_word32(k));
    mask_input(masked_state.S[1], be_load_word64(k + 4));
    mask_input(masked_state.S[2], be_load_word64(k + 12));
    mask_input(masked_state.S[3], be_load_word64(npub));
    mask_input(masked_state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[2], be_load_word32(k));
    mask_xor_const(masked_state.S[3], be_load_word64(k + 4));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 12));
#if ASCON_SLICED
    ascon_unmask_sliced(&state, &masked_state);
#else
    ascon_unmask(&state, &masked_state);
#endif

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    ascon_separator();

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_masked_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag in masked form */
#if ASCON_SLICED
    ascon_mask_sliced(&masked_state, &state);
#else
    ascon_mask(&masked_state, &state);
#endif
    mask_xor_const(masked_state.S[1], be_load_word64(k));
    mask_xor_const(masked_state.S[2], be_load_word64(k + 8));
    mask_xor_const(masked_state.S[3], ((uint64_t)(be_load_word32(k + 16))) << 32);
    ascon_permute_masked(&masked_state, 0);
    mask_xor_const(masked_state.S[3], be_load_word64(k + 4));
    mask_xor_const(masked_state.S[4], be_load_word64(k + 12));
    be_store_word64(state.B, mask_output(masked_state.S[3]));
    be_store_word64(state.B + 8, mask_output(masked_state.S[4]));
    aead_random_finish();
    return aead_check_tag
        (m, *mlen, state.B, c + *mlen, ASCON80PQ_MASKED_TAG_SIZE);
}

#else /* !AEAD_MASKING_KEY_ONLY */

/**
 * \brief Absorbs data into an ASCON state with an 8-byte block rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_absorb_masked_8
    (ascon_masked_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t first_round)
{
    unsigned char padded[8];
    unsigned temp;
    while (len >= 8) {
        mask_xor_const(state->S[0], be_load_word64(data));
        ascon_permute_masked(state, first_round);
        data += 8;
        len -= 8;
    }
    temp = (unsigned)len;
    memcpy(padded, data, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], be_load_word64(padded));
    ascon_permute_masked(state, first_round);
}

/**
 * \brief Absorbs data into an ASCON state with a 16-byte block rate.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 * \param first_round First round of the permutation to apply each block.
 */
static void ascon_absorb_masked_16
    (ascon_masked_state_t *state, const unsigned char *data,
     unsigned long long len, uint8_t first_round)
{
    unsigned char padded[16];
    unsigned temp;
    while (len >= 16) {
        mask_xor_const(state->S[0], be_load_word64(data));
        mask_xor_const(state->S[1], be_load_word64(data + 8));
        ascon_permute_masked(state, first_round);
        data += 16;
        len -= 16;
    }
    temp = (unsigned)len;
    memcpy(padded, data, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], be_load_word64(padded));
    mask_xor_const(state->S[1], be_load_word64(padded + 8));
    ascon_permute_masked(state, first_round);
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
static void ascon_encrypt_masked_8
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len,
     uint8_t first_round)
{
    unsigned char padded[8];
    unsigned temp;
    while (len >= 8) {
        mask_xor_const(state->S[0], be_load_word64(src));
        be_store_word64(dest, mask_output(state->S[0]));
        ascon_permute_masked(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    temp = (unsigned)len;
    memcpy(padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], be_load_word64(padded));
    be_store_word64(padded, mask_output(state->S[0]));
    memcpy(dest, padded, temp);
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
static void ascon_encrypt_masked_16
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len,
     uint8_t first_round)
{
    unsigned char padded[16];
    unsigned temp;
    while (len >= 16) {
        mask_xor_const(state->S[0], be_load_word64(src));
        mask_xor_const(state->S[1], be_load_word64(src + 8));
        be_store_word64(dest, mask_output(state->S[0]));
        be_store_word64(dest + 8, mask_output(state->S[1]));
        ascon_permute_masked(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    temp = (unsigned)len;
    memcpy(padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], be_load_word64(padded));
    mask_xor_const(state->S[1], be_load_word64(padded + 8));
    be_store_word64(padded, mask_output(state->S[0]));
    be_store_word64(padded + 8, mask_output(state->S[1]));
    memcpy(dest, padded, temp);
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
static void ascon_decrypt_masked_8
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len,
     uint8_t first_round)
{
    unsigned char padded[8];
    unsigned temp;
    uint64_t mword;
    while (len >= 8) {
        mword = mask_output(state->S[0]) ^ be_load_word64(src);
        mask_xor_const(state->S[0], mword);
        be_store_word64(dest, mword);
        ascon_permute_masked(state, first_round);
        dest += 8;
        src += 8;
        len -= 8;
    }
    temp = (unsigned)len;
    be_store_word64(padded, mask_output(state->S[0]));
    lw_xor_block_2_dest(dest, padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], be_load_word64(padded));
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
static void ascon_decrypt_masked_16
    (ascon_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len,
     uint8_t first_round)
{
    unsigned char padded[16];
    unsigned temp;
    uint64_t mword;
    while (len >= 16) {
        mword = mask_output(state->S[0]) ^ be_load_word64(src);
        mask_xor_const(state->S[0], mword);
        be_store_word64(dest, mword);
        mword = mask_output(state->S[1]) ^ be_load_word64(src + 8);
        mask_xor_const(state->S[1], mword);
        be_store_word64(dest + 8, mword);
        ascon_permute_masked(state, first_round);
        dest += 16;
        src += 16;
        len -= 16;
    }
    temp = (unsigned)len;
    be_store_word64(padded,     mask_output(state->S[0]));
    be_store_word64(padded + 8, mask_output(state->S[1]));
    lw_xor_block_2_dest(dest, padded, src, temp);
    padded[temp] = 0x80;
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mask_xor_const(state->S[0], be_load_word64(padded));
    mask_xor_const(state->S[1], be_load_word64(padded + 8));
}

int ascon128_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(state.S[0], ASCON128_MASKED_IV);
    mask_input(state.S[1], be_load_word64(k));
    mask_input(state.S[2], be_load_word64(k + 8));
    mask_input(state.S[3], be_load_word64(npub));
    mask_input(state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    mask_xor_const(state.S[4], 0x01);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_masked_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag in masked form */
    mask_xor_const(state.S[1], be_load_word64(k));
    mask_xor_const(state.S[2], be_load_word64(k + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));
    be_store_word64(c + mlen, mask_output(state.S[3]));
    be_store_word64(c + mlen + 8, mask_output(state.S[4]));
    aead_random_finish();
    return 0;
}

int ascon128_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t state;
    unsigned char tag[ASCON128_MASKED_TAG_SIZE];
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(state.S[0], ASCON128_MASKED_IV);
    mask_input(state.S[1], be_load_word64(k));
    mask_input(state.S[2], be_load_word64(k + 8));
    mask_input(state.S[3], be_load_word64(npub));
    mask_input(state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    mask_xor_const(state.S[4], 0x01);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_masked_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag in masked form */
    mask_xor_const(state.S[1], be_load_word64(k));
    mask_xor_const(state.S[2], be_load_word64(k + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));
    be_store_word64(tag, mask_output(state.S[3]));
    be_store_word64(tag + 8, mask_output(state.S[4]));
    aead_random_finish();
    return aead_check_tag(m, *mlen, tag, c + *mlen, ASCON128_MASKED_TAG_SIZE);
}

int ascon128a_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(state.S[0], ASCON128a_MASKED_IV);
    mask_input(state.S[1], be_load_word64(k));
    mask_input(state.S[2], be_load_word64(k + 8));
    mask_input(state.S[3], be_load_word64(npub));
    mask_input(state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    mask_xor_const(state.S[4], 0x01);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_masked_16(&state, c, m, mlen, 4);

    /* Finalize and compute the authentication tag in masked form */
    mask_xor_const(state.S[2], be_load_word64(k));
    mask_xor_const(state.S[3], be_load_word64(k + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));
    be_store_word64(c + mlen, mask_output(state.S[3]));
    be_store_word64(c + mlen + 8, mask_output(state.S[4]));
    aead_random_finish();
    return 0;
}

int ascon128a_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t state;
    unsigned char tag[ASCON128_MASKED_TAG_SIZE];
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON128_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(state.S[0], ASCON128a_MASKED_IV);
    mask_input(state.S[1], be_load_word64(k));
    mask_input(state.S[2], be_load_word64(k + 8));
    mask_input(state.S[3], be_load_word64(npub));
    mask_input(state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_16(&state, ad, adlen, 4);

    /* Separator between the associated data and the payload */
    mask_xor_const(state.S[4], 0x01);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_masked_16(&state, m, c, *mlen, 4);

    /* Finalize and check the authentication tag in masked form */
    mask_xor_const(state.S[2], be_load_word64(k));
    mask_xor_const(state.S[3], be_load_word64(k + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k));
    mask_xor_const(state.S[4], be_load_word64(k + 8));
    be_store_word64(tag, mask_output(state.S[3]));
    be_store_word64(tag + 8, mask_output(state.S[4]));
    aead_random_finish();
    return aead_check_tag(m, *mlen, tag, c + *mlen, ASCON128_MASKED_TAG_SIZE);
}

int ascon80pq_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ASCON80PQ_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(state.S[0], ASCON80PQ_MASKED_IV | be_load_word32(k));
    mask_input(state.S[1], be_load_word64(k + 4));
    mask_input(state.S[2], be_load_word64(k + 12));
    mask_input(state.S[3], be_load_word64(npub));
    mask_input(state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[2], be_load_word32(k));
    mask_xor_const(state.S[3], be_load_word64(k + 4));
    mask_xor_const(state.S[4], be_load_word64(k + 12));

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    mask_xor_const(state.S[4], 0x01);

    /* Encrypt the plaintext to create the ciphertext */
    ascon_encrypt_masked_8(&state, c, m, mlen, 6);

    /* Finalize and compute the authentication tag */
    mask_xor_const(state.S[1], be_load_word64(k));
    mask_xor_const(state.S[2], be_load_word64(k + 8));
    mask_xor_const(state.S[3], ((uint64_t)(be_load_word32(k + 16))) << 32);
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k + 4));
    mask_xor_const(state.S[4], be_load_word64(k + 12));
    be_store_word64(c + mlen, mask_output(state.S[3]));
    be_store_word64(c + mlen + 8, mask_output(state.S[4]));
    aead_random_finish();
    return 0;
}

int ascon80pq_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ascon_masked_state_t state;
    unsigned char tag[ASCON80PQ_MASKED_TAG_SIZE];
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < ASCON80PQ_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - ASCON80PQ_MASKED_TAG_SIZE;

    /* Initialize the ASCON state in masked form */
    aead_random_init();
    mask_input(state.S[0], ASCON80PQ_MASKED_IV | be_load_word32(k));
    mask_input(state.S[1], be_load_word64(k + 4));
    mask_input(state.S[2], be_load_word64(k + 12));
    mask_input(state.S[3], be_load_word64(npub));
    mask_input(state.S[4], be_load_word64(npub + 8));
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[2], be_load_word32(k));
    mask_xor_const(state.S[3], be_load_word64(k + 4));
    mask_xor_const(state.S[4], be_load_word64(k + 12));

    /* Absorb the associated data into the state */
    if (adlen > 0)
        ascon_absorb_masked_8(&state, ad, adlen, 6);

    /* Separator between the associated data and the payload */
    mask_xor_const(state.S[4], 0x01);

    /* Decrypt the ciphertext to create the plaintext */
    ascon_decrypt_masked_8(&state, m, c, *mlen, 6);

    /* Finalize and check the authentication tag in masked form */
    mask_xor_const(state.S[1], be_load_word64(k));
    mask_xor_const(state.S[2], be_load_word64(k + 8));
    mask_xor_const(state.S[3], ((uint64_t)(be_load_word32(k + 16))) << 32);
    ascon_permute_masked(&state, 0);
    mask_xor_const(state.S[3], be_load_word64(k + 4));
    mask_xor_const(state.S[4], be_load_word64(k + 12));
    be_store_word64(tag, mask_output(state.S[3]));
    be_store_word64(tag + 8, mask_output(state.S[4]));
    aead_random_finish();
    return aead_check_tag(m, *mlen, tag, c + *mlen, ASCON80PQ_MASKED_TAG_SIZE);
}

#endif /* !AEAD_MASKING_KEY_ONLY */
