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

#include "spix-masked.h"
#include "internal-sliscp-light.h"
#include "internal-sliscp-light-m.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const spix_masked_cipher = {
    "SPIX-Masked",
    SPIX_MASKED_KEY_SIZE,
    SPIX_MASKED_NONCE_SIZE,
    SPIX_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_SC_PROTECT_ALL,
#endif
    spix_masked_aead_encrypt,
    spix_masked_aead_decrypt
};

/**
 * \brief Rate for absorbing data into the sLiSCP-light state and for
 * squeezing data out again.
 */
#define SPIX_MASKED_RATE 8

#if AEAD_MASKING_KEY_ONLY

/**
 * \brief Size of the state for the internal sLiSCP-light permutation.
 */
#define SPIX_MASKED_STATE_SIZE SLISCP_LIGHT256_STATE_SIZE

/**
 * \brief Initializes the SPIX state.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spix_init_masked
    (unsigned char state[SPIX_MASKED_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    mask_uint32_t masked_state[8];
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    aead_random_init();
    mask_input(masked_state[0], be_load_word32(npub));
    mask_input(masked_state[1], be_load_word32(npub + 4));
    mask_input(masked_state[2], be_load_word32(k));
    mask_input(masked_state[3], be_load_word32(k + 4));
    mask_input(masked_state[4], be_load_word32(npub + 8));
    mask_input(masked_state[5], be_load_word32(npub + 12));
    mask_input(masked_state[6], be_load_word32(k + 8));
    mask_input(masked_state[7], be_load_word32(k + 12));

    /* Run the permutation to scramble the initial state */
    sliscp_light256_permute_masked(masked_state, 18);

    /* Absorb the key in two further permutation operations */
    mask_xor_const(masked_state[2], be_load_word32(k));
    mask_xor_const(masked_state[6], be_load_word32(k + 4));
    sliscp_light256_permute_masked(masked_state, 18);
    mask_xor_const(masked_state[2], be_load_word32(k + 8));
    mask_xor_const(masked_state[6], be_load_word32(k + 12));
    sliscp_light256_permute_masked(masked_state, 18);

    /* Convert the state into unmasked form */
    sliscp_light256_unmask(state, masked_state);
    sliscp_light256_swap_spix(state);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPIX_MASKED_RATE) {
            lw_xor_block(state + 8, ad, SPIX_MASKED_RATE);
            state[SPIX_MASKED_STATE_SIZE - 1] ^= 0x01; /* domain separation */
            sliscp_light256_permute_spix(state, 9);
            ad += SPIX_MASKED_RATE;
            adlen -= SPIX_MASKED_RATE;
        }
        temp = (unsigned)adlen;
        lw_xor_block(state + 8, ad, temp);
        state[temp + 8] ^= 0x80; /* padding */
        state[SPIX_MASKED_STATE_SIZE - 1] ^= 0x01; /* domain separation */
        sliscp_light256_permute_spix(state, 9);
    }
}

/**
 * \brief Finalizes the SPIX encryption or decryption operation.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spix_finalize_masked
    (unsigned char state[SPIX_MASKED_STATE_SIZE], const unsigned char *k,
     unsigned char *tag)
{
    mask_uint32_t masked_state[8];

    /* Convert the state back into masked form */
    sliscp_light256_swap_spix(state);
    sliscp_light256_mask(masked_state, state);

    /* Absorb the key into the state again */
    mask_xor_const(masked_state[2], be_load_word32(k));
    mask_xor_const(masked_state[6], be_load_word32(k + 4));
    sliscp_light256_permute_masked(masked_state, 18);
    mask_xor_const(masked_state[2], be_load_word32(k + 8));
    mask_xor_const(masked_state[6], be_load_word32(k + 12));
    sliscp_light256_permute_masked(masked_state, 18);

    /* Copy out the authentication tag */
    be_store_word32(tag,      mask_output(masked_state[2]));
    be_store_word32(tag + 4,  mask_output(masked_state[3]));
    be_store_word32(tag + 8,  mask_output(masked_state[6]));
    be_store_word32(tag + 12, mask_output(masked_state[7]));
    aead_random_finish();
}

int spix_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPIX_MASKED_STATE_SIZE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPIX_MASKED_TAG_SIZE;

    /* Initialize the SPIX state and absorb the associated data */
    spix_init_masked(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= SPIX_MASKED_RATE) {
        lw_xor_block_2_dest(c, state + 8, m, SPIX_MASKED_RATE);
        state[SPIX_MASKED_STATE_SIZE - 1] ^= 0x02; /* domain separation */
        sliscp_light256_permute_spix(state, 9);
        c += SPIX_MASKED_RATE;
        m += SPIX_MASKED_RATE;
        mlen -= SPIX_MASKED_RATE;
    }
    temp = (unsigned)mlen;
    lw_xor_block_2_dest(c, state + 8, m, temp);
    state[temp + 8] ^= 0x80; /* padding */
    state[SPIX_MASKED_STATE_SIZE - 1] ^= 0x02; /* domain separation */
    sliscp_light256_permute_spix(state, 9);
    c += mlen;

    /* Generate the authentication tag */
    spix_finalize_masked(state, k, c);
    return 0;
}

int spix_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[SPIX_MASKED_STATE_SIZE];
    unsigned char *mtemp = m;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPIX_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - SPIX_MASKED_TAG_SIZE;

    /* Initialize the SPIX state and absorb the associated data */
    spix_init_masked(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPIX_MASKED_TAG_SIZE;
    while (clen >= SPIX_MASKED_RATE) {
        lw_xor_block_swap(m, state + 8, c, SPIX_MASKED_RATE);
        state[SPIX_MASKED_STATE_SIZE - 1] ^= 0x02; /* domain separation */
        sliscp_light256_permute_spix(state, 9);
        c += SPIX_MASKED_RATE;
        m += SPIX_MASKED_RATE;
        clen -= SPIX_MASKED_RATE;
    }
    temp = (unsigned)clen;
    lw_xor_block_swap(m, state + 8, c, temp);
    state[temp + 8] ^= 0x80; /* padding */
    state[SPIX_MASKED_STATE_SIZE - 1] ^= 0x02; /* domain separation */
    sliscp_light256_permute_spix(state, 9);
    c += clen;

    /* Finalize the SPIX state and compare against the authentication tag */
    spix_finalize_masked(state, k, state);
    return aead_check_tag(mtemp, *mlen, state, c, SPIX_MASKED_TAG_SIZE);
}

#else /* !AEAD_MASKING_KEY_ONLY */

/**
 * \brief Size of the masked state for sLiSCP-light-256 in words.
 */
#define SPIX_MASKED_STATE_SIZE 8

/**
 * \brief Initializes the SPIX state.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spix_init_masked
    (mask_uint32_t state[SPIX_MASKED_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char padded[SPIX_MASKED_RATE];
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    aead_random_init();
    mask_input(state[0], be_load_word32(npub));
    mask_input(state[1], be_load_word32(npub + 4));
    mask_input(state[2], be_load_word32(k));
    mask_input(state[3], be_load_word32(k + 4));
    mask_input(state[4], be_load_word32(npub + 8));
    mask_input(state[5], be_load_word32(npub + 12));
    mask_input(state[6], be_load_word32(k + 8));
    mask_input(state[7], be_load_word32(k + 12));

    /* Run the permutation to scramble the initial state */
    sliscp_light256_permute_masked(state, 18);

    /* Absorb the key in two further permutation operations */
    mask_xor_const(state[2], be_load_word32(k));
    mask_xor_const(state[6], be_load_word32(k + 4));
    sliscp_light256_permute_masked(state, 18);
    mask_xor_const(state[2], be_load_word32(k + 8));
    mask_xor_const(state[6], be_load_word32(k + 12));
    sliscp_light256_permute_masked(state, 18);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPIX_MASKED_RATE) {
            mask_xor_const(state[2], be_load_word32(ad));
            mask_xor_const(state[6], be_load_word32(ad + 4));
            mask_xor_const(state[7], 0x01); /* domain separation */
            sliscp_light256_permute_masked(state, 9);
            ad += SPIX_MASKED_RATE;
            adlen -= SPIX_MASKED_RATE;
        }
        temp = (unsigned)adlen;
        memcpy(padded, ad, temp);
        padded[temp] = 0x80; /* padding */
        memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
        mask_xor_const(state[2], be_load_word32(padded));
        mask_xor_const(state[6], be_load_word32(padded + 4));
        mask_xor_const(state[7], 0x01); /* domain separation */
        sliscp_light256_permute_masked(state, 9);
    }
}

/**
 * \brief Finalizes the SPIX encryption or decryption operation.
 *
 * \param state sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spix_finalize_masked
    (mask_uint32_t state[SPIX_MASKED_STATE_SIZE],
     const unsigned char *k, unsigned char *tag)
{
    /* Absorb the key into the state again */
    mask_xor_const(state[2], be_load_word32(k));
    mask_xor_const(state[6], be_load_word32(k + 4));
    sliscp_light256_permute_masked(state, 18);
    mask_xor_const(state[2], be_load_word32(k + 8));
    mask_xor_const(state[6], be_load_word32(k + 12));
    sliscp_light256_permute_masked(state, 18);

    /* Copy out the authentication tag */
    be_store_word32(tag,      mask_output(state[2]));
    be_store_word32(tag + 4,  mask_output(state[3]));
    be_store_word32(tag + 8,  mask_output(state[6]));
    be_store_word32(tag + 12, mask_output(state[7]));
    aead_random_finish();
}

int spix_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[SPIX_MASKED_STATE_SIZE];
    unsigned char padded[SPIX_MASKED_RATE];
    uint32_t mword;
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPIX_MASKED_TAG_SIZE;

    /* Initialize the SPIX state and absorb the associated data */
    spix_init_masked(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= SPIX_MASKED_RATE) {
        mword = be_load_word32(m);
        mask_xor_const(state[2], mword);
        be_store_word32(c, mask_output(state[2]));
        mword = be_load_word32(m + 4);
        mask_xor_const(state[6], mword);
        be_store_word32(c + 4, mask_output(state[6]));
        mask_xor_const(state[7], 0x02); /* domain separation */
        sliscp_light256_permute_masked(state, 9);
        c += SPIX_MASKED_RATE;
        m += SPIX_MASKED_RATE;
        mlen -= SPIX_MASKED_RATE;
    }
    temp = (unsigned)mlen;
    memcpy(padded, m, temp);
    padded[temp] = 0x80; /* padding */
    memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
    mword = be_load_word32(padded);
    mask_xor_const(state[2], mword);
    be_store_word32(padded, mask_output(state[2]));
    mword = be_load_word32(padded + 4);
    mask_xor_const(state[6], mword);
    be_store_word32(padded + 4, mask_output(state[6]));
    mask_xor_const(state[7], 0x02); /* domain separation */
    sliscp_light256_permute_masked(state, 9);
    memcpy(c, padded, temp);
    c += mlen;

    /* Generate the authentication tag */
    spix_finalize_masked(state, k, c);
    return 0;
}

int spix_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[SPIX_MASKED_STATE_SIZE];
    unsigned char tag[SPIX_MASKED_TAG_SIZE];
    unsigned char *mtemp = m;
    unsigned temp;
    uint32_t mword;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPIX_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - SPIX_MASKED_TAG_SIZE;

    /* Initialize the SPIX state and absorb the associated data */
    spix_init_masked(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPIX_MASKED_TAG_SIZE;
    while (clen >= SPIX_MASKED_RATE) {
        mword = mask_output(state[2]) ^ be_load_word32(c);
        mask_xor_const(state[2], mword);
        be_store_word32(m, mword);
        mword = mask_output(state[6]) ^ be_load_word32(c + 4);
        mask_xor_const(state[6], mword);
        be_store_word32(m + 4, mword);
        mask_xor_const(state[7], 0x02); /* domain separation */
        sliscp_light256_permute_masked(state, 9);
        c += SPIX_MASKED_RATE;
        m += SPIX_MASKED_RATE;
        clen -= SPIX_MASKED_RATE;
    }
    temp = (unsigned)clen;
    be_store_word32(tag,     mask_output(state[2]));
    be_store_word32(tag + 4, mask_output(state[6]));
    lw_xor_block_2_dest(m, tag, c, temp);
    tag[temp] = 0x80;
    memset(tag + temp + 1, 0, SPIX_MASKED_RATE - (temp + 1));
    mask_xor_const(state[2], be_load_word32(tag));
    mask_xor_const(state[6], be_load_word32(tag + 4));
    mask_xor_const(state[7], 0x02); /* domain separation */
    sliscp_light256_permute_masked(state, 9);
    c += clen;

    /* Finalize the SPIX state and compare against the authentication tag */
    spix_finalize_masked(state, k, tag);
    return aead_check_tag(mtemp, *mlen, tag, c, SPIX_MASKED_TAG_SIZE);
}

#endif /* !AEAD_MASKING_KEY_ONLY */
