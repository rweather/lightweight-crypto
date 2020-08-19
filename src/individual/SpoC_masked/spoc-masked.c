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

#include "spoc-masked.h"
#include "internal-sliscp-light-m.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Size of the state for the masked sLiSCP-light-256 permutation.
 */
#define SPOC_128_MASKED_STATE_SIZE 8

/**
 * \brief Rate for absorbing data into the sLiSCP-light-256 state and for
 * squeezing data out again.
 */
#define SPOC_128_MASKED_RATE 16

/**
 * \brief Size of the state for the masked sLiSCP-light-192 permutation.
 */
#define SPOC_64_MASKED_STATE_SIZE 8

/**
 * \brief Rate for absorbing data into the sLiSCP-light-192 state and for
 * squeezing data out again.
 */
#define SPOC_64_MASKED_RATE 8

aead_cipher_t const spoc_128_masked_cipher = {
    "SpoC-128-Masked",
    SPOC_MASKED_KEY_SIZE,
    SPOC_MASKED_NONCE_SIZE,
    SPOC_128_MASKED_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    spoc_128_masked_aead_encrypt,
    spoc_128_masked_aead_decrypt
};

aead_cipher_t const spoc_64_masked_cipher = {
    "SpoC-64-Masked",
    SPOC_MASKED_KEY_SIZE,
    SPOC_MASKED_NONCE_SIZE,
    SPOC_64_MASKED_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    spoc_64_masked_aead_encrypt,
    spoc_64_masked_aead_decrypt
};

/**
 * \brief Initializes the masked SpoC-128 state.
 *
 * \param state Masked sLiSCP-light-256 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spoc_128_init_masked
    (mask_uint32_t state[SPOC_128_MASKED_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state by combining the key and nonce */
    aead_random_init();
    mask_input(state[0], be_load_word32(k));
    mask_input(state[1], be_load_word32(k + 4));
    mask_input(state[2], be_load_word32(npub));
    mask_input(state[3], be_load_word32(npub + 4));
    mask_input(state[4], be_load_word32(k + 8));
    mask_input(state[5], be_load_word32(k + 12));
    mask_input(state[6], be_load_word32(npub + 8));
    mask_input(state[7], be_load_word32(npub + 12));

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPOC_128_MASKED_RATE) {
            sliscp_light256_permute_masked(state, 18);
            mask_xor_const(state[2], be_load_word32(ad));
            mask_xor_const(state[3], be_load_word32(ad + 4));
            mask_xor_const(state[6], be_load_word32(ad + 8));
            mask_xor_const(state[7], be_load_word32(ad + 12));
            mask_xor_const(state[0], 0x20000000U); /* domain separation */
            ad += SPOC_128_MASKED_RATE;
            adlen -= SPOC_128_MASKED_RATE;
        }
        temp = (unsigned)adlen;
        if (temp > 0) {
            unsigned char padded[SPOC_128_MASKED_RATE];
            sliscp_light256_permute_masked(state, 18);
            memcpy(padded, ad, temp);
            padded[temp] = 0x80; /* padding */
            memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
            mask_xor_const(state[2], be_load_word32(padded));
            mask_xor_const(state[3], be_load_word32(padded + 4));
            mask_xor_const(state[6], be_load_word32(padded + 8));
            mask_xor_const(state[7], be_load_word32(padded + 12));
            mask_xor_const(state[0], 0x30000000U); /* domain separation */
        }
    }
}

/**
 * \brief Initializes the masked SpoC-64 state.
 *
 * \param state sLiSCP-light-192 permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void spoc_64_init_masked
    (mask_uint32_t state[SPOC_64_MASKED_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    aead_random_init();
    mask_input(state[0], be_load_word24(npub));
    mask_input(state[1], (((uint32_t)(npub[3])) << 16) | be_load_word16(k + 6));
    mask_input(state[2], be_load_word24(k));
    mask_input(state[3], be_load_word24(k + 3));
    mask_input(state[4], be_load_word24(npub + 4));
    mask_input(state[5], (((uint32_t)(npub[7])) << 16) | be_load_word16(k + 14));
    mask_input(state[6], be_load_word24(k + 8));
    mask_input(state[7], be_load_word24(k + 11));
    sliscp_light192_reduce_masked(state);
    sliscp_light192_permute_masked(state);
    mask_xor_const(state[2], be_load_word24(npub + 8));
    mask_xor_const(state[3], ((uint32_t)(npub[11])) << 16);
    mask_xor_const(state[6], be_load_word24(npub + 12));
    mask_xor_const(state[7], ((uint32_t)(npub[15])) << 16);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= SPOC_64_MASKED_RATE) {
            sliscp_light192_permute_masked(state);
            mask_xor_const(state[2], be_load_word24(ad));
            mask_xor_const(state[3], ((uint32_t)(ad[3])) << 16);
            mask_xor_const(state[6], be_load_word24(ad + 4));
            mask_xor_const(state[7], ((uint32_t)(ad[7])) << 16);
            mask_xor_const(state[0], 0x00200000U); /* domain separation */
            ad += SPOC_64_MASKED_RATE;
            adlen -= SPOC_64_MASKED_RATE;
        }
        temp = (unsigned)adlen;
        if (temp > 0) {
            unsigned char padded[SPOC_64_MASKED_RATE];
            sliscp_light192_permute_masked(state);
            memcpy(padded, ad, temp);
            padded[temp] = 0x80; /* padding */
            memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
            mask_xor_const(state[2], be_load_word24(padded));
            mask_xor_const(state[3], ((uint32_t)(padded[3])) << 16);
            mask_xor_const(state[6], be_load_word24(padded + 4));
            mask_xor_const(state[7], ((uint32_t)(padded[7])) << 16);
            mask_xor_const(state[0], 0x00300000U); /* domain separation */
        }
    }
}

/**
 * \brief Finalizes the SpoC-128 encryption or decryption operation.
 *
 * \param state Masked sLiSCP-light-256 permutation state.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spoc_128_finalize_masked
    (mask_uint32_t state[SPOC_128_MASKED_STATE_SIZE], unsigned char *tag)
{
    /* Pad and permute the state one more time */
    mask_xor_const(state[0], 0x80000000U);
    sliscp_light256_permute_masked(state, 18);

    /* Copy out the authentication tag */
    be_store_word32(tag,      mask_output(state[2]));
    be_store_word32(tag + 4,  mask_output(state[3]));
    be_store_word32(tag + 8,  mask_output(state[6]));
    be_store_word32(tag + 12, mask_output(state[7]));
    aead_random_finish();
}

/**
 * \brief Finalizes the SpoC-64 encryption or decryption operation.
 *
 * \param state sLiSCP-light-192 permutation state.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void spoc_64_finalize_masked
    (mask_uint32_t state[SPOC_64_MASKED_STATE_SIZE], unsigned char *tag)
{
    /* Pad and permute the state one more time */
    mask_xor_const(state[0], 0x00800000U);
    sliscp_light192_permute_masked(state);

    /* Copy out the authentication tag */
    be_store_word24(tag, mask_output(state[2]));
    tag[3] = (unsigned char)(mask_output(state[3]) >> 16);
    be_store_word24(tag + 4, mask_output(state[6]));
    tag[7] = (unsigned char)(mask_output(state[7]) >> 16);
    aead_random_finish();
}

int spoc_128_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[SPOC_128_MASKED_STATE_SIZE];
    uint32_t mword;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOC_128_MASKED_TAG_SIZE;

    /* Initialize the SpoC-128 state and absorb the associated data */
    spoc_128_init_masked(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen != 0) {
        while (mlen >= SPOC_128_MASKED_RATE) {
            sliscp_light256_permute_masked(state, 18);
            mword = be_load_word32(m);
            mask_xor_const(state[2], mword);
            be_store_word32(c, mask_output(state[0]) ^ mword);
            mword = be_load_word32(m + 4);
            mask_xor_const(state[3], mword);
            be_store_word32(c + 4, mask_output(state[1]) ^ mword);
            mword = be_load_word32(m + 8);
            mask_xor_const(state[6], mword);
            be_store_word32(c + 8, mask_output(state[4]) ^ mword);
            mword = be_load_word32(m + 12);
            mask_xor_const(state[7], mword);
            be_store_word32(c + 12, mask_output(state[5]) ^ mword);
            mask_xor_const(state[0], 0x40000000U); /* domain separation */
            c += SPOC_128_MASKED_RATE;
            m += SPOC_128_MASKED_RATE;
            mlen -= SPOC_128_MASKED_RATE;
        }
        if (mlen != 0) {
            unsigned char padded[SPOC_128_MASKED_RATE];
            unsigned temp = (unsigned)mlen;
            sliscp_light256_permute_masked(state, 18);
            memcpy(padded, m, temp);
            padded[temp] = 0x80; /* padding */
            memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
            mword = be_load_word32(padded);
            mask_xor_const(state[2], mword);
            be_store_word32(padded, mask_output(state[0]) ^ mword);
            mword = be_load_word32(padded + 4);
            mask_xor_const(state[3], mword);
            be_store_word32(padded + 4, mask_output(state[1]) ^ mword);
            mword = be_load_word32(padded + 8);
            mask_xor_const(state[6], mword);
            be_store_word32(padded + 8, mask_output(state[4]) ^ mword);
            mword = be_load_word32(padded + 12);
            mask_xor_const(state[7], mword);
            be_store_word32(padded + 12, mask_output(state[5]) ^ mword);
            mask_xor_const(state[0], 0x50000000U); /* domain separation */
            memcpy(c, padded, temp);
            c += mlen;
        }
    }

    /* Finalize and generate the authentication tag */
    spoc_128_finalize_masked(state, c);
    return 0;
}

int spoc_128_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[SPOC_128_MASKED_STATE_SIZE];
    unsigned char padded[SPOC_128_MASKED_RATE];
    unsigned char *mtemp = m;
    uint32_t mword;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOC_128_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - SPOC_128_MASKED_TAG_SIZE;

    /* Initialize the Spoc-128 state and absorb the associated data */
    spoc_128_init_masked(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOC_128_MASKED_TAG_SIZE;
    if (clen != 0) {
        while (clen >= SPOC_128_MASKED_RATE) {
            sliscp_light256_permute_masked(state, 18);
            mword = be_load_word32(c) ^ mask_output(state[0]);
            be_store_word32(m, mword);
            mask_xor_const(state[2], mword);
            mword = be_load_word32(c + 4) ^ mask_output(state[1]);
            be_store_word32(m + 4, mword);
            mask_xor_const(state[3], mword);
            mword = be_load_word32(c + 8) ^ mask_output(state[4]);
            be_store_word32(m + 8, mword);
            mask_xor_const(state[6], mword);
            mword = be_load_word32(c + 12) ^ mask_output(state[5]);
            be_store_word32(m + 12, mword);
            mask_xor_const(state[7], mword);
            mask_xor_const(state[0], 0x40000000U); /* domain separation */
            c += SPOC_128_MASKED_RATE;
            m += SPOC_128_MASKED_RATE;
            clen -= SPOC_128_MASKED_RATE;
        }
        if (clen != 0) {
            unsigned temp = (unsigned)clen;
            sliscp_light256_permute_masked(state, 18);
            memcpy(padded, c, temp);
            memset(padded + temp, 0, sizeof(padded) - temp);
            mword = be_load_word32(padded) ^ mask_output(state[0]);
            be_store_word32(padded, mword);
            mword = be_load_word32(padded + 4) ^ mask_output(state[1]);
            be_store_word32(padded + 4, mword);
            mword = be_load_word32(padded + 8) ^ mask_output(state[4]);
            be_store_word32(padded + 8, mword);
            mword = be_load_word32(padded + 12) ^ mask_output(state[5]);
            be_store_word32(padded + 12, mword);
            memcpy(m, padded, temp);
            padded[temp] = 0x80; /* padding */
            memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
            mask_xor_const(state[2], be_load_word32(padded));
            mask_xor_const(state[3], be_load_word32(padded + 4));
            mask_xor_const(state[6], be_load_word32(padded + 8));
            mask_xor_const(state[7], be_load_word32(padded + 12));
            mask_xor_const(state[0], 0x50000000U); /* domain separation */
            c += clen;
        }
    }

    /* Finalize and check the authentication tag */
    spoc_128_finalize_masked(state, padded);
    return aead_check_tag(mtemp, *mlen, padded, c, SPOC_128_MASKED_TAG_SIZE);
}

int spoc_64_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[SPOC_64_MASKED_STATE_SIZE];
    uint32_t mword;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SPOC_64_MASKED_TAG_SIZE;

    /* Initialize the SpoC-64 state and absorb the associated data */
    spoc_64_init_masked(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen != 0) {
        while (mlen >= SPOC_64_MASKED_RATE) {
            sliscp_light192_permute_masked(state);
            mword = be_load_word32(m);
            mask_xor_const(state[2], mword >> 8);
            mask_xor_const(state[3], (mword << 16) & 0x00FF0000U);
            mword ^= (mask_output(state[0]) << 8);
            mword ^= (mask_output(state[1]) >> 16);
            be_store_word32(c, mword);
            mword = be_load_word32(m + 4);
            mask_xor_const(state[6], mword >> 8);
            mask_xor_const(state[7], (mword << 16) & 0x00FF0000U);
            mword ^= (mask_output(state[4]) << 8);
            mword ^= (mask_output(state[5]) >> 16);
            be_store_word32(c + 4, mword);
            mask_xor_const(state[0], 0x00400000U); /* domain separation */
            c += SPOC_64_MASKED_RATE;
            m += SPOC_64_MASKED_RATE;
            mlen -= SPOC_64_MASKED_RATE;
        }
        if (mlen != 0) {
            unsigned char padded[SPOC_64_MASKED_RATE];
            unsigned temp = (unsigned)mlen;
            sliscp_light192_permute_masked(state);
            memcpy(padded, m, temp);
            padded[temp] = 0x80; /* padding */
            memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
            mword = be_load_word32(padded);
            mask_xor_const(state[2], mword >> 8);
            mask_xor_const(state[3], (mword << 16) & 0x00FF0000U);
            mword ^= (mask_output(state[0]) << 8);
            mword ^= (mask_output(state[1]) >> 16);
            be_store_word32(padded, mword);
            mword = be_load_word32(padded + 4);
            mask_xor_const(state[6], mword >> 8);
            mask_xor_const(state[7], (mword << 16) & 0x00FF0000U);
            mword ^= (mask_output(state[4]) << 8);
            mword ^= (mask_output(state[5]) >> 16);
            be_store_word32(padded + 4, mword);
            mask_xor_const(state[0], 0x00500000U); /* domain separation */
            memcpy(c, padded, temp);
            c += mlen;
        }
    }

    /* Finalize and generate the authentication tag */
    spoc_64_finalize_masked(state, c);
    return 0;
}

int spoc_64_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[SPOC_64_MASKED_STATE_SIZE];
    unsigned char padded[SPOC_64_MASKED_RATE];
    unsigned char *mtemp = m;
    uint32_t mword;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SPOC_64_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - SPOC_64_MASKED_TAG_SIZE;

    /* Initialize the Spoc-64 state and absorb the associated data */
    spoc_64_init_masked(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SPOC_64_MASKED_TAG_SIZE;
    if (clen != 0) {
        while (clen >= SPOC_64_MASKED_RATE) {
            sliscp_light192_permute_masked(state);
            mword = be_load_word32(c) ^ (mask_output(state[0]) << 8) ^
                    (mask_output(state[1]) >> 16);
            be_store_word32(m, mword);
            mask_xor_const(state[2], mword >> 8);
            mask_xor_const(state[3], (mword << 16) & 0x00FF0000U);
            mword = be_load_word32(c + 4) ^ (mask_output(state[4]) << 8) ^
                    (mask_output(state[5]) >> 16);
            be_store_word32(m + 4, mword);
            mask_xor_const(state[6], mword >> 8);
            mask_xor_const(state[7], (mword << 16) & 0x00FF0000U);
            mask_xor_const(state[0], 0x00400000U); /* domain separation */
            c += SPOC_64_MASKED_RATE;
            m += SPOC_64_MASKED_RATE;
            clen -= SPOC_64_MASKED_RATE;
        }
        if (clen != 0) {
            unsigned temp = (unsigned)clen;
            sliscp_light192_permute_masked(state);
            memcpy(padded, c, temp);
            memset(padded + temp, 0, sizeof(padded) - temp);
            mword = be_load_word32(padded) ^ (mask_output(state[0]) << 8) ^
                    (mask_output(state[1]) >> 16);
            be_store_word32(padded, mword);
            mword = be_load_word32(padded + 4) ^ (mask_output(state[4]) << 8) ^
                    (mask_output(state[5]) >> 16);
            be_store_word32(padded + 4, mword);
            memcpy(m, padded, temp);
            padded[temp] = 0x80; /* padding */
            memset(padded + temp + 1, 0, sizeof(padded) - (temp + 1));
            mword = be_load_word32(padded);
            mask_xor_const(state[2], mword >> 8);
            mask_xor_const(state[3], (mword << 16) & 0x00FF0000U);
            mword = be_load_word32(padded + 4);
            mask_xor_const(state[6], mword >> 8);
            mask_xor_const(state[7], (mword << 16) & 0x00FF0000U);
            mask_xor_const(state[0], 0x00500000U); /* domain separation */
            c += clen;
        }
    }

    /* Finalize and check the authentication tag */
    spoc_64_finalize_masked(state, padded);
    return aead_check_tag(mtemp, *mlen, padded, c, SPOC_64_MASKED_TAG_SIZE);
}
