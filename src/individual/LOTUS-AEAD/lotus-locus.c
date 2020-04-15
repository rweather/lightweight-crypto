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

#include "lotus-locus.h"
#include "internal-gift64.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const lotus_aead_cipher = {
    "LOTUS-AEAD",
    LOTUS_AEAD_KEY_SIZE,
    LOTUS_AEAD_NONCE_SIZE,
    LOTUS_AEAD_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    lotus_aead_encrypt,
    lotus_aead_decrypt
};

aead_cipher_t const locus_aead_cipher = {
    "LOCUS-AEAD",
    LOCUS_AEAD_KEY_SIZE,
    LOCUS_AEAD_NONCE_SIZE,
    LOCUS_AEAD_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    locus_aead_encrypt,
    locus_aead_decrypt
};

/**
 * \brief Multiplies a key by 2 in the GF(128) field.
 *
 * \param ks The key schedule structure containing the key in host byte order.
 */
STATIC_INLINE void lotus_or_locus_mul_2(gift64n_key_schedule_t *ks)
{
    uint32_t mask = (uint32_t)(((int32_t)(ks->k[0])) >> 31);
    ks->k[0] = (ks->k[0] << 1) | (ks->k[1] >> 31);
    ks->k[1] = (ks->k[1] << 1) | (ks->k[2] >> 31);
    ks->k[2] = (ks->k[2] << 1) | (ks->k[3] >> 31);
    ks->k[3] = (ks->k[3] << 1) ^ (mask & 0x87);
    gift64n_update_round_keys(ks);
}

/**
 * \brief Initializes a LOTUS-AEAD or LOCUS-AEAD cipher instance.
 *
 * \param ks Key schedule to initialize.
 * \param deltaN Delta-N value for the cipher state.
 * \param key Points to the 16-byte key for the cipher instance.
 * \param nonce Points to the 16-byte key for the cipher instance.
 * \param T Points to a temporary buffer of LOTUS_AEAD_KEY_SIZE bytes
 * that will be destroyed during this function.
 */
static void lotus_or_locus_init
    (gift64n_key_schedule_t *ks,
     unsigned char deltaN[GIFT64_BLOCK_SIZE],
     const unsigned char *key,
     const unsigned char *nonce,
     unsigned char *T)
{
    gift64n_init(ks, key);
    memset(deltaN, 0, GIFT64_BLOCK_SIZE);
    gift64t_encrypt(ks, deltaN, deltaN, GIFT64T_TWEAK_0);
    lw_xor_block_2_src(T, key, nonce, LOTUS_AEAD_KEY_SIZE);
    gift64n_init(ks, T);
    gift64t_encrypt(ks, deltaN, deltaN, GIFT64T_TWEAK_1);
}

/**
 * \brief Processes associated data for LOTUS-AEAD or LOCUS-AEAD.
 *
 * \param ks Points to the key schedule.
 * \param deltaN Points to the Delta-N value from the state.
 * \param V Points to the V value from the state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes, must be non-zero.
 */
static void lotus_or_locus_process_ad
    (gift64n_key_schedule_t *ks,
     const unsigned char deltaN[GIFT64_BLOCK_SIZE],
     unsigned char V[GIFT64_BLOCK_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char X[GIFT64_BLOCK_SIZE];
    unsigned char temp;
    while (adlen > GIFT64_BLOCK_SIZE) {
        lotus_or_locus_mul_2(ks);
        lw_xor_block_2_src(X, ad, deltaN, GIFT64_BLOCK_SIZE);
        gift64t_encrypt(ks, X, X, GIFT64T_TWEAK_2);
        lw_xor_block(V, X, GIFT64_BLOCK_SIZE);
        ad += GIFT64_BLOCK_SIZE;
        adlen -= GIFT64_BLOCK_SIZE;
    }
    lotus_or_locus_mul_2(ks);
    temp = (unsigned)adlen;
    if (temp < GIFT64_BLOCK_SIZE) {
        memcpy(X, deltaN, GIFT64_BLOCK_SIZE);
        lw_xor_block(X, ad, temp);
        X[temp] ^= 0x01;
        gift64t_encrypt(ks, X, X, GIFT64T_TWEAK_3);
    } else {
        lw_xor_block_2_src(X, ad, deltaN, GIFT64_BLOCK_SIZE);
        gift64t_encrypt(ks, X, X, GIFT64T_TWEAK_2);
    }
    lw_xor_block(V, X, GIFT64_BLOCK_SIZE);
}

/**
 * \brief Generates the authentication tag for LOTUS-AEAD or LOCUS-AEAD.
 *
 * \param ks Points to the key schedule.
 * \param tag Points to the buffer to receive the authentication tag.
 * \param deltaN Points to the Delta-N value from the state.
 * \param W Points to the W value from the state.
 * \param V Points to the V value from the state.
 */
static void lotus_or_locus_gen_tag
    (gift64n_key_schedule_t *ks, unsigned char *tag,
     unsigned char deltaN[GIFT64_BLOCK_SIZE],
     unsigned char W[GIFT64_BLOCK_SIZE],
     unsigned char V[GIFT64_BLOCK_SIZE])
{
    lotus_or_locus_mul_2(ks);
    lw_xor_block(W, deltaN, GIFT64_BLOCK_SIZE);
    lw_xor_block(W, V, GIFT64_BLOCK_SIZE);
    gift64t_encrypt(ks, W, W, GIFT64T_TWEAK_6);
    lw_xor_block_2_src(tag, W, deltaN, GIFT64_BLOCK_SIZE);
}

int lotus_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift64n_key_schedule_t ks;
    unsigned char WV[GIFT64_BLOCK_SIZE * 2];
    unsigned char deltaN[GIFT64_BLOCK_SIZE];
    unsigned char X1[GIFT64_BLOCK_SIZE];
    unsigned char X2[GIFT64_BLOCK_SIZE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + LOTUS_AEAD_TAG_SIZE;

    /* Initialize the state with the key and the nonce */
    lotus_or_locus_init(&ks, deltaN, k, npub, WV);
    memset(WV, 0, sizeof(WV));

    /* Process the associated data */
    if (adlen > 0) {
        lotus_or_locus_process_ad
            (&ks, deltaN, WV + GIFT64_BLOCK_SIZE, ad, adlen);
    }

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > (GIFT64_BLOCK_SIZE * 2)) {
            lotus_or_locus_mul_2(&ks);
            lw_xor_block_2_src(X1, m, deltaN, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X1, GIFT64T_TWEAK_4);
            lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_4);
            lw_xor_block_2_src
                (X2, m + GIFT64_BLOCK_SIZE, X2, GIFT64_BLOCK_SIZE);
            lw_xor_block_2_src(c, X2, deltaN, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_5);
            lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_5);
            lw_xor_block_2_src
                (c + GIFT64_BLOCK_SIZE, X1, X2, GIFT64_BLOCK_SIZE);
            c += GIFT64_BLOCK_SIZE * 2;
            m += GIFT64_BLOCK_SIZE * 2;
            mlen -= GIFT64_BLOCK_SIZE * 2;
        }
        temp = (unsigned)mlen;
        lotus_or_locus_mul_2(&ks);
        memcpy(X1, deltaN, GIFT64_BLOCK_SIZE);
        X1[0] ^= (unsigned char)temp;
        gift64t_encrypt(&ks, X2, X1, GIFT64T_TWEAK_12);
        lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
        gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_12);
        if (temp <= GIFT64_BLOCK_SIZE) {
            lw_xor_block(WV, m, temp);
            lw_xor_block(X2, m, temp);
            lw_xor_block_2_src(c, X2, deltaN, temp);
        } else {
            lw_xor_block(X2, m, GIFT64_BLOCK_SIZE);
            lw_xor_block_2_src(c, X2, deltaN, GIFT64_BLOCK_SIZE);
            c += GIFT64_BLOCK_SIZE;
            m += GIFT64_BLOCK_SIZE;
            temp -= GIFT64_BLOCK_SIZE;
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_13);
            lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_13);
            lw_xor_block(WV, m, temp);
            lw_xor_block(X1, X2, temp);
            lw_xor_block_2_src(c, X1, m, temp);
        }
        c += temp;
    }

    /* Generate the authentication tag */
    lotus_or_locus_gen_tag(&ks, c, deltaN, WV, WV + GIFT64_BLOCK_SIZE);
    return 0;
}

int lotus_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift64n_key_schedule_t ks;
    unsigned char WV[GIFT64_BLOCK_SIZE * 2];
    unsigned char deltaN[GIFT64_BLOCK_SIZE];
    unsigned char X1[GIFT64_BLOCK_SIZE];
    unsigned char X2[GIFT64_BLOCK_SIZE];
    unsigned char *mtemp = m;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < LOTUS_AEAD_TAG_SIZE)
        return -1;
    *mlen = clen - LOTUS_AEAD_TAG_SIZE;

    /* Initialize the state with the key and the nonce */
    lotus_or_locus_init(&ks, deltaN, k, npub, WV);
    memset(WV, 0, sizeof(WV));

    /* Process the associated data */
    if (adlen > 0) {
        lotus_or_locus_process_ad
            (&ks, deltaN, WV + GIFT64_BLOCK_SIZE, ad, adlen);
    }

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= LOTUS_AEAD_TAG_SIZE;
    if (clen > 0) {
        while (clen > (GIFT64_BLOCK_SIZE * 2)) {
            lotus_or_locus_mul_2(&ks);
            lw_xor_block_2_src(X1, c, deltaN, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X1, GIFT64T_TWEAK_5);
            lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_5);
            lw_xor_block(X2, c + GIFT64_BLOCK_SIZE, GIFT64_BLOCK_SIZE);
            lw_xor_block_2_src(m, X2, deltaN, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_4);
            lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_4);
            lw_xor_block_2_src
                (m + GIFT64_BLOCK_SIZE, X1, X2, GIFT64_BLOCK_SIZE);
            c += GIFT64_BLOCK_SIZE * 2;
            m += GIFT64_BLOCK_SIZE * 2;
            clen -= GIFT64_BLOCK_SIZE * 2;
        }
        temp = (unsigned)clen;
        lotus_or_locus_mul_2(&ks);
        memcpy(X1, deltaN, GIFT64_BLOCK_SIZE);
        X1[0] ^= (unsigned char)temp;
        gift64t_encrypt(&ks, X2, X1, GIFT64T_TWEAK_12);
        lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
        gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_12);
        if (temp <= GIFT64_BLOCK_SIZE) {
            lw_xor_block_2_src(m, X2, c, temp);
            lw_xor_block(m, deltaN, temp);
            lw_xor_block(X2, m, temp);
            lw_xor_block(WV, m, temp);
        } else {
            lw_xor_block_2_src(m, X2, c, GIFT64_BLOCK_SIZE);
            lw_xor_block(m, deltaN, GIFT64_BLOCK_SIZE);
            lw_xor_block(X2, m, GIFT64_BLOCK_SIZE);
            c += GIFT64_BLOCK_SIZE;
            m += GIFT64_BLOCK_SIZE;
            temp -= GIFT64_BLOCK_SIZE;
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_13);
            lw_xor_block(WV, X2, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X2, X2, GIFT64T_TWEAK_13);
            lw_xor_block(X1, X2, temp);
            lw_xor_block_2_src(m, X1, c, temp);
            lw_xor_block(WV, m, temp);
        }
        c += temp;
    }

    /* Check the authentication tag */
    lotus_or_locus_gen_tag(&ks, WV, deltaN, WV, WV + GIFT64_BLOCK_SIZE);
    return aead_check_tag(mtemp, *mlen, WV, c, LOTUS_AEAD_TAG_SIZE);
}

int locus_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift64n_key_schedule_t ks;
    unsigned char WV[GIFT64_BLOCK_SIZE * 2];
    unsigned char deltaN[GIFT64_BLOCK_SIZE];
    unsigned char X[GIFT64_BLOCK_SIZE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + LOCUS_AEAD_TAG_SIZE;

    /* Initialize the state with the key and the nonce */
    lotus_or_locus_init(&ks, deltaN, k, npub, WV);
    memset(WV, 0, sizeof(WV));

    /* Process the associated data */
    if (adlen > 0) {
        lotus_or_locus_process_ad
            (&ks, deltaN, WV + GIFT64_BLOCK_SIZE, ad, adlen);
    }

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > GIFT64_BLOCK_SIZE) {
            lotus_or_locus_mul_2(&ks);
            lw_xor_block_2_src(X, m, deltaN, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X, X, GIFT64T_TWEAK_4);
            lw_xor_block(WV, X, GIFT64_BLOCK_SIZE);
            gift64t_encrypt(&ks, X, X, GIFT64T_TWEAK_4);
            lw_xor_block_2_src(c, X, deltaN, GIFT64_BLOCK_SIZE);
            c += GIFT64_BLOCK_SIZE;
            m += GIFT64_BLOCK_SIZE;
            mlen -= GIFT64_BLOCK_SIZE;
        }
        temp = (unsigned)mlen;
        lotus_or_locus_mul_2(&ks);
        memcpy(X, deltaN, GIFT64_BLOCK_SIZE);
        X[0] ^= (unsigned char)temp;
        gift64t_encrypt(&ks, X, X, GIFT64T_TWEAK_5);
        lw_xor_block(WV, X, GIFT64_BLOCK_SIZE);
        lw_xor_block(WV, m, temp);
        gift64t_encrypt(&ks, X, X, GIFT64T_TWEAK_5);
        lw_xor_block(X, deltaN, temp);
        lw_xor_block_2_src(c, m, X, temp);
        c += temp;
    }

    /* Generate the authentication tag */
    lotus_or_locus_gen_tag(&ks, c, deltaN, WV, WV + GIFT64_BLOCK_SIZE);
    return 0;
}

int locus_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift64n_key_schedule_t ks;
    unsigned char WV[GIFT64_BLOCK_SIZE * 2];
    unsigned char deltaN[GIFT64_BLOCK_SIZE];
    unsigned char X[GIFT64_BLOCK_SIZE];
    unsigned char *mtemp = m;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < LOCUS_AEAD_TAG_SIZE)
        return -1;
    *mlen = clen - LOCUS_AEAD_TAG_SIZE;

    /* Initialize the state with the key and the nonce */
    lotus_or_locus_init(&ks, deltaN, k, npub, WV);
    memset(WV, 0, sizeof(WV));

    /* Process the associated data */
    if (adlen > 0) {
        lotus_or_locus_process_ad
            (&ks, deltaN, WV + GIFT64_BLOCK_SIZE, ad, adlen);
    }

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= LOCUS_AEAD_TAG_SIZE;
    if (clen > 0) {
        while (clen > GIFT64_BLOCK_SIZE) {
            lotus_or_locus_mul_2(&ks);
            lw_xor_block_2_src(X, c, deltaN, GIFT64_BLOCK_SIZE);
            gift64t_decrypt(&ks, X, X, GIFT64T_TWEAK_4);
            lw_xor_block(WV, X, GIFT64_BLOCK_SIZE);
            gift64t_decrypt(&ks, X, X, GIFT64T_TWEAK_4);
            lw_xor_block_2_src(m, X, deltaN, GIFT64_BLOCK_SIZE);
            c += GIFT64_BLOCK_SIZE;
            m += GIFT64_BLOCK_SIZE;
            clen -= GIFT64_BLOCK_SIZE;
        }
        temp = (unsigned)clen;
        lotus_or_locus_mul_2(&ks);
        memcpy(X, deltaN, GIFT64_BLOCK_SIZE);
        X[0] ^= (unsigned char)temp;
        gift64t_encrypt(&ks, X, X, GIFT64T_TWEAK_5);
        lw_xor_block(WV, X, GIFT64_BLOCK_SIZE);
        gift64t_encrypt(&ks, X, X, GIFT64T_TWEAK_5);
        lw_xor_block(X, deltaN, temp);
        lw_xor_block_2_src(m, c, X, temp);
        lw_xor_block(WV, m, temp);
        c += temp;
    }

    /* Check the authentication tag */
    lotus_or_locus_gen_tag(&ks, WV, deltaN, WV, WV + GIFT64_BLOCK_SIZE);
    return aead_check_tag(mtemp, *mlen, WV, c, LOCUS_AEAD_TAG_SIZE);
}
