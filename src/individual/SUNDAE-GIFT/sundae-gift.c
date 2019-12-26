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

#include "sundae-gift.h"
#include "internal-gift128.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const sundae_gift_0_cipher = {
    "SUNDAE-GIFT-0",
    SUNDAE_GIFT_KEY_SIZE,
    SUNDAE_GIFT_0_NONCE_SIZE,
    SUNDAE_GIFT_TAG_SIZE,
    AEAD_FLAG_NONE,
    sundae_gift_0_aead_encrypt,
    sundae_gift_0_aead_decrypt
};

aead_cipher_t const sundae_gift_64_cipher = {
    "SUNDAE-GIFT-64",
    SUNDAE_GIFT_KEY_SIZE,
    SUNDAE_GIFT_64_NONCE_SIZE,
    SUNDAE_GIFT_TAG_SIZE,
    AEAD_FLAG_NONE,
    sundae_gift_64_aead_encrypt,
    sundae_gift_64_aead_decrypt
};

aead_cipher_t const sundae_gift_96_cipher = {
    "SUNDAE-GIFT-96",
    SUNDAE_GIFT_KEY_SIZE,
    SUNDAE_GIFT_96_NONCE_SIZE,
    SUNDAE_GIFT_TAG_SIZE,
    AEAD_FLAG_NONE,
    sundae_gift_96_aead_encrypt,
    sundae_gift_96_aead_decrypt
};

aead_cipher_t const sundae_gift_128_cipher = {
    "SUNDAE-GIFT-128",
    SUNDAE_GIFT_KEY_SIZE,
    SUNDAE_GIFT_128_NONCE_SIZE,
    SUNDAE_GIFT_TAG_SIZE,
    AEAD_FLAG_NONE,
    sundae_gift_128_aead_encrypt,
    sundae_gift_128_aead_decrypt
};

/* Multiply a block value by 2 in the special byte field */
STATIC_INLINE void sundae_gift_multiply(unsigned char B[16])
{
    unsigned char B0 = B[0];
    unsigned index;
    for (index = 0; index < 15; ++index)
        B[index] = B[index + 1];
    B[15] = B0;
    B[10] ^= B0;
    B[12] ^= B0;
    B[14] ^= B0;
}

/* Compute a MAC over the concatenation of two data buffers */
static void sundae_gift_aead_mac
    (const gift128b_key_schedule_t *ks, unsigned char V[16],
     const unsigned char *data1, unsigned data1len,
     const unsigned char *data2, unsigned long data2len)
{
    unsigned len;

    /* Nothing to do if the input is empty */
    if (!data1len && !data2len)
        return;

    /* Format the first block.  We assume that data1len <= 16
     * as it is will be the nonce if it is non-zero in length */
    lw_xor_block(V, data1, data1len);
    len = 16 - data1len;
    if (len > data2len)
        len = (unsigned)data2len;
    lw_xor_block(V + data1len, data2, len);
    data2 += len;
    data2len -= len;
    len += data1len;

    /* Process as many full blocks as we can, except the last */
    while (data2len > 0) {
        gift128b_encrypt(ks, V, V);
        len = 16;
        if (len > data2len)
            len = (unsigned)data2len;
        lw_xor_block(V, data2, len);
        data2 += len;
        data2len -= len;
    }

    /* Pad and process the last block */
    if (len < 16) {
        V[len] ^= 0x80;
        sundae_gift_multiply(V);
        gift128b_encrypt(ks, V, V);
    } else {
        sundae_gift_multiply(V);
        sundae_gift_multiply(V);
        gift128b_encrypt(ks, V, V);
    }
}

static int sundae_gift_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub, unsigned npublen,
     const unsigned char *k, unsigned char domainsep)
{
    gift128b_key_schedule_t ks;
    unsigned char V[16];
    unsigned char T[16];
    unsigned char P[16];

    /* Compute the length of the output ciphertext */
    *clen = mlen + SUNDAE_GIFT_TAG_SIZE;

    /* Set the key schedule */
    if (!gift128b_init(&ks, k, SUNDAE_GIFT_KEY_SIZE))
        return -1;

    /* Format and encrypt the initial domain separation block */
    if (adlen > 0)
        domainsep |= 0x80;
    if (mlen > 0)
        domainsep |= 0x40;
    V[0] = domainsep;
    memset(V + 1, 0, sizeof(V) - 1);
    gift128b_encrypt(&ks, T, V);

    /* Authenticate the nonce and the associated data */
    sundae_gift_aead_mac(&ks, T, npub, npublen, ad, adlen);

    /* Authenticate the plaintext */
    sundae_gift_aead_mac(&ks, T, 0, 0, m, mlen);

    /* Encrypt the plaintext to produce the ciphertext.  We need to be
     * careful how we manage the data because we could be doing in-place
     * encryption.  In SUNDAE-GIFT, the first 16 bytes of the ciphertext
     * is the tag rather than the last 16 bytes in other algorithms.
     * We need to swap the plaintext for the current block with the
     * ciphertext or tag from the previous block */
    memcpy(V, T, 16);
    while (mlen >= 16) {
        gift128b_encrypt(&ks, V, V);
        lw_xor_block_2_src(P, V, m, 16);
        memcpy(c, T, 16);
        memcpy(T, P, 16);
        c += 16;
        m += 16;
        mlen -= 16;
    }
    if (mlen > 0) {
        unsigned leftover = (unsigned)mlen;
        gift128b_encrypt(&ks, V, V);
        lw_xor_block(V, m, leftover);
        memcpy(c, T, 16);
        memcpy(c + 16, V, leftover);
    } else {
        memcpy(c, T, 16);
    }
    return 0;
}

static int sundae_gift_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub, unsigned npublen,
     const unsigned char *k, unsigned char domainsep)
{
    gift128b_key_schedule_t ks;
    unsigned char V[16];
    unsigned char T[16];
    unsigned char *mtemp;
    unsigned long len;

    /* Bail out if the ciphertext is too short */
    if (clen < SUNDAE_GIFT_TAG_SIZE)
        return -1;
    len = *mlen = clen - SUNDAE_GIFT_TAG_SIZE;

    /* Set the key schedule */
    if (!gift128b_init(&ks, k, SUNDAE_GIFT_KEY_SIZE))
        return -1;

    /* Decrypt the ciphertext to produce the plaintext, using the
     * tag as the initialization vector for the decryption process */
    memcpy(T, c, SUNDAE_GIFT_TAG_SIZE);
    c += SUNDAE_GIFT_TAG_SIZE;
    mtemp = m;
    memcpy(V, T, 16);
    while (len >= 16) {
        gift128b_encrypt(&ks, V, V);
        lw_xor_block_2_src(mtemp, c, V, 16);
        c += 16;
        mtemp += 16;
        len -= 16;
    }
    if (len > 0) {
        gift128b_encrypt(&ks, V, V);
        lw_xor_block_2_src(mtemp, c, V, (unsigned)len);
    }

    /* Format and encrypt the initial domain separation block */
    if (adlen > 0)
        domainsep |= 0x80;
    if (clen > SUNDAE_GIFT_TAG_SIZE)
        domainsep |= 0x40;
    V[0] = domainsep;
    memset(V + 1, 0, sizeof(V) - 1);
    gift128b_encrypt(&ks, V, V);

    /* Authenticate the nonce and the associated data */
    sundae_gift_aead_mac(&ks, V, npub, npublen, ad, adlen);

    /* Authenticate the plaintext */
    sundae_gift_aead_mac(&ks, V, 0, 0, m, *mlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, T, V, 16, 0);
}

int sundae_gift_0_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    (void)npub;
    return sundae_gift_aead_encrypt
        (c, clen, m, mlen, ad, adlen, 0, 0, k, 0x00);
}

int sundae_gift_0_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    (void)npub;
    return sundae_gift_aead_decrypt
        (m, mlen, c, clen, ad, adlen, 0, 0, k, 0x00);
}

int sundae_gift_64_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    return sundae_gift_aead_encrypt
        (c, clen, m, mlen, ad, adlen,
         npub, SUNDAE_GIFT_64_NONCE_SIZE, k, 0x90);
}

int sundae_gift_64_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    return sundae_gift_aead_decrypt
        (m, mlen, c, clen, ad, adlen,
         npub, SUNDAE_GIFT_64_NONCE_SIZE, k, 0x90);
}

int sundae_gift_96_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    return sundae_gift_aead_encrypt
        (c, clen, m, mlen, ad, adlen,
         npub, SUNDAE_GIFT_96_NONCE_SIZE, k, 0xA0);
}

int sundae_gift_96_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    return sundae_gift_aead_decrypt
        (m, mlen, c, clen, ad, adlen,
         npub, SUNDAE_GIFT_96_NONCE_SIZE, k, 0xA0);
}

int sundae_gift_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    return sundae_gift_aead_encrypt
        (c, clen, m, mlen, ad, adlen,
         npub, SUNDAE_GIFT_128_NONCE_SIZE, k, 0xB0);
}

int sundae_gift_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    (void)nsec;
    return sundae_gift_aead_decrypt
        (m, mlen, c, clen, ad, adlen,
         npub, SUNDAE_GIFT_128_NONCE_SIZE, k, 0xB0);
}
