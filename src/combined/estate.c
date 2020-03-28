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

#include "estate.h"
#include "internal-gift128.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const estate_twegift_cipher = {
    "ESTATE_TweGIFT-128",
    ESTATE_TWEGIFT_KEY_SIZE,
    ESTATE_TWEGIFT_NONCE_SIZE,
    ESTATE_TWEGIFT_TAG_SIZE,
    AEAD_FLAG_NONE,
    estate_twegift_aead_encrypt,
    estate_twegift_aead_decrypt
};

/**
 * \brief Generates the FCBC MAC for a packet using ESTATE_TweGIFT-128.
 *
 * \param ks The key schedule for TweGIFT-128.
 * \param tag Rolling state of the authentication tag.
 * \param m Message to be authenticated.
 * \param mlen Length of the message to be authenticated; must be >= 1.
 * \param tweak1 Tweak value to use when the last block is full.
 * \param tweak2 Tweak value to use when the last block is partial.
 */
static void estate_twegift_fcbc
    (const gift128n_key_schedule_t *ks, unsigned char tag[16],
     const unsigned char *m, unsigned long long mlen,
     unsigned char tweak1, unsigned char tweak2)
{
    while (mlen > 16) {
        lw_xor_block(tag, m, 16);
        gift128n_encrypt(ks, tag, tag);
        m += 16;
        mlen -= 16;
    }
    if (mlen == 16) {
        lw_xor_block(tag, m, 16);
        gift128t_encrypt(ks, tag, tag, tweak1);
    } else {
        unsigned temp = (unsigned)mlen;
        lw_xor_block(tag, m, temp);
        tag[temp] ^= 0x01;
        gift128t_encrypt(ks, tag, tag, tweak2);
    }
}

/**
 * \brief Generates the MAC for a packet using ESTATE_TweGIFT-128.
 *
 * \param ks The key schedule for TweGIFT-128.
 * \param tag Rolling state of the authentication tag.
 * \param m Message to be authenticated.
 * \param mlen Length of the message to be authenticated.
 * \param ad Associated data to be authenticated.
 * \param adlen Length of the associated data to be authenticated.
 */
static void estate_twegift_authenticate
    (const gift128n_key_schedule_t *ks, unsigned char tag[16],
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen)
{
    /* Handle the case where both the message and associated data are empty */
    if (mlen == 0 && adlen == 0) {
        gift128t_encrypt(ks, tag, tag, /*tweak=*/8);
        return;
    }

    /* Encrypt the nonce */
    gift128t_encrypt(ks, tag, tag, /*tweak=*/1);

    /* Compute the FCBC MAC over the associated data */
    if (adlen != 0) {
        if (mlen != 0)
            estate_twegift_fcbc(ks, tag, ad, adlen, /*tweak1=*/2, /*tweak2=*/3);
        else
            estate_twegift_fcbc(ks, tag, ad, adlen, /*tweak1=*/6, /*tweak2=*/7);
    }

    /* Compute the FCBC MAC over the message data */
    if (mlen != 0)
        estate_twegift_fcbc(ks, tag, m, mlen, /*tweak1=*/4, /*tweak2=*/5);
}

/**
 * \brief Encrypts (or decrypts) a payload using ESTATE_TweGIFT-128.
 *
 * \param ks The key schedule for TweGIFT-128.
 * \param tag Pre-computed authentication tag for the packet.
 * \param c Ciphertext after encryption.
 * \param m Plaintext to be encrypted.
 * \param mlen Length of the plaintext to be encrypted.
 */
static void estate_twegift_encrypt
    (const gift128n_key_schedule_t *ks, const unsigned char tag[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    unsigned char block[16];
    memcpy(block, tag, 16);
    while (mlen >= 16) {
        gift128n_encrypt(ks, block, block);
        lw_xor_block_2_src(c, block, m, 16);
        c += 16;
        m += 16;
        mlen -= 16;
    }
    if (mlen > 0) {
        gift128n_encrypt(ks, block, block);
        lw_xor_block_2_src(c, block, m, (unsigned)mlen);
    }
}

int estate_twegift_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128n_key_schedule_t ks;
    unsigned char tag[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ESTATE_TWEGIFT_TAG_SIZE;

    /* Set up the key schedule and copy the nonce into the tag */
    gift128n_init(&ks, k);
    memcpy(tag, npub, 16);

    /* Authenticate the associated data and plaintext */
    estate_twegift_authenticate(&ks, tag, m, mlen, ad, adlen);

    /* Encrypt the plaintext to generate the ciphertext */
    estate_twegift_encrypt(&ks, tag, c, m, mlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, tag, 16);
    return 0;
}

int estate_twegift_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128n_key_schedule_t ks;
    unsigned char tag[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ESTATE_TWEGIFT_TAG_SIZE)
        return -1;
    *mlen = clen - ESTATE_TWEGIFT_TAG_SIZE;

    /* Set up the key schedule and copy the nonce into the tag */
    gift128n_init(&ks, k);
    memcpy(tag, npub, 16);

    /* Decrypt the ciphertext to generate the plaintext */
    estate_twegift_encrypt(&ks, c + *mlen, m, c, *mlen);

    /* Authenticate the associated data and plaintext */
    estate_twegift_authenticate(&ks, tag, m, *mlen, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, tag, c + *mlen, 16);
}
