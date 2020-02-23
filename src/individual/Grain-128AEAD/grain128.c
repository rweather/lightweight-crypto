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

#include "grain128.h"
#include "internal-grain128.h"
#include <string.h>

aead_cipher_t const grain128_aead_cipher = {
    "Grain-128AEAD",
    GRAIN128_KEY_SIZE,
    GRAIN128_NONCE_SIZE,
    GRAIN128_TAG_SIZE,
    AEAD_FLAG_NONE,
    grain128_aead_encrypt,
    grain128_aead_decrypt
};

/**
 * \brief Encodes the associated data length in DER.
 *
 * \param buf The buffer to encode the length into.
 * \param adlen The length of the associated data in bytes, which must be
 * less than 2^32 to limit the length of the DER encoding to 5 bytes.
 *
 * \return The length of the DER encoding that was written to \a buf.
 */
static unsigned grain128_encode_adlen
    (unsigned char buf[5], unsigned long long adlen)
{
    if (adlen < 0x80U) {
        buf[0] = (unsigned char)adlen;
        return 1;
    } else if (adlen < 0x100U) {
        buf[0] = 0x81;
        buf[1] = (unsigned char)adlen;
        return 2;
    } else if (adlen < 0x10000U) {
        buf[0] = 0x82;
        buf[1] = (unsigned char)(adlen >> 8);
        buf[2] = (unsigned char)adlen;
        return 3;
    } else if (adlen < 0x1000000U) {
        buf[0] = 0x83;
        buf[1] = (unsigned char)(adlen >> 16);
        buf[2] = (unsigned char)(adlen >> 8);
        buf[3] = (unsigned char)adlen;
        return 4;
    } else {
        buf[0] = 0x84;
        buf[1] = (unsigned char)(adlen >> 24);
        buf[2] = (unsigned char)(adlen >> 16);
        buf[3] = (unsigned char)(adlen >> 8);
        buf[4] = (unsigned char)adlen;
        return 5;
    }
}

int grain128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    grain128_state_t state;
    unsigned char der[5];
    unsigned derlen;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GRAIN128_TAG_SIZE;

    /* Limit the amount of associated data to make DER encoding easier */
    if (adlen >= 0x100000000ULL)
        return -2;

    /* Initialize the Grain-128 stream cipher with the key and nonce */
    grain128_setup(&state, k, npub);

    /* Authenticate the associated data, prefixed with the DER-encoded length */
    derlen = grain128_encode_adlen(der, adlen);
    grain128_authenticate(&state, der, derlen);
    grain128_authenticate(&state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    grain128_encrypt(&state, c, m, mlen);

    /* Generate the authentication tag */
    grain128_compute_tag(&state);
    memcpy(c + mlen, state.ks, GRAIN128_TAG_SIZE);
    return 0;
}

int grain128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    grain128_state_t state;
    unsigned char der[5];
    unsigned derlen;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < GRAIN128_TAG_SIZE)
        return -1;
    *mlen = clen - GRAIN128_TAG_SIZE;

    /* Limit the amount of associated data to make DER encoding easier */
    if (adlen >= 0x100000000ULL)
        return -2;

    /* Initialize the Grain-128 stream cipher with the key and nonce */
    grain128_setup(&state, k, npub);

    /* Authenticate the associated data, prefixed with the DER-encoded length */
    derlen = grain128_encode_adlen(der, adlen);
    grain128_authenticate(&state, der, derlen);
    grain128_authenticate(&state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= GRAIN128_TAG_SIZE;
    grain128_decrypt(&state, m, c, clen);

    /* Check the authentication tag */
    grain128_compute_tag(&state);
    return aead_check_tag(m, clen, state.ks, c + clen, GRAIN128_TAG_SIZE);
}
