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

#include "subterranean.h"
#include "internal-subterranean.h"
#include <string.h>

aead_cipher_t const subterranean_cipher = {
    "Subterranean",
    SUBTERRANEAN_KEY_SIZE,
    SUBTERRANEAN_NONCE_SIZE,
    SUBTERRANEAN_TAG_SIZE,
    AEAD_FLAG_NONE,
    subterranean_aead_encrypt,
    subterranean_aead_decrypt
};

aead_hash_algorithm_t const subterranean_hash_algorithm = {
    "Subterranean-Hash",
    sizeof(subterranean_hash_state_t),
    SUBTERRANEAN_HASH_SIZE,
    AEAD_FLAG_NONE,
    subterranean_hash,
    (aead_hash_init_t)subterranean_hash_init,
    (aead_hash_update_t)subterranean_hash_update,
    (aead_hash_finalize_t)subterranean_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

int subterranean_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    subterranean_state_t state;
    uint32_t x1, x2;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SUBTERRANEAN_TAG_SIZE;

    /* Initialize the state and absorb the key and nonce */
    memset(&state, 0, sizeof(state));
    subterranean_absorb(&state, k, SUBTERRANEAN_KEY_SIZE);
    subterranean_absorb(&state, npub, SUBTERRANEAN_NONCE_SIZE);
    subterranean_blank(&state);

    /* Absorb the associated data into the state */
    subterranean_absorb(&state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= 4) {
        x1 = le_load_word32(m);
        x2 = subterranean_extract(&state) ^ x1;
        subterranean_duplex_word(&state, x1);
        state.x[8] ^= 1; /* padding for 32-bit blocks */
        le_store_word32(c, x2);
        c += 4;
        m += 4;
        mlen -= 4;
    }
    switch ((unsigned char)mlen) {
    default:
        subterranean_duplex_0(&state);
        break;
    case 1:
        x2 = subterranean_extract(&state) ^ m[0];
        subterranean_duplex_n(&state, m, 1);
        c[0] = (unsigned char)x2;
        break;
    case 2:
        x2 = subterranean_extract(&state) ^ m[0] ^ (((uint32_t)(m[1])) << 8);
        subterranean_duplex_n(&state, m, 2);
        c[0] = (unsigned char)x2;
        c[1] = (unsigned char)(x2 >> 8);
        break;
    case 3:
        x2 = subterranean_extract(&state) ^
            m[0] ^ (((uint32_t)(m[1])) << 8) ^ (((uint32_t)(m[2])) << 16);
        subterranean_duplex_n(&state, m, 3);
        c[0] = (unsigned char)x2;
        c[1] = (unsigned char)(x2 >> 8);
        c[2] = (unsigned char)(x2 >> 16);
        break;
    }

    /* Generate the authentication tag */
    subterranean_blank(&state);
    subterranean_squeeze(&state, c + mlen, SUBTERRANEAN_TAG_SIZE);
    return 0;
}

int subterranean_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    subterranean_state_t state;
    unsigned char *mtemp = m;
    unsigned char tag[SUBTERRANEAN_TAG_SIZE];
    uint32_t x;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SUBTERRANEAN_TAG_SIZE)
        return -1;
    *mlen = clen - SUBTERRANEAN_TAG_SIZE;

    /* Initialize the state and absorb the key and nonce */
    memset(&state, 0, sizeof(state));
    subterranean_absorb(&state, k, SUBTERRANEAN_KEY_SIZE);
    subterranean_absorb(&state, npub, SUBTERRANEAN_NONCE_SIZE);
    subterranean_blank(&state);

    /* Absorb the associated data into the state */
    subterranean_absorb(&state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SUBTERRANEAN_TAG_SIZE;
    while (clen >= 4) {
        x = le_load_word32(c);
        x ^= subterranean_extract(&state);
        subterranean_duplex_word(&state, x);
        state.x[8] ^= 1; /* padding for 32-bit blocks */
        le_store_word32(m, x);
        c += 4;
        m += 4;
        clen -= 4;
    }
    switch ((unsigned char)clen) {
    default:
        subterranean_duplex_0(&state);
        break;
    case 1:
        m[0] = (unsigned char)(subterranean_extract(&state) ^ c[0]);
        subterranean_duplex_1(&state, m[0]);
        break;
    case 2:
        x = subterranean_extract(&state) ^ c[0] ^ (((uint32_t)(c[1])) << 8);
        m[0] = (unsigned char)x;
        m[1] = (unsigned char)(x >> 8);
        subterranean_duplex_word(&state, (x & 0xFFFFU) | 0x10000U);
        break;
    case 3:
        x = subterranean_extract(&state) ^
            c[0] ^ (((uint32_t)(c[1])) << 8) ^ (((uint32_t)(c[2])) << 16);
        m[0] = (unsigned char)x;
        m[1] = (unsigned char)(x >> 8);
        m[2] = (unsigned char)(x >> 16);
        subterranean_duplex_word(&state, (x & 0x00FFFFFFU) | 0x01000000U);
        break;
    }

    /* Check the authentication tag */
    subterranean_blank(&state);
    subterranean_squeeze(&state, tag, sizeof(tag));
    return aead_check_tag(mtemp, *mlen, tag, c + clen, SUBTERRANEAN_TAG_SIZE);
}

int subterranean_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    subterranean_state_t state;
    memset(&state, 0, sizeof(state));
    while (inlen > 0) {
        subterranean_duplex_1(&state, *in++);
        subterranean_duplex_0(&state);
        --inlen;
    }
    subterranean_duplex_0(&state);
    subterranean_duplex_0(&state);
    subterranean_blank(&state);
    subterranean_squeeze(&state, out, SUBTERRANEAN_HASH_SIZE);
    return 0;
}

void subterranean_hash_init(subterranean_hash_state_t *state)
{
    memset(state, 0, sizeof(subterranean_hash_state_t));
}

void subterranean_hash_update
    (subterranean_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    subterranean_state_t *st = (subterranean_state_t *)state;
    while (inlen > 0) {
        subterranean_duplex_1(st, *in++);
        subterranean_duplex_0(st);
        --inlen;
    }
}

void subterranean_hash_finalize
    (subterranean_hash_state_t *state, unsigned char *out)
{
    subterranean_state_t *st = (subterranean_state_t *)state;
    subterranean_duplex_0(st);
    subterranean_duplex_0(st);
    subterranean_blank(st);
    subterranean_squeeze(st, out, SUBTERRANEAN_HASH_SIZE);
}
