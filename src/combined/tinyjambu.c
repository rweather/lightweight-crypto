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

#include "tinyjambu.h"
#include "internal-tinyjambu.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const tiny_jambu_128_cipher = {
    "TinyJAMBU-128",
    TINY_JAMBU_128_KEY_SIZE,
    TINY_JAMBU_NONCE_SIZE,
    TINY_JAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_128_aead_encrypt,
    tiny_jambu_128_aead_decrypt
};

aead_cipher_t const tiny_jambu_192_cipher = {
    "TinyJAMBU-192",
    TINY_JAMBU_192_KEY_SIZE,
    TINY_JAMBU_NONCE_SIZE,
    TINY_JAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_192_aead_encrypt,
    tiny_jambu_192_aead_decrypt
};

aead_cipher_t const tiny_jambu_256_cipher = {
    "TinyJAMBU-256",
    TINY_JAMBU_256_KEY_SIZE,
    TINY_JAMBU_NONCE_SIZE,
    TINY_JAMBU_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_256_aead_encrypt,
    tiny_jambu_256_aead_decrypt
};

/**
 * \brief Set up the TinyJAMBU-128 state with the key and the nonce
 * and then absorbs the associated data.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the 4 key words.
 * \param nonce Points to the 96-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void tiny_jambu_setup_128
    (uint32_t state[TINY_JAMBU_STATE_SIZE],
     const uint32_t *key, const unsigned char *nonce,
     const unsigned char *ad, unsigned long long adlen)
{
    /* Initialize the state with the key */
    memset(state, 0, TINY_JAMBU_STATE_SIZE * sizeof(uint32_t));
    tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));

    /* Absorb the three 32-bit words of the 96-bit nonce */
    state[1] ^= 0x10; /* Domain separator for the nonce */
    tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce);
    state[1] ^= 0x10;
    tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce + 4);
    state[1] ^= 0x10;
    tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce + 8);

    /* Process as many full 32-bit words of associated data as we can */
    while (adlen >= 4) {
        state[1] ^= 0x30; /* Domain separator for associated data */
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word32(ad);
        ad += 4;
        adlen -= 4;
    }

    /* Handle the left-over associated data bytes, if any */
    if (adlen == 1) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= ad[0];
        state[1] ^= 0x01;
    } else if (adlen == 2) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word16(ad);
        state[1] ^= 0x02;
    } else if (adlen == 3) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word16(ad) | (((uint32_t)(ad[2])) << 16);
        state[1] ^= 0x03;
    }
}

/**
 * \brief Set up the TinyJAMBU-192 state with the key and the nonce
 * and then absorbs the associated data.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the 6 key words.
 * \param nonce Points to the 96-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void tiny_jambu_setup_192
    (uint32_t state[TINY_JAMBU_STATE_SIZE],
     const uint32_t *key, const unsigned char *nonce,
     const unsigned char *ad, unsigned long long adlen)
{
    /* Initialize the state with the key */
    memset(state, 0, TINY_JAMBU_STATE_SIZE * sizeof(uint32_t));
    tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));

    /* Absorb the three 32-bit words of the 96-bit nonce */
    state[1] ^= 0x10; /* Domain separator for the nonce */
    tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce);
    state[1] ^= 0x10;
    tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce + 4);
    state[1] ^= 0x10;
    tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce + 8);

    /* Process as many full 32-bit words of associated data as we can */
    while (adlen >= 4) {
        state[1] ^= 0x30; /* Domain separator for associated data */
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word32(ad);
        ad += 4;
        adlen -= 4;
    }

    /* Handle the left-over associated data bytes, if any */
    if (adlen == 1) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= ad[0];
        state[1] ^= 0x01;
    } else if (adlen == 2) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word16(ad);
        state[1] ^= 0x02;
    } else if (adlen == 3) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word16(ad) | (((uint32_t)(ad[2])) << 16);
        state[1] ^= 0x03;
    }
}

/**
 * \brief Set up the TinyJAMBU-256 state with the key and the nonce
 * and then absorbs the associated data.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the 8 key words.
 * \param nonce Points to the 96-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void tiny_jambu_setup_256
    (uint32_t state[TINY_JAMBU_STATE_SIZE],
     const uint32_t *key, const unsigned char *nonce,
     const unsigned char *ad, unsigned long long adlen)
{
    /* Initialize the state with the key */
    memset(state, 0, TINY_JAMBU_STATE_SIZE * sizeof(uint32_t));
    tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));

    /* Absorb the three 32-bit words of the 96-bit nonce */
    state[1] ^= 0x10; /* Domain separator for the nonce */
    tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce);
    state[1] ^= 0x10;
    tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce + 4);
    state[1] ^= 0x10;
    tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
    state[3] ^= le_load_word32(nonce + 8);

    /* Process as many full 32-bit words of associated data as we can */
    while (adlen >= 4) {
        state[1] ^= 0x30; /* Domain separator for associated data */
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word32(ad);
        ad += 4;
        adlen -= 4;
    }

    /* Handle the left-over associated data bytes, if any */
    if (adlen == 1) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= ad[0];
        state[1] ^= 0x01;
    } else if (adlen == 2) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word16(ad);
        state[1] ^= 0x02;
    } else if (adlen == 3) {
        state[1] ^= 0x30;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
        state[3] ^= le_load_word16(ad) | (((uint32_t)(ad[2])) << 16);
        state[1] ^= 0x03;
    }
}

/**
 * \brief Generates the final authentication tag for TinyJAMBU-128.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the key words.
 * \param tag Buffer to receive the tag.
 */
static void tiny_jambu_generate_tag_128
    (uint32_t state[TINY_JAMBU_STATE_SIZE],
     const uint32_t *key, unsigned char *tag)
{
    state[1] ^= 0x70; /* Domain separator for finalization */
    tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
    le_store_word32(tag, state[2]);
    state[1] ^= 0x70;
    tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(384));
    le_store_word32(tag + 4, state[2]);
}

/**
 * \brief Generates the final authentication tag for TinyJAMBU-192.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the key words.
 * \param tag Buffer to receive the tag.
 */
static void tiny_jambu_generate_tag_192
    (uint32_t state[TINY_JAMBU_STATE_SIZE],
     const uint32_t *key, unsigned char *tag)
{
    state[1] ^= 0x70; /* Domain separator for finalization */
    tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
    le_store_word32(tag, state[2]);
    state[1] ^= 0x70;
    tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(384));
    le_store_word32(tag + 4, state[2]);
}

/**
 * \brief Generates the final authentication tag for TinyJAMBU-256.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the key words.
 * \param tag Buffer to receive the tag.
 */
static void tiny_jambu_generate_tag_256
    (uint32_t state[TINY_JAMBU_STATE_SIZE],
     const uint32_t *key, unsigned char *tag)
{
    state[1] ^= 0x70; /* Domain separator for finalization */
    tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
    le_store_word32(tag, state[2]);
    state[1] ^= 0x70;
    tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(384));
    le_store_word32(tag + 4, state[2]);
}

int tiny_jambu_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t key[4];
    uint32_t data;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINY_JAMBU_TAG_SIZE;

    /* Unpack the key */
    key[0] = le_load_word32(k);
    key[1] = le_load_word32(k + 4);
    key[2] = le_load_word32(k + 8);
    key[3] = le_load_word32(k + 12);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_128(state, key, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= 4) {
        state[1] ^= 0x50; /* Domain separator for message data */
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = le_load_word32(m);
        state[3] ^= data;
        data ^= state[2];
        le_store_word32(c, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }
    if (mlen == 1) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = m[0];
        state[3] ^= data;
        state[1] ^= 0x01;
        c[0] = (uint8_t)(state[2] ^ data);
    } else if (mlen == 2) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = le_load_word16(m);
        state[3] ^= data;
        state[1] ^= 0x02;
        data ^= state[2];
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        state[3] ^= data;
        state[1] ^= 0x03;
        data ^= state[2];
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
        c[2] = (uint8_t)(data >> 16);
    }

    /* Generate the authentication tag */
    tiny_jambu_generate_tag_128(state, key, c + mlen);
    return 0;
}

int tiny_jambu_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char *mtemp = m;
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t key[4];
    unsigned char tag[TINY_JAMBU_TAG_SIZE];
    uint32_t data;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINY_JAMBU_TAG_SIZE)
        return -1;
    *mlen = clen - TINY_JAMBU_TAG_SIZE;

    /* Unpack the key */
    key[0] = le_load_word32(k);
    key[1] = le_load_word32(k + 4);
    key[2] = le_load_word32(k + 8);
    key[3] = le_load_word32(k + 12);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_128(state, key, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= TINY_JAMBU_TAG_SIZE;
    while (clen >= 4) {
        state[1] ^= 0x50; /* Domain separator for message data */
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = le_load_word32(c) ^ state[2];
        state[3] ^= data;
        le_store_word32(m, data);
        c += 4;
        m += 4;
        clen -= 4;
    }
    if (clen == 1) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = (c[0] ^ state[2]) & 0xFFU;
        state[3] ^= data;
        state[1] ^= 0x01;
        m[0] = (uint8_t)data;
        ++c;
    } else if (clen == 2) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = (le_load_word16(c) ^ state[2]) & 0xFFFFU;
        state[3] ^= data;
        state[1] ^= 0x02;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        c += 2;
    } else if (clen == 3) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_128(state, key, TINYJAMBU_ROUNDS(1024));
        data = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        data = (data ^ state[2]) & 0xFFFFFFU;
        state[3] ^= data;
        state[1] ^= 0x03;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        m[2] = (uint8_t)(data >> 16);
        c += 3;
    }

    /* Check the authentication tag */
    tiny_jambu_generate_tag_128(state, key, tag);
    return aead_check_tag(mtemp, *mlen, tag, c, TINY_JAMBU_TAG_SIZE);
}

int tiny_jambu_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t key[6];
    uint32_t data;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINY_JAMBU_TAG_SIZE;

    /* Unpack the key */
    key[0] = le_load_word32(k);
    key[1] = le_load_word32(k + 4);
    key[2] = le_load_word32(k + 8);
    key[3] = le_load_word32(k + 12);
    key[4] = le_load_word32(k + 16);
    key[5] = le_load_word32(k + 20);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_192(state, key, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= 4) {
        state[1] ^= 0x50; /* Domain separator for message data */
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = le_load_word32(m);
        state[3] ^= data;
        data ^= state[2];
        le_store_word32(c, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }
    if (mlen == 1) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = m[0];
        state[3] ^= data;
        state[1] ^= 0x01;
        c[0] = (uint8_t)(state[2] ^ data);
    } else if (mlen == 2) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = le_load_word16(m);
        state[3] ^= data;
        state[1] ^= 0x02;
        data ^= state[2];
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        state[3] ^= data;
        state[1] ^= 0x03;
        data ^= state[2];
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
        c[2] = (uint8_t)(data >> 16);
    }

    /* Generate the authentication tag */
    tiny_jambu_generate_tag_192(state, key, c + mlen);
    return 0;
}

int tiny_jambu_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char *mtemp = m;
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t key[6];
    unsigned char tag[TINY_JAMBU_TAG_SIZE];
    uint32_t data;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINY_JAMBU_TAG_SIZE)
        return -1;
    *mlen = clen - TINY_JAMBU_TAG_SIZE;

    /* Unpack the key */
    key[0] = le_load_word32(k);
    key[1] = le_load_word32(k + 4);
    key[2] = le_load_word32(k + 8);
    key[3] = le_load_word32(k + 12);
    key[4] = le_load_word32(k + 16);
    key[5] = le_load_word32(k + 20);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_192(state, key, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= TINY_JAMBU_TAG_SIZE;
    while (clen >= 4) {
        state[1] ^= 0x50; /* Domain separator for message data */
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = le_load_word32(c) ^ state[2];
        state[3] ^= data;
        le_store_word32(m, data);
        c += 4;
        m += 4;
        clen -= 4;
    }
    if (clen == 1) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = (c[0] ^ state[2]) & 0xFFU;
        state[3] ^= data;
        state[1] ^= 0x01;
        m[0] = (uint8_t)data;
        ++c;
    } else if (clen == 2) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = (le_load_word16(c) ^ state[2]) & 0xFFFFU;
        state[3] ^= data;
        state[1] ^= 0x02;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        c += 2;
    } else if (clen == 3) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_192(state, key, TINYJAMBU_ROUNDS(1152));
        data = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        data = (data ^ state[2]) & 0xFFFFFFU;
        state[3] ^= data;
        state[1] ^= 0x03;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        m[2] = (uint8_t)(data >> 16);
        c += 3;
    }

    /* Check the authentication tag */
    tiny_jambu_generate_tag_192(state, key, tag);
    return aead_check_tag(mtemp, *mlen, tag, c, TINY_JAMBU_TAG_SIZE);
}

int tiny_jambu_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t key[8];
    uint32_t data;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINY_JAMBU_TAG_SIZE;

    /* Unpack the key */
    key[0] = le_load_word32(k);
    key[1] = le_load_word32(k + 4);
    key[2] = le_load_word32(k + 8);
    key[3] = le_load_word32(k + 12);
    key[4] = le_load_word32(k + 16);
    key[5] = le_load_word32(k + 20);
    key[6] = le_load_word32(k + 24);
    key[7] = le_load_word32(k + 28);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_256(state, key, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= 4) {
        state[1] ^= 0x50; /* Domain separator for message data */
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = le_load_word32(m);
        state[3] ^= data;
        data ^= state[2];
        le_store_word32(c, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }
    if (mlen == 1) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = m[0];
        state[3] ^= data;
        state[1] ^= 0x01;
        c[0] = (uint8_t)(state[2] ^ data);
    } else if (mlen == 2) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = le_load_word16(m);
        state[3] ^= data;
        state[1] ^= 0x02;
        data ^= state[2];
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        state[3] ^= data;
        state[1] ^= 0x03;
        data ^= state[2];
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
        c[2] = (uint8_t)(data >> 16);
    }

    /* Generate the authentication tag */
    tiny_jambu_generate_tag_256(state, key, c + mlen);
    return 0;
}

int tiny_jambu_256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char *mtemp = m;
    uint32_t state[TINY_JAMBU_STATE_SIZE];
    uint32_t key[8];
    unsigned char tag[TINY_JAMBU_TAG_SIZE];
    uint32_t data;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINY_JAMBU_TAG_SIZE)
        return -1;
    *mlen = clen - TINY_JAMBU_TAG_SIZE;

    /* Unpack the key */
    key[0] = le_load_word32(k);
    key[1] = le_load_word32(k + 4);
    key[2] = le_load_word32(k + 8);
    key[3] = le_load_word32(k + 12);
    key[4] = le_load_word32(k + 16);
    key[5] = le_load_word32(k + 20);
    key[6] = le_load_word32(k + 24);
    key[7] = le_load_word32(k + 28);

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_256(state, key, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= TINY_JAMBU_TAG_SIZE;
    while (clen >= 4) {
        state[1] ^= 0x50; /* Domain separator for message data */
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = le_load_word32(c) ^ state[2];
        state[3] ^= data;
        le_store_word32(m, data);
        c += 4;
        m += 4;
        clen -= 4;
    }
    if (clen == 1) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = (c[0] ^ state[2]) & 0xFFU;
        state[3] ^= data;
        state[1] ^= 0x01;
        m[0] = (uint8_t)data;
        ++c;
    } else if (clen == 2) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = (le_load_word16(c) ^ state[2]) & 0xFFFFU;
        state[3] ^= data;
        state[1] ^= 0x02;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        c += 2;
    } else if (clen == 3) {
        state[1] ^= 0x50;
        tiny_jambu_permutation_256(state, key, TINYJAMBU_ROUNDS(1280));
        data = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        data = (data ^ state[2]) & 0xFFFFFFU;
        state[3] ^= data;
        state[1] ^= 0x03;
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        m[2] = (uint8_t)(data >> 16);
        c += 3;
    }

    /* Check the authentication tag */
    tiny_jambu_generate_tag_256(state, key, tag);
    return aead_check_tag(mtemp, *mlen, tag, c, TINY_JAMBU_TAG_SIZE);
}
