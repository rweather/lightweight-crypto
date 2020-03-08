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

#include "sparkle.h"
#include "internal-sparkle.h"
#include <string.h>

aead_cipher_t const schwaemm_256_128_cipher = {
    "Schwaemm256-128",
    SCHWAEMM_256_128_KEY_SIZE,
    SCHWAEMM_256_128_NONCE_SIZE,
    SCHWAEMM_256_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_256_128_aead_encrypt,
    schwaemm_256_128_aead_decrypt
};

aead_cipher_t const schwaemm_192_192_cipher = {
    "Schwaemm192-192",
    SCHWAEMM_192_192_KEY_SIZE,
    SCHWAEMM_192_192_NONCE_SIZE,
    SCHWAEMM_192_192_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_192_192_aead_encrypt,
    schwaemm_192_192_aead_decrypt
};

aead_cipher_t const schwaemm_128_128_cipher = {
    "Schwaemm128-128",
    SCHWAEMM_128_128_KEY_SIZE,
    SCHWAEMM_128_128_NONCE_SIZE,
    SCHWAEMM_128_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_128_128_aead_encrypt,
    schwaemm_128_128_aead_decrypt
};

aead_cipher_t const schwaemm_256_256_cipher = {
    "Schwaemm256-256",
    SCHWAEMM_256_256_KEY_SIZE,
    SCHWAEMM_256_256_NONCE_SIZE,
    SCHWAEMM_256_256_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    schwaemm_256_256_aead_encrypt,
    schwaemm_256_256_aead_decrypt
};

aead_hash_algorithm_t const esch_256_hash_algorithm = {
    "Esch256",
    sizeof(esch_256_hash_state_t),
    ESCH_256_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    esch_256_hash,
    (aead_hash_init_t)esch_256_hash_init,
    (aead_hash_update_t)esch_256_hash_update,
    (aead_hash_finalize_t)esch_256_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const esch_384_hash_algorithm = {
    "Esch384",
    sizeof(esch_384_hash_state_t),
    ESCH_384_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    esch_384_hash,
    (aead_hash_init_t)esch_384_hash_init,
    (aead_hash_update_t)esch_384_hash_update,
    (aead_hash_finalize_t)esch_384_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \def DOMAIN(value)
 * \brief Build a domain separation value as a 32-bit word.
 *
 * \param value The base value.
 * \return The domain separation value as a 32-bit word.
 */
#if defined(LW_UTIL_LITTLE_ENDIAN)
#define DOMAIN(value) (((uint32_t)(value)) << 24)
#else
#define DOMAIN(value) (value)
#endif

/**
 * \brief Rate at which bytes are processed by Schwaemm256-128.
 */
#define SCHWAEMM_256_128_RATE 32

/**
 * \brief Pointer to the left of the state for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_RIGHT(s) \
    (SCHWAEMM_256_128_LEFT(s) + SCHWAEMM_256_128_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm256-128.
 *
 * \param s SPARKLE-384 state.
 * \param domain Domain separator for this phase.
 */
#define schwaemm_256_128_rho(s, domain) \
    do { \
        uint32_t t0 = s[0]; \
        uint32_t t1 = s[1]; \
        uint32_t t2 = s[2]; \
        uint32_t t3 = s[3]; \
        if ((domain) != 0) \
            s[11] ^= DOMAIN(domain); \
        s[0] = s[4] ^ s[8]; \
        s[1] = s[5] ^ s[9]; \
        s[2] = s[6] ^ s[10]; \
        s[3] = s[7] ^ s[11]; \
        s[4] ^= t0  ^ s[8]; \
        s[5] ^= t1  ^ s[9]; \
        s[6] ^= t2  ^ s[10]; \
        s[7] ^= t3  ^ s[11]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm256-128.
 *
 * \param s SPARKLE-384 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_256_128_authenticate
    (uint32_t s[SPARKLE_384_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen > SCHWAEMM_256_128_RATE) {
        schwaemm_256_128_rho(s, 0x00);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_128_RATE);
        sparkle_384(s, 7);
        ad += SCHWAEMM_256_128_RATE;
        adlen -= SCHWAEMM_256_128_RATE;
    }
    if (adlen == SCHWAEMM_256_128_RATE) {
        schwaemm_256_128_rho(s, 0x05);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_128_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        schwaemm_256_128_rho(s, 0x04);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_384(s, 11);
}

int schwaemm_256_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    uint8_t block[SCHWAEMM_256_128_RATE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_256_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_128_LEFT(s), npub, SCHWAEMM_256_128_NONCE_SIZE);
    memcpy(SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_128_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            schwaemm_256_128_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            sparkle_384(s, 7);
            memcpy(c, block, SCHWAEMM_256_128_RATE);
            c += SCHWAEMM_256_128_RATE;
            m += SCHWAEMM_256_128_RATE;
            mlen -= SCHWAEMM_256_128_RATE;
        }
        if (mlen == SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            schwaemm_256_128_rho(s, 0x07);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            memcpy(c, block, SCHWAEMM_256_128_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            schwaemm_256_128_rho(s, 0x06);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_384(s, 11);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_TAG_SIZE);
    return 0;
}

int schwaemm_256_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_256_128_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_256_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_128_LEFT(s), npub, SCHWAEMM_256_128_NONCE_SIZE);
    memcpy(SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_128_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_256_128_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_128_RATE);
            schwaemm_256_128_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
            sparkle_384(s, 7);
            c += SCHWAEMM_256_128_RATE;
            m += SCHWAEMM_256_128_RATE;
            clen -= SCHWAEMM_256_128_RATE;
        }
        if (clen == SCHWAEMM_256_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_128_RATE);
            schwaemm_256_128_rho(s, 0x07);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_128_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            schwaemm_256_128_rho(s, 0x06);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_384(s, 11);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_256_128_RIGHT(s), k, SCHWAEMM_256_128_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_256_128_RIGHT(s), c, SCHWAEMM_256_128_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Schwaemm192-192.
 */
#define SCHWAEMM_192_192_RATE 24

/**
 * \brief Pointer to the left of the state for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_RIGHT(s) \
    (SCHWAEMM_192_192_LEFT(s) + SCHWAEMM_192_192_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm192-192.
 *
 * \param s SPARKLE-384 state.
 * \param domain Domain separator for this phase.
 */
#define schwaemm_192_192_rho(s, domain) \
    do { \
        uint32_t t0 = s[0]; \
        uint32_t t1 = s[1]; \
        uint32_t t2 = s[2]; \
        if ((domain) != 0) \
            s[11] ^= DOMAIN(domain); \
        s[0] = s[3] ^ s[6]; \
        s[1] = s[4] ^ s[7]; \
        s[2] = s[5] ^ s[8]; \
        s[3] ^= t0  ^ s[9]; \
        s[4] ^= t1  ^ s[10]; \
        s[5] ^= t2  ^ s[11]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm192-192.
 *
 * \param s SPARKLE-384 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_192_192_authenticate
    (uint32_t s[SPARKLE_384_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen > SCHWAEMM_192_192_RATE) {
        schwaemm_192_192_rho(s, 0x00);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_192_192_RATE);
        sparkle_384(s, 7);
        ad += SCHWAEMM_192_192_RATE;
        adlen -= SCHWAEMM_192_192_RATE;
    }
    if (adlen == SCHWAEMM_192_192_RATE) {
        schwaemm_192_192_rho(s, 0x09);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_192_192_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        schwaemm_192_192_rho(s, 0x08);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_384(s, 11);
}

int schwaemm_192_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    uint8_t block[SCHWAEMM_192_192_RATE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_192_192_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_192_192_LEFT(s), npub, SCHWAEMM_192_192_NONCE_SIZE);
    memcpy(SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_192_192_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            schwaemm_192_192_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            sparkle_384(s, 7);
            memcpy(c, block, SCHWAEMM_192_192_RATE);
            c += SCHWAEMM_192_192_RATE;
            m += SCHWAEMM_192_192_RATE;
            mlen -= SCHWAEMM_192_192_RATE;
        }
        if (mlen == SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            schwaemm_192_192_rho(s, 0x0B);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            memcpy(c, block, SCHWAEMM_192_192_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            schwaemm_192_192_rho(s, 0x0A);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_384(s, 11);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_TAG_SIZE);
    return 0;
}

int schwaemm_192_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_192_192_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_192_192_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_192_192_LEFT(s), npub, SCHWAEMM_192_192_NONCE_SIZE);
    memcpy(SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_KEY_SIZE);
    sparkle_384(s, 11);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_192_192_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_192_192_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_192_192_RATE);
            schwaemm_192_192_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
            sparkle_384(s, 7);
            c += SCHWAEMM_192_192_RATE;
            m += SCHWAEMM_192_192_RATE;
            clen -= SCHWAEMM_192_192_RATE;
        }
        if (clen == SCHWAEMM_192_192_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_192_192_RATE);
            schwaemm_192_192_rho(s, 0x0B);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_192_192_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            schwaemm_192_192_rho(s, 0x0A);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_384(s, 11);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_192_192_RIGHT(s), k, SCHWAEMM_192_192_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_192_192_RIGHT(s), c, SCHWAEMM_192_192_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Schwaemm128-128.
 */
#define SCHWAEMM_128_128_RATE 16

/**
 * \brief Pointer to the left of the state for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_RIGHT(s) \
    (SCHWAEMM_128_128_LEFT(s) + SCHWAEMM_128_128_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm128-128.
 *
 * \param s SPARKLE-256 state.
 * \param domain Domain separator for this phase.
 */
#define schwaemm_128_128_rho(s, domain) \
    do { \
        uint32_t t0 = s[0]; \
        uint32_t t1 = s[1]; \
        if ((domain) != 0) \
            s[7] ^= DOMAIN(domain); \
        s[0] = s[2] ^ s[4]; \
        s[1] = s[3] ^ s[5]; \
        s[2] ^= t0  ^ s[6]; \
        s[3] ^= t1  ^ s[7]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm128-128.
 *
 * \param s SPARKLE-256 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_128_128_authenticate
    (uint32_t s[SPARKLE_256_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen > SCHWAEMM_128_128_RATE) {
        schwaemm_128_128_rho(s, 0x00);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_128_128_RATE);
        sparkle_256(s, 7);
        ad += SCHWAEMM_128_128_RATE;
        adlen -= SCHWAEMM_128_128_RATE;
    }
    if (adlen == SCHWAEMM_128_128_RATE) {
        schwaemm_128_128_rho(s, 0x05);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_128_128_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        schwaemm_128_128_rho(s, 0x04);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_256(s, 10);
}

int schwaemm_128_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_256_STATE_SIZE];
    uint8_t block[SCHWAEMM_128_128_RATE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_128_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_128_128_LEFT(s), npub, SCHWAEMM_128_128_NONCE_SIZE);
    memcpy(SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_KEY_SIZE);
    sparkle_256(s, 10);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_128_128_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            schwaemm_128_128_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            sparkle_256(s, 7);
            memcpy(c, block, SCHWAEMM_128_128_RATE);
            c += SCHWAEMM_128_128_RATE;
            m += SCHWAEMM_128_128_RATE;
            mlen -= SCHWAEMM_128_128_RATE;
        }
        if (mlen == SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            schwaemm_128_128_rho(s, 0x07);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            memcpy(c, block, SCHWAEMM_128_128_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            schwaemm_128_128_rho(s, 0x06);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_256(s, 10);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_TAG_SIZE);
    return 0;
}

int schwaemm_128_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_256_STATE_SIZE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_128_128_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_128_128_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_128_128_LEFT(s), npub, SCHWAEMM_128_128_NONCE_SIZE);
    memcpy(SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_KEY_SIZE);
    sparkle_256(s, 10);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_128_128_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_128_128_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_128_128_RATE);
            schwaemm_128_128_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
            sparkle_256(s, 7);
            c += SCHWAEMM_128_128_RATE;
            m += SCHWAEMM_128_128_RATE;
            clen -= SCHWAEMM_128_128_RATE;
        }
        if (clen == SCHWAEMM_128_128_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_128_128_RATE);
            schwaemm_128_128_rho(s, 0x07);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_128_128_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            schwaemm_128_128_rho(s, 0x06);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_256(s, 10);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_128_128_RIGHT(s), k, SCHWAEMM_128_128_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_128_128_RIGHT(s), c, SCHWAEMM_128_128_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Schwaemm256-256.
 */
#define SCHWAEMM_256_256_RATE 32

/**
 * \brief Pointer to the left of the state for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_LEFT(s) ((unsigned char *)&(s[0]))

/**
 * \brief Pointer to the right of the state for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_RIGHT(s) \
    (SCHWAEMM_256_256_LEFT(s) + SCHWAEMM_256_256_RATE)

/**
 * \brief Perform the rho1 and rate whitening steps for Schwaemm256-256.
 *
 * \param s SPARKLE-512 state.
 * \param domain Domain separator for this phase.
 */
#define schwaemm_256_256_rho(s, domain) \
    do { \
        uint32_t t0 = s[0]; \
        uint32_t t1 = s[1]; \
        uint32_t t2 = s[2]; \
        uint32_t t3 = s[3]; \
        if ((domain) != 0) \
            s[15] ^= DOMAIN(domain); \
        s[0] = s[4] ^ s[8]; \
        s[1] = s[5] ^ s[9]; \
        s[2] = s[6] ^ s[10]; \
        s[3] = s[7] ^ s[11]; \
        s[4] ^= t0  ^ s[12]; \
        s[5] ^= t1  ^ s[13]; \
        s[6] ^= t2  ^ s[14]; \
        s[7] ^= t3  ^ s[15]; \
    } while (0)

/**
 * \brief Authenticates the associated data for Schwaemm256-256.
 *
 * \param s SPARKLE-512 state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data; must be >= 1.
 */
static void schwaemm_256_256_authenticate
    (uint32_t s[SPARKLE_512_STATE_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    while (adlen > SCHWAEMM_256_256_RATE) {
        schwaemm_256_256_rho(s, 0x00);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_256_RATE);
        sparkle_512(s, 8);
        ad += SCHWAEMM_256_256_RATE;
        adlen -= SCHWAEMM_256_256_RATE;
    }
    if (adlen == SCHWAEMM_256_256_RATE) {
        schwaemm_256_256_rho(s, 0x11);
        lw_xor_block((unsigned char *)s, ad, SCHWAEMM_256_256_RATE);
    } else {
        unsigned temp = (unsigned)adlen;
        schwaemm_256_256_rho(s, 0x10);
        lw_xor_block((unsigned char *)s, ad, temp);
        ((unsigned char *)s)[temp] ^= 0x80;
    }
    sparkle_512(s, 12);
}

int schwaemm_256_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_512_STATE_SIZE];
    uint8_t block[SCHWAEMM_256_256_RATE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SCHWAEMM_256_256_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_256_LEFT(s), npub, SCHWAEMM_256_256_NONCE_SIZE);
    memcpy(SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_KEY_SIZE);
    sparkle_512(s, 12);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_256_authenticate(s, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        while (mlen > SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            schwaemm_256_256_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            sparkle_512(s, 8);
            memcpy(c, block, SCHWAEMM_256_256_RATE);
            c += SCHWAEMM_256_256_RATE;
            m += SCHWAEMM_256_256_RATE;
            mlen -= SCHWAEMM_256_256_RATE;
        }
        if (mlen == SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (block, (unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            schwaemm_256_256_rho(s, 0x13);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            memcpy(c, block, SCHWAEMM_256_256_RATE);
        } else {
            unsigned temp = (unsigned)mlen;
            lw_xor_block_2_src(block, (unsigned char *)s, m, temp);
            schwaemm_256_256_rho(s, 0x12);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
            memcpy(c, block, temp);
        }
        sparkle_512(s, 12);
        c += mlen;
    }

    /* Generate the authentication tag */
    lw_xor_block_2_src
        (c, SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_TAG_SIZE);
    return 0;
}

int schwaemm_256_256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    uint32_t s[SPARKLE_512_STATE_SIZE];
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SCHWAEMM_256_256_TAG_SIZE)
        return -1;
    *mlen = clen - SCHWAEMM_256_256_TAG_SIZE;

    /* Initialize the state with the nonce and the key */
    memcpy(SCHWAEMM_256_256_LEFT(s), npub, SCHWAEMM_256_256_NONCE_SIZE);
    memcpy(SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_KEY_SIZE);
    sparkle_512(s, 12);

    /* Process the associated data */
    if (adlen > 0)
        schwaemm_256_256_authenticate(s, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= SCHWAEMM_256_256_TAG_SIZE;
    if (clen > 0) {
        while (clen > SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_256_RATE);
            schwaemm_256_256_rho(s, 0x00);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
            sparkle_512(s, 8);
            c += SCHWAEMM_256_256_RATE;
            m += SCHWAEMM_256_256_RATE;
            clen -= SCHWAEMM_256_256_RATE;
        }
        if (clen == SCHWAEMM_256_256_RATE) {
            lw_xor_block_2_src
                (m, (unsigned char *)s, c, SCHWAEMM_256_256_RATE);
            schwaemm_256_256_rho(s, 0x13);
            lw_xor_block((unsigned char *)s, m, SCHWAEMM_256_256_RATE);
        } else {
            unsigned temp = (unsigned)clen;
            lw_xor_block_2_src(m, (unsigned char *)s, c, temp);
            schwaemm_256_256_rho(s, 0x12);
            lw_xor_block((unsigned char *)s, m, temp);
            ((unsigned char *)s)[temp] ^= 0x80;
        }
        sparkle_512(s, 12);
        c += clen;
    }

    /* Check the authentication tag */
    lw_xor_block(SCHWAEMM_256_256_RIGHT(s), k, SCHWAEMM_256_256_TAG_SIZE);
    return aead_check_tag
        (mtemp, *mlen, SCHWAEMM_256_256_RIGHT(s), c, SCHWAEMM_256_256_TAG_SIZE);
}

/**
 * \brief Rate at which bytes are processed by Esch256.
 */
#define ESCH_256_RATE 16

/**
 * \brief Perform the M3 step for Esch256 to mix the input with the state.
 *
 * \param s SPARKLE-384 state.
 * \param block Block of input data that has been padded to the rate.
 * \param domain Domain separator for this phase.
 */
#define esch_256_m3(s, block, domain) \
    do { \
        uint32_t tx = (block)[0] ^ (block)[2]; \
        uint32_t ty = (block)[1] ^ (block)[3]; \
        tx = leftRotate16(tx ^ (tx << 16)); \
        ty = leftRotate16(ty ^ (ty << 16)); \
        s[0] ^= (block)[0] ^ ty; \
        s[1] ^= (block)[1] ^ tx; \
        s[2] ^= (block)[2] ^ ty; \
        s[3] ^= (block)[3] ^ tx; \
        if ((domain) != 0) \
            s[5] ^= DOMAIN(domain); \
        s[4] ^= ty; \
        s[5] ^= tx; \
    } while (0)

/** @cond esch_256 */

/**
 * \brief Word-based state for the Esch256 incremental hash mode.
 */
typedef union
{
    struct {
        uint32_t state[SPARKLE_384_STATE_SIZE];
        uint32_t block[4];
        unsigned char count;
    } s;
    unsigned long long align;

} esch_256_hash_state_wt;

/** @endcond */

int esch_256_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    uint32_t s[SPARKLE_384_STATE_SIZE];
    uint32_t block[ESCH_256_RATE / 4];
    memset(s, 0, sizeof(s));
    while (inlen > ESCH_256_RATE) {
        memcpy(block, in, ESCH_256_RATE);
        esch_256_m3(s, block, 0x00);
        sparkle_384(s, 7);
        in += ESCH_256_RATE;
        inlen -= ESCH_256_RATE;
    }
    if (inlen == ESCH_256_RATE) {
        memcpy(block, in, ESCH_256_RATE);
        esch_256_m3(s, block, 0x02);
    } else {
        unsigned temp = (unsigned)inlen;
        memcpy(block, in, temp);
        ((unsigned char *)block)[temp] = 0x80;
        memset(((unsigned char *)block) + temp + 1, 0,
               ESCH_256_RATE - temp - 1);
        esch_256_m3(s, block, 0x01);
    }
    sparkle_384(s, 11);
    memcpy(out, s, ESCH_256_RATE);
    sparkle_384(s, 7);
    memcpy(out + ESCH_256_RATE, s, ESCH_256_RATE);
    return 0;
}

void esch_256_hash_init(esch_256_hash_state_t *state)
{
    memset(state, 0, sizeof(esch_256_hash_state_t));
}

void esch_256_hash_update
    (esch_256_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    esch_256_hash_state_wt *st = (esch_256_hash_state_wt *)state;
    unsigned temp;
    while (inlen > 0) {
        if (st->s.count == ESCH_256_RATE) {
            esch_256_m3(st->s.state, st->s.block, 0x00);
            sparkle_384(st->s.state, 7);
            st->s.count = 0;
        }
        temp = ESCH_256_RATE - st->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        memcpy(((unsigned char *)(st->s.block)) + st->s.count, in, temp);
        st->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void esch_256_hash_finalize
    (esch_256_hash_state_t *state, unsigned char *out)
{
    esch_256_hash_state_wt *st = (esch_256_hash_state_wt *)state;

    /* Pad and process the last block */
    if (st->s.count == ESCH_256_RATE) {
        esch_256_m3(st->s.state, st->s.block, 0x02);
    } else {
        unsigned temp = st->s.count;
        ((unsigned char *)(st->s.block))[temp] = 0x80;
        memset(((unsigned char *)(st->s.block)) + temp + 1, 0,
               ESCH_256_RATE - temp - 1);
        esch_256_m3(st->s.state, st->s.block, 0x01);
    }
    sparkle_384(st->s.state, 11);

    /* Generate the final hash value */
    memcpy(out, st->s.state, ESCH_256_RATE);
    sparkle_384(st->s.state, 7);
    memcpy(out + ESCH_256_RATE, st->s.state, ESCH_256_RATE);
}

/**
 * \brief Rate at which bytes are processed by Esch384.
 */
#define ESCH_384_RATE 16

/**
 * \brief Perform the M4 step for Esch384 to mix the input with the state.
 *
 * \param s SPARKLE-512 state.
 * \param block Block of input data that has been padded to the rate.
 * \param domain Domain separator for this phase.
 */
#define esch_384_m4(s, block, domain) \
    do { \
        uint32_t tx = block[0] ^ block[2]; \
        uint32_t ty = block[1] ^ block[3]; \
        tx = leftRotate16(tx ^ (tx << 16)); \
        ty = leftRotate16(ty ^ (ty << 16)); \
        s[0] ^= block[0] ^ ty; \
        s[1] ^= block[1] ^ tx; \
        s[2] ^= block[2] ^ ty; \
        s[3] ^= block[3] ^ tx; \
        if ((domain) != 0) \
            s[7] ^= DOMAIN(domain); \
        s[4] ^= ty; \
        s[5] ^= tx; \
        s[6] ^= ty; \
        s[7] ^= tx; \
    } while (0)

/** @cond esch_384 */

/**
 * \brief Word-based state for the Esch384 incremental hash mode.
 */
typedef union
{
    struct {
        uint32_t state[SPARKLE_512_STATE_SIZE];
        uint32_t block[4];
        unsigned char count;
    } s;
    unsigned long long align;

} esch_384_hash_state_wt;

/** @endcond */

int esch_384_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    uint32_t s[SPARKLE_512_STATE_SIZE];
    uint32_t block[ESCH_256_RATE / 4];
    memset(s, 0, sizeof(s));
    while (inlen > ESCH_384_RATE) {
        memcpy(block, in, ESCH_384_RATE);
        esch_384_m4(s, block, 0x00);
        sparkle_512(s, 8);
        in += ESCH_384_RATE;
        inlen -= ESCH_384_RATE;
    }
    if (inlen == ESCH_384_RATE) {
        memcpy(block, in, ESCH_384_RATE);
        esch_384_m4(s, block, 0x02);
    } else {
        unsigned temp = (unsigned)inlen;
        memcpy(block, in, temp);
        ((unsigned char *)block)[temp] = 0x80;
        memset(((unsigned char *)block) + temp + 1, 0,
               ESCH_384_RATE - temp - 1);
        esch_384_m4(s, block, 0x01);
    }
    sparkle_512(s, 12);
    memcpy(out, s, ESCH_384_RATE);
    sparkle_512(s, 8);
    memcpy(out + ESCH_384_RATE, s, ESCH_384_RATE);
    sparkle_512(s, 8);
    memcpy(out + ESCH_384_RATE * 2, s, ESCH_384_RATE);
    return 0;
}

void esch_384_hash_init(esch_384_hash_state_t *state)
{
    memset(state, 0, sizeof(esch_384_hash_state_t));
}

void esch_384_hash_update
    (esch_384_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    esch_384_hash_state_wt *st = (esch_384_hash_state_wt *)state;
    unsigned temp;
    while (inlen > 0) {
        if (st->s.count == ESCH_384_RATE) {
            esch_384_m4(st->s.state, st->s.block, 0x00);
            sparkle_512(st->s.state, 8);
            st->s.count = 0;
        }
        temp = ESCH_384_RATE - st->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        memcpy(((unsigned char *)(st->s.block)) + st->s.count, in, temp);
        st->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void esch_384_hash_finalize
    (esch_384_hash_state_t *state, unsigned char *out)
{
    esch_384_hash_state_wt *st = (esch_384_hash_state_wt *)state;

    /* Pad and process the last block */
    if (st->s.count == ESCH_384_RATE) {
        esch_384_m4(st->s.state, st->s.block, 0x02);
    } else {
        unsigned temp = st->s.count;
        ((unsigned char *)(st->s.block))[temp] = 0x80;
        memset(((unsigned char *)(st->s.block)) + temp + 1, 0,
               ESCH_384_RATE - temp - 1);
        esch_384_m4(st->s.state, st->s.block, 0x01);
    }
    sparkle_512(st->s.state, 12);

    /* Generate the final hash value */
    memcpy(out, st->s.state, ESCH_384_RATE);
    sparkle_512(st->s.state, 8);
    memcpy(out + ESCH_384_RATE, st->s.state, ESCH_384_RATE);
    sparkle_512(st->s.state, 8);
    memcpy(out + ESCH_384_RATE * 2, st->s.state, ESCH_384_RATE);
}
