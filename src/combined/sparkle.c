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
#include "internal-util.h"
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

/* The 8 basic round constants from the specification */
#define RC_0 0xB7E15162
#define RC_1 0xBF715880
#define RC_2 0x38B4DA56
#define RC_3 0x324E7738
#define RC_4 0xBB1185EB
#define RC_5 0x4F7C7B57
#define RC_6 0xCFBFA1C8
#define RC_7 0xC2B3293D

/* Round constants for all SPARKLE steps; maximum of 12 for SPARKLE-512 */
static uint32_t const sparkle_rc[12] = {
    RC_0, RC_1, RC_2, RC_3, RC_4, RC_5, RC_6, RC_7,
    RC_0, RC_1, RC_2, RC_3
};

/**
 * \brief Alzette block cipher that implements the ARXbox layer of the
 * SPARKLE permutation.
 *
 * \param x Left half of the 64-bit block.
 * \param y Right half of the 64-bit block.
 * \param k 32-bit round key.
 */
#define alzette(x, y, k) \
    do { \
        (x) += leftRotate1((y)); \
        (y) ^= leftRotate8((x)); \
        (x) ^= (k); \
        (x) += leftRotate15((y)); \
        (y) ^= leftRotate15((x)); \
        (x) ^= (k); \
        (x) += (y); \
        (y) ^= leftRotate1((x)); \
        (x) ^= (k); \
        (x) += leftRotate8((y)); \
        (y) ^= leftRotate16((x)); \
        (x) ^= (k); \
    } while (0)

/**
 * \brief Size of the state for SPARKLE-256.
 */
#define SPARKLE_256_STATE_SIZE 8

/**
 * \brief Performs the SPARKLE-256 permutation.
 *
 * \param s The words of the SPARKLE-256 state in little-endian byte order.
 * \param steps The number of steps to perform, 7 or 10.
 */
static void sparkle_256(uint32_t s[SPARKLE_256_STATE_SIZE], unsigned steps)
{
    uint32_t x0, x1, x2, x3;
    uint32_t y0, y1, y2, y3;
    uint32_t tx, ty, tz, tw;
    unsigned step;

    /* Load the SPARKLE-256 state up into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = s[0];
    y0 = s[1];
    x1 = s[2];
    y1 = s[3];
    x2 = s[4];
    y2 = s[5];
    x3 = s[6];
    y3 = s[7];
#else
    x0 = le_load_word32((const uint8_t *)&(s[0]));
    y0 = le_load_word32((const uint8_t *)&(s[1]));
    x1 = le_load_word32((const uint8_t *)&(s[2]));
    y1 = le_load_word32((const uint8_t *)&(s[3]));
    x2 = le_load_word32((const uint8_t *)&(s[4]));
    y2 = le_load_word32((const uint8_t *)&(s[5]));
    x3 = le_load_word32((const uint8_t *)&(s[6]));
    y3 = le_load_word32((const uint8_t *)&(s[7]));
#endif

    /* Perform all requested steps */
    for (step = 0; step < steps; ++step) {
        /* Add round constants */
        y0 ^= sparkle_rc[step];
        y1 ^= step;

        /* ARXbox layer */
        alzette(x0, y0, RC_0);
        alzette(x1, y1, RC_1);
        alzette(x2, y2, RC_2);
        alzette(x3, y3, RC_3);

        /* Linear layer */
        tx = x0 ^ x1;
        ty = y0 ^ y1;
        tw = x0;
        tz = y0;
        tx = leftRotate16(tx ^ (tx << 16));
        ty = leftRotate16(ty ^ (ty << 16));
        x0 = x3 ^ x1 ^ ty;
        x3 = x1;
        y0 = y3 ^ y1 ^ tx;
        y3 = y1;
        x1 = x2 ^ tw ^ ty;
        x2 = tw;
        y1 = y2 ^ tz ^ tx;
        y2 = tz;
    }

    /* Write the local variables back to the SPARKLE-256 state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s[0] = x0;
    s[1] = y0;
    s[2] = x1;
    s[3] = y1;
    s[4] = x2;
    s[5] = y2;
    s[6] = x3;
    s[7] = y3;
#else
    le_store_word32((uint8_t *)&(s[0]), x0);
    le_store_word32((uint8_t *)&(s[1]), y0);
    le_store_word32((uint8_t *)&(s[2]), x1);
    le_store_word32((uint8_t *)&(s[3]), y1);
    le_store_word32((uint8_t *)&(s[4]), x2);
    le_store_word32((uint8_t *)&(s[5]), y2);
    le_store_word32((uint8_t *)&(s[6]), x3);
    le_store_word32((uint8_t *)&(s[7]), y3);
#endif
}

/**
 * \brief Size of the state for SPARKLE-384.
 */
#define SPARKLE_384_STATE_SIZE 12

/**
 * \brief Performs the SPARKLE-384 permutation.
 *
 * \param s The words of the SPARKLE-384 state in little-endian byte order.
 * \param steps The number of steps to perform, 7 or 11.
 */
static void sparkle_384(uint32_t s[SPARKLE_384_STATE_SIZE], unsigned steps)
{
    uint32_t x0, x1, x2, x3, x4, x5;
    uint32_t y0, y1, y2, y3, y4, y5;
    uint32_t tx, ty, tz, tw;
    unsigned step;

    /* Load the SPARKLE-384 state up into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = s[0];
    y0 = s[1];
    x1 = s[2];
    y1 = s[3];
    x2 = s[4];
    y2 = s[5];
    x3 = s[6];
    y3 = s[7];
    x4 = s[8];
    y4 = s[9];
    x5 = s[10];
    y5 = s[11];
#else
    x0 = le_load_word32((const uint8_t *)&(s[0]));
    y0 = le_load_word32((const uint8_t *)&(s[1]));
    x1 = le_load_word32((const uint8_t *)&(s[2]));
    y1 = le_load_word32((const uint8_t *)&(s[3]));
    x2 = le_load_word32((const uint8_t *)&(s[4]));
    y2 = le_load_word32((const uint8_t *)&(s[5]));
    x3 = le_load_word32((const uint8_t *)&(s[6]));
    y3 = le_load_word32((const uint8_t *)&(s[7]));
    x4 = le_load_word32((const uint8_t *)&(s[8]));
    y4 = le_load_word32((const uint8_t *)&(s[9]));
    x5 = le_load_word32((const uint8_t *)&(s[10]));
    y5 = le_load_word32((const uint8_t *)&(s[11]));
#endif

    /* Perform all requested steps */
    for (step = 0; step < steps; ++step) {
        /* Add round constants */
        y0 ^= sparkle_rc[step];
        y1 ^= step;

        /* ARXbox layer */
        alzette(x0, y0, RC_0);
        alzette(x1, y1, RC_1);
        alzette(x2, y2, RC_2);
        alzette(x3, y3, RC_3);
        alzette(x4, y4, RC_4);
        alzette(x5, y5, RC_5);

        /* Linear layer */
        tx = x0 ^ x1 ^ x2;
        ty = y0 ^ y1 ^ y2;
        tw = x0;
        tz = y0;
        tx = leftRotate16(tx ^ (tx << 16));
        ty = leftRotate16(ty ^ (ty << 16));
        x0 = x4 ^ x1 ^ ty;
        x4 = x1;
        y0 = y4 ^ y1 ^ tx;
        y4 = y1;
        x1 = x5 ^ x2 ^ ty;
        x5 = x2;
        y1 = y5 ^ y2 ^ tx;
        y5 = y2;
        x2 = x3 ^ tw ^ ty;
        x3 = tw;
        y2 = y3 ^ tz ^ tx;
        y3 = tz;
    }

    /* Write the local variables back to the SPARKLE-384 state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s[0]  = x0;
    s[1]  = y0;
    s[2]  = x1;
    s[3]  = y1;
    s[4]  = x2;
    s[5]  = y2;
    s[6]  = x3;
    s[7]  = y3;
    s[8]  = x4;
    s[9]  = y4;
    s[10] = x5;
    s[11] = y5;
#else
    le_store_word32((uint8_t *)&(s[0]),  x0);
    le_store_word32((uint8_t *)&(s[1]),  y0);
    le_store_word32((uint8_t *)&(s[2]),  x1);
    le_store_word32((uint8_t *)&(s[3]),  y1);
    le_store_word32((uint8_t *)&(s[4]),  x2);
    le_store_word32((uint8_t *)&(s[5]),  y2);
    le_store_word32((uint8_t *)&(s[6]),  x3);
    le_store_word32((uint8_t *)&(s[7]),  y3);
    le_store_word32((uint8_t *)&(s[8]),  x4);
    le_store_word32((uint8_t *)&(s[9]),  y4);
    le_store_word32((uint8_t *)&(s[10]), x5);
    le_store_word32((uint8_t *)&(s[11]), y5);
#endif
}

/**
 * \brief Size of the state for SPARKLE-512.
 */
#define SPARKLE_512_STATE_SIZE 16

/**
 * \brief Performs the SPARKLE-512 permutation.
 *
 * \param s The words of the SPARKLE-512 state in little-endian byte order.
 * \param steps The number of steps to perform, 8 or 12.
 */
static void sparkle_512(uint32_t s[SPARKLE_512_STATE_SIZE], unsigned steps)
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t y0, y1, y2, y3, y4, y5, y6, y7;
    uint32_t tx, ty, tz, tw;
    unsigned step;

    /* Load the SPARKLE-512 state up into local variables */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    x0 = s[0];
    y0 = s[1];
    x1 = s[2];
    y1 = s[3];
    x2 = s[4];
    y2 = s[5];
    x3 = s[6];
    y3 = s[7];
    x4 = s[8];
    y4 = s[9];
    x5 = s[10];
    y5 = s[11];
    x6 = s[12];
    y6 = s[13];
    x7 = s[14];
    y7 = s[15];
#else
    x0 = le_load_word32((const uint8_t *)&(s[0]));
    y0 = le_load_word32((const uint8_t *)&(s[1]));
    x1 = le_load_word32((const uint8_t *)&(s[2]));
    y1 = le_load_word32((const uint8_t *)&(s[3]));
    x2 = le_load_word32((const uint8_t *)&(s[4]));
    y2 = le_load_word32((const uint8_t *)&(s[5]));
    x3 = le_load_word32((const uint8_t *)&(s[6]));
    y3 = le_load_word32((const uint8_t *)&(s[7]));
    x4 = le_load_word32((const uint8_t *)&(s[8]));
    y4 = le_load_word32((const uint8_t *)&(s[9]));
    x5 = le_load_word32((const uint8_t *)&(s[10]));
    y5 = le_load_word32((const uint8_t *)&(s[11]));
    x6 = le_load_word32((const uint8_t *)&(s[12]));
    y6 = le_load_word32((const uint8_t *)&(s[13]));
    x7 = le_load_word32((const uint8_t *)&(s[14]));
    y7 = le_load_word32((const uint8_t *)&(s[15]));
#endif

    /* Perform all requested steps */
    for (step = 0; step < steps; ++step) {
        /* Add round constants */
        y0 ^= sparkle_rc[step];
        y1 ^= step;

        /* ARXbox layer */
        alzette(x0, y0, RC_0);
        alzette(x1, y1, RC_1);
        alzette(x2, y2, RC_2);
        alzette(x3, y3, RC_3);
        alzette(x4, y4, RC_4);
        alzette(x5, y5, RC_5);
        alzette(x6, y6, RC_6);
        alzette(x7, y7, RC_7);

        /* Linear layer */
        tx = x0 ^ x1 ^ x2 ^ x3;
        ty = y0 ^ y1 ^ y2 ^ y3;
        tw = x0;
        tz = y0;
        tx = leftRotate16(tx ^ (tx << 16));
        ty = leftRotate16(ty ^ (ty << 16));
        x0 = x5 ^ x1 ^ ty;
        x5 = x1;
        y0 = y5 ^ y1 ^ tx;
        y5 = y1;
        x1 = x6 ^ x2 ^ ty;
        x6 = x2;
        y1 = y6 ^ y2 ^ tx;
        y6 = y2;
        x2 = x7 ^ x3 ^ ty;
        x7 = x3;
        y2 = y7 ^ y3 ^ tx;
        y7 = y3;
        x3 = x4 ^ tw ^ ty;
        x4 = tw;
        y3 = y4 ^ tz ^ tx;
        y4 = tz;
    }

    /* Write the local variables back to the SPARKLE-512 state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    s[0]  = x0;
    s[1]  = y0;
    s[2]  = x1;
    s[3]  = y1;
    s[4]  = x2;
    s[5]  = y2;
    s[6]  = x3;
    s[7]  = y3;
    s[8]  = x4;
    s[9]  = y4;
    s[10] = x5;
    s[11] = y5;
    s[12] = x6;
    s[13] = y6;
    s[14] = x7;
    s[15] = y7;
#else
    le_store_word32((uint8_t *)&(s[0]),  x0);
    le_store_word32((uint8_t *)&(s[1]),  y0);
    le_store_word32((uint8_t *)&(s[2]),  x1);
    le_store_word32((uint8_t *)&(s[3]),  y1);
    le_store_word32((uint8_t *)&(s[4]),  x2);
    le_store_word32((uint8_t *)&(s[5]),  y2);
    le_store_word32((uint8_t *)&(s[6]),  x3);
    le_store_word32((uint8_t *)&(s[7]),  y3);
    le_store_word32((uint8_t *)&(s[8]),  x4);
    le_store_word32((uint8_t *)&(s[9]),  y4);
    le_store_word32((uint8_t *)&(s[10]), x5);
    le_store_word32((uint8_t *)&(s[11]), y5);
    le_store_word32((uint8_t *)&(s[12]), x6);
    le_store_word32((uint8_t *)&(s[13]), y6);
    le_store_word32((uint8_t *)&(s[14]), x7);
    le_store_word32((uint8_t *)&(s[15]), y7);
#endif
}

/**
 * \def DOMAIN(value)
 * \brief Build a domain separation value as a 32-bit word.
 *
 * \param value The base value.
 * \return The domain separation value as a 32-bit word.
 */
#if defined(LW_UTIL_LITTLE_ENDIAN)
#define DOMAIN(value) ((value) << 24)
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
    unsigned temp;
    while (inlen > 0) {
        if (state->s.count == ESCH_256_RATE) {
            esch_256_m3(state->s.state, state->s.block, 0x00);
            sparkle_384(state->s.state, 7);
            state->s.count = 0;
        }
        temp = ESCH_256_RATE - state->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        memcpy(((unsigned char *)(state->s.block)) + state->s.count, in, temp);
        state->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void esch_256_hash_finalize
    (esch_256_hash_state_t *state, unsigned char *out)
{
    /* Pad and process the last block */
    if (state->s.count == ESCH_256_RATE) {
        esch_256_m3(state->s.state, state->s.block, 0x02);
    } else {
        unsigned temp = state->s.count;
        ((unsigned char *)(state->s.block))[temp] = 0x80;
        memset(((unsigned char *)(state->s.block)) + temp + 1, 0,
               ESCH_256_RATE - temp - 1);
        esch_256_m3(state->s.state, state->s.block, 0x01);
    }
    sparkle_384(state->s.state, 11);

    /* Generate the final hash value */
    memcpy(out, state->s.state, ESCH_256_RATE);
    sparkle_384(state->s.state, 7);
    memcpy(out + ESCH_256_RATE, state->s.state, ESCH_256_RATE);
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
    unsigned temp;
    while (inlen > 0) {
        if (state->s.count == ESCH_384_RATE) {
            esch_384_m4(state->s.state, state->s.block, 0x00);
            sparkle_512(state->s.state, 8);
            state->s.count = 0;
        }
        temp = ESCH_384_RATE - state->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        memcpy(((unsigned char *)(state->s.block)) + state->s.count, in, temp);
        state->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void esch_384_hash_finalize
    (esch_384_hash_state_t *state, unsigned char *out)
{
    /* Pad and process the last block */
    if (state->s.count == ESCH_384_RATE) {
        esch_384_m4(state->s.state, state->s.block, 0x02);
    } else {
        unsigned temp = state->s.count;
        ((unsigned char *)(state->s.block))[temp] = 0x80;
        memset(((unsigned char *)(state->s.block)) + temp + 1, 0,
               ESCH_384_RATE - temp - 1);
        esch_384_m4(state->s.state, state->s.block, 0x01);
    }
    sparkle_512(state->s.state, 12);

    /* Generate the final hash value */
    memcpy(out, state->s.state, ESCH_384_RATE);
    sparkle_512(state->s.state, 8);
    memcpy(out + ESCH_384_RATE, state->s.state, ESCH_384_RATE);
    sparkle_512(state->s.state, 8);
    memcpy(out + ESCH_384_RATE * 2, state->s.state, ESCH_384_RATE);
}
