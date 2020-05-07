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

#include "skinny-aead.h"
#include "internal-skinny128.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const skinny_aead_m1_cipher = {
    "SKINNY-AEAD-M1",
    SKINNY_AEAD_KEY_SIZE,
    SKINNY_AEAD_M1_NONCE_SIZE,
    SKINNY_AEAD_M1_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    skinny_aead_m1_encrypt,
    skinny_aead_m1_decrypt
};

aead_cipher_t const skinny_aead_m2_cipher = {
    "SKINNY-AEAD-M2",
    SKINNY_AEAD_KEY_SIZE,
    SKINNY_AEAD_M2_NONCE_SIZE,
    SKINNY_AEAD_M2_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    skinny_aead_m2_encrypt,
    skinny_aead_m2_decrypt
};

aead_cipher_t const skinny_aead_m3_cipher = {
    "SKINNY-AEAD-M3",
    SKINNY_AEAD_KEY_SIZE,
    SKINNY_AEAD_M3_NONCE_SIZE,
    SKINNY_AEAD_M3_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    skinny_aead_m3_encrypt,
    skinny_aead_m3_decrypt
};

aead_cipher_t const skinny_aead_m4_cipher = {
    "SKINNY-AEAD-M4",
    SKINNY_AEAD_KEY_SIZE,
    SKINNY_AEAD_M4_NONCE_SIZE,
    SKINNY_AEAD_M4_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    skinny_aead_m4_encrypt,
    skinny_aead_m4_decrypt
};

aead_cipher_t const skinny_aead_m5_cipher = {
    "SKINNY-AEAD-M5",
    SKINNY_AEAD_KEY_SIZE,
    SKINNY_AEAD_M5_NONCE_SIZE,
    SKINNY_AEAD_M5_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    skinny_aead_m5_encrypt,
    skinny_aead_m5_decrypt
};

aead_cipher_t const skinny_aead_m6_cipher = {
    "SKINNY-AEAD-M6",
    SKINNY_AEAD_KEY_SIZE,
    SKINNY_AEAD_M6_NONCE_SIZE,
    SKINNY_AEAD_M6_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    skinny_aead_m6_encrypt,
    skinny_aead_m6_decrypt
};

/* Domain separator prefixes for all of the SKINNY-AEAD family members */
#define DOMAIN_SEP_M1 0x00
#define DOMAIN_SEP_M2 0x10
#define DOMAIN_SEP_M3 0x08
#define DOMAIN_SEP_M4 0x18
#define DOMAIN_SEP_M5 0x10
#define DOMAIN_SEP_M6 0x18

/**
 * \brief Initialize the key and nonce for SKINNY-128-384 based AEAD schemes.
 *
 * \param ks The key schedule to initialize.
 * \param key Points to the 16 bytes of the key.
 * \param nonce Points to the nonce.
 * \param nonce_len Length of the nonce in bytes.
 */
static void skinny_aead_128_384_init
    (skinny_128_384_key_schedule_t *ks, const unsigned char *key,
     const unsigned char *nonce, unsigned nonce_len)
{
    unsigned char k[48];
    memset(k, 0, 16);
    memcpy(k + 16, nonce, nonce_len);
    memset(k + 16 + nonce_len, 0, 16 - nonce_len);
    memcpy(k + 32, key, 16);
    skinny_128_384_init(ks, k);
}

/**
 * \brief Set the domain separation value in the tweak for SKINNY-128-384.
 *
 * \param ks Key schedule for the block cipher.
 * \param d Domain separation value to write into the tweak.
 */
#define skinny_aead_128_384_set_domain(ks,d) ((ks)->TK1[15] = (d))

/**
 * \brief Sets the LFSR field in the tweak for SKINNY-128-384.
 *
 * \param ks Key schedule for the block cipher.
 * \param lfsr 64-bit LFSR value.
 */
#define skinny_aead_128_384_set_lfsr(ks,lfsr) le_store_word64((ks)->TK1, (lfsr))

/**
 * \brief Updates the LFSR value for SKINNY-128-384.
 *
 * \param lfsr 64-bit LFSR value to be updated.
 */
#define skinny_aead_128_384_update_lfsr(lfsr) \
    do { \
        uint8_t feedback = ((lfsr) & (1ULL << 63)) ? 0x1B : 0x00; \
        (lfsr) = ((lfsr) << 1) ^ feedback; \
    } while (0)

/**
 * \brief Authenticates the associated data for a SKINNY-128-384 based AEAD.
 *
 * \param ks The key schedule to use.
 * \param prefix Domain separation prefix for the family member.
 * \param tag Final tag to XOR the authentication checksum into.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void skinny_aead_128_384_authenticate
    (skinny_128_384_key_schedule_t *ks, unsigned char prefix,
     unsigned char tag[SKINNY_128_BLOCK_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char block[SKINNY_128_BLOCK_SIZE];
    uint64_t lfsr = 1;
    skinny_aead_128_384_set_domain(ks, prefix | 2);
    while (adlen >= SKINNY_128_BLOCK_SIZE) {
        skinny_aead_128_384_set_lfsr(ks, lfsr);
        skinny_128_384_encrypt(ks, block, ad);
        lw_xor_block(tag, block, SKINNY_128_BLOCK_SIZE);
        ad += SKINNY_128_BLOCK_SIZE;
        adlen -= SKINNY_128_BLOCK_SIZE;
        skinny_aead_128_384_update_lfsr(lfsr);
    }
    if (adlen > 0) {
        unsigned temp = (unsigned)adlen;
        skinny_aead_128_384_set_lfsr(ks, lfsr);
        skinny_aead_128_384_set_domain(ks, prefix | 3);
        memcpy(block, ad, temp);
        block[temp] = 0x80;
        memset(block + temp + 1, 0, SKINNY_128_BLOCK_SIZE - temp - 1);
        skinny_128_384_encrypt(ks, block, block);
        lw_xor_block(tag, block, SKINNY_128_BLOCK_SIZE);
    }
}

/**
 * \brief Encrypts the plaintext for a SKINNY-128-384 based AEAD.
 *
 * \param ks The key schedule to use.
 * \param prefix Domain separation prefix for the family member.
 * \param sum Authenticated checksum over the plaintext.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the plaintext buffer.
 * \param mlen Number of bytes of plaintext to be encrypted.
 */
static void skinny_aead_128_384_encrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char prefix,
     unsigned char sum[SKINNY_128_BLOCK_SIZE], unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    unsigned char block[SKINNY_128_BLOCK_SIZE];
    uint64_t lfsr = 1;
    memset(sum, 0, SKINNY_128_BLOCK_SIZE);
    skinny_aead_128_384_set_domain(ks, prefix | 0);
    while (mlen >= SKINNY_128_BLOCK_SIZE) {
        skinny_aead_128_384_set_lfsr(ks, lfsr);
        lw_xor_block(sum, m, SKINNY_128_BLOCK_SIZE);
        skinny_128_384_encrypt(ks, c, m);
        c += SKINNY_128_BLOCK_SIZE;
        m += SKINNY_128_BLOCK_SIZE;
        mlen -= SKINNY_128_BLOCK_SIZE;
        skinny_aead_128_384_update_lfsr(lfsr);
    }
    skinny_aead_128_384_set_lfsr(ks, lfsr);
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        skinny_aead_128_384_set_domain(ks, prefix | 1);
        lw_xor_block(sum, m, temp);
        sum[temp] ^= 0x80;
        memset(block, 0, SKINNY_128_BLOCK_SIZE);
        skinny_128_384_encrypt(ks, block, block);
        lw_xor_block_2_src(c, block, m, temp);
        skinny_aead_128_384_update_lfsr(lfsr);
        skinny_aead_128_384_set_lfsr(ks, lfsr);
        skinny_aead_128_384_set_domain(ks, prefix | 5);
    } else {
        skinny_aead_128_384_set_domain(ks, prefix | 4);
    }
    skinny_128_384_encrypt(ks, sum, sum);
}

/**
 * \brief Decrypts the ciphertext for a SKINNY-128-384 based AEAD.
 *
 * \param ks The key schedule to use.
 * \param prefix Domain separation prefix for the family member.
 * \param sum Authenticated checksum over the plaintext.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the ciphertext buffer.
 * \param mlen Number of bytes of ciphertext to be decrypted.
 */
static void skinny_aead_128_384_decrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char prefix,
     unsigned char sum[SKINNY_128_BLOCK_SIZE], unsigned char *m,
     const unsigned char *c, unsigned long long mlen)
{
    unsigned char block[SKINNY_128_BLOCK_SIZE];
    uint64_t lfsr = 1;
    memset(sum, 0, SKINNY_128_BLOCK_SIZE);
    skinny_aead_128_384_set_domain(ks, prefix | 0);
    while (mlen >= SKINNY_128_BLOCK_SIZE) {
        skinny_aead_128_384_set_lfsr(ks, lfsr);
        skinny_128_384_decrypt(ks, m, c);
        lw_xor_block(sum, m, SKINNY_128_BLOCK_SIZE);
        c += SKINNY_128_BLOCK_SIZE;
        m += SKINNY_128_BLOCK_SIZE;
        mlen -= SKINNY_128_BLOCK_SIZE;
        skinny_aead_128_384_update_lfsr(lfsr);
    }
    skinny_aead_128_384_set_lfsr(ks, lfsr);
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        skinny_aead_128_384_set_domain(ks, prefix | 1);
        memset(block, 0, SKINNY_128_BLOCK_SIZE);
        skinny_128_384_encrypt(ks, block, block);
        lw_xor_block_2_src(m, block, c, temp);
        lw_xor_block(sum, m, temp);
        sum[temp] ^= 0x80;
        skinny_aead_128_384_update_lfsr(lfsr);
        skinny_aead_128_384_set_lfsr(ks, lfsr);
        skinny_aead_128_384_set_domain(ks, prefix | 5);
    } else {
        skinny_aead_128_384_set_domain(ks, prefix | 4);
    }
    skinny_128_384_encrypt(ks, sum, sum);
}

int skinny_aead_m1_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SKINNY_AEAD_M1_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M1_NONCE_SIZE);

    /* Encrypt to plaintext to produce the ciphertext */
    skinny_aead_128_384_encrypt(&ks, DOMAIN_SEP_M1, sum, c, m, mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M1, sum, ad, adlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, sum, SKINNY_AEAD_M1_TAG_SIZE);
    return 0;
}

int skinny_aead_m1_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SKINNY_AEAD_M1_TAG_SIZE)
        return -1;
    *mlen = clen - SKINNY_AEAD_M1_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M1_NONCE_SIZE);

    /* Decrypt to ciphertext to produce the plaintext */
    skinny_aead_128_384_decrypt(&ks, DOMAIN_SEP_M1, sum, m, c, *mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M1, sum, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, sum, c + *mlen, SKINNY_AEAD_M1_TAG_SIZE);
}

int skinny_aead_m2_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SKINNY_AEAD_M2_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M2_NONCE_SIZE);

    /* Encrypt to plaintext to produce the ciphertext */
    skinny_aead_128_384_encrypt(&ks, DOMAIN_SEP_M2, sum, c, m, mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M2, sum, ad, adlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, sum, SKINNY_AEAD_M2_TAG_SIZE);
    return 0;
}

int skinny_aead_m2_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SKINNY_AEAD_M2_TAG_SIZE)
        return -1;
    *mlen = clen - SKINNY_AEAD_M2_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M2_NONCE_SIZE);

    /* Decrypt to ciphertext to produce the plaintext */
    skinny_aead_128_384_decrypt(&ks, DOMAIN_SEP_M2, sum, m, c, *mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M2, sum, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, sum, c + *mlen, SKINNY_AEAD_M2_TAG_SIZE);
}

int skinny_aead_m3_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SKINNY_AEAD_M3_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M3_NONCE_SIZE);

    /* Encrypt to plaintext to produce the ciphertext */
    skinny_aead_128_384_encrypt(&ks, DOMAIN_SEP_M3, sum, c, m, mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M3, sum, ad, adlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, sum, SKINNY_AEAD_M3_TAG_SIZE);
    return 0;
}

int skinny_aead_m3_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SKINNY_AEAD_M3_TAG_SIZE)
        return -1;
    *mlen = clen - SKINNY_AEAD_M3_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M3_NONCE_SIZE);

    /* Decrypt to ciphertext to produce the plaintext */
    skinny_aead_128_384_decrypt(&ks, DOMAIN_SEP_M3, sum, m, c, *mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M3, sum, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, sum, c + *mlen, SKINNY_AEAD_M3_TAG_SIZE);
}

int skinny_aead_m4_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SKINNY_AEAD_M4_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M4_NONCE_SIZE);

    /* Encrypt to plaintext to produce the ciphertext */
    skinny_aead_128_384_encrypt(&ks, DOMAIN_SEP_M4, sum, c, m, mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M4, sum, ad, adlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, sum, SKINNY_AEAD_M4_TAG_SIZE);
    return 0;
}

int skinny_aead_m4_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SKINNY_AEAD_M4_TAG_SIZE)
        return -1;
    *mlen = clen - SKINNY_AEAD_M4_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_384_init(&ks, k, npub, SKINNY_AEAD_M4_NONCE_SIZE);

    /* Decrypt to ciphertext to produce the plaintext */
    skinny_aead_128_384_decrypt(&ks, DOMAIN_SEP_M4, sum, m, c, *mlen);

    /* Process the associated data */
    skinny_aead_128_384_authenticate(&ks, DOMAIN_SEP_M4, sum, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, sum, c + *mlen, SKINNY_AEAD_M4_TAG_SIZE);
}

/**
 * \brief Initialize the key and nonce for SKINNY-128-256 based AEAD schemes.
 *
 * \param ks The key schedule to initialize.
 * \param key Points to the 16 bytes of the key.
 * \param nonce Points to the nonce.
 * \param nonce_len Length of the nonce in bytes.
 */
static void skinny_aead_128_256_init
    (skinny_128_256_key_schedule_t *ks, const unsigned char *key,
     const unsigned char *nonce, unsigned nonce_len)
{
    unsigned char k[32];
    memset(k, 0, 16 - nonce_len);
    memcpy(k + 16 - nonce_len, nonce, nonce_len);
    memcpy(k + 16, key, 16);
    skinny_128_256_init(ks, k);
}

/**
 * \brief Set the domain separation value in the tweak for SKINNY-128-256.
 *
 * \param ks Key schedule for the block cipher.
 * \param d Domain separation value to write into the tweak.
 */
#define skinny_aead_128_256_set_domain(ks,d) ((ks)->TK1[3] = (d))

/**
 * \brief Sets the LFSR field in the tweak for SKINNY-128-256.
 *
 * \param ks Key schedule for the block cipher.
 * \param lfsr 24-bit LFSR value.
 */
#define skinny_aead_128_256_set_lfsr(ks,lfsr) \
    do { \
        (ks)->TK1[0] = (uint8_t)(lfsr); \
        (ks)->TK1[1] = (uint8_t)((lfsr) >> 8); \
        (ks)->TK1[2] = (uint8_t)((lfsr) >> 16); \
    } while (0)

/**
 * \brief Updates the LFSR value for SKINNY-128-256.
 *
 * \param lfsr 24-bit LFSR value to be updated.
 */
#define skinny_aead_128_256_update_lfsr(lfsr) \
    do { \
        uint32_t feedback = ((lfsr) & (((uint32_t)1) << 23)) ? 0x1B : 0x00; \
        (lfsr) = ((lfsr) << 1) ^ (feedback); \
    } while (0)

/**
 * \brief Authenticates the associated data for a SKINNY-128-256 based AEAD.
 *
 * \param ks The key schedule to use.
 * \param prefix Domain separation prefix for the family member.
 * \param tag Final tag to XOR the authentication checksum into.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void skinny_aead_128_256_authenticate
    (skinny_128_256_key_schedule_t *ks, unsigned char prefix,
     unsigned char tag[SKINNY_128_BLOCK_SIZE],
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char block[SKINNY_128_BLOCK_SIZE];
    uint32_t lfsr = 1;
    skinny_aead_128_256_set_domain(ks, prefix | 2);
    while (adlen >= SKINNY_128_BLOCK_SIZE) {
        skinny_aead_128_256_set_lfsr(ks, lfsr);
        skinny_128_256_encrypt(ks, block, ad);
        lw_xor_block(tag, block, SKINNY_128_BLOCK_SIZE);
        ad += SKINNY_128_BLOCK_SIZE;
        adlen -= SKINNY_128_BLOCK_SIZE;
        skinny_aead_128_256_update_lfsr(lfsr);
    }
    if (adlen > 0) {
        unsigned temp = (unsigned)adlen;
        skinny_aead_128_256_set_lfsr(ks, lfsr);
        skinny_aead_128_256_set_domain(ks, prefix | 3);
        memcpy(block, ad, temp);
        block[temp] = 0x80;
        memset(block + temp + 1, 0, SKINNY_128_BLOCK_SIZE - temp - 1);
        skinny_128_256_encrypt(ks, block, block);
        lw_xor_block(tag, block, SKINNY_128_BLOCK_SIZE);
    }
}

/**
 * \brief Encrypts the plaintext for a SKINNY-128-256 based AEAD.
 *
 * \param ks The key schedule to use.
 * \param prefix Domain separation prefix for the family member.
 * \param sum Authenticated checksum over the plaintext.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the plaintext buffer.
 * \param mlen Number of bytes of plaintext to be encrypted.
 */
static void skinny_aead_128_256_encrypt
    (skinny_128_256_key_schedule_t *ks, unsigned char prefix,
     unsigned char sum[SKINNY_128_BLOCK_SIZE], unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    unsigned char block[SKINNY_128_BLOCK_SIZE];
    uint32_t lfsr = 1;
    memset(sum, 0, SKINNY_128_BLOCK_SIZE);
    skinny_aead_128_256_set_domain(ks, prefix | 0);
    while (mlen >= SKINNY_128_BLOCK_SIZE) {
        skinny_aead_128_256_set_lfsr(ks, lfsr);
        lw_xor_block(sum, m, SKINNY_128_BLOCK_SIZE);
        skinny_128_256_encrypt(ks, c, m);
        c += SKINNY_128_BLOCK_SIZE;
        m += SKINNY_128_BLOCK_SIZE;
        mlen -= SKINNY_128_BLOCK_SIZE;
        skinny_aead_128_256_update_lfsr(lfsr);
    }
    skinny_aead_128_256_set_lfsr(ks, lfsr);
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        skinny_aead_128_256_set_domain(ks, prefix | 1);
        lw_xor_block(sum, m, temp);
        sum[temp] ^= 0x80;
        memset(block, 0, SKINNY_128_BLOCK_SIZE);
        skinny_128_256_encrypt(ks, block, block);
        lw_xor_block_2_src(c, block, m, temp);
        skinny_aead_128_256_update_lfsr(lfsr);
        skinny_aead_128_256_set_lfsr(ks, lfsr);
        skinny_aead_128_256_set_domain(ks, prefix | 5);
    } else {
        skinny_aead_128_256_set_domain(ks, prefix | 4);
    }
    skinny_128_256_encrypt(ks, sum, sum);
}

/**
 * \brief Decrypts the ciphertext for a SKINNY-128-256 based AEAD.
 *
 * \param ks The key schedule to use.
 * \param prefix Domain separation prefix for the family member.
 * \param sum Authenticated checksum over the plaintext.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the ciphertext buffer.
 * \param mlen Number of bytes of ciphertext to be decrypted.
 */
static void skinny_aead_128_256_decrypt
    (skinny_128_256_key_schedule_t *ks, unsigned char prefix,
     unsigned char sum[SKINNY_128_BLOCK_SIZE], unsigned char *m,
     const unsigned char *c, unsigned long long mlen)
{
    unsigned char block[SKINNY_128_BLOCK_SIZE];
    uint32_t lfsr = 1;
    memset(sum, 0, SKINNY_128_BLOCK_SIZE);
    skinny_aead_128_256_set_domain(ks, prefix | 0);
    while (mlen >= SKINNY_128_BLOCK_SIZE) {
        skinny_aead_128_256_set_lfsr(ks, lfsr);
        skinny_128_256_decrypt(ks, m, c);
        lw_xor_block(sum, m, SKINNY_128_BLOCK_SIZE);
        c += SKINNY_128_BLOCK_SIZE;
        m += SKINNY_128_BLOCK_SIZE;
        mlen -= SKINNY_128_BLOCK_SIZE;
        skinny_aead_128_256_update_lfsr(lfsr);
    }
    skinny_aead_128_256_set_lfsr(ks, lfsr);
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        skinny_aead_128_256_set_domain(ks, prefix | 1);
        memset(block, 0, SKINNY_128_BLOCK_SIZE);
        skinny_128_256_encrypt(ks, block, block);
        lw_xor_block_2_src(m, block, c, temp);
        lw_xor_block(sum, m, temp);
        sum[temp] ^= 0x80;
        skinny_aead_128_256_update_lfsr(lfsr);
        skinny_aead_128_256_set_lfsr(ks, lfsr);
        skinny_aead_128_256_set_domain(ks, prefix | 5);
    } else {
        skinny_aead_128_256_set_domain(ks, prefix | 4);
    }
    skinny_128_256_encrypt(ks, sum, sum);
}

int skinny_aead_m5_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SKINNY_AEAD_M5_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_256_init(&ks, k, npub, SKINNY_AEAD_M5_NONCE_SIZE);

    /* Encrypt to plaintext to produce the ciphertext */
    skinny_aead_128_256_encrypt(&ks, DOMAIN_SEP_M5, sum, c, m, mlen);

    /* Process the associated data */
    skinny_aead_128_256_authenticate(&ks, DOMAIN_SEP_M5, sum, ad, adlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, sum, SKINNY_AEAD_M5_TAG_SIZE);
    return 0;
}

int skinny_aead_m5_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SKINNY_AEAD_M5_TAG_SIZE)
        return -1;
    *mlen = clen - SKINNY_AEAD_M5_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_256_init(&ks, k, npub, SKINNY_AEAD_M5_NONCE_SIZE);

    /* Decrypt to ciphertext to produce the plaintext */
    skinny_aead_128_256_decrypt(&ks, DOMAIN_SEP_M5, sum, m, c, *mlen);

    /* Process the associated data */
    skinny_aead_128_256_authenticate(&ks, DOMAIN_SEP_M5, sum, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, sum, c + *mlen, SKINNY_AEAD_M5_TAG_SIZE);
}

int skinny_aead_m6_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SKINNY_AEAD_M6_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_256_init(&ks, k, npub, SKINNY_AEAD_M6_NONCE_SIZE);

    /* Encrypt to plaintext to produce the ciphertext */
    skinny_aead_128_256_encrypt(&ks, DOMAIN_SEP_M6, sum, c, m, mlen);

    /* Process the associated data */
    skinny_aead_128_256_authenticate(&ks, DOMAIN_SEP_M6, sum, ad, adlen);

    /* Generate the authentication tag */
    memcpy(c + mlen, sum, SKINNY_AEAD_M6_TAG_SIZE);
    return 0;
}

int skinny_aead_m6_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char sum[SKINNY_128_BLOCK_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SKINNY_AEAD_M6_TAG_SIZE)
        return -1;
    *mlen = clen - SKINNY_AEAD_M6_TAG_SIZE;

    /* Set up the key schedule with the key and the nonce */
    skinny_aead_128_256_init(&ks, k, npub, SKINNY_AEAD_M6_NONCE_SIZE);

    /* Decrypt to ciphertext to produce the plaintext */
    skinny_aead_128_256_decrypt(&ks, DOMAIN_SEP_M6, sum, m, c, *mlen);

    /* Process the associated data */
    skinny_aead_128_256_authenticate(&ks, DOMAIN_SEP_M6, sum, ad, adlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, sum, c + *mlen, SKINNY_AEAD_M6_TAG_SIZE);
}
