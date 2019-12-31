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

#include "comet.h"
#include "internal-cham.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const comet_128_cham_cipher = {
    "COMET-128_CHAM-128/128",
    COMET_KEY_SIZE,
    COMET_128_NONCE_SIZE,
    COMET_128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    comet_128_cham_aead_encrypt,
    comet_128_cham_aead_decrypt
};

aead_cipher_t const comet_64_cham_cipher = {
    "COMET-64_CHAM-64/128",
    COMET_KEY_SIZE,
    COMET_64_NONCE_SIZE,
    COMET_64_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    comet_64_cham_aead_encrypt,
    comet_64_cham_aead_decrypt
};

aead_cipher_t const comet_64_speck_cipher = {
    "COMET-64_SPECK-64/128",
    COMET_KEY_SIZE,
    COMET_64_NONCE_SIZE,
    COMET_64_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    comet_64_speck_aead_encrypt,
    comet_64_speck_aead_decrypt
};

/**
 * \brief Adjusts the Z state to generate the key to use on the next block.
 *
 * \param Z The Z state to be adjusted.
 */
static void comet_adjust_block_key(unsigned char Z[16])
{
    /* Doubles the 64-bit prefix to Z in the F(2^64) field */
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)(Z[7])) >> 7);
    for (index = 7; index > 0; --index)
        Z[index] = (Z[index] << 1) | (Z[index - 1] >> 7);
    Z[0] = (Z[0] << 1) ^ (mask & 0x1B);
}

/* Function prototype for the encrypt function of the underyling cipher */
typedef void (*comet_encrypt_block_t)
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input);

/**
 * \brief Processes the associated data for COMET.
 *
 * \param Y Internal COMET block state of \a block_size bytes in size.
 * \param Z Internal COMET key state of 16 bytes in size.
 * \param block_size Size of the block for the underlying cipher.
 * \param encrypt Encryption function for the underlying cipher.
 * \param ad Points to the associated data.
 * \param adlen Number of bytes of associated data; must be >= 1.
 */
static void comet_process_ad
    (unsigned char *Y, unsigned char Z[16], unsigned block_size,
     comet_encrypt_block_t encrypt, const unsigned char *ad,
     unsigned long long adlen)
{
    /* Domain separator for associated data */
    Z[15] ^= 0x08;

    /* Process all associated data blocks except the last partial block */
    while (adlen >= block_size) {
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        lw_xor_block(Y, ad, block_size);
        ad += block_size;
        adlen -= block_size;
    }

    /* Pad and process the partial block on the end */
    if (adlen > 0) {
        unsigned temp = (unsigned)adlen;
        Z[15] ^= 0x10;
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        lw_xor_block(Y, ad, temp);
        Y[temp] ^= 0x01;
    }
}

/**
 * \brief Shuffles the words in a 128-bit block.
 *
 * \param out The output block after shuffling.
 * \param in The input block to be shuffled.
 */
STATIC_INLINE void comet_shuffle_block_128
    (unsigned char out[16], const unsigned char in[16])
{
    uint32_t x0, x1, x2, x3;
    x0 = le_load_word32(in);
    x1 = le_load_word32(in + 4);
    x2 = le_load_word32(in + 8);
    x3 = le_load_word32(in + 12);
    le_store_word32(out,      x3);
    le_store_word32(out + 4,  rightRotate1(x2));
    le_store_word32(out + 8,  x0);
    le_store_word32(out + 12, x1);
}

/**
 * \brief Shuffles the words in a 64-bit block.
 *
 * \param out The output block after shuffling.
 * \param in The input block to be shuffled.
 */
STATIC_INLINE void comet_shuffle_block_64
    (unsigned char out[8], const unsigned char in[8])
{
    uint32_t x01 = le_load_word32(in);
    uint16_t x2 = ((uint16_t)(in[4])) | (((uint16_t)(in[5])) << 8);
    out[0] = in[6];
    out[1] = in[7];
    x2 = (x2 >> 1) | (x2 << 15);
    out[2] = (uint8_t)x2;
    out[3] = (uint8_t)(x2 >> 8);
    le_store_word32(out + 4, x01);
}

/**
 * \brief Encrypts the plaintext with COMET-128 to produce the ciphertext.
 *
 * \param Y Internal COMET block state of 16 bytes in size.
 * \param Z Internal COMET key state of 16 bytes in size.
 * \param encrypt Encryption function for the underlying cipher.
 * \param c Ciphertext on output.
 * \param m Plaintext message on input.
 * \param mlen Length of the plaintext message and the ciphertext.
 */
static void comet_encrypt_128
    (unsigned char Y[16], unsigned char Z[16],
     comet_encrypt_block_t encrypt, unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    unsigned char Ys[16];

    /* Domain separator for payload data */
    Z[15] ^= 0x20;

    /* Process all payload data blocks except the last partial block */
    while (mlen >= 16) {
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_128(Ys, Y);
        lw_xor_block(Y, m, 16);
        lw_xor_block_2_src(c, m, Ys, 16);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the partial block on the end */
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        Z[15] ^= 0x40;
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_128(Ys, Y);
        lw_xor_block(Y, m, temp);
        lw_xor_block_2_src(c, m, Ys, temp);
        Y[temp] ^= 0x01;
    }
}

/**
 * \brief Encrypts the plaintext with COMET-64 to produce the ciphertext.
 *
 * \param Y Internal COMET block state of 8 bytes in size.
 * \param Z Internal COMET key state of 16 bytes in size.
 * \param encrypt Encryption function for the underlying cipher.
 * \param c Ciphertext on output.
 * \param m Plaintext message on input.
 * \param mlen Length of the plaintext message and the ciphertext.
 */
static void comet_encrypt_64
    (unsigned char Y[8], unsigned char Z[16],
     comet_encrypt_block_t encrypt, unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    unsigned char Ys[8];

    /* Domain separator for payload data */
    Z[15] ^= 0x20;

    /* Process all payload data blocks except the last partial block */
    while (mlen >= 8) {
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_64(Ys, Y);
        lw_xor_block(Y, m, 8);
        lw_xor_block_2_src(c, m, Ys, 8);
        c += 8;
        m += 8;
        mlen -= 8;
    }

    /* Pad and process the partial block on the end */
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        Z[15] ^= 0x40;
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_64(Ys, Y);
        lw_xor_block(Y, m, temp);
        lw_xor_block_2_src(c, m, Ys, temp);
        Y[temp] ^= 0x01;
    }
}

/**
 * \brief Decrypts the ciphertext with COMET-128 to produce the plaintext.
 *
 * \param Y Internal COMET block state of 16 bytes in size.
 * \param Z Internal COMET key state of 16 bytes in size.
 * \param encrypt Encryption function for the underlying cipher.
 * \param m Plaintext message on output.
 * \param c Ciphertext on input.
 * \param mlen Length of the plaintext message and the ciphertext.
 */
static void comet_decrypt_128
    (unsigned char Y[16], unsigned char Z[16],
     comet_encrypt_block_t encrypt, unsigned char *m,
     const unsigned char *c, unsigned long long mlen)
{
    unsigned char Ys[16];

    /* Domain separator for payload data */
    Z[15] ^= 0x20;

    /* Process all payload data blocks except the last partial block */
    while (mlen >= 16) {
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_128(Ys, Y);
        lw_xor_block_2_src(m, c, Ys, 16);
        lw_xor_block(Y, m, 16);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the partial block on the end */
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        Z[15] ^= 0x40;
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_128(Ys, Y);
        lw_xor_block_2_src(m, c, Ys, temp);
        lw_xor_block(Y, m, temp);
        Y[temp] ^= 0x01;
    }
}

/**
 * \brief Decrypts the ciphertext with COMET-64 to produce the plaintext.
 *
 * \param Y Internal COMET block state of 8 bytes in size.
 * \param Z Internal COMET key state of 16 bytes in size.
 * \param encrypt Encryption function for the underlying cipher.
 * \param m Plaintext message on output.
 * \param c Ciphertext on input.
 * \param mlen Length of the plaintext message and the ciphertext.
 */
static void comet_decrypt_64
    (unsigned char Y[8], unsigned char Z[16],
     comet_encrypt_block_t encrypt, unsigned char *m,
     const unsigned char *c, unsigned long long mlen)
{
    unsigned char Ys[8];

    /* Domain separator for payload data */
    Z[15] ^= 0x20;

    /* Process all payload data blocks except the last partial block */
    while (mlen >= 8) {
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_64(Ys, Y);
        lw_xor_block_2_src(m, c, Ys, 8);
        lw_xor_block(Y, m, 8);
        c += 8;
        m += 8;
        mlen -= 8;
    }

    /* Pad and process the partial block on the end */
    if (mlen > 0) {
        unsigned temp = (unsigned)mlen;
        Z[15] ^= 0x40;
        comet_adjust_block_key(Z);
        encrypt(Z, Y, Y);
        comet_shuffle_block_64(Ys, Y);
        lw_xor_block_2_src(m, c, Ys, temp);
        lw_xor_block(Y, m, temp);
        Y[temp] ^= 0x01;
    }
}

int comet_128_cham_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char Y[16];
    unsigned char Z[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + COMET_128_TAG_SIZE;

    /* Set up the initial state of Y and Z */
    memcpy(Y, k, 16);
    cham128_128_encrypt(Y, Z, npub);

    /* Process the associated data */
    if (adlen > 0)
        comet_process_ad(Y, Z, 16, cham128_128_encrypt, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        comet_encrypt_128(Y, Z, cham128_128_encrypt, c, m, mlen);

    /* Generate the authentication tag */
    Z[15] ^= 0x80;
    comet_adjust_block_key(Z);
    cham128_128_encrypt(Z, c + mlen, Y);
    return 0;
}

int comet_128_cham_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char Y[16];
    unsigned char Z[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < COMET_128_TAG_SIZE)
        return -1;
    *mlen = clen - COMET_128_TAG_SIZE;

    /* Set up the initial state of Y and Z */
    memcpy(Y, k, 16);
    cham128_128_encrypt(Y, Z, npub);

    /* Process the associated data */
    if (adlen > 0)
        comet_process_ad(Y, Z, 16, cham128_128_encrypt, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > COMET_128_TAG_SIZE)
        comet_decrypt_128(Y, Z, cham128_128_encrypt, m, c, *mlen);

    /* Check the authentication tag */
    Z[15] ^= 0x80;
    comet_adjust_block_key(Z);
    cham128_128_encrypt(Z, Y, Y);
    return aead_check_tag(m, *mlen, Y, c + *mlen, COMET_128_TAG_SIZE);
}

int comet_64_cham_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char Y[8];
    unsigned char Z[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + COMET_64_TAG_SIZE;

    /* Set up the initial state of Y and Z */
    memset(Y, 0, 8);
    cham64_128_encrypt(k, Y, Y);
    memcpy(Z, npub, 15);
    Z[15] = 0;
    lw_xor_block(Z, k, 16);

    /* Process the associated data */
    if (adlen > 0)
        comet_process_ad(Y, Z, 8, cham64_128_encrypt, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        comet_encrypt_64(Y, Z, cham64_128_encrypt, c, m, mlen);

    /* Generate the authentication tag */
    Z[15] ^= 0x80;
    comet_adjust_block_key(Z);
    cham64_128_encrypt(Z, c + mlen, Y);
    return 0;
}

int comet_64_cham_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char Y[8];
    unsigned char Z[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < COMET_64_TAG_SIZE)
        return -1;
    *mlen = clen - COMET_64_TAG_SIZE;

    /* Set up the initial state of Y and Z */
    memset(Y, 0, 8);
    cham64_128_encrypt(k, Y, Y);
    memcpy(Z, npub, 15);
    Z[15] = 0;
    lw_xor_block(Z, k, 16);

    /* Process the associated data */
    if (adlen > 0)
        comet_process_ad(Y, Z, 8, cham64_128_encrypt, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > COMET_64_TAG_SIZE)
        comet_decrypt_64(Y, Z, cham64_128_encrypt, m, c, *mlen);

    /* Check the authentication tag */
    Z[15] ^= 0x80;
    comet_adjust_block_key(Z);
    cham64_128_encrypt(Z, Y, Y);
    return aead_check_tag(m, *mlen, Y, c + *mlen, COMET_64_TAG_SIZE);
}

/**
 * \brief Encrypts a 64-bit block with SPECK-64-128 in COMET byte order.
 *
 * \param key Points to the 16 bytes of the key.
 * \param output Output buffer which must be at least 8 bytes in length.
 * \param input Input buffer which must be at least 8 bytes in length.
 *
 * The \a input and \a output buffers can be the same buffer for
 * in-place encryption.
 *
 * \note This version differs from standard SPECK-64 in that it uses the
 * little-endian byte order from the COMET specification which is different
 * from the big-endian byte order from the original SPECK paper.
 */
static void speck64_128_comet_encrypt
    (const unsigned char *key, unsigned char *output,
     const unsigned char *input)
{
    uint32_t l[4];
    uint32_t x, y, s;
    uint8_t round;
    uint8_t li_in = 0;
    uint8_t li_out = 3;

    /* Unpack the key and the input block */
    s    = le_load_word32(key);
    l[0] = le_load_word32(key + 4);
    l[1] = le_load_word32(key + 8);
    l[2] = le_load_word32(key + 12);
    y = le_load_word32(input);
    x = le_load_word32(input + 4);

    /* Perform all encryption rounds except the last */
    for (round = 0; round < 26; ++round) {
        /* Perform the round with the current key schedule word */
        x = (rightRotate8(x) + y) ^ s;
        y = leftRotate3(y) ^ x;

        /* Calculate the next key schedule word */
        l[li_out] = (s + rightRotate8(l[li_in])) ^ round;
        s = leftRotate3(s) ^ l[li_out];
        li_in = (li_in + 1) & 0x03;
        li_out = (li_out + 1) & 0x03;
    }

    /* Perform the last encryption round and write the result to the output */
    x = (rightRotate8(x) + y) ^ s;
    y = leftRotate3(y) ^ x;
    le_store_word32(output, y);
    le_store_word32(output + 4, x);
}

int comet_64_speck_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char Y[8];
    unsigned char Z[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + COMET_64_TAG_SIZE;

    /* Set up the initial state of Y and Z */
    memset(Y, 0, 8);
    speck64_128_comet_encrypt(k, Y, Y);
    memcpy(Z, npub, 15);
    Z[15] = 0;
    lw_xor_block(Z, k, 16);

    /* Process the associated data */
    if (adlen > 0)
        comet_process_ad(Y, Z, 8, speck64_128_comet_encrypt, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0)
        comet_encrypt_64(Y, Z, speck64_128_comet_encrypt, c, m, mlen);

    /* Generate the authentication tag */
    Z[15] ^= 0x80;
    comet_adjust_block_key(Z);
    speck64_128_comet_encrypt(Z, c + mlen, Y);
    return 0;
}

int comet_64_speck_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char Y[8];
    unsigned char Z[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < COMET_64_TAG_SIZE)
        return -1;
    *mlen = clen - COMET_64_TAG_SIZE;

    /* Set up the initial state of Y and Z */
    memset(Y, 0, 8);
    speck64_128_comet_encrypt(k, Y, Y);
    memcpy(Z, npub, 15);
    Z[15] = 0;
    lw_xor_block(Z, k, 16);

    /* Process the associated data */
    if (adlen > 0)
        comet_process_ad(Y, Z, 8, speck64_128_comet_encrypt, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > COMET_64_TAG_SIZE)
        comet_decrypt_64(Y, Z, speck64_128_comet_encrypt, m, c, *mlen);

    /* Check the authentication tag */
    Z[15] ^= 0x80;
    comet_adjust_block_key(Z);
    speck64_128_comet_encrypt(Z, Y, Y);
    return aead_check_tag(m, *mlen, Y, c + *mlen, COMET_64_TAG_SIZE);
}
