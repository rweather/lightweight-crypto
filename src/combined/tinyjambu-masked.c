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

#include "tinyjambu-masked.h"
#include "internal-tinyjambu-m.h"
#include "internal-util.h"

aead_cipher_t const tiny_jambu_128_masked_cipher = {
    "TinyJAMBU-128-Masked",
    TINY_JAMBU_MASKED_128_KEY_SIZE,
    TINY_JAMBU_MASKED_NONCE_SIZE,
    TINY_JAMBU_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_128_masked_aead_encrypt,
    tiny_jambu_128_masked_aead_decrypt
};

aead_cipher_t const tiny_jambu_192_masked_cipher = {
    "TinyJAMBU-192-Masked",
    TINY_JAMBU_MASKED_192_KEY_SIZE,
    TINY_JAMBU_MASKED_NONCE_SIZE,
    TINY_JAMBU_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_192_masked_aead_encrypt,
    tiny_jambu_192_masked_aead_decrypt
};

aead_cipher_t const tiny_jambu_256_masked_cipher = {
    "TinyJAMBU-256-Masked",
    TINY_JAMBU_MASKED_256_KEY_SIZE,
    TINY_JAMBU_MASKED_NONCE_SIZE,
    TINY_JAMBU_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    tiny_jambu_256_masked_aead_encrypt,
    tiny_jambu_256_masked_aead_decrypt
};

/**
 * \brief Set up the masked TinyJAMBU state with the key and the nonce.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the masked key words.
 * \param key_words The number of words in the masked key.
 * \param rounds The number of rounds to perform to absorb the key.
 * \param nonce Points to the nonce.
 *
 * \sa tiny_jambu_permutation_masked()
 */
static void tiny_jambu_setup_masked
    (mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE],
     const mask_uint32_t *key, unsigned key_words,
     unsigned rounds, const unsigned char *nonce)
{
    /* Initialize the state with the key */
    mask_input(state[0], 0);
    mask_input(state[1], 0);
    mask_input(state[2], 0);
    mask_input(state[3], 0);
    tiny_jambu_permutation_masked(state, key, key_words, rounds);

    /* Absorb the three 32-bit words of the 96-bit nonce */
    mask_xor_const(state[1], 0x10); /* Domain separator for the nonce */
    tiny_jambu_permutation_masked
        (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
    mask_xor_const(state[3], le_load_word32(nonce));
    mask_xor_const(state[1], 0x10);
    tiny_jambu_permutation_masked
        (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
    mask_xor_const(state[3], le_load_word32(nonce + 4));
    mask_xor_const(state[1], 0x10);
    tiny_jambu_permutation_masked
        (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
    mask_xor_const(state[3], le_load_word32(nonce + 8));
}

/**
 * \brief Processes the associated data for masked TinyJAMBU.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the masked key words.
 * \param key_words The number of words in the masked key.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void tiny_jambu_process_ad_masked
    (mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE],
     const mask_uint32_t *key, unsigned key_words,
     const unsigned char *ad, unsigned long long adlen)
{
    /* Process as many full 32-bit words as we can */
    while (adlen >= 4) {
        mask_xor_const(state[1], 0x30); /* Domain separator for associated data */
        tiny_jambu_permutation_masked
            (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
        mask_xor_const(state[3], le_load_word32(ad));
        ad += 4;
        adlen -= 4;
    }

    /* Handle the left-over associated data bytes, if any */
    if (adlen == 1) {
        mask_xor_const(state[1], 0x30);
        tiny_jambu_permutation_masked
            (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
        mask_xor_const(state[3], ad[0]);
        mask_xor_const(state[1], 0x01);
    } else if (adlen == 2) {
        mask_xor_const(state[1], 0x30);
        tiny_jambu_permutation_masked
            (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
        mask_xor_const(state[3], le_load_word16(ad));
        mask_xor_const(state[1], 0x02);
    } else if (adlen == 3) {
        mask_xor_const(state[1], 0x30);
        tiny_jambu_permutation_masked
            (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
        mask_xor_const
            (state[3], le_load_word16(ad) | (((uint32_t)(ad[2])) << 16));
        mask_xor_const(state[1], 0x03);
    }
}

/**
 * \brief Encrypts the plaintext with TinyJAMBU to produce the ciphertext.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the masked key words.
 * \param key_words The number of words in the masked key.
 * \param rounds The number of rounds to perform to process the plaintext.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param mlen Length of the plaintext in bytes.
 */
static void tiny_jambu_encrypt_masked
    (mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE],
     const mask_uint32_t *key, unsigned key_words,
     unsigned rounds, unsigned char *c,
     const unsigned char *m, unsigned long long mlen)
{
    uint32_t data;

    /* Process as many full 32-bit words as we can */
    while (mlen >= 4) {
        mask_xor_const(state[1], 0x50); /* Domain separator for message data */
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = le_load_word32(m);
        mask_xor_const(state[3], data);
        data ^= mask_output(state[2]);
        le_store_word32(c, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }

    /* Handle the left-over plaintext data bytes, if any */
    if (mlen == 1) {
        mask_xor_const(state[1], 0x50);
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = m[0];
        mask_xor_const(state[3], data);
        mask_xor_const(state[1], 0x01);
        c[0] = (uint8_t)(mask_output(state[2]) ^ data);
    } else if (mlen == 2) {
        mask_xor_const(state[1], 0x50);
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = le_load_word16(m);
        mask_xor_const(state[3], data);
        mask_xor_const(state[1], 0x02);
        data ^= mask_output(state[2]);
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        mask_xor_const(state[1], 0x50);
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = le_load_word16(m) | (((uint32_t)(m[2])) << 16);
        mask_xor_const(state[3], data);
        mask_xor_const(state[1], 0x03);
        data ^= mask_output(state[2]);
        c[0] = (uint8_t)data;
        c[1] = (uint8_t)(data >> 8);
        c[2] = (uint8_t)(data >> 16);
    }
}

/**
 * \brief Decrypts the ciphertext with TinyJAMBU to produce the plaintext.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the masked key words.
 * \param key_words The number of words in the masked key.
 * \param rounds The number of rounds to perform to process the ciphertext.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param mlen Length of the plaintext in bytes.
 */
static void tiny_jambu_decrypt_masked
    (mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE],
     const mask_uint32_t *key, unsigned key_words,
     unsigned rounds, unsigned char *m,
     const unsigned char *c, unsigned long long mlen)
{
    uint32_t data;

    /* Process as many full 32-bit words as we can */
    while (mlen >= 4) {
        mask_xor_const(state[1], 0x50); /* Domain separator for message data */
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = le_load_word32(c) ^ mask_output(state[2]);
        mask_xor_const(state[3], data);
        le_store_word32(m, data);
        c += 4;
        m += 4;
        mlen -= 4;
    }

    /* Handle the left-over ciphertext data bytes, if any */
    if (mlen == 1) {
        mask_xor_const(state[1], 0x50);
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = (c[0] ^ mask_output(state[2])) & 0xFFU;
        mask_xor_const(state[3], data);
        mask_xor_const(state[1], 0x01);
        m[0] = (uint8_t)data;
    } else if (mlen == 2) {
        mask_xor_const(state[1], 0x50);
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = (le_load_word16(c) ^ mask_output(state[2])) & 0xFFFFU;
        mask_xor_const(state[3], data);
        mask_xor_const(state[1], 0x02);
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
    } else if (mlen == 3) {
        mask_xor_const(state[1], 0x50);
        tiny_jambu_permutation_masked(state, key, key_words, rounds);
        data = le_load_word16(c) | (((uint32_t)(c[2])) << 16);
        data = (data ^ mask_output(state[2])) & 0xFFFFFFU;
        mask_xor_const(state[3], data);
        mask_xor_const(state[1], 0x03);
        m[0] = (uint8_t)data;
        m[1] = (uint8_t)(data >> 8);
        m[2] = (uint8_t)(data >> 16);
    }
}

/**
 * \brief Generates the final authentication tag for masked TinyJAMBU.
 *
 * \param state TinyJAMBU state to be permuted.
 * \param key Points to the masked key words.
 * \param key_words The number of words in the masked key.
 * \param rounds The number of rounds to perform to generate the tag.
 * \param tag Buffer to receive the tag.
 */
static void tiny_jambu_generate_tag_masked
    (mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE],
     const mask_uint32_t *key, unsigned key_words,
     unsigned rounds, unsigned char *tag)
{
    mask_xor_const(state[1], 0x70); /* Domain separator for finalization */
    tiny_jambu_permutation_masked(state, key, key_words, rounds);
    le_store_word32(tag, mask_output(state[2]));
    mask_xor_const(state[1], 0x70);
    tiny_jambu_permutation_masked
        (state, key, key_words, TINYJAMBU_MASKED_ROUNDS(384));
    le_store_word32(tag + 4, mask_output(state[2]));
}

int tiny_jambu_128_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t key[4];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINY_JAMBU_MASKED_TAG_SIZE;

    /* Unpack the key */
    mask_input(key[0], le_load_word32(k));
    mask_input(key[1], le_load_word32(k + 4));
    mask_input(key[2], le_load_word32(k + 8));
    mask_input(key[3], le_load_word32(k + 12));

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_masked
        (state, key, 4, TINYJAMBU_MASKED_ROUNDS(1024), npub);
    tiny_jambu_process_ad_masked(state, key, 4, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    tiny_jambu_encrypt_masked
        (state, key, 4, TINYJAMBU_MASKED_ROUNDS(1024), c, m, mlen);

    /* Generate the authentication tag */
    tiny_jambu_generate_tag_masked
        (state, key, 4, TINYJAMBU_MASKED_ROUNDS(1024), c + mlen);
    return 0;
}

int tiny_jambu_128_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t key[4];
    unsigned char tag[TINY_JAMBU_MASKED_TAG_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINY_JAMBU_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - TINY_JAMBU_MASKED_TAG_SIZE;

    /* Unpack the key */
    mask_input(key[0], le_load_word32(k));
    mask_input(key[1], le_load_word32(k + 4));
    mask_input(key[2], le_load_word32(k + 8));
    mask_input(key[3], le_load_word32(k + 12));

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_masked
        (state, key, 4, TINYJAMBU_MASKED_ROUNDS(1024), npub);
    tiny_jambu_process_ad_masked(state, key, 4, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    tiny_jambu_decrypt_masked
        (state, key, 4, TINYJAMBU_MASKED_ROUNDS(1024), m, c, *mlen);

    /* Check the authentication tag */
    tiny_jambu_generate_tag_masked
        (state, key, 4, TINYJAMBU_MASKED_ROUNDS(1024), tag);
    return aead_check_tag(m, *mlen, tag, c + *mlen, TINY_JAMBU_MASKED_TAG_SIZE);
}

int tiny_jambu_192_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t key[12];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINY_JAMBU_MASKED_TAG_SIZE;

    /* Unpack the key and duplicate it to make the length a multiple of 4 */
    mask_input(key[0],  le_load_word32(k));
    mask_input(key[1],  le_load_word32(k + 4));
    mask_input(key[2],  le_load_word32(k + 8));
    mask_input(key[3],  le_load_word32(k + 12));
    mask_input(key[4],  le_load_word32(k + 16));
    mask_input(key[5],  le_load_word32(k + 20));
    mask_input(key[6],  le_load_word32(k));
    mask_input(key[7],  le_load_word32(k + 4));
    mask_input(key[8],  le_load_word32(k + 8));
    mask_input(key[9],  le_load_word32(k + 12));
    mask_input(key[10], le_load_word32(k + 16));
    mask_input(key[11], le_load_word32(k + 20));

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_masked
        (state, key, 12, TINYJAMBU_MASKED_ROUNDS(1152), npub);
    tiny_jambu_process_ad_masked(state, key, 12, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    tiny_jambu_encrypt_masked
        (state, key, 12, TINYJAMBU_MASKED_ROUNDS(1152), c, m, mlen);

    /* Generate the authentication tag */
    tiny_jambu_generate_tag_masked
        (state, key, 12, TINYJAMBU_MASKED_ROUNDS(1152), c + mlen);
    return 0;
}

int tiny_jambu_192_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t key[12];
    unsigned char tag[TINY_JAMBU_MASKED_TAG_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINY_JAMBU_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - TINY_JAMBU_MASKED_TAG_SIZE;

    /* Unpack the key and duplicate it to make the length a multiple of 4 */
    mask_input(key[0],  le_load_word32(k));
    mask_input(key[1],  le_load_word32(k + 4));
    mask_input(key[2],  le_load_word32(k + 8));
    mask_input(key[3],  le_load_word32(k + 12));
    mask_input(key[4],  le_load_word32(k + 16));
    mask_input(key[5],  le_load_word32(k + 20));
    mask_input(key[6],  le_load_word32(k));
    mask_input(key[7],  le_load_word32(k + 4));
    mask_input(key[8],  le_load_word32(k + 8));
    mask_input(key[9],  le_load_word32(k + 12));
    mask_input(key[10], le_load_word32(k + 16));
    mask_input(key[11], le_load_word32(k + 20));

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_masked
        (state, key, 12, TINYJAMBU_MASKED_ROUNDS(1152), npub);
    tiny_jambu_process_ad_masked(state, key, 12, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    tiny_jambu_decrypt_masked
        (state, key, 12, TINYJAMBU_MASKED_ROUNDS(1152), m, c, *mlen);

    /* Check the authentication tag */
    tiny_jambu_generate_tag_masked
        (state, key, 12, TINYJAMBU_MASKED_ROUNDS(1152), tag);
    return aead_check_tag(m, *mlen, tag, c + *mlen, TINY_JAMBU_MASKED_TAG_SIZE);
}

int tiny_jambu_256_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t key[8];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + TINY_JAMBU_MASKED_TAG_SIZE;

    /* Unpack the key */
    mask_input(key[0], le_load_word32(k));
    mask_input(key[1], le_load_word32(k + 4));
    mask_input(key[2], le_load_word32(k + 8));
    mask_input(key[3], le_load_word32(k + 12));
    mask_input(key[4], le_load_word32(k + 16));
    mask_input(key[5], le_load_word32(k + 20));
    mask_input(key[6], le_load_word32(k + 24));
    mask_input(key[7], le_load_word32(k + 28));

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_masked
        (state, key, 8, TINYJAMBU_MASKED_ROUNDS(1280), npub);
    tiny_jambu_process_ad_masked(state, key, 8, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    tiny_jambu_encrypt_masked
        (state, key, 8, TINYJAMBU_MASKED_ROUNDS(1280), c, m, mlen);

    /* Generate the authentication tag */
    tiny_jambu_generate_tag_masked
        (state, key, 8, TINYJAMBU_MASKED_ROUNDS(1280), c + mlen);
    return 0;
}

int tiny_jambu_256_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[TINY_JAMBU_MASKED_STATE_SIZE];
    mask_uint32_t key[8];
    unsigned char tag[TINY_JAMBU_MASKED_TAG_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < TINY_JAMBU_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - TINY_JAMBU_MASKED_TAG_SIZE;

    /* Unpack the key */
    mask_input(key[0], le_load_word32(k));
    mask_input(key[1], le_load_word32(k + 4));
    mask_input(key[2], le_load_word32(k + 8));
    mask_input(key[3], le_load_word32(k + 12));
    mask_input(key[4], le_load_word32(k + 16));
    mask_input(key[5], le_load_word32(k + 20));
    mask_input(key[6], le_load_word32(k + 24));
    mask_input(key[7], le_load_word32(k + 28));

    /* Set up the TinyJAMBU state with the key, nonce, and associated data */
    tiny_jambu_setup_masked
        (state, key, 8, TINYJAMBU_MASKED_ROUNDS(1280), npub);
    tiny_jambu_process_ad_masked(state, key, 8, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    tiny_jambu_decrypt_masked
        (state, key, 8, TINYJAMBU_MASKED_ROUNDS(1280), m, c, *mlen);

    /* Check the authentication tag */
    tiny_jambu_generate_tag_masked
        (state, key, 8, TINYJAMBU_MASKED_ROUNDS(1280), tag);
    return aead_check_tag(m, *mlen, tag, c + *mlen, TINY_JAMBU_MASKED_TAG_SIZE);
}
