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

#include "orange.h"
#include "internal-photon256.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const orange_zest_cipher = {
    "ORANGE-Zest",
    ORANGE_ZEST_KEY_SIZE,
    ORANGE_ZEST_NONCE_SIZE,
    ORANGE_ZEST_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    orange_zest_aead_encrypt,
    orange_zest_aead_decrypt
};

aead_hash_algorithm_t const orangish_hash_algorithm = {
    "ORANGISH",
    sizeof(int),
    ORANGISH_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    orangish_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \brief Doubles a block in the GF(128) field a number of times.
 *
 * \param block The block to be doubled.
 * \param value The number of times to double the block.
 */
static void orange_block_double(unsigned char block[16], unsigned char value)
{
    unsigned index;
    unsigned char mask;
    while (value > 0) {
        mask = (unsigned char)(((signed char)(block[15])) >> 7);
        for (index = 15; index > 0; --index)
            block[index] = (block[index] << 1) | (block[index - 1] >> 7);
        block[0] = (block[0] << 1) ^ (mask & 0x87);
        --value;
    }
}

/**
 * \brief Rotates a block left by 1 bit.
 *
 * \param out The output block to be set to the rotated version.
 * \param in The input block to be rotated, must not overlap with \a out.
 */
static void orange_block_rotate
    (unsigned char out[16], const unsigned char in[16])
{
    unsigned index;
    for (index = 15; index > 0; --index)
        out[index] = (in[index] << 1) | (in[index - 1] >> 7);
    out[0] = (in[0] << 1) | (in[15] >> 7);
}

/**
 * \brief Hash input data with ORANGE.
 *
 * \param state PHOTON-256 permutation state.
 * \param data Points to the data to be hashed.
 * \param len Length of the data to be hashed, must not be zero.
 * \param domain0 Domain separation value for full last block.
 * \param domain1 Domain separation value for partial last block.
 */
static void orange_process_hash
    (unsigned char state[PHOTON256_STATE_SIZE],
     const unsigned char *data, unsigned long long len,
     unsigned char domain0, unsigned char domain1)
{
    unsigned temp;
    while (len > PHOTON256_STATE_SIZE) {
        photon256_permute(state);
        lw_xor_block(state, data, PHOTON256_STATE_SIZE);
        data += PHOTON256_STATE_SIZE;
        len -= PHOTON256_STATE_SIZE;
    }
    photon256_permute(state);
    temp = (unsigned)len;
    if (temp < PHOTON256_STATE_SIZE) {
        orange_block_double(state + 16, domain1);
        state[temp] ^= 0x01; /* padding */
    } else {
        orange_block_double(state + 16, domain0);
    }
    lw_xor_block(state, data, temp);
}

/**
 * \brief Applies the rho function to the ORANGE state.
 *
 * \param KS Output keystream to use to encrypt the plaintext or to
 * decrypt the ciphertext.
 * \param S Rolling key state.
 * \param state Rolling PHOTON-256 permutation state.
 */
static void orange_rho
    (unsigned char KS[32], unsigned char S[16], const unsigned char state[32])
{
    orange_block_double(S, 1);
    orange_block_rotate(KS, state);
    lw_xor_block_2_src(KS + 16, state + 16, S, 16);
    memcpy(S, state + 16, 16);
}

/**
 * \brief Encrypts plaintext with ORANGE.
 *
 * \param state PHOTON-256 permutation state.
 * \param k Points to the key for the cipher.
 * \param c Points to the ciphertext output buffer.
 * \param m Points to the plaintext input buffer.
 * \param len Length of the plaintext in bytes, must not be zero.
 */
static void orange_encrypt
    (unsigned char state[PHOTON256_STATE_SIZE], const unsigned char *k,
     unsigned char *c, const unsigned char *m, unsigned long long len)
{
    unsigned char S[ORANGE_ZEST_KEY_SIZE];
    unsigned char KS[PHOTON256_STATE_SIZE];
    unsigned temp;
    memcpy(S, k, ORANGE_ZEST_KEY_SIZE);
    while (len > PHOTON256_STATE_SIZE) {
        photon256_permute(state);
        orange_rho(KS, S, state);
        lw_xor_block_2_src(c, m, KS, PHOTON256_STATE_SIZE);
        lw_xor_block(state, c, PHOTON256_STATE_SIZE);
        c += PHOTON256_STATE_SIZE;
        m += PHOTON256_STATE_SIZE;
        len -= PHOTON256_STATE_SIZE;
    }
    photon256_permute(state);
    temp = (unsigned)len;
    if (temp < PHOTON256_STATE_SIZE) {
        orange_block_double(state + 16, 2);
        orange_rho(KS, S, state);
        lw_xor_block_2_src(c, m, KS, temp);
        lw_xor_block(state, c, temp);
        state[temp] ^= 0x01; /* padding */
    } else {
        orange_block_double(state + 16, 1);
        orange_rho(KS, S, state);
        lw_xor_block_2_src(c, m, KS, PHOTON256_STATE_SIZE);
        lw_xor_block(state, c, PHOTON256_STATE_SIZE);
    }
}

/**
 * \brief Decrypts ciphertext with ORANGE.
 *
 * \param state PHOTON-256 permutation state.
 * \param k Points to the key for the cipher.
 * \param m Points to the plaintext output buffer.
 * \param c Points to the ciphertext input buffer.
 * \param len Length of the plaintext in bytes, must not be zero.
 */
static void orange_decrypt
    (unsigned char state[PHOTON256_STATE_SIZE], const unsigned char *k,
     unsigned char *m, const unsigned char *c, unsigned long long len)
{
    unsigned char S[ORANGE_ZEST_KEY_SIZE];
    unsigned char KS[PHOTON256_STATE_SIZE];
    unsigned temp;
    memcpy(S, k, ORANGE_ZEST_KEY_SIZE);
    while (len > PHOTON256_STATE_SIZE) {
        photon256_permute(state);
        orange_rho(KS, S, state);
        lw_xor_block(state, c, PHOTON256_STATE_SIZE);
        lw_xor_block_2_src(m, c, KS, PHOTON256_STATE_SIZE);
        c += PHOTON256_STATE_SIZE;
        m += PHOTON256_STATE_SIZE;
        len -= PHOTON256_STATE_SIZE;
    }
    photon256_permute(state);
    temp = (unsigned)len;
    if (temp < PHOTON256_STATE_SIZE) {
        orange_block_double(state + 16, 2);
        orange_rho(KS, S, state);
        lw_xor_block(state, c, temp);
        lw_xor_block_2_src(m, c, KS, temp);
        state[temp] ^= 0x01; /* padding */
    } else {
        orange_block_double(state + 16, 1);
        orange_rho(KS, S, state);
        lw_xor_block(state, c, PHOTON256_STATE_SIZE);
        lw_xor_block_2_src(m, c, KS, PHOTON256_STATE_SIZE);
    }
}

/**
 * \brief Generates the authentication tag for ORANGE-Zest.
 *
 * \param state PHOTON-256 permutation state.
 *
 * The tag will be left in the leading bytes of the state on exit.
 */
static void orange_generate_tag(unsigned char state[PHOTON256_STATE_SIZE])
{
    /* Swap the two halves of the state and run the permutation again */
    unsigned posn;
    for (posn = 0; posn < (PHOTON256_STATE_SIZE / 2); ++posn) {
        unsigned char temp = state[posn];
        state[posn] = state[posn + (PHOTON256_STATE_SIZE / 2)];
        state[posn + (PHOTON256_STATE_SIZE / 2)] = temp;
    }
    photon256_permute(state);
}

int orange_zest_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ORANGE_ZEST_TAG_SIZE;

    /* Initialize the PHOTON-256 state with the nonce and key */
    memcpy(state, npub, 16);
    memcpy(state + 16, k, 16);

    /* Handle the associated data and message payload */
    if (adlen == 0) {
        if (mlen == 0) {
            state[16] ^= 2; /* domain separation */
            photon256_permute(state);
            memcpy(c + mlen, state, ORANGE_ZEST_TAG_SIZE);
            return 0;
        } else {
            state[16] ^= 1; /* domain separation */
            orange_encrypt(state, k, c, m, mlen);
        }
    } else {
        orange_process_hash(state, ad, adlen, 1, 2);
        if (mlen != 0)
            orange_encrypt(state, k, c, m, mlen);
    }

    /* Generate the authentication tag */
    orange_generate_tag(state);
    memcpy(c + mlen, state, ORANGE_ZEST_TAG_SIZE);
    return 0;
}

int orange_zest_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ORANGE_ZEST_TAG_SIZE)
        return -1;
    *mlen = clen - ORANGE_ZEST_TAG_SIZE;

    /* Initialize the PHOTON-256 state with the nonce and key */
    memcpy(state, npub, 16);
    memcpy(state + 16, k, 16);

    /* Handle the associated data and message payload */
    clen -= ORANGE_ZEST_TAG_SIZE;
    if (adlen == 0) {
        if (clen == 0) {
            state[16] ^= 2; /* domain separation */
            photon256_permute(state);
            return aead_check_tag(m, 0, state, c, ORANGE_ZEST_TAG_SIZE);
        } else {
            state[16] ^= 1; /* domain separation */
            orange_decrypt(state, k, m, c, clen);
        }
    } else {
        orange_process_hash(state, ad, adlen, 1, 2);
        if (clen != 0)
            orange_decrypt(state, k, m, c, clen);
    }

    /* Check the authentication tag */
    orange_generate_tag(state);
    return aead_check_tag(m, clen, state, c + clen, ORANGE_ZEST_TAG_SIZE);
}

/**
 * \brief Rate of absorbing data into the ORANGISH hash state.
 */
#define ORANGISH_RATE 16

int orangish_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char state[PHOTON256_STATE_SIZE];
    unsigned temp;
    memset(state, 0, sizeof(state));
    if (inlen == 0) {
        /* No absorption necessary for a zero-length input */
    } else if (inlen < ORANGISH_RATE) {
        /* Single partial block */
        temp = (unsigned)inlen;
        memcpy(state, in, temp);
        state[temp] ^= 0x01; /* padding */
        photon256_permute(state);
        lw_xor_block(state + 16, in, temp);
        state[16 + temp] ^= 0x01; /* padding */
        state[0] ^= 0x02; /* domain separation */
    } else if (inlen == ORANGISH_RATE) {
        /* Single full block */
        memcpy(state, in, ORANGISH_RATE);
        photon256_permute(state);
        lw_xor_block(state + 16, in, ORANGISH_RATE);
        state[0] ^= 0x01; /* domain separation */
    } else {
        /* Process double blocks until we run out */
        memcpy(state, in, ORANGISH_RATE);
        photon256_permute(state);
        lw_xor_block(state + 16, in, ORANGISH_RATE);
        in += ORANGISH_RATE;
        inlen -= ORANGISH_RATE;
        while (inlen > ORANGISH_RATE) {
            lw_xor_block(state, in, ORANGISH_RATE);
            photon256_permute(state);
            lw_xor_block(state + 16, in, ORANGISH_RATE);
            in += ORANGISH_RATE;
            inlen -= ORANGISH_RATE;
        }
        temp = (unsigned)inlen;
        if (temp < ORANGISH_RATE) {
            /* Last double block is partial */
            lw_xor_block(state, in, temp);
            state[temp] ^= 0x01; /* padding */
            photon256_permute(state);
            lw_xor_block(state + 16, in, temp);
            state[16 + temp] ^= 0x01; /* padding */
            state[0] ^= 0x02; /* domain separation */
        } else {
            /* Last double block is full */
            lw_xor_block(state, in, ORANGISH_RATE);
            photon256_permute(state);
            lw_xor_block(state + 16, in, ORANGISH_RATE);
            state[0] ^= 0x01; /* domain separation */
        }
    }
    photon256_permute(state);
    memcpy(out, state, 16);
    photon256_permute(state);
    memcpy(out + 16, state, 16);
    return 0;
}
