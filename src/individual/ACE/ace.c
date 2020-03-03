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

#include "ace.h"
#include "internal-sliscp-light.h"
#include "internal-util.h"
#include <string.h>

/**
 * \brief Size of the state for the internal ACE permutation.
 */
#define ACE_STATE_SIZE SLISCP_LIGHT320_STATE_SIZE

/**
 * \brief Rate for absorbing data into the ACE state and for
 * squeezing data out again.
 */
#define ACE_RATE 8

aead_cipher_t const ace_cipher = {
    "ACE",
    ACE_KEY_SIZE,
    ACE_NONCE_SIZE,
    ACE_TAG_SIZE,
    AEAD_FLAG_NONE,
    ace_aead_encrypt,
    ace_aead_decrypt
};

aead_hash_algorithm_t const ace_hash_algorithm = {
    "ACE-HASH",
    sizeof(ace_hash_state_t),
    ACE_HASH_SIZE,
    AEAD_FLAG_NONE,
    ace_hash,
    (aead_hash_init_t)ace_hash_init,
    (aead_hash_update_t)ace_hash_update,
    (aead_hash_finalize_t)ace_hash_finalize,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/* Indices of where a rate byte is located in the state.  We don't
 * need this array any more because sliscp_light320_permute() operates
 * on byte-swapped states where the rate bytes are contiguous in the
 * first 8 bytes */
/*
static unsigned char const ace_rate_posn[8] = {
    0, 1, 2, 3, 16, 17, 18, 19
};
*/

/**
 * \brief Initializes the ACE state.
 *
 * \param state ACE permutation state.
 * \param k Points to the 128-bit key.
 * \param npub Points to the 128-bit nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void ace_init
    (unsigned char state[ACE_STATE_SIZE],
     const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned temp;

    /* Initialize the state by interleaving the key and nonce */
    memcpy(state, k, 8);
    memcpy(state + 8, npub, 8);
    memcpy(state + 16, k + 8, 8);
    memset(state + 24, 0, 8);
    memcpy(state + 32, npub + 8, 8);

    /* Swap some of the state bytes to make the rate bytes contiguous */
    sliscp_light320_swap(state);

    /* Run the permutation to scramble the initial state */
    sliscp_light320_permute(state);

    /* Absorb the key in two further permutation operations */
    lw_xor_block(state, k, 8);
    sliscp_light320_permute(state);
    lw_xor_block(state, k + 8, 8);
    sliscp_light320_permute(state);

    /* Absorb the associated data into the state */
    if (adlen != 0) {
        while (adlen >= ACE_RATE) {
            lw_xor_block(state, ad, ACE_RATE);
            state[ACE_STATE_SIZE - 1] ^= 0x01; /* domain separation */
            sliscp_light320_permute(state);
            ad += ACE_RATE;
            adlen -= ACE_RATE;
        }
        temp = (unsigned)adlen;
        lw_xor_block(state, ad, temp);
        state[temp] ^= 0x80; /* padding */
        state[ACE_STATE_SIZE - 1] ^= 0x01; /* domain separation */
        sliscp_light320_permute(state);
    }
}

/**
 * \brief Finalizes the ACE encryption or decryption operation.
 *
 * \param state ACE permutation state.
 * \param k Points to the 128-bit key.
 * \param tag Points to the 16 byte buffer to receive the computed tag.
 */
static void ace_finalize
    (unsigned char state[ACE_STATE_SIZE], const unsigned char *k,
     unsigned char *tag)
{
    /* Absorb the key into the state again */
    lw_xor_block(state, k, 8);
    sliscp_light320_permute(state);
    lw_xor_block(state, k + 8, 8);
    sliscp_light320_permute(state);

    /* Swap the state bytes back to the canonical order */
    sliscp_light320_swap(state);

    /* Copy out the authentication tag */
    memcpy(tag, state, 8);
    memcpy(tag + 8, state + 16, 8);
}

int ace_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[ACE_STATE_SIZE];
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ACE_TAG_SIZE;

    /* Initialize the ACE state and absorb the associated data */
    ace_init(state, k, npub, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= ACE_RATE) {
        lw_xor_block_2_dest(c, state, m, ACE_RATE);
        state[ACE_STATE_SIZE - 1] ^= 0x02; /* domain separation */
        sliscp_light320_permute(state);
        c += ACE_RATE;
        m += ACE_RATE;
        mlen -= ACE_RATE;
    }
    temp = (unsigned)mlen;
    lw_xor_block_2_dest(c, state, m, temp);
    state[temp] ^= 0x80; /* padding */
    state[ACE_STATE_SIZE - 1] ^= 0x02; /* domain separation */
    sliscp_light320_permute(state);
    c += mlen;

    /* Generate the authentication tag */
    ace_finalize(state, k, c);
    return 0;
}

int ace_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char state[ACE_STATE_SIZE];
    unsigned char *mtemp = m;
    unsigned temp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ACE_TAG_SIZE)
        return -1;
    *mlen = clen - ACE_TAG_SIZE;

    /* Initialize the ACE state and absorb the associated data */
    ace_init(state, k, npub, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= ACE_TAG_SIZE;
    while (clen >= ACE_RATE) {
        lw_xor_block_swap(m, state, c, ACE_RATE);
        state[ACE_STATE_SIZE - 1] ^= 0x02; /* domain separation */
        sliscp_light320_permute(state);
        c += ACE_RATE;
        m += ACE_RATE;
        clen -= ACE_RATE;
    }
    temp = (unsigned)clen;
    lw_xor_block_swap(m, state, c, temp);
    state[temp] ^= 0x80; /* padding */
    state[ACE_STATE_SIZE - 1] ^= 0x02; /* domain separation */
    sliscp_light320_permute(state);
    c += clen;

    /* Finalize the ACE state and compare against the authentication tag */
    ace_finalize(state, k, state);
    return aead_check_tag(mtemp, *mlen, state, c, ACE_TAG_SIZE);
}

/* Pre-hashed version of the ACE-HASH initialization vector */
static unsigned char const ace_hash_iv[ACE_STATE_SIZE] = {
    0xb9, 0x7d, 0xda, 0x3f, 0x66, 0x2c, 0xd1, 0xa6,
    0x65, 0xd1, 0x80, 0xd6, 0x49, 0xdc, 0xa1, 0x8c,
    0x0c, 0x5f, 0x0e, 0xca, 0x70, 0x37, 0x58, 0x75,
    0x29, 0x7d, 0xb0, 0xb0, 0x72, 0x73, 0xce, 0xa8,
    0x99, 0x71, 0xde, 0x8a, 0x9a, 0x65, 0x72, 0x24
};

int ace_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char state[ACE_STATE_SIZE];
    unsigned temp;

    /* Load the initialization vector and hash it, which can be pre-computed */
    /*
    memset(state, 0, sizeof(state));
    state[8]  = 0x80;
    state[9]  = 0x40;
    state[10] = 0x40;
    sliscp_light320_swap(state);
    sliscp_light320_permute(state);
    */
    memcpy(state, ace_hash_iv, ACE_STATE_SIZE);

    /* Absorb the input data */
    while (inlen >= ACE_RATE) {
        lw_xor_block(state, in, ACE_RATE);
        sliscp_light320_permute(state);
        in += ACE_RATE;
        inlen -= ACE_RATE;
    }
    temp = (unsigned)inlen;
    lw_xor_block(state, in, temp);
    state[temp] ^= 0x80; /* padding */
    sliscp_light320_permute(state);

    /* Squeeze out the hash value */
    memcpy(out, state, 8);
    for (temp = 0; temp < 3; ++temp) {
        out += 8;
        sliscp_light320_permute(state);
        memcpy(out, state, 8);
    }
    return 0;
}

void ace_hash_init(ace_hash_state_t *state)
{
    memcpy(state->s.state, ace_hash_iv, ACE_STATE_SIZE);
    state->s.count = 0;
}

void ace_hash_update
    (ace_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    unsigned len;

    /* Handle the left-over rate block from last time */
    if (state->s.count != 0) {
        len = ACE_RATE - state->s.count;
        if (len > inlen)
            len = (unsigned)inlen;
        lw_xor_block(state->s.state + state->s.count, in, len);
        in += len;
        inlen -= len;
        state->s.count += len;
        if (state->s.count >= ACE_RATE) {
            sliscp_light320_permute(state->s.state);
            state->s.count = 0;
        } else {
            /* Not enough input data yet to fill up the whole block */
            return;
        }
    }

    /* Process as many full rate blocks as we can */
    while (inlen >= ACE_RATE) {
        lw_xor_block(state->s.state, in, ACE_RATE);
        sliscp_light320_permute(state->s.state);
        in += ACE_RATE;
        inlen -= ACE_RATE;
    }

    /* Handle any left-over data */
    len = (unsigned)inlen;
    lw_xor_block(state->s.state, in, len);
    state->s.count = len;
}

void ace_hash_finalize(ace_hash_state_t *state, unsigned char *out)
{
    unsigned temp;

    /* Pad and hash the final input block */
    state->s.state[state->s.count] ^= 0x80;
    sliscp_light320_permute(state->s.state);
    state->s.count = 0;

    /* Squeeze out the hash value */
    memcpy(out, state->s.state, 9);
    for (temp = 0; temp < 3; ++temp) {
        out += 8;
        sliscp_light320_permute(state->s.state);
        memcpy(out, state->s.state, 8);
    }
}
