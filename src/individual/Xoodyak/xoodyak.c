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

#include "xoodyak.h"
#include "internal-xoodoo.h"
#include <string.h>

aead_cipher_t const xoodyak_cipher = {
    "Xoodyak",
    XOODYAK_KEY_SIZE,
    XOODYAK_NONCE_SIZE,
    XOODYAK_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    xoodyak_aead_encrypt,
    xoodyak_aead_decrypt
};

aead_hash_algorithm_t const xoodyak_hash_algorithm = {
    "Xoodyak-Hash",
    sizeof(xoodyak_hash_state_t),
    XOODYAK_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    xoodyak_hash,
    (aead_hash_init_t)xoodyak_hash_init,
    (aead_hash_update_t)xoodyak_hash_absorb,
    (aead_hash_finalize_t)xoodyak_hash_finalize,
    (aead_xof_absorb_t)xoodyak_hash_absorb,
    (aead_xof_squeeze_t)xoodyak_hash_squeeze
};

/**
 * \brief Rate for absorbing data into the sponge state.
 */
#define XOODYAK_ABSORB_RATE 44

/**
 * \brief Rate for squeezing data out of the sponge.
 */
#define XOODYAK_SQUEEZE_RATE 24

/**
 * \brief Rate for absorbing and squeezing in hashing mode.
 */
#define XOODYAK_HASH_RATE 16

/**
 * \brief Phase identifier for "up" mode, which indicates that a block
 * permutation has just been performed.
 */
#define XOODYAK_PHASE_UP 0

/**
 * \brief Phase identifier for "down" mode, which indicates that data has
 * been absorbed but that a block permutation has not been done yet.
 */
#define XOODYAK_PHASE_DOWN 1

/**
 * \brief Absorbs data into the Xoodoo permutation state.
 *
 * \param state Xoodoo permutation state.
 * \param phase Points to the current phase, up or down.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 */
static void xoodyak_absorb
    (xoodoo_state_t *state, uint8_t *phase,
     const unsigned char *data, unsigned long long len)
{
    uint8_t domain = 0x03;
    unsigned temp;
    while (len > XOODYAK_ABSORB_RATE) {
        if (*phase != XOODYAK_PHASE_UP)
            xoodoo_permute(state);
        lw_xor_block(state->B, data, XOODYAK_ABSORB_RATE);
        state->B[XOODYAK_ABSORB_RATE] ^= 0x01; /* Padding */
        state->B[sizeof(state->B) - 1] ^= domain;
        data += XOODYAK_ABSORB_RATE;
        len -= XOODYAK_ABSORB_RATE;
        domain = 0x00;
        *phase = XOODYAK_PHASE_DOWN;
    }
    temp = (unsigned)len;
    if (*phase != XOODYAK_PHASE_UP)
        xoodoo_permute(state);
    lw_xor_block(state->B, data, temp);
    state->B[temp] ^= 0x01; /* Padding */
    state->B[sizeof(state->B) - 1] ^= domain;
    *phase = XOODYAK_PHASE_DOWN;
}

int xoodyak_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t phase, domain;
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + XOODYAK_TAG_SIZE;

    /* Initialize the state with the key */
    memcpy(state.B, k, XOODYAK_KEY_SIZE);
    memset(state.B + XOODYAK_KEY_SIZE, 0, sizeof(state.B) - XOODYAK_KEY_SIZE);
    state.B[XOODYAK_KEY_SIZE + 1] = 0x01; /* Padding */
    state.B[sizeof(state.B) - 1] = 0x02;  /* Domain separation */
    phase = XOODYAK_PHASE_DOWN;

    /* Absorb the nonce and associated data */
    xoodyak_absorb(&state, &phase, npub, XOODYAK_NONCE_SIZE);
    xoodyak_absorb(&state, &phase, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    domain = 0x80;
    while (mlen > XOODYAK_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_2_dest(c, state.B, m, XOODYAK_SQUEEZE_RATE);
        state.B[XOODYAK_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_SQUEEZE_RATE;
        m += XOODYAK_SQUEEZE_RATE;
        mlen -= XOODYAK_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)mlen;
    lw_xor_block_2_dest(c, state.B, m, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Generate the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    memcpy(c, state.B, XOODYAK_TAG_SIZE);
    return 0;
}

int xoodyak_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t phase, domain;
    unsigned temp;
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < XOODYAK_TAG_SIZE)
        return -1;
    *mlen = clen - XOODYAK_TAG_SIZE;

    /* Initialize the state with the key */
    memcpy(state.B, k, XOODYAK_KEY_SIZE);
    memset(state.B + XOODYAK_KEY_SIZE, 0, sizeof(state.B) - XOODYAK_KEY_SIZE);
    state.B[XOODYAK_KEY_SIZE + 1] = 0x01; /* Padding */
    state.B[sizeof(state.B) - 1] = 0x02;  /* Domain separation */
    phase = XOODYAK_PHASE_DOWN;

    /* Absorb the nonce and associated data */
    xoodyak_absorb(&state, &phase, npub, XOODYAK_NONCE_SIZE);
    xoodyak_absorb(&state, &phase, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    domain = 0x80;
    clen -= XOODYAK_TAG_SIZE;
    while (clen > XOODYAK_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_swap(m, state.B, c, XOODYAK_SQUEEZE_RATE);
        state.B[XOODYAK_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_SQUEEZE_RATE;
        m += XOODYAK_SQUEEZE_RATE;
        clen -= XOODYAK_SQUEEZE_RATE;
        domain = 0;
    }
    state.B[sizeof(state.B) - 1] ^= domain;
    xoodoo_permute(&state);
    temp = (unsigned)clen;
    lw_xor_block_swap(m, state.B, c, temp);
    state.B[temp] ^= 0x01; /* Padding */
    c += temp;

    /* Check the authentication tag */
    state.B[sizeof(state.B) - 1] ^= 0x40; /* Domain separation */
    xoodoo_permute(&state);
    return aead_check_tag(mtemp, *mlen, state.B, c, XOODYAK_TAG_SIZE);
}

int xoodyak_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    xoodyak_hash_state_t state;
    xoodyak_hash_init(&state);
    xoodyak_hash_absorb(&state, in, inlen);
    xoodyak_hash_squeeze(&state, out, XOODYAK_HASH_SIZE);
    return 0;
}

#define XOODYAK_HASH_MODE_INIT_ABSORB 0
#define XOODYAK_HASH_MODE_ABSORB 1
#define XOODYAK_HASH_MODE_SQUEEZE 2

#define xoodoo_hash_permute(state) \
    xoodoo_permute((xoodoo_state_t *)((state)->s.state))

void xoodyak_hash_init(xoodyak_hash_state_t *state)
{
    memset(state, 0, sizeof(xoodyak_hash_state_t));
    state->s.mode = XOODYAK_HASH_MODE_INIT_ABSORB;
}

void xoodyak_hash_absorb
    (xoodyak_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    uint8_t domain;
    unsigned temp;

    /* If we were squeezing, then restart the absorb phase */
    if (state->s.mode == XOODYAK_HASH_MODE_SQUEEZE) {
        xoodoo_hash_permute(state);
        state->s.mode = XOODYAK_HASH_MODE_INIT_ABSORB;
        state->s.count = 0;
    }

    /* The first block needs a different domain separator to the others */
    domain = (state->s.mode == XOODYAK_HASH_MODE_INIT_ABSORB) ? 0x01 : 0x00;

    /* Absorb the input data into the state */
    while (inlen > 0) {
        if (state->s.count >= XOODYAK_HASH_RATE) {
            state->s.state[XOODYAK_HASH_RATE] ^= 0x01; /* Padding */
            state->s.state[sizeof(state->s.state) - 1] ^= domain;
            xoodoo_hash_permute(state);
            state->s.mode = XOODYAK_HASH_MODE_ABSORB;
            state->s.count = 0;
            domain = 0x00;
        }
        temp = XOODYAK_HASH_RATE - state->s.count;
        if (temp > inlen)
            temp = (unsigned)inlen;
        lw_xor_block(state->s.state + state->s.count, in, temp);
        state->s.count += temp;
        in += temp;
        inlen -= temp;
    }
}

void xoodyak_hash_squeeze
    (xoodyak_hash_state_t *state, unsigned char *out,
     unsigned long long outlen)
{
    uint8_t domain;
    unsigned temp;

    /* If we were absorbing, then terminate the absorb phase */
    if (state->s.mode != XOODYAK_HASH_MODE_SQUEEZE) {
        domain = (state->s.mode == XOODYAK_HASH_MODE_INIT_ABSORB) ? 0x01 : 0x00;
        state->s.state[state->s.count] ^= 0x01; /* Padding */
        state->s.state[sizeof(state->s.state) - 1] ^= domain;
        xoodoo_hash_permute(state);
        state->s.mode = XOODYAK_HASH_MODE_SQUEEZE;
        state->s.count = 0;
    }

    /* Squeeze data out of the state */
    while (outlen > 0) {
        if (state->s.count >= XOODYAK_HASH_RATE) {
            /* Padding is always at index 0 for squeezing subsequent
             * blocks because the number of bytes we have absorbed
             * since the previous block was squeezed out is zero */
            state->s.state[0] ^= 0x01;
            xoodoo_hash_permute(state);
            state->s.count = 0;
        }
        temp = XOODYAK_HASH_RATE - state->s.count;
        if (temp > outlen)
            temp = (unsigned)outlen;
        memcpy(out, state->s.state + state->s.count, temp);
        state->s.count += temp;
        out += temp;
        outlen -= temp;
    }
}

void xoodyak_hash_finalize
    (xoodyak_hash_state_t *state, unsigned char *out)
{
    xoodyak_hash_squeeze(state, out, XOODYAK_HASH_SIZE);
}
