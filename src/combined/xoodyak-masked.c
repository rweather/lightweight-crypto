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

#include "xoodyak-masked.h"
#include "internal-xoodoo.h"
#include "internal-xoodoo-m.h"
#include <string.h>

aead_cipher_t const xoodyak_masked_cipher = {
    "Xoodyak-Masked",
    XOODYAK_MASKED_KEY_SIZE,
    XOODYAK_MASKED_NONCE_SIZE,
    XOODYAK_MASKED_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    xoodyak_masked_aead_encrypt,
    xoodyak_masked_aead_decrypt
};

/**
 * \brief Rate for absorbing data into the sponge state.
 */
#define XOODYAK_MASKED_ABSORB_RATE 44

/**
 * \brief Rate for squeezing data out of the sponge.
 */
#define XOODYAK_MASKED_SQUEEZE_RATE 24

/**
 * \brief Initializes the Xoodyak state in masked mode.
 *
 * \param state The state after the key and nonce have been absorbed.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void xoodyak_init_masked
    (xoodoo_state_t *state, const unsigned char *k,
     const unsigned char *npub)
{
    mask_uint32_t mstate[12];
    int index;

    /* Mask the key and initialize the state */
    mask_input(mstate[0], le_load_word32(k));
    mask_input(mstate[1], le_load_word32(k + 4));
    mask_input(mstate[2], le_load_word32(k + 8));
    mask_input(mstate[3], le_load_word32(k + 12));
    mask_input(mstate[4], 0x00000100U); /* Padding */
    for (index = 5; index < 11; ++index)
        mask_input(mstate[index], 0);
    mask_input(mstate[11], 0x02000000U); /* Domain separation */

    /* Absorb the nonce into the masked state */
    xoodoo_permute_masked(mstate);
    mask_xor_const(mstate[0], le_load_word32(npub));
    mask_xor_const(mstate[1], le_load_word32(npub + 4));
    mask_xor_const(mstate[2], le_load_word32(npub + 8));
    mask_xor_const(mstate[3], le_load_word32(npub + 12));
    mask_xor_const(mstate[4],  0x00000001U); /* Padding */
    mask_xor_const(mstate[11], 0x03000000U); /* Domain separation */

    /* Convert the state into unmasked form */
    xoodoo_unmask(state->W, mstate);
}

/**
 * \brief Absorbs data into the Xoodoo permutation state.
 *
 * \param state Xoodoo permutation state.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 */
static void xoodyak_absorb_masked
    (xoodoo_state_t *state, const unsigned char *data, unsigned long long len)
{
    uint8_t domain = 0x03;
    unsigned temp;
    while (len > XOODYAK_MASKED_ABSORB_RATE) {
        xoodoo_permute(state);
        lw_xor_block(state->B, data, XOODYAK_MASKED_ABSORB_RATE);
        state->B[XOODYAK_MASKED_ABSORB_RATE] ^= 0x01; /* Padding */
        state->B[sizeof(state->B) - 1] ^= domain;
        data += XOODYAK_MASKED_ABSORB_RATE;
        len -= XOODYAK_MASKED_ABSORB_RATE;
        domain = 0x00;
    }
    temp = (unsigned)len;
    xoodoo_permute(state);
    lw_xor_block(state->B, data, temp);
    state->B[temp] ^= 0x01; /* Padding */
    state->B[sizeof(state->B) - 1] ^= domain;
}

int xoodyak_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t domain;
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + XOODYAK_MASKED_TAG_SIZE;

    /* Initialize the state with the key and nonce */
    xoodyak_init_masked(&state, k, npub);

    /* Absorb the associated data */
    xoodyak_absorb_masked(&state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    domain = 0x80;
    while (mlen > XOODYAK_MASKED_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_2_dest(c, state.B, m, XOODYAK_MASKED_SQUEEZE_RATE);
        state.B[XOODYAK_MASKED_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_MASKED_SQUEEZE_RATE;
        m += XOODYAK_MASKED_SQUEEZE_RATE;
        mlen -= XOODYAK_MASKED_SQUEEZE_RATE;
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
    memcpy(c, state.B, XOODYAK_MASKED_TAG_SIZE);
    return 0;
}

int xoodyak_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    xoodoo_state_t state;
    uint8_t domain;
    unsigned temp;
    unsigned char *mtemp = m;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < XOODYAK_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - XOODYAK_MASKED_TAG_SIZE;

    /* Initialize the state with the key and nonce */
    xoodyak_init_masked(&state, k, npub);

    /* Absorb the associated data */
    xoodyak_absorb_masked(&state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    domain = 0x80;
    clen -= XOODYAK_MASKED_TAG_SIZE;
    while (clen > XOODYAK_MASKED_SQUEEZE_RATE) {
        state.B[sizeof(state.B) - 1] ^= domain;
        xoodoo_permute(&state);
        lw_xor_block_swap(m, state.B, c, XOODYAK_MASKED_SQUEEZE_RATE);
        state.B[XOODYAK_MASKED_SQUEEZE_RATE] ^= 0x01; /* Padding */
        c += XOODYAK_MASKED_SQUEEZE_RATE;
        m += XOODYAK_MASKED_SQUEEZE_RATE;
        clen -= XOODYAK_MASKED_SQUEEZE_RATE;
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
    return aead_check_tag(mtemp, *mlen, state.B, c, XOODYAK_MASKED_TAG_SIZE);
}
