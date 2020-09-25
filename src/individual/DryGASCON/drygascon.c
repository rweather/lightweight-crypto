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

#include "drygascon.h"
#include "internal-drysponge.h"
#include <string.h>

uint8_t drygascon128k32_expected[DRYGASCON128_TAG_SIZE]={0x66,0x5A,0xDE,0x6C,0x0F,0xBD,0x48,0x8C,0x5E,0xA4,0x77,0x5D,0xD6,0x24,0xDA,0xD7};

uint8_t drygascon128k56_expected[DRYGASCON128_TAG_SIZE]={0x7B,0x8B,0x9D,0x58,0xA7,0xF7,0x5F,0x1E,0x56,0x99,0x46,0xD6,0x24,0xC4,0xF7,0x68};

uint8_t drygascon128k16_expected[DRYGASCON128_TAG_SIZE]={0x14,0xA5,0x21,0x17,0xFF,0x52,0x4F,0x7C,0xCB,0xB3,0xEB,0xE4,0x05,0xEF,0x18,0xA4};

uint8_t drygascon256_expected[DRYGASCON256_TAG_SIZE]={0};//TODO

aead_cipher_t const drygascon128k32_cipher = {
    "DryGASCON128k32",
    DRYGASCON128_FASTKEY_SIZE,
    DRYGASCON128_NONCE_SIZE,
    DRYGASCON128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
    drygascon128k32_aead_encrypt,
    drygascon128k32_aead_decrypt
};

aead_cipher_t const drygascon128_cipher = {
	"DryGASCON128k32",
	DRYGASCON128_FASTKEY_SIZE,
	DRYGASCON128_NONCE_SIZE,
	DRYGASCON128_TAG_SIZE,
	AEAD_FLAG_LITTLE_ENDIAN,
	drygascon128k32_aead_encrypt,
	drygascon128k32_aead_decrypt
};

aead_cipher_t const drygascon128k56_cipher = {
    "DryGASCON128k56",
    DRYGASCON128_SAFEKEY_SIZE,
    DRYGASCON128_NONCE_SIZE,
    DRYGASCON128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
    drygascon128k56_aead_encrypt,
    drygascon128k56_aead_decrypt
};

aead_cipher_t const drygascon128k16_cipher = {
    "DryGASCON128k16",
    DRYGASCON128_MINKEY_SIZE,
    DRYGASCON128_NONCE_SIZE,
    DRYGASCON128_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
    drygascon128k16_aead_encrypt,
    drygascon128k16_aead_decrypt
};

aead_cipher_t const drygascon256_cipher = {
    "DryGASCON256",
    DRYGASCON256_KEY_SIZE,
    DRYGASCON256_NONCE_SIZE,
    DRYGASCON256_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
    drygascon256_aead_encrypt,
    drygascon256_aead_decrypt
};

aead_hash_algorithm_t const drygascon128_hash_algorithm = {
    "DryGASCON128-HASH",
    sizeof(int),
    DRYGASCON128_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
    drygascon128_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

aead_hash_algorithm_t const drygascon256_hash_algorithm = {
    "DryGASCON256-HASH",
    sizeof(int),
    DRYGASCON256_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
    drygascon256_hash,
    (aead_hash_init_t)0,
    (aead_hash_update_t)0,
    (aead_hash_finalize_t)0,
    (aead_xof_absorb_t)0,
    (aead_xof_squeeze_t)0
};

/**
 * \brief Processes associated data for DryGASCON128.
 *
 * \param state DrySPONGE128 sponge state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must not be zero.
 * \param finalize Non-zero to finalize packet processing because
 * the message is zero-length.
 */
static void drygascon128_process_ad
    (drysponge128_state_t *state, const unsigned char *ad,
     unsigned long long adlen, int finalize)
{
    /* Process all blocks except the last one */
    while (adlen > DRYSPONGE128_RATE) {
        drygascon128_f_wrap(state, ad, DRYSPONGE128_RATE);
        //drysponge128_g_core(state);
        ad += DRYSPONGE128_RATE;
        adlen -= DRYSPONGE128_RATE;
    }

    /* Process the last block with domain separation and padding */
    state->domain = DRYDOMAIN128_ASSOC_DATA;
    if (finalize)
        state->domain |= DRYDOMAIN128_FINAL;
    if (adlen < DRYSPONGE128_RATE)
        state->domain |= DRYDOMAIN128_PADDED;
    drygascon128_f_wrap(state, ad, (unsigned)adlen);
    //drysponge128_g(state);
}

/**
 * \brief Processes associated data for DryGASCON256.
 *
 * \param state DrySPONGE256 sponge state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data, must not be zero.
 * \param finalize Non-zero to finalize packet processing because
 * the message is zero-length.
 */
static void drygascon256_process_ad
    (drysponge256_state_t *state, const unsigned char *ad,
     unsigned long long adlen, int finalize)
{
    /* Process all blocks except the last one */
    while (adlen > DRYSPONGE256_RATE) {
        drysponge256_f_absorb(state, ad, DRYSPONGE256_RATE);
        drysponge256_g_core(state);
        ad += DRYSPONGE256_RATE;
        adlen -= DRYSPONGE256_RATE;
    }

    /* Process the last block with domain separation and padding */
    state->domain = DRYDOMAIN256_ASSOC_DATA;
    if (finalize)
        state->domain |= DRYDOMAIN256_FINAL;
    if (adlen < DRYSPONGE256_RATE)
        state->domain |= DRYDOMAIN256_PADDED;
    drysponge256_f_absorb(state, ad, (unsigned)adlen);
    drysponge256_g(state);
}

int drygascon128_aead_encrypt_core
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
	 unsigned int keysize,
     const unsigned char *npub,
     const unsigned char *k)
{
    drysponge128_state_t state;
    unsigned temp;

    /* Check we are safe */
	if(!drysponge128_safe_alignement(&state)){
		return -1;
	}

    /* Set the length of the returned ciphertext */
    *clen = mlen + DRYGASCON128_TAG_SIZE;

    /* Initialize the sponge state with the key and nonce */
    drysponge128_setup(&state, k, keysize, npub, adlen == 0 && mlen == 0);

    /* Process the associated data */
    if (adlen > 0)
        drygascon128_process_ad(&state, ad, adlen, mlen == 0);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        if(c==m) {
            /* Deal with in-place encryption case */
            drysponge128_rate_t tmp; 
            unsigned char *m2 = (unsigned char *)&tmp;
            /* Processs all blocks except the last one */
            while (mlen > DRYSPONGE128_RATE) {
                memcpy(m2,m,DRYSPONGE128_RATE);
                lw_xor_block_2_src(c, m, state.r.B, DRYSPONGE128_RATE);
                drygascon128_f_wrap(&state, m2, DRYSPONGE128_RATE);
                c += DRYSPONGE128_RATE;
                m += DRYSPONGE128_RATE;
                mlen -= DRYSPONGE128_RATE;
            }
        }else{
            /* Processs all blocks except the last one */
            while (mlen > DRYSPONGE128_RATE) {
                lw_xor_block_2_src(c, m, state.r.B, DRYSPONGE128_RATE);
                drygascon128_f_wrap(&state, m, DRYSPONGE128_RATE);
                c += DRYSPONGE128_RATE;
                m += DRYSPONGE128_RATE;
                mlen -= DRYSPONGE128_RATE;
            }
        }

        /* Process the last block with domain separation and padding */
        state.domain = DRYDOMAIN128_MESSAGE | DRYDOMAIN128_FINAL;
        if (mlen < DRYSPONGE128_RATE)
            state.domain |= DRYDOMAIN128_PADDED;
        temp = (unsigned)mlen;
        if(c==m) {
            /* Deal with in-place encryption case */
            drysponge128_rate_t tmp; 
            unsigned char *m2 = (unsigned char *)&tmp;
            memcpy(m2,m,DRYSPONGE128_RATE);
            lw_xor_block_2_src(c, m, state.r.B, temp);
            drygascon128_f_wrap(&state, m2, temp);
        }else{
            lw_xor_block_2_src(c, m, state.r.B, temp);
            drygascon128_f_wrap(&state, m, temp);
        }
        c += temp;
    }

    /* Generate the authentication tag */
    memcpy(c, state.r.B, DRYGASCON128_TAG_SIZE);
    return 0;
}

int drygascon128_aead_decrypt_core
    (unsigned char *m, unsigned long long *mlen,
     unsigned int keysize,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    drysponge128_state_t state;
    unsigned char *mtemp = m;
    unsigned temp;

    /* Check we are safe */
    if(!drysponge128_safe_alignement(&state)){
		return -1;
	}

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < DRYGASCON128_TAG_SIZE)
        return -1;
    *mlen = clen - DRYGASCON128_TAG_SIZE;

    /* Initialize the sponge state with the key and nonce */
    clen -= DRYGASCON128_TAG_SIZE;
    drysponge128_setup(&state, k, keysize, npub, adlen == 0 && clen == 0);

    /* Process the associated data */
    if (adlen > 0)
        drygascon128_process_ad(&state, ad, adlen, clen == 0);

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > 0) {
        /* Processs all blocks except the last one */
        while (clen > DRYSPONGE128_RATE) {
            lw_xor_block_2_src(m, c, state.r.B, DRYSPONGE128_RATE);
            drygascon128_f_wrap(&state, m, DRYSPONGE128_RATE);
            //drysponge128_g(&state);
            c += DRYSPONGE128_RATE;
            m += DRYSPONGE128_RATE;
            clen -= DRYSPONGE128_RATE;
        }

        /* Process the last block with domain separation and padding */
        state.domain = DRYDOMAIN128_MESSAGE | DRYDOMAIN128_FINAL;
        if (clen < DRYSPONGE128_RATE)
            state.domain |= DRYDOMAIN128_PADDED;
        temp = (unsigned)clen;
        lw_xor_block_2_src(m, c, state.r.B, temp);
        drygascon128_f_wrap(&state, m, temp);
        //drysponge128_g(&state);
        c += temp;
    }

    /* Check the authentication tag */
    return aead_check_tag(mtemp, *mlen, state.r.B, c, DRYGASCON128_TAG_SIZE);
}

int drygascon128k16_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_encrypt_core(c,clen,m,mlen,ad,adlen,16,npub,k);
}

int drygascon128k32_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_encrypt_core(c,clen,m,mlen,ad,adlen,32,npub,k);
}

int drygascon128k56_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_encrypt_core(c,clen,m,mlen,ad,adlen,56,npub,k);
}


int drygascon128k16_aead_decrypt
	(unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_decrypt_core(m,mlen,16,c,clen,ad,adlen,npub,k);
}

int drygascon128k32_aead_decrypt
	(unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_decrypt_core(m,mlen,32,c,clen,ad,adlen,npub,k);
}

int drygascon128k56_aead_decrypt
	(unsigned char *m, unsigned long long *mlen,
	 unsigned char *nsec,
	 const unsigned char *c, unsigned long long clen,
	 const unsigned char *ad, unsigned long long adlen,
	 const unsigned char *npub,
	 const unsigned char *k){
    (void)nsec;
	return drygascon128_aead_decrypt_core(m,mlen,56,c,clen,ad,adlen,npub,k);
}

int drygascon256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    drysponge256_state_t state;
    unsigned temp;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + DRYGASCON256_TAG_SIZE;

    /* Initialize the sponge state with the key and nonce */
    drysponge256_setup(&state, k, npub, adlen == 0 && mlen == 0);

    /* Process the associated data */
    if (adlen > 0)
        drygascon256_process_ad(&state, ad, adlen, mlen == 0);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        /* Processs all blocks except the last one */
        while (mlen > DRYSPONGE256_RATE) {
            drysponge256_f_absorb(&state, m, DRYSPONGE256_RATE);
            lw_xor_block_2_src(c, m, state.r.B, DRYSPONGE256_RATE);
            drysponge256_g(&state);
            c += DRYSPONGE256_RATE;
            m += DRYSPONGE256_RATE;
            mlen -= DRYSPONGE256_RATE;
        }

        /* Process the last block with domain separation and padding */
        state.domain = DRYDOMAIN256_MESSAGE | DRYDOMAIN256_FINAL;
        if (mlen < DRYSPONGE256_RATE)
            state.domain |= DRYDOMAIN256_PADDED;
        temp = (unsigned)mlen;
        drysponge256_f_absorb(&state, m, temp);
        lw_xor_block_2_src(c, m, state.r.B, temp);
        drysponge256_g(&state);
        c += temp;
    }

    /* Generate the authentication tag */
    memcpy(c, state.r.B, 16);
    drysponge256_g(&state);
    memcpy(c + 16, state.r.B, 16);
    return 0;
}

int drygascon256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    drysponge256_state_t state;
    unsigned char *mtemp = m;
    unsigned temp;
    int result;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < DRYGASCON256_TAG_SIZE)
        return -1;
    *mlen = clen - DRYGASCON256_TAG_SIZE;

    /* Initialize the sponge state with the key and nonce */
    clen -= DRYGASCON256_TAG_SIZE;
    drysponge256_setup(&state, k, npub, adlen == 0 && clen == 0);

    /* Process the associated data */
    if (adlen > 0)
        drygascon256_process_ad(&state, ad, adlen, clen == 0);

    /* Decrypt the ciphertext to produce the plaintext */
    if (clen > 0) {
        /* Processs all blocks except the last one */
        while (clen > DRYSPONGE256_RATE) {
            lw_xor_block_2_src(m, c, state.r.B, DRYSPONGE256_RATE);
            drysponge256_f_absorb(&state, m, DRYSPONGE256_RATE);
            drysponge256_g(&state);
            c += DRYSPONGE256_RATE;
            m += DRYSPONGE256_RATE;
            clen -= DRYSPONGE256_RATE;
        }

        /* Process the last block with domain separation and padding */
        state.domain = DRYDOMAIN256_MESSAGE | DRYDOMAIN256_FINAL;
        if (clen < DRYSPONGE256_RATE)
            state.domain |= DRYDOMAIN256_PADDED;
        temp = (unsigned)clen;
        lw_xor_block_2_src(m, c, state.r.B, temp);
        drysponge256_f_absorb(&state, m, temp);
        drysponge256_g(&state);
        c += temp;
    }

    /* Check the authentication tag which is split into two pieces */
    result = aead_check_tag(0, 0, state.r.B, c, 16);
    drysponge256_g(&state);
    return aead_check_tag_precheck
        (mtemp, *mlen, state.r.B, c + 16, 16, ~result);
}

/**
 * \brief Precomputed initialization vector for DryGASCON128-HASH.
 *
 * This is the CST_H value from the DryGASCON specification after it
 * has been processed by the key setup function for DrySPONGE128.
 */
static unsigned char const drygascon128_hash_init[] = {
    /* c */
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    /* x */
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
    0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89
};

int drygascon128_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    drysponge128_state_t state;
    memcpy(state.c.B, drygascon128_hash_init, sizeof(state.c.B));
    memcpy(state.x.B, drygascon128_hash_init + sizeof(state.c.B),
           sizeof(state.x.B));
    state.domain = 0;
    state.rounds = DRYSPONGE128_ROUNDS;
    drygascon128_process_ad(&state, in, inlen, 1);
    memcpy(out, state.r.B, 16);
    drysponge128_g(&state);
    memcpy(out + 16, state.r.B, 16);
    return 0;
}

/**
 * \brief Precomputed initialization vector for DryGASCON256-HASH.
 *
 * This is the CST_H value from the DryGASCON specification after it
 * has been processed by the key setup function for DrySPONGE256.
 */
static unsigned char const drygascon256_hash_init[] = {
    /* c */
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
    0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    0x13, 0x19, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x44,
    0xa4, 0x09, 0x38, 0x22, 0x29, 0x9f, 0x31, 0xd0,
    0x08, 0x2e, 0xfa, 0x98, 0xec, 0x4e, 0x6c, 0x89,
    0x24, 0x3f, 0x6a, 0x88, 0x85, 0xa3, 0x08, 0xd3,
    /* x */
    0x45, 0x28, 0x21, 0xe6, 0x38, 0xd0, 0x13, 0x77,
    0xbe, 0x54, 0x66, 0xcf, 0x34, 0xe9, 0x0c, 0x6c
};

int drygascon256_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    drysponge256_state_t state;
    memcpy(state.c.B, drygascon256_hash_init, sizeof(state.c.B));
    memcpy(state.x.B, drygascon256_hash_init + sizeof(state.c.B),
           sizeof(state.x.B));
    state.domain = 0;
    state.rounds = DRYSPONGE256_ROUNDS;
    drygascon256_process_ad(&state, in, inlen, 1);
    memcpy(out, state.r.B, 16);
    drysponge256_g(&state);
    memcpy(out + 16, state.r.B, 16);
    drysponge256_g(&state);
    memcpy(out + 32, state.r.B, 16);
    drysponge256_g(&state);
    memcpy(out + 48, state.r.B, 16);
    return 0;
}
