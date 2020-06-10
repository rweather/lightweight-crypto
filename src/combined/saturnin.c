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

#include "saturnin.h"
#include "internal-saturnin.h"
#include <string.h>

aead_cipher_t const saturnin_cipher = {
    "SATURNIN-CTR-Cascade",
    SATURNIN_KEY_SIZE,
    SATURNIN_NONCE_SIZE,
    SATURNIN_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    saturnin_aead_encrypt,
    saturnin_aead_decrypt
};

aead_cipher_t const saturnin_short_cipher = {
    "SATURNIN-Short",
    SATURNIN_KEY_SIZE,
    SATURNIN_NONCE_SIZE,
    SATURNIN_TAG_SIZE,
    AEAD_FLAG_NONE,
    saturnin_short_aead_encrypt,
    saturnin_short_aead_decrypt
};

aead_hash_algorithm_t const saturnin_hash_algorithm = {
    "SATURNIN-Hash",
    sizeof(saturnin_hash_state_t),
    SATURNIN_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    saturnin_hash,
    (aead_hash_init_t)saturnin_hash_init,
    (aead_hash_update_t)saturnin_hash_update,
    (aead_hash_finalize_t)saturnin_hash_finalize,
    0, /* absorb */
    0  /* squeeze */
};

/**
 * \brief Encrypts a 256-bit block with the SATURNIN block cipher and
 * then XOR's itself to generate a new key.
 *
 * \param block Block to be encrypted and then XOR'ed with itself.
 * \param key Points to the 32 byte key for the block cipher.
 * \param domain Domain separator and round counter.
 */
static void saturnin_block_encrypt_xor
    (const unsigned char *block, unsigned char *key, unsigned domain)
{
    saturnin_key_schedule_t ks;
    unsigned char *temp = (unsigned char *)ks.k; /* Reuse some stack space */
    saturnin_setup_key(&ks, key);
    saturnin_encrypt_block(&ks, temp, block, domain);
    lw_xor_block_2_src(key, block, temp, SATURNIN_BLOCK_SIZE);
}

/**
 * \brief Encrypts (or decrypts) a data packet in CTR mode.
 *
 * \param c Output ciphertext buffer.
 * \param m Input plaintext buffer.
 * \param mlen Length of the plaintext in bytes.
 * \param ks Points to the key schedule.
 * \param block Points to the pre-formatted nonce block.
 */
static void saturnin_ctr_encrypt
    (unsigned char *c, const unsigned char *m, unsigned long long mlen,
     const saturnin_key_schedule_t *ks, unsigned char *block)
{
    /* Note: Specification requires a 95-bit counter but we only use 32-bit.
     * This limits the maximum packet size to 128Gb.  That should be OK */
    uint32_t counter = 1;
    unsigned char out[SATURNIN_BLOCK_SIZE];
    while (mlen >= 32) {
        be_store_word32(block + 28, counter);
        saturnin_encrypt_block(ks, out, block, SATURNIN_DOMAIN_10_1);
        lw_xor_block_2_src(c, out, m, 32);
        c += 32;
        m += 32;
        mlen -= 32;
        ++counter;
    }
    if (mlen > 0) {
        be_store_word32(block + 28, counter);
        saturnin_encrypt_block(ks, out, block, SATURNIN_DOMAIN_10_1);
        lw_xor_block_2_src(c, out, m, (unsigned)mlen);
    }
}

/**
 * \brief Pads an authenticates a message.
 *
 * \param tag Points to the authentication tag.
 * \param block Temporary block of 32 bytes from the caller.
 * \param m Points to the message to be authenticated.
 * \param mlen Length of the message to be authenticated in bytes.
 * \param domain1 Round count and domain separator for full blocks.
 * \param domain2 Round count and domain separator for the last block.
 */
static void saturnin_authenticate
    (unsigned char *tag, unsigned char *block,
     const unsigned char *m, unsigned long long mlen,
     unsigned domain1, unsigned domain2)
{
    unsigned temp;
    while (mlen >= 32) {
        saturnin_block_encrypt_xor(m, tag, domain1);
        m += 32;
        mlen -= 32;
    }
    temp = (unsigned)mlen;
    memcpy(block, m, temp);
    block[temp] = 0x80;
    memset(block + temp + 1, 0, 31 - temp);
    saturnin_block_encrypt_xor(block, tag, domain2);
}

int saturnin_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    saturnin_key_schedule_t ks;
    unsigned char block[32];
    unsigned char *tag;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SATURNIN_TAG_SIZE;

    /* Format the input block from the padded nonce */
    memcpy(block, npub, 16);
    block[16] = 0x80;
    memset(block + 17, 0, 15);

    /* Encrypt the plaintext in counter mode to produce the ciphertext */
    saturnin_setup_key(&ks, k);
    saturnin_ctr_encrypt(c, m, mlen, &ks, block);

    /* Set the counter back to zero and then encrypt the nonce */
    tag = c + mlen;
    memcpy(tag, k, 32);
    memset(block + 17, 0, 15);
    saturnin_block_encrypt_xor(block, tag, SATURNIN_DOMAIN_10_2);

    /* Authenticate the associated data and the ciphertext */
    saturnin_authenticate
        (tag, block, ad, adlen, SATURNIN_DOMAIN_10_2, SATURNIN_DOMAIN_10_3);
    saturnin_authenticate
        (tag, block, c, mlen, SATURNIN_DOMAIN_10_4, SATURNIN_DOMAIN_10_5);
    return 0;
}

int saturnin_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    saturnin_key_schedule_t ks;
    unsigned char block[32];
    unsigned char tag[32];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SATURNIN_TAG_SIZE)
        return -1;
    *mlen = clen - SATURNIN_TAG_SIZE;

    /* Format the input block from the padded nonce */
    memcpy(block, npub, 16);
    block[16] = 0x80;
    memset(block + 17, 0, 15);

    /* Encrypt the nonce to initialize the authentication phase */
    memcpy(tag, k, 32);
    saturnin_block_encrypt_xor(block, tag, SATURNIN_DOMAIN_10_2);

    /* Authenticate the associated data and the ciphertext */
    saturnin_authenticate
        (tag, block, ad, adlen, SATURNIN_DOMAIN_10_2, SATURNIN_DOMAIN_10_3);
    saturnin_authenticate
        (tag, block, c, *mlen, SATURNIN_DOMAIN_10_4, SATURNIN_DOMAIN_10_5);

    /* Decrypt the ciphertext in counter mode to produce the plaintext */
    memcpy(block, npub, 16);
    block[16] = 0x80;
    memset(block + 17, 0, 15);
    saturnin_setup_key(&ks, k);
    saturnin_ctr_encrypt(m, c, *mlen, &ks, block);

    /* Check the authentication tag at the end of the message */
    return aead_check_tag
        (m, *mlen, tag, c + *mlen, SATURNIN_TAG_SIZE);
}

int saturnin_short_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    saturnin_key_schedule_t ks;
    unsigned char block[32];
    unsigned temp;
    (void)nsec;
    (void)ad;

    /* Validate the parameters: no associated data allowed and m <= 15 bytes */
    if (adlen > 0 || mlen > 15)
        return -2;

    /* Format the input block from the nonce and plaintext */
    temp = (unsigned)mlen;
    memcpy(block, npub, 16);
    memcpy(block + 16, m, temp);
    block[16 + temp] = 0x80; /* Padding */
    memset(block + 17 + temp, 0, 15 - temp);

    /* Encrypt the input block to produce the output ciphertext */
    saturnin_setup_key(&ks, k);
    saturnin_encrypt_block(&ks, c, block, SATURNIN_DOMAIN_10_6);
    *clen = 32;
    return 0;
}

int saturnin_short_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    saturnin_key_schedule_t ks;
    unsigned char block[32];
    unsigned check1, check2, len;
    int index, result;
    (void)nsec;
    (void)ad;

    /* Validate the parameters: no associated data and c is always 32 bytes */
    if (adlen > 0)
        return -2;
    if (clen != 32)
        return -1;

    /* Decrypt the ciphertext block */
    saturnin_setup_key(&ks, k);
    saturnin_decrypt_block(&ks, block, c, SATURNIN_DOMAIN_10_6);

    /* Verify that the output block starts with the nonce and that it is
     * padded correctly.  We need to do this very carefully to avoid leaking
     * any information that could be used in a padding oracle attack.  Use the
     * same algorithm as the reference implementation of SATURNIN-Short */
    check1 = 0;
    for (index = 0; index < 16; ++index)
        check1 |= npub[index] ^ block[index];
    check2 = 0xFF;
    len = 0;
    for (index = 15; index >= 0; --index) {
        unsigned temp = block[16 + index];
        unsigned temp2 = check2 & -(1 - (((temp ^ 0x80) + 0xFF) >> 8));
        len |= temp2 & (unsigned)index;
        check2 &= ~temp2;
        check1 |= check2 & ((temp + 0xFF) >> 8);
    }
    check1 |= check2;

    /* At this point, check1 is zero if the nonce and plaintext are good,
     * or non-zero if there was an error in the decrypted data */
    result = (((int)check1) - 1) >> 8;

    /* The "result" is -1 if the data is good or zero if the data is invalid.
     * Copy either the plaintext or zeroes to the output buffer.  We assume
     * that the output buffer has space for up to 15 bytes.  This may return
     * some of the padding to the caller but as long as they restrict
     * themselves to the first *mlen bytes then it shouldn't be a problem */
    for (index = 0; index < 15; ++index)
        m[index] = block[16 + index] & result;
    *mlen = len;
    return ~result;
}

int saturnin_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char tag[32];
    unsigned char block[32];
    memset(tag, 0, sizeof(tag));
    saturnin_authenticate
        (tag, block, in, inlen, SATURNIN_DOMAIN_16_7, SATURNIN_DOMAIN_16_8);
    memcpy(out, tag, 32);
    return 0;
}

void saturnin_hash_init(saturnin_hash_state_t *state)
{
    memset(state, 0, sizeof(saturnin_hash_state_t));
}

void saturnin_hash_update
    (saturnin_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    unsigned temp;

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = 32 - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            memcpy(state->s.block + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        memcpy(state->s.block + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
        saturnin_block_encrypt_xor
            (state->s.block, state->s.hash, SATURNIN_DOMAIN_16_7);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= 32) {
        saturnin_block_encrypt_xor
            (in, state->s.hash, SATURNIN_DOMAIN_16_7);
        in += 32;
        inlen -= 32;
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    memcpy(state->s.block, in, temp);
    state->s.count = temp;
}

void saturnin_hash_finalize
    (saturnin_hash_state_t *state, unsigned char *out)
{
    /* Pad the final block */
    state->s.block[state->s.count] = 0x80;
    memset(state->s.block + state->s.count + 1, 0, 31 - state->s.count);

    /* Generate the final hash value */
    saturnin_block_encrypt_xor
        (state->s.block, state->s.hash, SATURNIN_DOMAIN_16_8);
    memcpy(out, state->s.hash, 32);
}
