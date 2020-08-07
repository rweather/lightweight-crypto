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

#include "gimli24-masked.h"
#include "internal-gimli24.h"
#include "internal-gimli24-m.h"
#include <string.h>

aead_cipher_t const gimli24_masked_cipher = {
    "GIMLI-24-Masked",
    GIMLI24_MASKED_KEY_SIZE,
    GIMLI24_MASKED_NONCE_SIZE,
    GIMLI24_MASKED_TAG_SIZE,
#if AEAD_MASKING_KEY_ONLY
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_KEY,
#else
    AEAD_FLAG_LITTLE_ENDIAN | AEAD_FLAG_SC_PROTECT_ALL,
#endif
    gimli24_masked_aead_encrypt,
    gimli24_masked_aead_decrypt
};

/**
 * \brief Number of bytes of input or output data to process per block.
 */
#define GIMLI24_MASKED_BLOCK_SIZE 16

#if AEAD_MASKING_KEY_ONLY

/**
 * \brief Structure of the GIMLI-24 state as both an array of words
 * and an array of bytes.
 */
typedef union
{
    uint32_t words[12];     /**< Words in the state */
    uint8_t bytes[48];      /**< Bytes in the state */

} gimli24_masked_state_t;

/**
 * \brief Absorbs data into a GIMLI-24 state.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 */
static void gimli24_masked_absorb
    (gimli24_masked_state_t *state, const unsigned char *data, unsigned long long len)
{
    unsigned temp;
    while (len >= GIMLI24_MASKED_BLOCK_SIZE) {
        lw_xor_block(state->bytes, data, GIMLI24_MASKED_BLOCK_SIZE);
        gimli24_permute(state->words);
        data += GIMLI24_MASKED_BLOCK_SIZE;
        len -= GIMLI24_MASKED_BLOCK_SIZE;
    }
    temp = (unsigned)len;
    lw_xor_block(state->bytes, data, temp);
    state->bytes[temp] ^= 0x01; /* Padding */
    state->bytes[47] ^= 0x01;
    gimli24_permute(state->words);
}

/**
 * \brief Encrypts a block of data with a GIMLI-24 state.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 */
static void gimli24_masked_encrypt
    (gimli24_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len)
{
    unsigned temp;
    while (len >= GIMLI24_MASKED_BLOCK_SIZE) {
        lw_xor_block_2_dest(dest, state->bytes, src, GIMLI24_MASKED_BLOCK_SIZE);
        gimli24_permute(state->words);
        dest += GIMLI24_MASKED_BLOCK_SIZE;
        src += GIMLI24_MASKED_BLOCK_SIZE;
        len -= GIMLI24_MASKED_BLOCK_SIZE;
    }
    temp = (unsigned)len;
    lw_xor_block_2_dest(dest, state->bytes, src, temp);
    state->bytes[temp] ^= 0x01; /* Padding */
    state->bytes[47] ^= 0x01;
    gimli24_permute(state->words);
}

/**
 * \brief Decrypts a block of data with a GIMLI-24 state.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 */
static void gimli24_masked_decrypt
    (gimli24_masked_state_t *state, unsigned char *dest,
     const unsigned char *src, unsigned long long len)
{
    unsigned temp;
    while (len >= GIMLI24_MASKED_BLOCK_SIZE) {
        lw_xor_block_swap(dest, state->bytes, src, GIMLI24_MASKED_BLOCK_SIZE);
        gimli24_permute(state->words);
        dest += GIMLI24_MASKED_BLOCK_SIZE;
        src += GIMLI24_MASKED_BLOCK_SIZE;
        len -= GIMLI24_MASKED_BLOCK_SIZE;
    }
    temp = (unsigned)len;
    lw_xor_block_swap(dest, state->bytes, src, temp);
    state->bytes[temp] ^= 0x01; /* Padding */
    state->bytes[47] ^= 0x01;
    gimli24_permute(state->words);
}

/**
 * \brief Initializes the GIMLI-24 state from the key and nonce.
 *
 * \param state Regular unmasked GIMLI-24 state on output.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 *
 * Internally this uses the masked version of the GIMLI-24 permutation
 * to attempt to mask the absorption of the key into the state.
 */
static void gimli24_masked_init
    (gimli24_masked_state_t *state, const unsigned char *k,
     const unsigned char *npub)
{
    mask_uint32_t first_state[12];
    aead_random_init();
    mask_input(first_state[0], le_load_word32(npub));
    mask_input(first_state[1], le_load_word32(npub + 4));
    mask_input(first_state[2], le_load_word32(npub + 8));
    mask_input(first_state[3], le_load_word32(npub + 12));
    mask_input(first_state[4], le_load_word32(k));
    mask_input(first_state[5], le_load_word32(k + 4));
    mask_input(first_state[6], le_load_word32(k + 8));
    mask_input(first_state[7], le_load_word32(k + 12));
    mask_input(first_state[8], le_load_word32(k + 16));
    mask_input(first_state[9], le_load_word32(k + 20));
    mask_input(first_state[10], le_load_word32(k + 24));
    mask_input(first_state[11], le_load_word32(k + 28));
    gimli24_permute_masked(first_state);
    gimli24_unmask(state->words, first_state);
}

int gimli24_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gimli24_masked_state_t state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GIMLI24_MASKED_TAG_SIZE;

    /* Format the initial GIMLI state from the nonce and the key */
    gimli24_masked_init(&state, k, npub);

    /* Absorb the associated data */
    gimli24_masked_absorb(&state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    gimli24_masked_encrypt(&state, c, m, mlen);

    /* Generate the authentication tag at the end of the ciphertext */
    memcpy(c + mlen, state.bytes, GIMLI24_MASKED_TAG_SIZE);
    return 0;
}

int gimli24_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gimli24_masked_state_t state;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < GIMLI24_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - GIMLI24_MASKED_TAG_SIZE;

    /* Format the initial GIMLI state from the nonce and the key */
    gimli24_masked_init(&state, k, npub);

    /* Absorb the associated data */
    gimli24_masked_absorb(&state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    gimli24_masked_decrypt(&state, m, c, *mlen);

    /* Check the authentication tag at the end of the packet */
    return aead_check_tag
        (m, *mlen, state.bytes, c + *mlen, GIMLI24_MASKED_TAG_SIZE);
}

#else /* !AEAD_MASKING_KEY_ONLY */

/**
 * \brief Absorbs data into a GIMLI-24 state.
 *
 * \param state The state to absorb the data into.
 * \param data Points to the data to be absorbed.
 * \param len Length of the data to be absorbed.
 */
static void gimli24_masked_absorb
    (mask_uint32_t state[12], const unsigned char *data, unsigned long long len)
{
    unsigned char padded[GIMLI24_MASKED_BLOCK_SIZE];
    unsigned temp;
    while (len >= GIMLI24_MASKED_BLOCK_SIZE) {
        mask_xor_const(state[0], le_load_word32(data));
        mask_xor_const(state[1], le_load_word32(data + 4));
        mask_xor_const(state[2], le_load_word32(data + 8));
        mask_xor_const(state[3], le_load_word32(data + 12));
        gimli24_permute_masked(state);
        data += GIMLI24_MASKED_BLOCK_SIZE;
        len -= GIMLI24_MASKED_BLOCK_SIZE;
    }
    temp = (unsigned)len;
    memcpy(padded, data, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, GIMLI24_MASKED_BLOCK_SIZE - (temp + 1));
    mask_xor_const(state[0], le_load_word32(padded));
    mask_xor_const(state[1], le_load_word32(padded + 4));
    mask_xor_const(state[2], le_load_word32(padded + 8));
    mask_xor_const(state[3], le_load_word32(padded + 12));
    mask_xor_const(state[11], 0x01000000U); /* Domain separation */
    gimli24_permute_masked(state);
}

/**
 * \brief Encrypts a block of data with a GIMLI-24 state.
 *
 * \param state The state to encrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to encrypt from \a src into \a dest.
 */
static void gimli24_masked_encrypt
    (mask_uint32_t state[12], unsigned char *dest,
     const unsigned char *src, unsigned long long len)
{
    unsigned char padded[GIMLI24_MASKED_BLOCK_SIZE];
    unsigned temp;
    while (len >= GIMLI24_MASKED_BLOCK_SIZE) {
        mask_xor_const(state[0], le_load_word32(src));
        mask_xor_const(state[1], le_load_word32(src + 4));
        mask_xor_const(state[2], le_load_word32(src + 8));
        mask_xor_const(state[3], le_load_word32(src + 12));
        le_store_word32(dest,      mask_output(state[0]));
        le_store_word32(dest + 4,  mask_output(state[1]));
        le_store_word32(dest + 8,  mask_output(state[2]));
        le_store_word32(dest + 12, mask_output(state[3]));
        gimli24_permute_masked(state);
        dest += GIMLI24_MASKED_BLOCK_SIZE;
        src += GIMLI24_MASKED_BLOCK_SIZE;
        len -= GIMLI24_MASKED_BLOCK_SIZE;
    }
    temp = (unsigned)len;
    memcpy(padded, src, temp);
    padded[temp] = 0x01; /* Padding */
    memset(padded + temp + 1, 0, GIMLI24_MASKED_BLOCK_SIZE - (temp + 1));
    mask_xor_const(state[0], le_load_word32(padded));
    mask_xor_const(state[1], le_load_word32(padded + 4));
    mask_xor_const(state[2], le_load_word32(padded + 8));
    mask_xor_const(state[3], le_load_word32(padded + 12));
    le_store_word32(padded,      mask_output(state[0]));
    le_store_word32(padded + 4,  mask_output(state[1]));
    le_store_word32(padded + 8,  mask_output(state[2]));
    le_store_word32(padded + 12, mask_output(state[3]));
    memcpy(dest, padded, temp);
    mask_xor_const(state[11], 0x01000000U); /* Domain separation */
    gimli24_permute_masked(state);
}

/**
 * \brief Decrypts a block of data with a GIMLI-24 state.
 *
 * \param state The state to decrypt with.
 * \param dest Points to the destination buffer.
 * \param src Points to the source buffer.
 * \param len Length of the data to decrypt from \a src into \a dest.
 */
static void gimli24_masked_decrypt
    (mask_uint32_t state[12], unsigned char *dest,
     const unsigned char *src, unsigned long long len)
{
    unsigned temp;
    uint32_t mword;
    while (len >= GIMLI24_MASKED_BLOCK_SIZE) {
        mword = mask_output(state[0]) ^ le_load_word32(src);
        mask_xor_const(state[0], mword);
        le_store_word32(dest, mword);
        mword = mask_output(state[1]) ^ le_load_word32(src + 4);
        mask_xor_const(state[1], mword);
        le_store_word32(dest + 4, mword);
        mword = mask_output(state[2]) ^ le_load_word32(src + 8);
        mask_xor_const(state[2], mword);
        le_store_word32(dest + 8, mword);
        mword = mask_output(state[3]) ^ le_load_word32(src + 12);
        mask_xor_const(state[3], mword);
        le_store_word32(dest + 12, mword);
        gimli24_permute_masked(state);
        dest += GIMLI24_MASKED_BLOCK_SIZE;
        src += GIMLI24_MASKED_BLOCK_SIZE;
        len -= GIMLI24_MASKED_BLOCK_SIZE;
    }
    temp = 0;
    while (len >= 4) {
        mword = mask_output(state[temp]) ^ le_load_word32(src);
        mask_xor_const(state[temp], mword);
        le_store_word32(dest, mword);
        src += 4;
        dest += 4;
        len -= 4;
        ++temp;
    }
    if (len == 0) {
        mask_xor_const(state[temp], 0x01); /* Padding */
    } else if (len == 1) {
        mword = (unsigned char)(mask_output(state[temp]) ^ src[0]);
        mask_xor_const(state[temp], mword);
        dest[0] = (unsigned char)mword;
        mask_xor_const(state[temp], 0x0100); /* Padding */
    } else if (len == 2) {
        mword = (uint16_t)(mask_output(state[temp]) ^ le_load_word16(src));
        mask_xor_const(state[temp], mword);
        dest[0] = (unsigned char)mword;
        dest[1] = (unsigned char)(mword >> 8);
        mask_xor_const(state[temp], 0x010000); /* Padding */
    } else {
        mword = le_load_word16(src) | (((uint32_t)(src[2])) << 16);
        mword = (mword ^ mask_output(state[temp])) & 0x00FFFFFFU;
        mask_xor_const(state[temp], mword);
        dest[0] = (unsigned char)mword;
        dest[1] = (unsigned char)(mword >> 8);
        dest[2] = (unsigned char)(mword >> 16);
        mask_xor_const(state[temp], 0x01000000); /* Padding */
    }
    mask_xor_const(state[11], 0x01000000U); /* Domain separation */
    gimli24_permute_masked(state);
}

/**
 * \brief Initializes the GIMLI-24 state from the key and nonce.
 *
 * \param state Regular unmasked GIMLI-24 state on output.
 * \param k Points to the key.
 * \param npub Points to the nonce.
 */
static void gimli24_masked_init
    (mask_uint32_t state[12], const unsigned char *k,
     const unsigned char *npub)
{
    aead_random_init();
    mask_input(state[0], le_load_word32(npub));
    mask_input(state[1], le_load_word32(npub + 4));
    mask_input(state[2], le_load_word32(npub + 8));
    mask_input(state[3], le_load_word32(npub + 12));
    mask_input(state[4], le_load_word32(k));
    mask_input(state[5], le_load_word32(k + 4));
    mask_input(state[6], le_load_word32(k + 8));
    mask_input(state[7], le_load_word32(k + 12));
    mask_input(state[8], le_load_word32(k + 16));
    mask_input(state[9], le_load_word32(k + 20));
    mask_input(state[10], le_load_word32(k + 24));
    mask_input(state[11], le_load_word32(k + 28));
    gimli24_permute_masked(state);
}

int gimli24_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[12];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GIMLI24_MASKED_TAG_SIZE;

    /* Format the initial GIMLI state from the nonce and the key */
    gimli24_masked_init(state, k, npub);

    /* Absorb the associated data */
    gimli24_masked_absorb(state, ad, adlen);

    /* Encrypt the plaintext to produce the ciphertext */
    gimli24_masked_encrypt(state, c, m, mlen);

    /* Generate the authentication tag at the end of the ciphertext */
    c += mlen;
    le_store_word32(c,      mask_output(state[0]));
    le_store_word32(c + 4,  mask_output(state[1]));
    le_store_word32(c + 8,  mask_output(state[2]));
    le_store_word32(c + 12, mask_output(state[3]));
    return 0;
}

int gimli24_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    mask_uint32_t state[12];
    unsigned char tag[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < GIMLI24_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - GIMLI24_MASKED_TAG_SIZE;

    /* Format the initial GIMLI state from the nonce and the key */
    gimli24_masked_init(state, k, npub);

    /* Absorb the associated data */
    gimli24_masked_absorb(state, ad, adlen);

    /* Decrypt the ciphertext to produce the plaintext */
    gimli24_masked_decrypt(state, m, c, *mlen);

    /* Check the authentication tag at the end of the packet */
    le_store_word32(tag,      mask_output(state[0]));
    le_store_word32(tag + 4,  mask_output(state[1]));
    le_store_word32(tag + 8,  mask_output(state[2]));
    le_store_word32(tag + 12, mask_output(state[3]));
    return aead_check_tag(m, *mlen, tag, c + *mlen, GIMLI24_MASKED_TAG_SIZE);
}

#endif /* !AEAD_MASKING_KEY_ONLY */
