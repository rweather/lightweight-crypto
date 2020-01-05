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

/* We expect a number of macros to be defined before this file
 * is included to configure the underlying ISAP variant.
 *
 * ISAP_ALG_NAME        Name of the ISAP algorithm; e.g. isap_keccak_128
 * ISAP_RATE            Number of bytes in the rate for hashing and encryption.
 * ISAP_sH              Number of rounds for hashing.
 * ISAP_sE              Number of rounds for encryption.
 * ISAP_sB              Number of rounds for key bit absorption.
 * ISAP_sK              Number of rounds for keying.
 * ISAP_STATE           Type for the permuation state; e.g. ascon_state_t
 * ISAP_PERMUTE(s,r)    Permutes the state "s" with number of rounds "r".
 */
#if defined(ISAP_ALG_NAME)

#define ISAP_CONCAT_INNER(name,suffix) name##suffix
#define ISAP_CONCAT(name,suffix) ISAP_CONCAT_INNER(name,suffix)

/* IV string for initialising the associated data */
static unsigned char const ISAP_CONCAT(ISAP_ALG_NAME,_IV_A)
        [sizeof(ISAP_STATE) - ISAP_NONCE_SIZE] = {
    0x01, ISAP_KEY_SIZE * 8, ISAP_RATE * 8, 1,
    ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK
};

/* IV string for authenticating associated data */
static unsigned char const ISAP_CONCAT(ISAP_ALG_NAME,_IV_KA)
        [sizeof(ISAP_STATE) - ISAP_KEY_SIZE] = {
    0x02, ISAP_KEY_SIZE * 8, ISAP_RATE * 8, 1,
    ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK
};

/* IV string for encrypting payload data */
static unsigned char const ISAP_CONCAT(ISAP_ALG_NAME,_IV_KE)
        [sizeof(ISAP_STATE) - ISAP_KEY_SIZE] = {
    0x03, ISAP_KEY_SIZE * 8, ISAP_RATE * 8, 1,
    ISAP_sH, ISAP_sB, ISAP_sE, ISAP_sK
};

/**
 * \brief Re-keys the ISAP permutation state.
 *
 * \param state The permutation state to be re-keyed.
 * \param k Points to the 128-bit key for the ISAP cipher.
 * \param iv Points to the initialization vector for this re-keying operation.
 * \param data Points to the data to be absorbed to perform the re-keying.
 * \param data_len Length of the data to be absorbed.
 *
 * The output key will be left in the leading bytes of \a state.
 */
static void ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
    (ISAP_STATE *state, const unsigned char *k, const unsigned char *iv,
     const unsigned char *data, unsigned data_len)
{
    unsigned bit, num_bits;

    /* Initialize the state with the key and IV */
    memcpy(state->B, k, ISAP_KEY_SIZE);
    memcpy(state->B + ISAP_KEY_SIZE, iv, sizeof(state->B) - ISAP_KEY_SIZE);
    ISAP_PERMUTE(state, ISAP_sK);

    /* Absorb all of the bits of the data buffer one by one */
    num_bits = data_len * 8 - 1;
    for (bit = 0; bit < num_bits; ++bit) {
        state->B[0] ^= (data[bit / 8] << (bit % 8)) & 0x80;
        ISAP_PERMUTE(state, ISAP_sB);
    }
    state->B[0] ^= (data[bit / 8] << (bit % 8)) & 0x80;
    ISAP_PERMUTE(state, ISAP_sK);
}

/**
 * \brief Encrypts (or decrypts) a message payload with ISAP.
 *
 * \param state ISAP permutation state.
 * \param k Points to the 128-bit key for the ISAP cipher.
 * \param npub Points to the 128-bit nonce for the ISAP cipher.
 * \param c Buffer to receive the output ciphertext.
 * \param m Buffer to receive the input plaintext.
 * \param mlen Length of the input plaintext.
 */
static void ISAP_CONCAT(ISAP_ALG_NAME,_encrypt)
    (ISAP_STATE *state, const unsigned char *k, const unsigned char *npub,
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    /* Set up the re-keyed encryption key and nonce in the state */
    ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
        (state, k, ISAP_CONCAT(ISAP_ALG_NAME,_IV_KE), npub, ISAP_NONCE_SIZE);
    memcpy(state->B + sizeof(ISAP_STATE) - ISAP_NONCE_SIZE,
           npub, ISAP_NONCE_SIZE);

    /* Encrypt the plaintext to produce the ciphertext */
    while (mlen >= ISAP_RATE) {
        ISAP_PERMUTE(state, ISAP_sE);
        lw_xor_block_2_src(c, state->B, m, ISAP_RATE);
        c += ISAP_RATE;
        m += ISAP_RATE;
        mlen -= ISAP_RATE;
    }
    if (mlen > 0) {
        ISAP_PERMUTE(state, ISAP_sE);
        lw_xor_block_2_src(c, state->B, m, (unsigned)mlen);
    }
}

/**
 * \brief Authenticates the associated data and ciphertext using ISAP.
 *
 * \param state ISAP permutation state.
 * \param k Points to the 128-bit key for the ISAP cipher.
 * \param npub Points to the 128-bit nonce for the ISAP cipher.
 * \param ad Buffer containing the associated data.
 * \param adlen Length of the associated data.
 * \param c Buffer containing the ciphertext.
 * \param clen Length of the ciphertext.
 */
static void ISAP_CONCAT(ISAP_ALG_NAME,_mac)
    (ISAP_STATE *state, const unsigned char *k, const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *c, unsigned long long clen,
     unsigned char *tag)
{
    unsigned char preserve[sizeof(ISAP_STATE) - ISAP_TAG_SIZE];
    unsigned temp;

    /* Absorb the associated data */
    memcpy(state->B, npub, ISAP_NONCE_SIZE);
    memcpy(state->B + ISAP_NONCE_SIZE, ISAP_CONCAT(ISAP_ALG_NAME,_IV_A),
           sizeof(state->B) - ISAP_NONCE_SIZE);
    ISAP_PERMUTE(state, ISAP_sH);
    while (adlen >= ISAP_RATE) {
        lw_xor_block(state->B, ad, ISAP_RATE);
        ISAP_PERMUTE(state, ISAP_sH);
        ad += ISAP_RATE;
        adlen -= ISAP_RATE;
    }
    temp = (unsigned)adlen;
    lw_xor_block(state->B, ad, temp);
    state->B[temp] ^= 0x80; /* padding */
    ISAP_PERMUTE(state, ISAP_sH);
    state->B[sizeof(state->B) - 1] ^= 0x01; /* domain separation */

    /* Absorb the ciphertext */
    while (clen >= ISAP_RATE) {
        lw_xor_block(state->B, c, ISAP_RATE);
        ISAP_PERMUTE(state, ISAP_sH);
        c += ISAP_RATE;
        clen -= ISAP_RATE;
    }
    temp = (unsigned)clen;
    lw_xor_block(state->B, c, temp);
    state->B[temp] ^= 0x80; /* padding */
    ISAP_PERMUTE(state, ISAP_sH);

    /* Re-key the state and generate the authentication tag */
    memcpy(tag, state->B, ISAP_TAG_SIZE);
    memcpy(preserve, state->B + ISAP_TAG_SIZE, sizeof(preserve));
    ISAP_CONCAT(ISAP_ALG_NAME,_rekey)
        (state, k, ISAP_CONCAT(ISAP_ALG_NAME,_IV_KA), tag, ISAP_TAG_SIZE);
    memcpy(state->B + ISAP_TAG_SIZE, preserve, sizeof(preserve));
    ISAP_PERMUTE(state, ISAP_sH);
    memcpy(tag, state->B, ISAP_TAG_SIZE);
}

int ISAP_CONCAT(ISAP_ALG_NAME,_aead_encrypt)
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    ISAP_STATE state;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ISAP_TAG_SIZE;

    /* Encrypt the plaintext to produce the ciphertext */
    ISAP_CONCAT(ISAP_ALG_NAME,_encrypt)(&state, k, npub, c, m, mlen);

    /* Authenticate the associated data and ciphertext to generate the tag */
    ISAP_CONCAT(ISAP_ALG_NAME,_mac)
        (&state, k, npub, ad, adlen, c, mlen, c + mlen);
    return 0;
}

int ISAP_CONCAT(ISAP_ALG_NAME,_aead_decrypt)
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    ISAP_STATE state;
    unsigned char tag[ISAP_TAG_SIZE];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ISAP_TAG_SIZE)
        return -1;
    *mlen = clen - ISAP_TAG_SIZE;

    /* Authenticate the associated data and ciphertext to generate the tag */
    ISAP_CONCAT(ISAP_ALG_NAME,_mac)(&state, k, npub, ad, adlen, c, *mlen, tag);

    /* Decrypt the ciphertext to produce the plaintext */
    ISAP_CONCAT(ISAP_ALG_NAME,_encrypt)(&state, k, npub, m, c, *mlen);

    /* Check the authentication tag */
    return aead_check_tag(m, *mlen, tag, c + *mlen, ISAP_TAG_SIZE);
}

#endif /* ISAP_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the ISAP algorithm */
#undef ISAP_ALG_NAME
#undef ISAP_RATE
#undef ISAP_sH
#undef ISAP_sE
#undef ISAP_sB
#undef ISAP_sK
#undef ISAP_STATE
#undef ISAP_PERMUTE
