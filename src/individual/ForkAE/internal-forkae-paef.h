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
 * is included to configure the underlying ForkAE PAEF variant.
 *
 * FORKAE_ALG_NAME        Name of the FORKAE algorithm; e.g. forkae_paef_128_256
 * FORKAE_BLOCK_SIZE      Size of the block for the cipher (8 or 16 bytes).
 * FORKAE_NONCE_SIZE      Size of the nonce for the cipher in bytes.
 * FORKAE_COUNTER_SIZE    Size of the counter value for the cipher in bytes.
 * FORKAE_TWEAKEY_SIZE    Size of the tweakey for the underlying forked cipher.
 * FORKAE_BLOCK_FUNC      Name of the block function; e.g. forkskinny_128_256
 */
#if defined(FORKAE_ALG_NAME)

#define FORKAE_CONCAT_INNER(name,suffix) name##suffix
#define FORKAE_CONCAT(name,suffix) FORKAE_CONCAT_INNER(name,suffix)

/* Limit on the amount of data we can process based on the counter size */
#define FORKAE_PAEF_DATA_LIMIT  \
    ((unsigned long long)((1ULL << (FORKAE_COUNTER_SIZE * 8)) * \
                          (FORKAE_BLOCK_SIZE / 8)) - FORKAE_BLOCK_SIZE)

/* Processes the associated data in PAEF mode */
STATIC_INLINE void FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)
    (unsigned char tweakey[FORKAE_TWEAKEY_SIZE],
     unsigned long long counter, unsigned char domain)
{
    unsigned posn;
    counter |= (((unsigned long long)domain) << (FORKAE_COUNTER_SIZE * 8 - 3));
    for (posn = 0; posn < FORKAE_COUNTER_SIZE; ++posn) {
        tweakey[16 + FORKAE_NONCE_SIZE + FORKAE_COUNTER_SIZE - 1 - posn] =
            (unsigned char)counter;
        counter >>= 8;
    }
}

/* Check that the last block is padded correctly; -1 if ok, 0 if not */
STATIC_INLINE int FORKAE_CONCAT(FORKAE_ALG_NAME,_is_padding)
    (const unsigned char *block, unsigned len)
{
    int check = block[0] ^ 0x80;
    while (len > 1) {
        --len;
        check |= block[len];
    }
    return (check - 1) >> 8;
}

int FORKAE_CONCAT(FORKAE_ALG_NAME,_aead_encrypt)
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char tweakey[FORKAE_TWEAKEY_SIZE];
    unsigned char tag[FORKAE_BLOCK_SIZE];
    unsigned char block[FORKAE_BLOCK_SIZE];
    unsigned long long counter;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + FORKAE_BLOCK_SIZE;

    /* Validate the size of the associated data and plaintext as there
     * is a limit on the size of the PAEF counter field */
    if (adlen > FORKAE_PAEF_DATA_LIMIT || mlen > FORKAE_PAEF_DATA_LIMIT)
        return -2;

    /* Format the initial tweakey with the key and nonce */
    memcpy(tweakey, k, 16);
    memcpy(tweakey + 16, npub, FORKAE_NONCE_SIZE);
    memset(tweakey + 16 + FORKAE_NONCE_SIZE, 0,
           FORKAE_TWEAKEY_SIZE - 16 - FORKAE_NONCE_SIZE);

    /* Tag value starts at zero.  We will XOR this with all of the
     * intermediate tag values that are calculated for each block */
    memset(tag, 0, sizeof(tag));

    /* Process the associated data */
    counter = 1;
    while (adlen > FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 0);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, block, ad);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
        ad += FORKAE_BLOCK_SIZE;
        adlen -= FORKAE_BLOCK_SIZE;
        ++counter;
    }
    if (adlen == FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 1);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, block, ad);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
    } else if (adlen != 0 || mlen == 0) {
        unsigned temp = (unsigned)adlen;
        memcpy(block, ad, temp);
        block[temp] = 0x80;
        memset(block + temp + 1, 0, sizeof(block) - temp - 1);
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 3);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, block, block);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
    }

    /* If there is no message payload, then generate the tag and we are done */
    if (!mlen) {
        memcpy(c, tag, sizeof(tag));
        return 0;
    }

    /* Encrypt all plaintext blocks except the last */
    counter = 1;
    while (mlen > FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 4);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, c, block, m);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
        c += FORKAE_BLOCK_SIZE;
        m += FORKAE_BLOCK_SIZE;
        mlen -= FORKAE_BLOCK_SIZE;
        ++counter;
    }

    /* Encrypt the last block and generate the final authentication tag */
    if (mlen == FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 5);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, c, block, m);
        lw_xor_block(c, tag, FORKAE_BLOCK_SIZE);
        memcpy(c + FORKAE_BLOCK_SIZE, block, FORKAE_BLOCK_SIZE);
    } else {
        unsigned temp = (unsigned)mlen;
        memcpy(block, m, temp);
        block[temp] = 0x80;
        memset(block + temp + 1, 0, sizeof(block) - temp - 1);
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 7);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, c, block, block);
        lw_xor_block(c, tag, FORKAE_BLOCK_SIZE);
        memcpy(c + FORKAE_BLOCK_SIZE, block, temp);
    }
    return 0;
}

int FORKAE_CONCAT(FORKAE_ALG_NAME,_aead_decrypt)
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char tweakey[FORKAE_TWEAKEY_SIZE];
    unsigned char tag[FORKAE_BLOCK_SIZE];
    unsigned char block[FORKAE_BLOCK_SIZE];
    unsigned char *mtemp = m;
    unsigned long long counter;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < FORKAE_BLOCK_SIZE)
        return -1;
    clen -= FORKAE_BLOCK_SIZE;
    *mlen = clen;

    /* Validate the size of the associated data and plaintext as there
     * is a limit on the size of the PAEF counter field */
    if (adlen > FORKAE_PAEF_DATA_LIMIT || clen > FORKAE_PAEF_DATA_LIMIT)
        return -2;

    /* Format the initial tweakey with the key and nonce */
    memcpy(tweakey, k, 16);
    memcpy(tweakey + 16, npub, FORKAE_NONCE_SIZE);
    memset(tweakey + 16 + FORKAE_NONCE_SIZE, 0,
           FORKAE_TWEAKEY_SIZE - 16 - FORKAE_NONCE_SIZE);

    /* Tag value starts at zero.  We will XOR this with all of the
     * intermediate tag values that are calculated for each block */
    memset(tag, 0, sizeof(tag));

    /* Process the associated data */
    counter = 1;
    while (adlen > FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 0);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, block, ad);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
        ad += FORKAE_BLOCK_SIZE;
        adlen -= FORKAE_BLOCK_SIZE;
        ++counter;
    }
    if (adlen == FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 1);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, block, ad);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
    } else if (adlen != 0 || clen == 0) {
        unsigned temp = (unsigned)adlen;
        memcpy(block, ad, temp);
        block[temp] = 0x80;
        memset(block + temp + 1, 0, sizeof(block) - temp - 1);
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 3);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, block, block);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
    }

    /* If there is no message payload, then check the tag and we are done */
    if (!clen)
        return aead_check_tag(m, clen, tag, c, sizeof(tag));

    /* Decrypt all ciphertext blocks except the last */
    counter = 1;
    while (clen > FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 4);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_decrypt)(tweakey, m, block, c);
        lw_xor_block(tag, block, FORKAE_BLOCK_SIZE);
        c += FORKAE_BLOCK_SIZE;
        m += FORKAE_BLOCK_SIZE;
        clen -= FORKAE_BLOCK_SIZE;
        ++counter;
    }

    /* Decrypt the last block and check the final authentication tag */
    if (clen == FORKAE_BLOCK_SIZE) {
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 5);
        lw_xor_block_2_src(m, c, tag, FORKAE_BLOCK_SIZE);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_decrypt)(tweakey, m, block, m);
        return aead_check_tag
            (mtemp, *mlen, block, c + FORKAE_BLOCK_SIZE, sizeof(tag));
    } else {
        unsigned temp = (unsigned)clen;
        unsigned char block2[FORKAE_BLOCK_SIZE];
        int check;
        FORKAE_CONCAT(FORKAE_ALG_NAME,_set_counter)(tweakey, counter, 7);
        lw_xor_block_2_src(block2, tag, c, FORKAE_BLOCK_SIZE);
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_decrypt)
            (tweakey, block2, block, block2);
        check = FORKAE_CONCAT(FORKAE_ALG_NAME,_is_padding)
            (block2 + temp, FORKAE_BLOCK_SIZE - temp);
        memcpy(m, block2, temp);
        return aead_check_tag_precheck
            (mtemp, *mlen, block, c + FORKAE_BLOCK_SIZE, temp, check);
    }
}

#endif /* FORKAE_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the ForkAE PAEF algorithm */
#undef FORKAE_ALG_NAME
#undef FORKAE_BLOCK_SIZE
#undef FORKAE_NONCE_SIZE
#undef FORKAE_COUNTER_SIZE
#undef FORKAE_TWEAKEY_SIZE
#undef FORKAE_BLOCK_FUNC
#undef FORKAE_CONCAT_INNER
#undef FORKAE_CONCAT
#undef FORKAE_PAEF_DATA_LIMIT
