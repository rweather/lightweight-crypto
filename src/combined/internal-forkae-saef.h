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
 * is included to configure the underlying ForkAE SAEF variant.
 *
 * FORKAE_ALG_NAME        Name of the FORKAE algorithm; e.g. forkae_saef_128_256
 * FORKAE_BLOCK_SIZE      Size of the block for the cipher (8 or 16 bytes).
 * FORKAE_NONCE_SIZE      Size of the nonce for the cipher in bytes.
 * FORKAE_TWEAKEY_SIZE    Size of the tweakey for the underlying forked cipher.
 * FORKAE_REDUCED_TWEAKEY_SIZE Size of the reduced tweakey without padding.
 * FORKAE_BLOCK_FUNC      Name of the block function; e.g. forkskinny_128_256
 */
#if defined(FORKAE_ALG_NAME)

#define FORKAE_CONCAT_INNER(name,suffix) name##suffix
#define FORKAE_CONCAT(name,suffix) FORKAE_CONCAT_INNER(name,suffix)

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
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + FORKAE_BLOCK_SIZE;

    /* Format the initial tweakey with the key and nonce */
    memcpy(tweakey, k, 16);
    memcpy(tweakey + 16, npub, FORKAE_NONCE_SIZE);
    memset(tweakey + 16 + FORKAE_NONCE_SIZE, 0,
           FORKAE_TWEAKEY_SIZE - 16 - FORKAE_NONCE_SIZE);
    tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] = 0x08;

    /* Tag value starts at zero */
    memset(tag, 0, sizeof(tag));

    /* Process the associated data */
    if (adlen > 0 || mlen == 0) {
        while (adlen > FORKAE_BLOCK_SIZE) {
            lw_xor_block(tag, ad, FORKAE_BLOCK_SIZE);
            FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, tag, tag);
            memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
            ad += FORKAE_BLOCK_SIZE;
            adlen -= FORKAE_BLOCK_SIZE;
        }
        if (mlen == 0)
            tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x04;
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x02;
        if (adlen == FORKAE_BLOCK_SIZE) {
            lw_xor_block(tag, ad, FORKAE_BLOCK_SIZE);
            FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, tag, tag);
            memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
        } else if (adlen != 0 || mlen == 0) {
            unsigned temp = (unsigned)adlen;
            lw_xor_block(tag, ad, temp);
            tag[temp] ^= 0x80;
            tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x01;
            FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, tag, tag);
            memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
        }
    }

    /* If there is no message payload, then generate the tag and we are done */
    if (!mlen) {
        memcpy(c, tag, sizeof(tag));
        return 0;
    }

    /* Encrypt all plaintext blocks except the last */
    while (mlen > FORKAE_BLOCK_SIZE) {
        lw_xor_block_2_src(block, m, tag, FORKAE_BLOCK_SIZE);
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x01;
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, c, block, block);
        lw_xor_block(c, tag, FORKAE_BLOCK_SIZE);
        memcpy(tag, block, FORKAE_BLOCK_SIZE);
        memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
        c += FORKAE_BLOCK_SIZE;
        m += FORKAE_BLOCK_SIZE;
        mlen -= FORKAE_BLOCK_SIZE;
    }

    /* Encrypt the last block and generate the final authentication tag */
    if (mlen == FORKAE_BLOCK_SIZE) {
        lw_xor_block_2_src(block, m, tag, FORKAE_BLOCK_SIZE);
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x04;
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, c, block, block);
        lw_xor_block(c, tag, FORKAE_BLOCK_SIZE);
        memcpy(c + FORKAE_BLOCK_SIZE, block, FORKAE_BLOCK_SIZE);
    } else {
        unsigned temp = (unsigned)mlen;
        memcpy(block, tag, FORKAE_BLOCK_SIZE);
        lw_xor_block(block, m, temp);
        block[temp] ^= 0x80;
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x05;
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
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < FORKAE_BLOCK_SIZE)
        return -1;
    clen -= FORKAE_BLOCK_SIZE;
    *mlen = clen;

    /* Format the initial tweakey with the key and nonce */
    memcpy(tweakey, k, 16);
    memcpy(tweakey + 16, npub, FORKAE_NONCE_SIZE);
    memset(tweakey + 16 + FORKAE_NONCE_SIZE, 0,
           FORKAE_TWEAKEY_SIZE - 16 - FORKAE_NONCE_SIZE);
    tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] = 0x08;

    /* Tag value starts at zero */
    memset(tag, 0, sizeof(tag));

    /* Process the associated data */
    if (adlen > 0 || clen == 0) {
        while (adlen > FORKAE_BLOCK_SIZE) {
            lw_xor_block(tag, ad, FORKAE_BLOCK_SIZE);
            FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, tag, tag);
            memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
            ad += FORKAE_BLOCK_SIZE;
            adlen -= FORKAE_BLOCK_SIZE;
        }
        if (clen == 0)
            tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x04;
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x02;
        if (adlen == FORKAE_BLOCK_SIZE) {
            lw_xor_block(tag, ad, FORKAE_BLOCK_SIZE);
            FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, tag, tag);
            memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
        } else if (adlen != 0 || clen == 0) {
            unsigned temp = (unsigned)adlen;
            lw_xor_block(tag, ad, temp);
            tag[temp] ^= 0x80;
            tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x01;
            FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_encrypt)(tweakey, 0, tag, tag);
            memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
        }
    }

    /* If there is no message payload, then check the tag and we are done */
    if (!clen)
        return aead_check_tag(m, clen, tag, c, sizeof(tag));

    /* Decrypt all ciphertext blocks except the last */
    while (clen > FORKAE_BLOCK_SIZE) {
        lw_xor_block_2_src(block, c, tag, FORKAE_BLOCK_SIZE);
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x01;
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_decrypt)(tweakey, m, block, block);
        lw_xor_block(m, tag, FORKAE_BLOCK_SIZE);
        memcpy(tag, block, FORKAE_BLOCK_SIZE);
        memset(tweakey + 16, 0, FORKAE_TWEAKEY_SIZE - 16);
        c += FORKAE_BLOCK_SIZE;
        m += FORKAE_BLOCK_SIZE;
        clen -= FORKAE_BLOCK_SIZE;
    }

    /* Decrypt the last block and check the final authentication tag */
    if (clen == FORKAE_BLOCK_SIZE) {
        lw_xor_block_2_src(block, c, tag, FORKAE_BLOCK_SIZE);
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x04;
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_decrypt)(tweakey, m, block, block);
        lw_xor_block(m, tag, FORKAE_BLOCK_SIZE);
        return aead_check_tag
            (mtemp, *mlen, block, c + FORKAE_BLOCK_SIZE, FORKAE_BLOCK_SIZE);
    } else {
        unsigned temp = (unsigned)clen;
        unsigned char mblock[FORKAE_BLOCK_SIZE];
        int check;
        lw_xor_block_2_src(block, c, tag, FORKAE_BLOCK_SIZE);
        tweakey[FORKAE_TWEAKEY_REDUCED_SIZE - 1] ^= 0x05;
        FORKAE_CONCAT(FORKAE_BLOCK_FUNC,_decrypt)
            (tweakey, mblock, block, block);
        lw_xor_block(mblock, tag, FORKAE_BLOCK_SIZE);
        memcpy(m, mblock, temp);
        check = FORKAE_CONCAT(FORKAE_ALG_NAME,_is_padding)
            (mblock + temp, FORKAE_BLOCK_SIZE - temp);
        return aead_check_tag_precheck
            (mtemp, *mlen, block, c + FORKAE_BLOCK_SIZE, temp, check);
    }
}

#endif /* FORKAE_ALG_NAME */

/* Now undefine everything so that we can include this file again for
 * another variant on the ForkAE SAEF algorithm */
#undef FORKAE_ALG_NAME
#undef FORKAE_BLOCK_SIZE
#undef FORKAE_NONCE_SIZE
#undef FORKAE_COUNTER_SIZE
#undef FORKAE_TWEAKEY_SIZE
#undef FORKAE_TWEAKEY_REDUCED_SIZE
#undef FORKAE_BLOCK_FUNC
#undef FORKAE_CONCAT_INNER
#undef FORKAE_CONCAT
