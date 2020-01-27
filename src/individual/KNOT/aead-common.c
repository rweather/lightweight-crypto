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

#include "aead-common.h"

/**
 * \brief Formats a nonce from a sequence number.
 *
 * \param aead The aead_cipher_t meta-information block for the AEAD cipher.
 * \param nonce Points to the nonce to be formatted.
 * \param seq_num The sequence number to format into the nonce.
 */
static void aead_format_nonce
    (const aead_cipher_t *aead, unsigned char *nonce,
     unsigned long long seq_num)
{
    unsigned index;
    if (aead->flags & AEAD_FLAG_LITTLE_ENDIAN) {
        for (index = 0; index < aead->nonce_len; ++index) {
            nonce[index] = (unsigned char)seq_num;
            seq_num >>= 8;
        }
    } else {
        for (index = aead->nonce_len; index > 0; --index) {
            nonce[index - 1] = (unsigned char)seq_num;
            seq_num >>= 8;
        }
    }
}

int aead_encrypt_packet
    (const aead_cipher_t *aead, unsigned char *ciphertext, int ciphertext_max,
     const unsigned char *plaintext, int plaintext_len,
     unsigned long long seq_num, const unsigned char *key, int key_len)
{
    unsigned char nonce[aead ? aead->nonce_len : 16];
    unsigned long long ciphertext_len;
    int result;

    /* Validate the parameters */
    if (!aead || !ciphertext || !key || plaintext_len < 0)
        return -1;
    if (ciphertext_max < (int)(aead->tag_len))
        return -1;
    if ((ciphertext_max - (int)(aead->tag_len)) < plaintext_len)
        return -1;
    if (!plaintext && plaintext_len)
        return -1;
    if (key_len != (int)(aead->key_len))
        return -1;

    /* Format the nonce value */
    aead_format_nonce(aead, nonce, seq_num);

    /* Encrypt the packet with the cipher.  Result is 0 if OK, or -1 on error */
    result = (*(aead->encrypt))
        (ciphertext, &ciphertext_len, plaintext, plaintext_len,
         0, 0, 0, nonce, key);

    /* Return the length of the ciphertext if OK, or -1 on error */
    return ((int)ciphertext_len) | result;
}

int aead_decrypt_packet
    (const aead_cipher_t *aead, unsigned char *plaintext, int plaintext_max,
     const unsigned char *ciphertext, int ciphertext_len,
     unsigned long long seq_num, const unsigned char *key, int key_len)
{
    unsigned char nonce[aead ? aead->nonce_len : 16];
    unsigned long long plaintext_len;
    int result;

    /* Validate the parameters */
    if (!aead || !ciphertext || !plaintext || !key)
        return -1;
    if (ciphertext_len < (int)(aead->tag_len))
        return -1;
    if (plaintext_max < (ciphertext_len - (int)(aead->tag_len)))
        return -1;
    if (key_len != (int)(aead->key_len))
        return -1;

    /* Format the nonce value */
    aead_format_nonce(aead, nonce, seq_num);

    /* Decrypt the packet with the cipher.  Result is 0 if OK, or -1 on error */
    result = (*(aead->decrypt))
        (plaintext, &plaintext_len, 0, ciphertext, ciphertext_len,
         0, 0, nonce, key);

    /* Return the length of the plaintext if OK, or -1 on error */
    return ((int)plaintext_len) | result;
}

int aead_check_tag
    (unsigned char *plaintext, unsigned long long plaintext_len,
     const unsigned char *tag1, const unsigned char *tag2,
     unsigned size)
{
    /* Set "accum" to -1 if the tags match, or 0 if they don't match */
    int accum = 0;
    while (size > 0) {
        accum |= (*tag1++ ^ *tag2++);
        --size;
    }
    accum = (accum - 1) >> 16;

    /* Destroy the plaintext if the tag match failed */
    while (plaintext_len > 0) {
        *plaintext++ &= accum;
        --plaintext_len;
    }

    /* If "accum" is 0, return -1, otherwise return 0 */
    return ~accum;
}
