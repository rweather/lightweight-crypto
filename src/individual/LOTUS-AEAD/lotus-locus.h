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

#ifndef LWCRYPTO_LOTUS_LOCUS_H
#define LWCRYPTO_LOTUS_LOCUS_H

#include "aead-common.h"

/**
 * \file lotus-locus.h
 * \brief LOTUS-AEAD and LOCUS-AEAD authenticated encryption algorithms.
 *
 * LOTUS-AEAD and LOCUS-AEAD are authenticated encryption algorithms
 * that are based around a tweakable variant of the GIFT-64 block cipher
 * called TweGIFT-64.  Both AEAD algorithms have a 128-bit key, a 128-bit
 * nonce, and a 64-bit tag.
 *
 * The two algorithms have the same key initialization, associated data
 * processing, and tag generation mechanisms.  They differ in how the
 * input is encrypted with TweGIFT-64.
 *
 * LOTUS-AEAD uses a method similar to the block cipher mode OTR.
 * TweGIFT-64 is essentially converted into a 128-bit block cipher
 * using a Feistel construction and four TweGIFT-64 block operations
 * every 16 bytes of input.
 *
 * LOCUS-AEAD uses a method similar to the block cipher mode OCB
 * with two TweGIFT-64 block operations for every 8 bytes of input.
 * LOCUS-AEAD requires both the block encrypt and block decrypt
 * operations of TweGIFT-64, which increases the overall code size.
 * LOTUS-AEAD only needs the block encrypt operation.
 *
 * LOTUS-AEAD is the primary member of the family.
 *
 * References: https://www.isical.ac.in/~lightweight/lotus/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for LOTUS-AEAD.
 */
#define LOTUS_AEAD_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for LOTUS-AEAD.
 */
#define LOTUS_AEAD_TAG_SIZE 8

/**
 * \brief Size of the nonce for LOTUS-AEAD.
 */
#define LOTUS_AEAD_NONCE_SIZE 16

/**
 * \brief Size of the key for LOCUS-AEAD.
 */
#define LOCUS_AEAD_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for LOCUS-AEAD.
 */
#define LOCUS_AEAD_TAG_SIZE 8

/**
 * \brief Size of the nonce for LOCUS-AEAD.
 */
#define LOCUS_AEAD_NONCE_SIZE 16

/**
 * \brief Meta-information block for the LOTUS-AEAD cipher.
 */
extern aead_cipher_t const lotus_aead_cipher;

/**
 * \brief Meta-information block for the LOCUS-AEAD cipher.
 */
extern aead_cipher_t const locus_aead_cipher;

/**
 * \brief Encrypts and authenticates a packet with LOTUS-AEAD.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa lotus_aead_decrypt()
 */
int lotus_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with LOTUS-AEAD.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 9 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa lotus_aead_encrypt()
 */
int lotus_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with LOCUS-AEAD.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 8 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa locus_aead_decrypt()
 */
int locus_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with LOCUS-AEAD.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 9 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa locus_aead_encrypt()
 */
int locus_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

#ifdef __cplusplus
}
#endif

#endif
