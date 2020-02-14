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

#ifndef LWCRYPTO_PHOTON_BEETLE_H
#define LWCRYPTO_PHOTON_BEETLE_H

#include "aead-common.h"

/**
 * \file photon-beetle.h
 * \brief PHOTON-Beetle authenticated encryption algorithm.
 *
 * PHOTON-Beetle is a family of authenticated encryption algorithms based
 * on the PHOTON-256 permutation and using the Beetle sponge mode.
 * There are three algorithms in the family:
 *
 * \li PHOTON-Beetle-AEAD-ENC-128 with a 128-bit key, a 128-bit nonce, and a
 * 128-bit tag.  Data is handled in 16 byte blocks.  This is the primary
 * member of the family for encryption.
 * \li PHOTON-Beetle-AEAD-ENC-32 with a 128-bit key, a 128-bit nonce, and a
 * 128-bit tag.  Data is handled in 4 byte blocks.
 * \li PHOTON-Beetle-Hash with a 256-bit hash output.  The initial data is
 * handled as a 16 byte block, and then the remaining bytes are processed
 * in 4 byte blocks.
 *
 * References: https://www.isical.ac.in/~lightweight/beetle/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for PHOTON-Beetle.
 */
#define PHOTON_BEETLE_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for PHOTON-Beetle.
 */
#define PHOTON_BEETLE_TAG_SIZE 16

/**
 * \brief Size of the nonce for PHOTON-Beetle.
 */
#define PHOTON_BEETLE_NONCE_SIZE 16

/**
 * \brief Size of the hahs output for PHOTON-Beetle-HASH.
 */
#define PHOTON_BEETLE_HASH_SIZE 32

/**
 * \brief Meta-information block for the PHOTON-Beetle-AEAD-ENC-128 cipher.
 */
extern aead_cipher_t const photon_beetle_128_cipher;

/**
 * \brief Meta-information block for the PHOTON-Beetle-AEAD-ENC-32 cipher.
 */
extern aead_cipher_t const photon_beetle_32_cipher;

/**
 * \brief Meta-information block for the PHOTON-Beetle-HASH algorithm.
 */
extern aead_hash_algorithm_t const photon_beetle_hash_algorithm;

/**
 * \brief Encrypts and authenticates a packet with PHOTON-Beetle-AEAD-ENC-128.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
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
 * \sa photon_beetle_128_aead_decrypt()
 */
int photon_beetle_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with PHOTON-Beetle-AEAD-ENC-128.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
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
 * \sa photon_beetle_128_aead_encrypt()
 */
int photon_beetle_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with PHOTON-Beetle-AEAD-ENC-32.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 16 byte authentication tag.
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
 * \sa photon_beetle_32_aead_decrypt()
 */
int photon_beetle_32_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with PHOTON-Beetle-AEAD-ENC-32.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 16 byte authentication tag.
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
 * \sa photon_beetle_32_aead_encrypt()
 */
int photon_beetle_32_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with PHOTON-Beetle-HASH to
 * generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * PHOTON_BEETLE_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int photon_beetle_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif

#endif
