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

#ifndef LWCRYPTO_SKINNY_AEAD_H
#define LWCRYPTO_SKINNY_AEAD_H

#include "aead-common.h"

/**
 * \file skinny-aead.h
 * \brief Authenticated encryption based on the SKINNY block cipher.
 *
 * SKINNY-AEAD is a family of authenticated encryption algorithms
 * that are built around the SKINNY tweakable block cipher.  There
 * are six members in the family:
 *
 * \li SKINNY-AEAD-M1 has a 128-bit key, a 128-bit nonce, and a 128-bit tag,
 * based around the SKINNY-128-384 tweakable block cipher.  This is the
 * primary member of the family.
 * \li SKINNY-AEAD-M2 has a 128-bit key, a 96-bit nonce, and a 128-bit tag,
 * based around the SKINNY-128-384 tweakable block cipher.
 * \li SKINNY-AEAD-M3 has a 128-bit key, a 128-bit nonce, and a 64-bit tag,
 * based around the SKINNY-128-384 tweakable block cipher.
 * \li SKINNY-AEAD-M4 has a 128-bit key, a 96-bit nonce, and a 64-bit tag,
 * based around the SKINNY-128-384 tweakable block cipher.
 * \li SKINNY-AEAD-M5 has a 128-bit key, a 96-bit nonce, and a 128-bit tag,
 * based around the SKINNY-128-256 tweakable block cipher.
 * \li SKINNY-AEAD-M6 has a 128-bit key, a 96-bit nonce, and a 64-bit tag,
 * based around the SKINNY-128-256 tweakable block cipher.
 *
 * The SKINNY-AEAD family also includes two hash algorithms:
 *
 * \li SKINNY-tk3-HASH with a 256-bit hash output, based around the
 * SKINNY-128-384 tweakable block cipher.  This is the primary hashing
 * member of the family.
 * \li SKINNY-tk2-HASH with a 256-bit hash output, based around the
 * SKINNY-128-256 tweakable block cipher.
 *
 * References: https://sites.google.com/site/skinnycipher/home
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for all SKINNY-AEAD family members.
 */
#define SKINNY_AEAD_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for SKINNY-AEAD-M1.
 */
#define SKINNY_AEAD_M1_TAG_SIZE 16

/**
 * \brief Size of the nonce for SKINNY-AEAD-M1.
 */
#define SKINNY_AEAD_M1_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for SKINNY-AEAD-M2.
 */
#define SKINNY_AEAD_M2_TAG_SIZE 16

/**
 * \brief Size of the nonce for SKINNY-AEAD-M2.
 */
#define SKINNY_AEAD_M2_NONCE_SIZE 12

/**
 * \brief Size of the authentication tag for SKINNY-AEAD-M3.
 */
#define SKINNY_AEAD_M3_TAG_SIZE 8

/**
 * \brief Size of the nonce for SKINNY-AEAD-M3.
 */
#define SKINNY_AEAD_M3_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for SKINNY-AEAD-M4.
 */
#define SKINNY_AEAD_M4_TAG_SIZE 8

/**
 * \brief Size of the nonce for SKINNY-AEAD-M4.
 */
#define SKINNY_AEAD_M4_NONCE_SIZE 12

/**
 * \brief Size of the authentication tag for SKINNY-AEAD-M5.
 */
#define SKINNY_AEAD_M5_TAG_SIZE 16

/**
 * \brief Size of the nonce for SKINNY-AEAD-M5.
 */
#define SKINNY_AEAD_M5_NONCE_SIZE 12

/**
 * \brief Size of the authentication tag for SKINNY-AEAD-M6.
 */
#define SKINNY_AEAD_M6_TAG_SIZE 8

/**
 * \brief Size of the nonce for SKINNY-AEAD-M6.
 */
#define SKINNY_AEAD_M6_NONCE_SIZE 12

/**
 * \brief Meta-information block for the SKINNY-AEAD-M1 cipher.
 */
extern aead_cipher_t const skinny_aead_m1_cipher;

/**
 * \brief Meta-information block for the SKINNY-AEAD-M2 cipher.
 */
extern aead_cipher_t const skinny_aead_m2_cipher;

/**
 * \brief Meta-information block for the SKINNY-AEAD-M3 cipher.
 */
extern aead_cipher_t const skinny_aead_m3_cipher;

/**
 * \brief Meta-information block for the SKINNY-AEAD-M4 cipher.
 */
extern aead_cipher_t const skinny_aead_m4_cipher;

/**
 * \brief Meta-information block for the SKINNY-AEAD-M5 cipher.
 */
extern aead_cipher_t const skinny_aead_m5_cipher;

/**
 * \brief Meta-information block for the SKINNY-AEAD-M6 cipher.
 */
extern aead_cipher_t const skinny_aead_m6_cipher;

/**
 * \brief Encrypts and authenticates a packet with SKINNY-AEAD-M1.
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
 * \sa skinny_aead_m1_decrypt()
 */
int skinny_aead_m1_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SKINNY-AEAD-M1.
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
 * \sa skinny_aead_m1_encrypt()
 */
int skinny_aead_m1_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SKINNY-AEAD-M2.
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
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa skinny_aead_m2_decrypt()
 */
int skinny_aead_m2_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SKINNY-AEAD-M2.
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
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa skinny_aead_m2_encrypt()
 */
int skinny_aead_m2_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SKINNY-AEAD-M3.
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
 * \sa skinny_aead_m3_decrypt()
 */
int skinny_aead_m3_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SKINNY-AEAD-M3.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
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
 * \sa skinny_aead_m3_encrypt()
 */
int skinny_aead_m3_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SKINNY-AEAD-M4.
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
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa skinny_aead_m4_decrypt()
 */
int skinny_aead_m4_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SKINNY-AEAD-M4.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa skinny_aead_m4_encrypt()
 */
int skinny_aead_m4_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SKINNY-AEAD-M5.
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
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa skinny_aead_m5_decrypt()
 */
int skinny_aead_m5_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SKINNY-AEAD-M5.
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
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa skinny_aead_m5_encrypt()
 */
int skinny_aead_m5_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SKINNY-AEAD-M6.
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
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa skinny_aead_m6_decrypt()
 */
int skinny_aead_m6_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SKINNY-AEAD-M6.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 8 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 12 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa skinny_aead_m6_encrypt()
 */
int skinny_aead_m6_decrypt
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
