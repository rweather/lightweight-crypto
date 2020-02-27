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

#ifndef LWCRYPTO_FORKAE_H
#define LWCRYPTO_FORKAE_H

#include "aead-common.h"

/**
 * \file forkae.h
 * \brief ForkAE authenticated encryption algorithm family.
 *
 * ForkAE is a family of authenticated encryption algorithms based on a
 * modified version of the SKINNY tweakable block cipher.  The modifications
 * introduce "forking" where each input block produces two output blocks
 * for use in encryption and authentication.  There are six members in
 * the ForkAE family:
 *
 * \li PAEF-ForkSkinny-64-192 has a 128-bit key, a 48-bit nonce, and a
 * 64-bit authentication tag.  The associated data and plaintext are
 * limited to 2<sup>16</sup> bytes.
 * \li PAEF-ForkSkinny-128-192 has a 128-bit key, a 48-bit nonce, and a
 * 128-bit authentication tag.  The associated data and plaintext are
 * limited to 2<sup>17</sup> bytes.
 * \li PAEF-ForkSkinny-128-256 has a 128-bit key, a 112-bit nonce, and a
 * 128-bit authentication tag.  The associated data and plaintext are
 * limited to 2<sup>17</sup> bytes.
 * \li PAEF-ForkSkinny-128-288 has a 128-bit key, a 104-bit nonce, and a
 * 128-bit authentication tag.  The associated data and plaintext are
 * limited to 2<sup>57</sup> bytes.  This is the primary member of the family.
 * \li SAEF-ForkSkinny-128-192 has a 128-bit key, a 56-bit nonce, and a
 * 128-bit authentication tag.  The associated data and plaintext may be
 * unlimited in size.
 * \li SAEF-ForkSkinny-128-256 has a 128-bit key, a 120-bit nonce, and a
 * 128-bit authentication tag.  The associated data and plaintext may be
 * unlimited in size.
 *
 * The PAEF variants support parallel encryption and decryption for
 * higher throughput.  The SAEF variants encrypt or decrypt blocks
 * sequentially.
 *
 * ForkAE is designed to be efficient on small packet sizes so most of
 * the PAEF algorithms have a limit of 64k or 128k on the amount of
 * payload in a single packet.  Obviously the input can be split into
 * separate packets for larger amounts of data.
 *
 * References: https://www.esat.kuleuven.be/cosic/forkae/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for PAEF-ForkSkinny-64-192.
 */
#define FORKAE_PAEF_64_192_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for PAEF-ForkSkinny-64-192.
 */
#define FORKAE_PAEF_64_192_TAG_SIZE 8

/**
 * \brief Size of the nonce for PAEF-ForkSkinny-64-192.
 */
#define FORKAE_PAEF_64_192_NONCE_SIZE 6

/**
 * \brief Size of the key for PAEF-ForkSkinny-128-192.
 */
#define FORKAE_PAEF_128_192_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for PAEF-ForkSkinny-128-192.
 */
#define FORKAE_PAEF_128_192_TAG_SIZE 16

/**
 * \brief Size of the nonce for PAEF-ForkSkinny-128-192.
 */
#define FORKAE_PAEF_128_192_NONCE_SIZE 6

/**
 * \brief Size of the key for PAEF-ForkSkinny-128-256.
 */
#define FORKAE_PAEF_128_256_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for PAEF-ForkSkinny-128-256.
 */
#define FORKAE_PAEF_128_256_TAG_SIZE 16

/**
 * \brief Size of the nonce for PAEF-ForkSkinny-128-256.
 */
#define FORKAE_PAEF_128_256_NONCE_SIZE 14

/**
 * \brief Size of the key for PAEF-ForkSkinny-128-288.
 */
#define FORKAE_PAEF_128_288_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for PAEF-ForkSkinny-128-288.
 */
#define FORKAE_PAEF_128_288_TAG_SIZE 16

/**
 * \brief Size of the nonce for PAEF-ForkSkinny-128-288.
 */
#define FORKAE_PAEF_128_288_NONCE_SIZE 13

/**
 * \brief Size of the key for SAEF-ForkSkinny-128-192.
 */
#define FORKAE_SAEF_128_192_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for SAEF-ForkSkinny-128-192.
 */
#define FORKAE_SAEF_128_192_TAG_SIZE 16

/**
 * \brief Size of the nonce for SAEF-ForkSkinny-128-192.
 */
#define FORKAE_SAEF_128_192_NONCE_SIZE 7

/**
 * \brief Size of the key for SAEF-ForkSkinny-128-256.
 */
#define FORKAE_SAEF_128_256_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for SAEF-ForkSkinny-128-256.
 */
#define FORKAE_SAEF_128_256_TAG_SIZE 16

/**
 * \brief Size of the nonce for SAEF-ForkSkinny-128-256.
 */
#define FORKAE_SAEF_128_256_NONCE_SIZE 15

/**
 * \brief Meta-information block for the PAEF-ForkSkinny-64-192 cipher.
 */
extern aead_cipher_t const forkae_paef_64_192_cipher;

/**
 * \brief Meta-information block for the PAEF-ForkSkinny-128-192 cipher.
 */
extern aead_cipher_t const forkae_paef_128_192_cipher;

/**
 * \brief Meta-information block for the PAEF-ForkSkinny-128-256 cipher.
 */
extern aead_cipher_t const forkae_paef_128_256_cipher;

/**
 * \brief Meta-information block for the PAEF-ForkSkinny-128-288 cipher.
 */
extern aead_cipher_t const forkae_paef_128_288_cipher;

/**
 * \brief Meta-information block for the SAEF-ForkSkinny-128-192 cipher.
 */
extern aead_cipher_t const forkae_saef_128_192_cipher;

/**
 * \brief Meta-information block for the SAEF-ForkSkinny-128-256 cipher.
 */
extern aead_cipher_t const forkae_saef_128_256_cipher;

/**
 * \brief Encrypts and authenticates a packet with PAEF-ForkSkinny-64-192.
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
 * be 6 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa forkae_paef_64_192_aead_decrypt()
 */
int forkae_paef_64_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with PAEF-ForkSkinny-64-192.
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
 * be 6 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa forkae_paef_64_192_aead_encrypt()
 */
int forkae_paef_64_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with PAEF-ForkSkinny-128-192.
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
 * be 6 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa forkae_paef_128_192_aead_decrypt()
 */
int forkae_paef_128_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with PAEF-ForkSkinny-128-192.
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
 * be 6 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa forkae_paef_128_192_aead_encrypt()
 */
int forkae_paef_128_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with PAEF-ForkSkinny-128-256.
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
 * be 14 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa forkae_paef_128_256_aead_decrypt()
 */
int forkae_paef_128_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with PAEF-ForkSkinny-128-256.
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
 * be 14 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa forkae_paef_128_256_aead_encrypt()
 */
int forkae_paef_128_256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with PAEF-ForkSkinny-128-288.
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
 * be 13 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa forkae_paef_128_288_aead_decrypt()
 */
int forkae_paef_128_288_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with PAEF-ForkSkinny-128-288.
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
 * be 13 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa forkae_paef_128_288_aead_encrypt()
 */
int forkae_paef_128_288_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SAEF-ForkSkinny-128-192.
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
 * be 7 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa forkae_saef_128_192_aead_decrypt()
 */
int forkae_saef_128_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SAEF-ForkSkinny-128-192.
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
 * be 7 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa forkae_saef_128_192_aead_encrypt()
 */
int forkae_saef_128_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SAEF-ForkSkinny-128-256.
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
 * be 15 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa forkae_saef_128_256_aead_decrypt()
 */
int forkae_saef_128_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SAEF-ForkSkinny-128-256.
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
 * be 15 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa forkae_saef_128_256_aead_encrypt()
 */
int forkae_saef_128_256_aead_decrypt
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
