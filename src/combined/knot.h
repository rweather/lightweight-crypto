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

#ifndef LWCRYPTO_KNOT_H
#define LWCRYPTO_KNOT_H

#include "aead-common.h"

/**
 * \file knot.h
 * \brief KNOT authenticated encryption and hash algorithms.
 *
 * KNOT is a family of authenticated encryption and hash algorithms built
 * around a permutation and the MonkeyDuplex sponge construction.  The
 * family members are:
 *
 * \li KNOT-AEAD-128-256 with a 128-bit key, a 128-bit nonce, and a
 * 128-bit tag, built around a 256-bit permutation.  This is the primary
 * encryption member of the family.
 * \li KNOT-AEAD-128-384 with a 128-bit key, a 128-bit nonce, and a
 * 128-bit tag, built around a 384-bit permutation.
 * \li KNOT-AEAD-192-384 with a 192-bit key, a 192-bit nonce, and a
 * 192-bit tag, built around a 384-bit permutation.
 * \li KNOT-AEAD-256-512 with a 256-bit key, a 256-bit nonce, and a
 * 256-bit tag, built around a 512-bit permutation.
 * \li KNOT-HASH-256-256 with a 256-bit hash output, built around a
 * 256-bit permutation.  This is the primary hashing member of the family.
 * \li KNOT-HASH-256-384 with a 256-bit hash output, built around a
 * 384-bit permutation.
 * \li KNOT-HASH-384-384 with a 384-bit hash output, built around a
 * 384-bit permutation.
 * \li KNOT-HASH-512-512 with a 512-bit hash output, built around a
 * 512-bit permutation.
 *
 * References: https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/knot-spec-round.pdf
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for KNOT-AEAD-128-256 and KNOT-AEAD-128-384.
 */
#define KNOT_AEAD_128_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for KNOT-AEAD-128-256 and
 * KNOT-AEAD-128-384.
 */
#define KNOT_AEAD_128_TAG_SIZE 16

/**
 * \brief Size of the nonce for KNOT-AEAD-128-256 and KNOT-AEAD-128-384.
 */
#define KNOT_AEAD_128_NONCE_SIZE 16

/**
 * \brief Size of the key for KNOT-AEAD-192-384.
 */
#define KNOT_AEAD_192_KEY_SIZE 24

/**
 * \brief Size of the authentication tag for KNOT-AEAD-192-384.
 */
#define KNOT_AEAD_192_TAG_SIZE 24

/**
 * \brief Size of the nonce for KNOT-AEAD-128-256 and KNOT-AEAD-192-384.
 */
#define KNOT_AEAD_192_NONCE_SIZE 24

/**
 * \brief Size of the key for KNOT-AEAD-256-512.
 */
#define KNOT_AEAD_256_KEY_SIZE 32

/**
 * \brief Size of the authentication tag for KNOT-AEAD-256-512.
 */
#define KNOT_AEAD_256_TAG_SIZE 32

/**
 * \brief Size of the nonce for KNOT-AEAD-128-256 and KNOT-AEAD-128-384.
 */
#define KNOT_AEAD_256_NONCE_SIZE 32

/**
 * \brief Size of the hash for KNOT-HASH-256-256 and KNOT-HASH-256-384.
 */
#define KNOT_HASH_256_SIZE 32

/**
 * \brief Size of the hash for KNOT-HASH-384-384.
 */
#define KNOT_HASH_384_SIZE 48

/**
 * \brief Size of the hash for KNOT-HASH-512-512.
 */
#define KNOT_HASH_512_SIZE 64

/**
 * \brief Meta-information block for the KNOT-AEAD-128-256 cipher.
 */
extern aead_cipher_t const knot_aead_128_256_cipher;

/**
 * \brief Meta-information block for the KNOT-AEAD-128-384 cipher.
 */
extern aead_cipher_t const knot_aead_128_384_cipher;

/**
 * \brief Meta-information block for the KNOT-AEAD-192-384 cipher.
 */
extern aead_cipher_t const knot_aead_192_384_cipher;

/**
 * \brief Meta-information block for the KNOT-AEAD-256-512 cipher.
 */
extern aead_cipher_t const knot_aead_256_512_cipher;

/**
 * \brief Meta-information block for the KNOT-HASH-256-256 algorithm.
 */
extern aead_hash_algorithm_t const knot_hash_256_256_algorithm;

/**
 * \brief Meta-information block for the KNOT-HASH-256-384 algorithm.
 */
extern aead_hash_algorithm_t const knot_hash_256_384_algorithm;

/**
 * \brief Meta-information block for the KNOT-HASH-384-384 algorithm.
 */
extern aead_hash_algorithm_t const knot_hash_384_384_algorithm;

/**
 * \brief Meta-information block for the KNOT-HASH-512-512 algorithm.
 */
extern aead_hash_algorithm_t const knot_hash_512_512_algorithm;

/**
 * \brief Encrypts and authenticates a packet with KNOT-AEAD-128-256.
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
 * \sa knot_aead_128_256_decrypt()
 */
int knot_aead_128_256_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with KNOT-AEAD-128-256.
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
 * \sa knot_aead_128_256_encrypt()
 */
int knot_aead_128_256_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with KNOT-AEAD-128-384.
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
 * \sa knot_aead_128_384_decrypt()
 */
int knot_aead_128_384_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with KNOT-AEAD-128-384.
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
 * \sa knot_aead_128_384_encrypt()
 */
int knot_aead_128_384_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);


/**
 * \brief Encrypts and authenticates a packet with KNOT-AEAD-192-384.
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
 * \sa knot_aead_192_384_decrypt()
 */
int knot_aead_192_384_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with KNOT-AEAD-192-384.
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
 * \sa knot_aead_192_384_encrypt()
 */
int knot_aead_192_384_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with KNOT-AEAD-256-512.
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
 * \sa knot_aead_256_512_decrypt()
 */
int knot_aead_256_512_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with KNOT-AEAD-256-512.
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
 * \sa knot_aead_256_512_encrypt()
 */
int knot_aead_256_512_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with KNOT-HASH-256-256.
 *
 * \param out Buffer to receive the hash output which must be at least
 * KNOT_HASH_256_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int knot_hash_256_256
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Hashes a block of input data with KNOT-HASH-256-384.
 *
 * \param out Buffer to receive the hash output which must be at least
 * KNOT_HASH_256_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int knot_hash_256_384
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Hashes a block of input data with KNOT-HASH-384-384.
 *
 * \param out Buffer to receive the hash output which must be at least
 * KNOT_HASH_384_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int knot_hash_384_384
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Hashes a block of input data with KNOT-HASH-512-512.
 *
 * \param out Buffer to receive the hash output which must be at least
 * KNOT_HASH_512_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int knot_hash_512_512
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif

#endif
