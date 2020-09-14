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

#ifndef LWCRYPTO_DRYGASCON_H
#define LWCRYPTO_DRYGASCON_H

#include "aead-common.h"

/**
 * \file drygascon.h
 * \brief DryGASCON authenticated encryption algorithm.
 *
 * DryGASCON is a family of authenticated encryption algorithms based
 * around a generalised version of the ASCON permutation.  DryGASCON
 * is designed to provide some protection against power analysis.
 *
 * There are four algorithms in the DryGASCON family:
 *
 * \li DryGASCON128 is an authenticated encryption algorithm with a
 * 128-bit key, a 128-bit nonce, and a 128-bit authentication tag.
 * \li DryGASCON256 is an authenticated encryption algorithm with a
 * 256-bit key, a 128-bit nonce, and a 128-256 authentication tag.
 * \li DryGASCON128-HASH is a hash algorithm with a 256-bit output.
 * \li DryGASCON256-HASH is a hash algorithm with a 512-bit output.
 *
 * DryGASCON128 and DryGASCON128-HASH are the primary members of the family.
 *
 * References: https://github.com/sebastien-riou/DryGASCON
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Minimum Size of the key for DryGASCON128.
 */
#define DRYGASCON128_MINKEY_SIZE 16

/**
 * \brief Fast Size of the key for DryGASCON128.
 */
#define DRYGASCON128_FASTKEY_SIZE 32

/**
 * \brief Safe (and fast) Size of the key for DryGASCON128.
 * Safe here means the size of the key helps prevent SPA during key loading
 */
#define DRYGASCON128_SAFEKEY_SIZE 56

/**
 * \brief Size of the key for DryGASCON128 (default to "fast" size).
 */
#define DRYGASCON128_KEY_SIZE DRYGASCON128_FASTKEY_SIZE

/**
 * \brief Size of the authentication tag for DryGASCON128.
 */
#define DRYGASCON128_TAG_SIZE 16

/**
 * \brief Size of the nonce for DryGASCON128.
 */
#define DRYGASCON128_NONCE_SIZE 16

/**
 * \brief Size of the hash output for DryGASCON128-HASH.
 */
#define DRYGASCON128_HASH_SIZE 32

/**
 * \brief Size of the key for DryGASCON256.
 */
#define DRYGASCON256_KEY_SIZE 32

/**
 * \brief Size of the authentication tag for DryGASCON256.
 */
#define DRYGASCON256_TAG_SIZE 32

/**
 * \brief Size of the nonce for DryGASCON256.
 */
#define DRYGASCON256_NONCE_SIZE 16

/**
 * \brief Size of the hash output for DryGASCON256-HASH.
 */
#define DRYGASCON256_HASH_SIZE 64

/**
 * \brief Meta-information block for the DryGASCON128 cipher with 32 bytes key.
 */
extern aead_cipher_t const drygascon128k32_cipher;

/**
 * \brief Meta-information block for the DryGASCON128 cipher with 56 bytes key.
 */
extern aead_cipher_t const drygascon128k56_cipher;

/**
 * \brief Meta-information block for the DryGASCON128 cipher with 16 bytes key.
 */
extern aead_cipher_t const drygascon128k16_cipher;

/**
 * \brief Meta-information block for the DryGASCON128 cipher (default to 32 bytes key).
 */
extern aead_cipher_t const drygascon128_cipher;

/**
 * \brief Meta-information block for the DryGASCON256 cipher.
 */
extern aead_cipher_t const drygascon256_cipher;

/**
 * \brief Meta-information block for DryGASCON128-HASH.
 */
extern aead_hash_algorithm_t const drygascon128_hash_algorithm;

/**
 * \brief Meta-information block for DryGASCON256-HASH.
 */
extern aead_hash_algorithm_t const drygascon256_hash_algorithm;

/**
 * \brief Encrypts and authenticates a packet with DryGASCON128 with 32 bytes key.
 *
 *	Use this key size if SPA attacks are not a concern in your use case.
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
 * \param k Points to the 32 bytes of the key to use to encrypt the packet.
 *
 * Note that the function blocks if the 16 last bytes of the key are "invalid".
 * Here "invalid" means that 32 bit words shall be different from each other.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa drygascon128k32_aead_decrypt()
 */
int drygascon128k32_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with DryGASCON128 with 32 bytes key.
 *
 *	Use this key size if SPA attacks are not a concern in your use case.
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
 * \param k Points to the 32 bytes of the key to use to decrypt the packet.
 *
 * Note that the function blocks if the 16 last bytes of the key are "invalid".
 * Here "invalid" means that 32 bit words shall be different from each other.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa drygascon128k32_aead_encrypt()
 */
int drygascon128k32_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with DryGASCON128 with 56 bytes key.
 *
 *	Use this key size if you want to prevent SPA attacks
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
 * \param k Points to the 56 bytes of the key to use to encrypt the packet.
 *
 * Note that the function blocks if the 16 last bytes of the key are "invalid".
 * Here "invalid" means that 32 bit words shall be different from each other.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa drygascon128k56_aead_decrypt()
 */
int drygascon128k56_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with DryGASCON128 with 56 bytes key.
 *
 *	Use this key size if you want to prevent SPA attacks
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
 * \param k Points to the 56 bytes of the key to use to decrypt the packet.
 *
 * Note that the function blocks if the 16 last bytes of the key are "invalid".
 * Here "invalid" means that 32 bit words shall be different from each other.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa drygascon128k56_aead_encrypt()
 */
int drygascon128k56_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with DryGASCON128 with 16 bytes key.
 *
 *	Use this key size only if you really cannot use the 32 bytes key.
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
 * \sa drygascon128k16_aead_decrypt()
 */
int drygascon128k16_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with DryGASCON128 with 16 bytes key.
 *
 *	Use this key size only if you really cannot use the 32 bytes key.
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
 * \sa drygascon128k16_aead_encrypt()
 */
int drygascon128k16_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with DryGASCON256.
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
 * \sa drygascon256_aead_decrypt()
 */
int drygascon256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with DryGASCON256.
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
 * \sa drygascon256_aead_encrypt()
 */
int drygascon256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with DRYGASCON128.
 *
 * \param out Buffer to receive the hash output which must be at least
 * DRYGASCON128_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int drygascon128_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Hashes a block of input data with DRYGASCON256.
 *
 * \param out Buffer to receive the hash output which must be at least
 * DRYGASCON256_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int drygascon256_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

#ifdef __cplusplus
}
#endif

#endif
