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

#ifndef LWCRYPTO_SPARKLE_H
#define LWCRYPTO_SPARKLE_H

#include "aead-common.h"

/**
 * \file sparkle.h
 * \brief Encryption and hash algorithms based on the SPARKLE permutation.
 *
 * SPARKLE is a family of encryption and hash algorithms that are based
 * around the SPARKLE permutation.  There are three versions of the
 * permutation with 256-bit, 384-bit, and 512-bit state sizes.
 * The algorithms in the family are:
 *
 * \li Schwaemm256-128 with a 128-bit key, a 256-bit nonce, and a 128-bit tag.
 * This is the primary encryption algorithm in the family.
 * \li Schwaemm192-192 with a 192-bit key, a 192-bit nonce, and a 192-bit tag.
 * \li Schwaemm128-128 with a 128-bit key, a 128-bit nonce, and a 128-bit tag.
 * \li Schwaemm256-256 with a 256-bit key, a 256-bit nonce, and a 256-bit tag.
 * \li Esch256 hash algorithm with a 256-bit digest output.  This is the
 * primary hash algorithm in the family.
 * \li Esch384 hash algorithm with a 384-bit digest output.
 *
 * References: https://www.cryptolux.org/index.php/Sparkle
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_TAG_SIZE 16

/**
 * \brief Size of the nonce for Schwaemm256-128.
 */
#define SCHWAEMM_256_128_NONCE_SIZE 32

/**
 * \brief Size of the key for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_KEY_SIZE 24

/**
 * \brief Size of the authentication tag for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_TAG_SIZE 24

/**
 * \brief Size of the nonce for Schwaemm192-192.
 */
#define SCHWAEMM_192_192_NONCE_SIZE 24

/**
 * \brief Size of the key for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_TAG_SIZE 16

/**
 * \brief Size of the nonce for Schwaemm128-128.
 */
#define SCHWAEMM_128_128_NONCE_SIZE 16

/**
 * \brief Size of the key for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_KEY_SIZE 32

/**
 * \brief Size of the authentication tag for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_TAG_SIZE 32

/**
 * \brief Size of the nonce for Schwaemm256-256.
 */
#define SCHWAEMM_256_256_NONCE_SIZE 32

/**
 * \brief Size of the hash output for Esch256.
 */
#define ESCH_256_HASH_SIZE 32

/**
 * \brief Size of the hash output for Esch384.
 */
#define ESCH_384_HASH_SIZE 48

/**
 * \brief Meta-information block for the Schwaemm256-128 cipher.
 */
extern aead_cipher_t const schwaemm_256_128_cipher;

/**
 * \brief Meta-information block for the Schwaemm192-192 cipher.
 */
extern aead_cipher_t const schwaemm_192_192_cipher;

/**
 * \brief Meta-information block for the Schwaemm128-128 cipher.
 */
extern aead_cipher_t const schwaemm_128_128_cipher;

/**
 * \brief Meta-information block for the Schwaemm256-256 cipher.
 */
extern aead_cipher_t const schwaemm_256_256_cipher;

/**
 * \brief Meta-information block for the Esch256 hash algorithm.
 */
extern aead_hash_algorithm_t const esch_256_hash_algorithm;

/**
 * \brief Meta-information block for the Esch384 hash algorithm.
 */
extern aead_hash_algorithm_t const esch_384_hash_algorithm;

/**
 * \brief State information for the Esch256 incremental hash mode.
 */
typedef union
{
    struct {
        unsigned char state[48];    /**< Current hash state */
        unsigned char block[16];    /**< Partial input data block */
        unsigned char count;        /**< Number of bytes in the current block */
    } s;                            /**< State */
    unsigned long long align;       /**< For alignment of this structure */

} esch_256_hash_state_t;

/**
 * \brief State information for the Esch384 incremental hash mode.
 */
typedef union
{
    struct {
        unsigned char state[64];    /**< Current hash state */
        unsigned char block[16];    /**< Partial input data block */
        unsigned char count;        /**< Number of bytes in the current block */
    } s;                            /**< State */
    unsigned long long align;       /**< For alignment of this structure */

} esch_384_hash_state_t;

/**
 * \brief Encrypts and authenticates a packet with Schwaemm256-128.
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
 * be 32 bytes in length.
 * \param k Points to the 16 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa schwaemm_256_128_aead_decrypt()
 */
int schwaemm_256_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Schwaemm256-128.
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
 * be 32 bytes in length.
 * \param k Points to the 16 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa schwaemm_256_128_aead_encrypt()
 */
int schwaemm_256_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with Schwaemm192-192.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 24 byte authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 24 bytes in length.
 * \param k Points to the 24 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa schwaemm_192_192_aead_decrypt()
 */
int schwaemm_192_192_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Schwaemm192-192.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 24 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 24 bytes in length.
 * \param k Points to the 24 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa schwaemm_192_192_aead_encrypt()
 */
int schwaemm_192_192_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with Schwaemm128-128.
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
 * \sa schwaemm_128_128_aead_decrypt()
 */
int schwaemm_128_128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Schwaemm128-128.
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
 * \sa schwaemm_128_128_aead_encrypt()
 */
int schwaemm_128_128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with Schwaemm256-256.
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
 * \sa schwaemm_256_256_aead_decrypt()
 */
int schwaemm_256_256_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Schwaemm256-256.
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
 * \sa schwaemm_256_256_aead_encrypt()
 */
int schwaemm_256_256_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with Esch256 to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ESCH_256_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int esch_256_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an Esch256 hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa esch_256_hash_update(), esch_256_hash_finalize(), esch_256_hash()
 */
void esch_256_hash_init(esch_256_hash_state_t *state);

/**
 * \brief Updates an Esch256 state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa esch_256_hash_init(), esch_256_hash_finalize()
 */
void esch_256_hash_update
    (esch_256_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an Esch256 hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa esch_256_hash_init(), esch_256_hash_update()
 */
void esch_256_hash_finalize
    (esch_256_hash_state_t *state, unsigned char *out);

/**
 * \brief Hashes a block of input data with Esch384 to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ESCH_384_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int esch_384_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an Esch384 hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa esch_384_hash_update(), esch_384_hash_finalize(), esch_384_hash()
 */
void esch_384_hash_init(esch_384_hash_state_t *state);

/**
 * \brief Updates an Esch384 state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa esch_384_hash_init(), esch_384_hash_finalize()
 */
void esch_384_hash_update
    (esch_384_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an Esch384 hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 48-byte hash value.
 *
 * \sa esch_384_hash_init(), esch_384_hash_update()
 */
void esch_384_hash_finalize
    (esch_384_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
