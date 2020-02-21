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

#ifndef LWCRYPTO_SUBTERRANEAN_H
#define LWCRYPTO_SUBTERRANEAN_H

#include "aead-common.h"

/**
 * \file subterranean.h
 * \brief Subterranean authenticated encryption algorithm.
 *
 * Subterranean (technically "Subterranean 2.0") is a family of
 * algorithms built around the 257-bit Subterranean permutation:
 *
 * \li Subterranean is an authenticated encryption algorithm with a 128-bit
 * key, a 128-bit nonce, and a 128-bit tag.
 * \li Subterranean-Hash is a hash algorithm with a 256-bit output.
 *
 * The Subterranean permutation is intended for hardware implementation.
 * It is not structured for efficient software implementation.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for Subterranean.
 */
#define SUBTERRANEAN_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for Subterranean.
 */
#define SUBTERRANEAN_TAG_SIZE 16

/**
 * \brief Size of the nonce for Subterranean.
 */
#define SUBTERRANEAN_NONCE_SIZE 16

/**
 * \brief Size of the hash output for Subterranean-Hash.
 */
#define SUBTERRANEAN_HASH_SIZE 32

/**
 * \brief Meta-information block for the Subterranean cipher.
 */
extern aead_cipher_t const subterranean_cipher;

/**
 * \brief Meta-information block for the SUBTERRANEAN hash algorithm.
 */
extern aead_hash_algorithm_t const subterranean_hash_algorithm;

/**
 * \brief State information for the Subterreaan incremental hash mode.
 */
typedef union
{
    unsigned char state[40];    /**< Current hash state */
    unsigned long long align;   /**< For alignment of this structure */

} subterranean_hash_state_t;

/**
 * \brief Encrypts and authenticates a packet with Subterranean.
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
 * \sa subterranean_aead_decrypt()
 */
int subterranean_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Subterranean.
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
 * \sa subterranean_aead_encrypt()
 */
int subterranean_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with Subterranean.
 *
 * \param out Buffer to receive the hash output which must be at least
 * SUBTERRANEAN_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa subterranean_hash_init()
 */
int subterranean_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for a Subterranean hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa subterranean_hash_update(), subterranean_hash_finalize(),
 * subterranean_hash()
 */
void subterranean_hash_init(subterranean_hash_state_t *state);

/**
 * \brief Updates a Subterranean state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa subterranean_hash_init(), subterranean_hash_finalize()
 */
void subterranean_hash_update
    (subterranean_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from a Subterranean hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa subterranean_hash_init(), subterranean_hash_update()
 */
void subterranean_hash_finalize
    (subterranean_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
