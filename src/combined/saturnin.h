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

#ifndef LWCRYPTO_SATURNIN_H
#define LWCRYPTO_SATURNIN_H

#include "aead-common.h"

/**
 * \file saturnin.h
 * \brief Saturnin authenticated encryption algorithm.
 *
 * The Saturnin family consists of two members: SATURNIN-CTR-Cascade and
 * SATURNIN-Short.  Both take a 256-bit key and a 128-bit nonce.
 * Internally they use a 256-bit block cipher similar in construction to AES.
 *
 * SATURNIN-Short does not support associated data or plaintext packets
 * with more than 15 bytes.  This makes it very efficient on short packets
 * with only a single block operation involved.
 *
 * This implementation of SATURNIN-Short will return an error if the
 * caller supplies associated data or more than 15 bytes of plaintext.
 *
 * References: https://project.inria.fr/saturnin/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for all SATURNIN family members.
 */
#define SATURNIN_KEY_SIZE 32

/**
 * \brief Size of the authentication tag for SATURNIN-CTR-Cascade or the
 * total size of the ciphertext for SATURNIN-Short.
 */
#define SATURNIN_TAG_SIZE 32

/**
 * \brief Size of the nonce for all SATURNIN family members.
 */
#define SATURNIN_NONCE_SIZE 16

/**
 * \brief Size of the hash for SATURNIN-Hash.
 */
#define SATURNIN_HASH_SIZE 32

/**
 * \brief State information for SATURNIN-Hash incremental modes.
 */
typedef union
{
    struct {
        unsigned char hash[32];  /**< Current hash state */
        unsigned char block[32]; /**< Left-over block data from last update */
        unsigned char count;     /**< Number of bytes in the current block */
        unsigned char mode;      /**< Hash mode: 0 for absorb, 1 for squeeze */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} saturnin_hash_state_t;

/**
 * \brief Meta-information block for the SATURNIN-CTR-Cascade cipher.
 */
extern aead_cipher_t const saturnin_cipher;

/**
 * \brief Meta-information block for the SATURNIN-Short cipher.
 */
extern aead_cipher_t const saturnin_short_cipher;

/**
 * \brief Meta-information block for SATURNIN-Hash.
 */
extern aead_hash_algorithm_t const saturnin_hash_algorithm;

/**
 * \brief Encrypts and authenticates a packet with SATURNIN-CTR-Cascade.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the 32 byte authentication tag.
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
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa saturnin_aead_decrypt()
 */
int saturnin_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SATURNIN-CTR-Cascade.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the 32 byte authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 32 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa saturnin_aead_encrypt()
 */
int saturnin_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with SATURNIN-Short.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which is always 32.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes, which must be
 * less than or equal to 15 bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes, which must be zero.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 32 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or -2 if the caller supplied too many bytes of
 * plaintext or they supplied associated data.
 *
 * \sa saturnin_short_aead_decrypt()
 */
int saturnin_short_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with SATURNIN-Short.
 *
 * \param m Buffer to receive the plaintext message on output.  There must
 * be at least 15 bytes of space in this buffer even if the caller expects
 * to receive less data than that.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - not used by this algorithm.
 * \param c Buffer that contains the ciphertext to decrypt.
 * \param clen Length of the input data in bytes, which must be 32.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes, which must be zero.
 * \param npub Points to the public nonce for the packet which must
 * be 16 bytes in length.
 * \param k Points to the 32 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or -2 if the caller supplied associated data.
 *
 * \sa saturnin_short_aead_encrypt()
 */
int saturnin_short_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with SATURNIN to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * SATURNIN_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int saturnin_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an SATURNIN-Hash hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa saturnin_hash_update(), saturnin_hash_finalize(), saturnin_hash()
 */
void saturnin_hash_init(saturnin_hash_state_t *state);

/**
 * \brief Updates an SATURNIN-Hash state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa saturnin_hash_init(), saturnin_hash_finalize()
 */
void saturnin_hash_update
    (saturnin_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an SATURNIN-Hash hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa saturnin_hash_init(), saturnin_hash_update()
 */
void saturnin_hash_finalize
    (saturnin_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
