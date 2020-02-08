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

#ifndef LWCRYPTO_ACE_H
#define LWCRYPTO_ACE_H

#include "aead-common.h"

/**
 * \file ace.h
 * \brief ACE authenticated encryption algorithm.
 *
 * ACE is an authenticated encryption algorithm with a 128-bit key,
 * a 128-bit nonce, and a 128-bit tag.  It uses a duplex construction
 * on top of a 320-bit permutation.  The permutation is a generalised
 * version of sLiSCP-light, extended from 256 bits to 320 bits.
 * ACE also has a companion hash algorithm with a 256-bit output.
 *
 * References: https://uwaterloo.ca/communications-security-lab/lwc/ace
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for ACE.
 */
#define ACE_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for ACE.
 */
#define ACE_TAG_SIZE 16

/**
 * \brief Size of the nonce for ACE.
 */
#define ACE_NONCE_SIZE 16

/**
 * \brief Size of the hash output for ACE-HASH.
 */
#define ACE_HASH_SIZE 32

/**
 * \brief Meta-information block for the ACE cipher.
 */
extern aead_cipher_t const ace_cipher;

/**
 * \brief Meta-information block for the ACE-HASH hash algorithm.
 */
extern aead_hash_algorithm_t const ace_hash_algorithm;

/**
 * \brief State information for the ACE-HASH incremental hash mode.
 */
typedef union
{
    struct {
        unsigned char state[40]; /**< Current hash state */
        unsigned char count;     /**< Number of bytes in the current block */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} ace_hash_state_t;

/**
 * \brief Encrypts and authenticates a packet with ACE.
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
 * \sa ace_aead_decrypt()
 */
int ace_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with ACE.
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
 * \sa ace_aead_encrypt()
 */
int ace_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with ACE-HASH to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * ACE_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int ace_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an ACE-HASH hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa ace_hash_update(), ace_hash_finalize(), ace_hash()
 */
void ace_hash_init(ace_hash_state_t *state);

/**
 * \brief Updates the ACE-HASH state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa ace_hash_init(), ace_hash_finalize()
 */
void ace_hash_update
    (ace_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an ACE-HASH hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa ace_hash_init(), ace_hash_update()
 */
void ace_hash_finalize(ace_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
