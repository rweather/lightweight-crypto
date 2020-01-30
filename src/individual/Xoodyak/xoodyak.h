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

#ifndef LWCRYPTO_XOODYAK_H
#define LWCRYPTO_XOODYAK_H

#include "aead-common.h"

/**
 * \file xoodyak.h
 * \brief Xoodyak authenticated encryption algorithm.
 *
 * Xoodyak is an authenticated encryption and hash algorithm pair based
 * around the 384-bit Xoodoo permutation that is similar in structure to
 * Keccak but is more efficient than Keccak on 32-bit embedded devices.
 * The Cyclist mode of operation is used to convert the permutation
 * into a sponge for the higher-level algorithms.
 *
 * The Xoodyak encryption mode has a 128-bit key, a 128-bit nonce,
 * and a 128-bit authentication tag.  The Xoodyak hashing mode has a
 * 256-bit fixed hash output and can also be used as an extensible
 * output function (XOF).
 *
 * The Xoodyak specification describes a re-keying mechanism where the
 * key for one packet is used to derive the key to use on the next packet.
 * This provides some resistance against side channel attacks by making
 * the session key a moving target.  This library does not currently
 * implement re-keying.
 *
 * References: https://keccak.team/xoodyak.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for Xoodyak.
 */
#define XOODYAK_KEY_SIZE 16

/**
 * \brief Size of the authentication tag for Xoodyak.
 */
#define XOODYAK_TAG_SIZE 16

/**
 * \brief Size of the nonce for Xoodyak.
 */
#define XOODYAK_NONCE_SIZE 16

/**
 * \brief Size of the hash output for Xoodyak.
 */
#define XOODYAK_HASH_SIZE 32

/**
 * \brief State information for Xoodyak incremental hashing modes.
 */
typedef union
{
    struct {
        unsigned char state[48]; /**< Current hash state */
        unsigned char count;     /**< Number of bytes in the current block */
        unsigned char mode;      /**< Hash mode: absorb or squeeze */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} xoodyak_hash_state_t;

/**
 * \brief Meta-information block for the Xoodyak cipher.
 */
extern aead_cipher_t const xoodyak_cipher;

/**
 * \brief Meta-information block for the Xoodyak hash algorithm.
 */
extern aead_hash_algorithm_t const xoodyak_hash_algorithm;

/**
 * \brief Encrypts and authenticates a packet with Xoodyak.
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
 * \sa xoodyak_aead_decrypt()
 */
int xoodyak_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with Xoodyak.
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
 * \sa xoodyak_aead_encrypt()
 */
int xoodyak_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with Xoodyak to generate a hash value.
 *
 * \param out Buffer to receive the hash output which must be at least
 * XOODYAK_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
int xoodyak_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for a Xoodyak hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa xoodyak_hash_absorb(), xoodyak_hash_squeeze(), xoodyak_hash()
 */
void xoodyak_hash_init(xoodyak_hash_state_t *state);

/**
 * \brief Aborbs more input data into a Xoodyak hashing state.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa xoodyak_hash_init(), xoodyak_hash_squeeze()
 */
void xoodyak_hash_absorb
    (xoodyak_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Squeezes output data from a Xoodyak hashing state.
 *
 * \param state Hash state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa xoodyak_hash_init(), xoodyak_hash_absorb()
 */
void xoodyak_hash_squeeze
    (xoodyak_hash_state_t *state, unsigned char *out,
     unsigned long long outlen);

/**
 * \brief Returns the final hash value from a Xoodyak hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the hash value.
 *
 * \note This is a wrapper around xoodyak_hash_squeeze() for a fixed length
 * of XOODYAK_HASH_SIZE bytes.
 *
 * \sa xoodyak_hash_init(), xoodyak_hash_absorb()
 */
void xoodyak_hash_finalize
    (xoodyak_hash_state_t *state, unsigned char *out);

#ifdef __cplusplus
}
#endif

#endif
