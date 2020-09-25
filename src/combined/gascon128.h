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

#ifndef LWCRYPTO_GASCON_H
#define LWCRYPTO_GASCON_H

#include "aead-common.h"

/**
 * \file gascon128.h
 * \brief GASCON-128 encryption algorithm and related family members.
 *
 * The GASCON family consists of several related algorithms:
 *
 * \li GASCON-128 with a 128-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 64 bits.
 * \li GASCON-128a with a 128-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 128 bits.  This is faster than GASCON-128 but may
 * not be as secure.
 * \li GASCON-80pq with a 160-bit key, a 128-bit nonce, a 128-bit authentication
 * tag, and a block rate of 64 bits.  This is similar to GASCON-128 but has a
 * 160-bit key instead which may be more resistant against quantum computers.
 * \li GASCON-HASH with a 256-bit hash output.
 *
 * References: https://gascon.iaik.tugraz.at/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for GASCON-128 and GASCON-128a.
 */
#define GASCON128_KEY_SIZE 16

/**
 * \brief Size of the nonce for GASCON-128 and GASCON-128a.
 */
#define GASCON128_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for GASCON-128 and GASCON-128a.
 */
#define GASCON128_TAG_SIZE 16

/**
 * \brief Size of the key for GASCON-80pq.
 */
#define GASCON80PQ_KEY_SIZE 20

/**
 * \brief Size of the nonce for GASCON-80pq.
 */
#define GASCON80PQ_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for GASCON-80pq.
 */
#define GASCON80PQ_TAG_SIZE 16

/**
 * \brief Size of the hash output for GASCON-HASH.
 */
#define GASCON_HASH_SIZE 32

/**
 * \brief State information for GASCON-HASH and GASCON-XOF incremental modes.
 */
typedef union
{
    struct {
        unsigned char state[40]; /**< Current hash state */
        unsigned char count;     /**< Number of bytes in the current block */
        unsigned char mode;      /**< Hash mode: 0 for absorb, 1 for squeeze */
    } s;                         /**< State */
    unsigned long long align;    /**< For alignment of this structure */

} gascon_hash_state_t;

/**
 * \brief Meta-information block for the GASCON-128 cipher.
 */
extern aead_cipher_t const gascon128_cipher;

/**
 * \brief Meta-information block for the GASCON-128a cipher.
 */
extern aead_cipher_t const gascon128a_cipher;

/**
 * \brief Meta-information block for the GASCON-80pq cipher.
 */
extern aead_cipher_t const gascon80pq_cipher;

/**
 * \brief Meta-information block for the GASCON-HASH algorithm.
 */
extern aead_hash_algorithm_t const gascon_hash_algorithm;

/**
 * \brief Meta-information block for the GASCON-XOF algorithm.
 */
extern aead_hash_algorithm_t const gascon_xof_algorithm;

/**
 * \brief Encrypts and authenticates a packet with GASCON-128.
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
 * \sa gascon128_aead_decrypt()
 */
int gascon128_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with GASCON-128.
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
 * \sa gascon128_aead_encrypt()
 */
int gascon128_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with GASCON-128a.
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
 * \sa gascon128a_aead_decrypt()
 */
int gascon128a_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with GASCON-128a.
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
 * \sa gascon128a_aead_encrypt()
 */
int gascon128a_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Encrypts and authenticates a packet with GASCON-80pq.
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
 * \param k Points to the 20 bytes of the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa gascon80pq_aead_decrypt()
 */
int gascon80pq_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with GASCON-80pq.
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
 * \param k Points to the 20 bytes of the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa gascon80pq_aead_encrypt()
 */
int gascon80pq_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data with GASCON-HASH.
 *
 * \param out Buffer to receive the hash output which must be at least
 * GASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * \sa gascon_hash_init(), gascon_hash_absorb(), gascon_hash_squeeze()
 */
int gascon_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an GASCON-HASH hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa gascon_hash_update(), gascon_hash_finalize(), gascon_hash()
 */
void gascon_hash_init(gascon_hash_state_t *state);

/**
 * \brief Updates an GASCON-HASH state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 *
 * \sa gascon_hash_init(), gascon_hash_finalize()
 */
void gascon_hash_update
    (gascon_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Returns the final hash value from an GASCON-HASH hashing operation.
 *
 * \param state Hash state to be finalized.
 * \param out Points to the output buffer to receive the 32-byte hash value.
 *
 * \sa gascon_hash_init(), gascon_hash_update()
 */
void gascon_hash_finalize
    (gascon_hash_state_t *state, unsigned char *out);

/**
 * \brief Hashes a block of input data with GASCON-XOF and generates a
 * fixed-length 32 byte output.
 *
 * \param out Buffer to receive the hash output which must be at least
 * GASCON_HASH_SIZE bytes in length.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 *
 * Use gascon_xof_squeeze() instead if you need variable-length XOF ouutput.
 *
 * \sa gascon_xof_init(), gascon_xof_absorb(), gascon_xof_squeeze()
 */
int gascon_xof
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for an GASCON-XOF hashing operation.
 *
 * \param state Hash state to be initialized.
 *
 * \sa gascon_xof_absorb(), gascon_xof_squeeze(), gascon_xof()
 */
void gascon_xof_init(gascon_hash_state_t *state);

/**
 * \brief Aborbs more input data into an GASCON-XOF state.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa gascon_xof_init(), gascon_xof_squeeze()
 */
void gascon_xof_absorb
    (gascon_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen);

/**
 * \brief Squeezes output data from an GASCON-XOF state.
 *
 * \param state Hash state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 *
 * \sa gascon_xof_init(), gascon_xof_update()
 */
void gascon_xof_squeeze
    (gascon_hash_state_t *state, unsigned char *out, unsigned long long outlen);

#ifdef __cplusplus
}
#endif

#endif
