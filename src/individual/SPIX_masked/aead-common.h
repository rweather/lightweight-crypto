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

#ifndef LWCRYPTO_AEAD_COMMON_H
#define LWCRYPTO_AEAD_COMMON_H

#include <stddef.h>

/**
 * \file aead-common.h
 * \brief Definitions that are common across AEAD schemes.
 *
 * AEAD stands for "Authenticated Encryption with Associated Data".
 * It is a standard API pattern for securely encrypting and
 * authenticating packets of data.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Encrypts and authenticates a packet with an AEAD scheme.
 *
 * \param c Buffer to receive the output.
 * \param clen On exit, set to the length of the output which includes
 * the ciphertext and the authentication tag.
 * \param m Buffer that contains the plaintext message to encrypt.
 * \param mlen Length of the plaintext message in bytes.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param nsec Secret nonce - normally not used by AEAD schemes.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key to use to encrypt the packet.
 *
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 */
typedef int (*aead_cipher_encrypt_t)
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with an AEAD scheme.
 *
 * \param m Buffer to receive the plaintext message on output.
 * \param mlen Receives the length of the plaintext message on output.
 * \param nsec Secret nonce - normally not used by AEAD schemes.
 * \param c Buffer that contains the ciphertext and authentication
 * tag to decrypt.
 * \param clen Length of the input data in bytes, which includes the
 * ciphertext and the authentication tag.
 * \param ad Buffer that contains associated data to authenticate
 * along with the packet but which does not need to be encrypted.
 * \param adlen Length of the associated data in bytes.
 * \param npub Points to the public nonce for the packet.
 * \param k Points to the key to use to decrypt the packet.
 *
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 */
typedef int (*aead_cipher_decrypt_t)
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Hashes a block of input data.
 *
 * \param out Buffer to receive the hash output.
 * \param in Points to the input data to be hashed.
 * \param inlen Length of the input data in bytes.
 *
 * \return Returns zero on success or -1 if there was an error in the
 * parameters.
 */
typedef int (*aead_hash_t)
    (unsigned char *out, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Initializes the state for a hashing operation.
 *
 * \param state Hash state to be initialized.
 */
typedef void (*aead_hash_init_t)(void *state);

/**
 * \brief Updates a hash state with more input data.
 *
 * \param state Hash state to be updated.
 * \param in Points to the input data to be incorporated into the state.
 * \param inlen Length of the input data to be incorporated into the state.
 */
typedef void (*aead_hash_update_t)
    (void *state, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Returns the final hash value from a hashing operation.
 *
 * \param Hash state to be finalized.
 * \param out Points to the output buffer to receive the hash value.
 */
typedef void (*aead_hash_finalize_t)(void *state, unsigned char *out);

/**
 * \brief Aborbs more input data into an XOF state.
 *
 * \param state XOF state to be updated.
 * \param in Points to the input data to be absorbed into the state.
 * \param inlen Length of the input data to be absorbed into the state.
 *
 * \sa ascon_xof_init(), ascon_xof_squeeze()
 */
typedef void (*aead_xof_absorb_t)
    (void *state, const unsigned char *in, unsigned long long inlen);

/**
 * \brief Squeezes output data from an XOF state.
 *
 * \param state XOF state to squeeze the output data from.
 * \param out Points to the output buffer to receive the squeezed data.
 * \param outlen Number of bytes of data to squeeze out of the state.
 */
typedef void (*aead_xof_squeeze_t)
    (void *state, unsigned char *out, unsigned long long outlen);

/**
 * \brief No special AEAD features.
 */
#define AEAD_FLAG_NONE              0x0000

/**
 * \brief The natural byte order of the AEAD cipher is little-endian.
 *
 * If this flag is not present, then the natural byte order of the
 * AEAD cipher should be assumed to be big-endian.
 *
 * The natural byte order may be useful when formatting packet sequence
 * numbers as nonces.  The application needs to know whether the sequence
 * number should be packed into the leading or trailing bytes of the nonce.
 */
#define AEAD_FLAG_LITTLE_ENDIAN     0x0001

/**
 * \brief The AEAD mode provides side-channel protection for the key.
 */
#define AEAD_FLAG_SC_PROTECT_KEY    0x0002

/**
 * \brief The AEAD mode provides side-channel protection for all block
 * operations.
 */
#define AEAD_FLAG_SC_PROTECT_ALL    0x0004

/**
 * \brief Meta-information about an AEAD cipher.
 */
typedef struct
{
    const char *name;               /**< Name of the cipher */
    unsigned key_len;               /**< Length of the key in bytes */
    unsigned nonce_len;             /**< Length of the nonce in bytes */
    unsigned tag_len;               /**< Length of the tag in bytes */
    unsigned flags;                 /**< Flags for extra features */
    aead_cipher_encrypt_t encrypt;  /**< AEAD encryption function */
    aead_cipher_decrypt_t decrypt;  /**< AEAD decryption function */

} aead_cipher_t;

/**
 * \brief Meta-information about a hash algorithm that is related to an AEAD.
 *
 * Regular hash algorithms should provide the "hash", "init", "update",
 * and "finalize" functions.  Extensible Output Functions (XOF's) should
 * proivde the "hash", "init", "absorb", and "squeeze" functions.
 */
typedef struct
{
    const char *name;           /**< Name of the hash algorithm */
    size_t state_size;          /**< Size of the incremental state structure */
    unsigned hash_len;          /**< Length of the hash in bytes */
    unsigned flags;             /**< Flags for extra features */
    aead_hash_t hash;           /**< All in one hashing function */
    aead_hash_init_t init;      /**< Incremental hash/XOF init function */
    aead_hash_update_t update;  /**< Incremental hash update function */
    aead_hash_finalize_t finalize; /**< Incremental hash finalize function */
    aead_xof_absorb_t absorb;   /**< Incremental XOF absorb function */
    aead_xof_squeeze_t squeeze; /**< Incremental XOF squeeze function */

} aead_hash_algorithm_t;

/**
 * \brief Check an authentication tag in constant time.
 *
 * \param plaintext Points to the plaintext data.
 * \param plaintext_len Length of the plaintext in bytes.
 * \param tag1 First tag to compare.
 * \param tag2 Second tag to compare.
 * \param tag_len Length of the tags in bytes.
 *
 * \return Returns -1 if the tag check failed or 0 if the check succeeded.
 *
 * If the tag check fails, then the \a plaintext will also be zeroed to
 * prevent it from being used accidentally by the application when the
 * ciphertext was invalid.
 */
int aead_check_tag
    (unsigned char *plaintext, unsigned long long plaintext_len,
     const unsigned char *tag1, const unsigned char *tag2,
     unsigned tag_len);

/**
 * \brief Check an authentication tag in constant time with a previous check.
 *
 * \param plaintext Points to the plaintext data.
 * \param plaintext_len Length of the plaintext in bytes.
 * \param tag1 First tag to compare.
 * \param tag2 Second tag to compare.
 * \param tag_len Length of the tags in bytes.
 * \param precheck Set to -1 if previous check succeeded or 0 if it failed.
 *
 * \return Returns -1 if the tag check failed or 0 if the check succeeded.
 *
 * If the tag check fails, then the \a plaintext will also be zeroed to
 * prevent it from being used accidentally by the application when the
 * ciphertext was invalid.
 *
 * This version can be used to incorporate other information about the
 * correctness of the plaintext into the final result.
 */
int aead_check_tag_precheck
    (unsigned char *plaintext, unsigned long long plaintext_len,
     const unsigned char *tag1, const unsigned char *tag2,
     unsigned tag_len, int precheck);

#ifdef __cplusplus
}
#endif

#endif
