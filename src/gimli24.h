/*
 * Copyright (C) 2019 Southern Storm Software, Pty Ltd.
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

#ifndef LWCRYPTO_GIMLI24_H
#define LWCRYPTO_GIMLI24_H

/**
 * \file gimli24.h
 * \brief GIMLI encryption algorithm with 24 rounds.
 *
 * References: https://gimli.cr.yp.to/
 */

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the key for GIMLI-24.
 */
#define GIMLI24_KEY_SIZE 32

/**
 * \brief Size of the nonce for GIMLI-24.
 */
#define GIMLI24_NONCE_SIZE 16

/**
 * \brief Size of the authentication tag for GIMLI-24.
 */
#define GIMLI24_TAG_SIZE 16

/**
 * \brief Simple encryption and authentication of a packet with GIMLI-24.
 *
 * \param ciphertext Buffer to receive the ciphertext output.
 * \param ciphertext_max Maximum number of bytes in the output buffer,
 * which must be at least \a plaintext_len + GIMLI24_TAG_SIZE.
 * \param plaintext Buffer that contains the plaintext to encrypt.
 * \param plaintext_len Length of the plaintext in bytes.
 * \param seq_num The 32-bit packet sequence number, which must be
 * different for every packet.
 * \param key Points to the key to use to encrypt the packet.
 * \param key_len Length of the key in bytes, which must be GIMLI24_KEY_SIZE.
 *
 * \return The number of bytes that were written to \a ciphertext which
 * includes the encrypted plaintext and the 16 byte authentication tag.
 * Returns zero if the parameters are invalid in some fashion.
 *
 * This function is simpler than gimli24_aead_encrypt() in that it dispenses
 * with the associated data and uses a simple 32-bit sequence number
 * instead of a nonce.  The sequence number is encoded into the 128-bit
 * nonce as a little-endian 32-bit value padded with zeroes.
 *
 * It is incredibly important that the sequence number be different
 * for every packet that is encrypted under the same key.  The simplest
 * is to increment the sequence number after every packet.  The application
 * must change to a new key before 32-bit overflow occurs.
 *
 * \sa gimli24_decrypt_packet(), gimli24_aead_encrypt()
 */
size_t gimli24_encrypt_packet
    (unsigned char *ciphertext, size_t ciphertext_max,
     const unsigned char *plaintext, size_t plaintext_len,
     unsigned long seq_num, const unsigned char *key, size_t key_len);

size_t gimli24_decrypt_packet
    (unsigned char *plaintext, size_t plaintext_max,
     const unsigned char *ciphertext, size_t ciphertext_len,
     unsigned long seq_num, const unsigned char *key, size_t key_len);

/**
 * \brief Encrypts and authenticates a packet with GIMLI-24 using the
 * full AEAD mode.
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
 * \return 0 on success, or a negative value if there was an error in
 * the parameters.
 *
 * \sa gimli24_aead_decrypt(), gimli24_encrypt_packet()
 */
int gimli24_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k);

/**
 * \brief Decrypts and authenticates a packet with GIMLI-24 using the
 * full AEAD mode.
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
 * \return 0 on success, -1 if the authentication tag was incorrect,
 * or some other negative number if there was an error in the parameters.
 *
 * \sa gimli24_aead_encrypt(), gimli24_decrypt_packet()
 */
int gimli24_aead_decrypt
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
