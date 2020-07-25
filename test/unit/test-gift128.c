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

#include "internal-gift128.h"
#include "internal-gift128-m.h"
#include "test-cipher.h"
#include <stdio.h>

/* Information block for the GIFT-128 block cipher (bit-sliced version) */
static block_cipher_t const gift128b = {
    "GIFT-128-b",
    sizeof(gift128b_key_schedule_t),
    (block_cipher_init_t)gift128b_init,
    (block_cipher_encrypt_t)gift128b_encrypt,
    (block_cipher_decrypt_t)gift128b_decrypt
};

/* Information block for the GIFT-128 block cipher (nibble-based version) */
static block_cipher_t const gift128n = {
    "GIFT-128-n",
    sizeof(gift128n_key_schedule_t),
    (block_cipher_init_t)gift128n_init,
    (block_cipher_encrypt_t)gift128n_encrypt,
    (block_cipher_decrypt_t)gift128n_decrypt
};

/* Information block for the masked GIFT-128 block cipher (bit-sliced) */
static block_cipher_t const gift128b_masked = {
    "GIFT-128-b-masked",
    sizeof(gift128b_masked_key_schedule_t),
    (block_cipher_init_t)gift128b_init_masked,
    (block_cipher_encrypt_t)gift128b_encrypt_masked,
    (block_cipher_decrypt_t)gift128b_decrypt_masked
};

/* Information block for the masked GIFT-128 block cipher (nibble-based) */
static block_cipher_t const gift128n_masked = {
    "GIFT-128-n-masked",
    sizeof(gift128n_masked_key_schedule_t),
    (block_cipher_init_t)gift128n_init_masked,
    (block_cipher_encrypt_t)gift128n_encrypt_masked,
    (block_cipher_decrypt_t)gift128n_decrypt_masked
};

/* Test vectors for GIFT-128 (bit-sliced version) from the GIFT-COFB spec:
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/gift-cofb-spec-round2.pdf */
static block_cipher_test_vector_128_t const gift128b_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* plaintext */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0xA9, 0x4A, 0xF7, 0xF9, 0xBA, 0x18, 0x1D, 0xF9,    /* ciphertext */
     0xB2, 0xB0, 0x0E, 0xB7, 0xDB, 0xFA, 0x93, 0xDF}
};
static block_cipher_test_vector_128_t const gift128b_2 = {
    "Test Vector 2",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x33, 0x31, 0xEF, 0xC3, 0xA6, 0x60, 0x4F, 0x95,    /* ciphertext */
     0x99, 0xED, 0x42, 0xB7, 0xDB, 0xC0, 0x2A, 0x38}
};
/* Test vectors for GIFT-128b generated with the fixslicing reference code */
static block_cipher_test_vector_128_t const gift128b_3 = {
    "Test Vector 3",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x5e, 0x8e, 0x3a, 0x2e, 0x16, 0x97, 0xa7, 0x7d,    /* ciphertext */
     0xcc, 0x0b, 0x89, 0xdc, 0xd9, 0x7a, 0x64, 0xee}
};
static block_cipher_test_vector_128_t const gift128b_4 = {
    "Test Vector 4",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0x22, 0x58, 0x14, 0x37, 0xe5, 0xe9, 0x61, 0xef,    /* ciphertext */
     0x6d, 0x12, 0x50, 0x46, 0xc5, 0xf2, 0x07, 0x88}
};
static block_cipher_test_vector_128_t const gift128b_5 = {
    "Test Vector 5",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0xda, 0x1d, 0xc8, 0x87, 0x38, 0x23, 0xe3, 0x25,    /* ciphertext */
     0xc4, 0xb4, 0xa7, 0x7c, 0x1a, 0x73, 0x33, 0x0e}
};

/* Test vectors for GIFT-128 (nibble-based version) that were generated
 * with the GIFT-128 implementation in the HYENA submission, which has a
 * different byte order than the original GIFT-128 paper but is otherwise
 * equivalent to it */
static block_cipher_test_vector_128_t const gift128n_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x92, 0xff, 0xb6, 0xce, 0x36, 0x5a, 0xb1, 0x68,    /* ciphertext */
     0xf6, 0xd3, 0x8a, 0x38, 0x38, 0xd7, 0x0b, 0xcd}
};
static block_cipher_test_vector_128_t const gift128n_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0xeb, 0xda, 0xda, 0xa8, 0xbc, 0x83, 0xd5, 0x16,    /* ciphertext */
     0xd5, 0x0a, 0x45, 0x6e, 0xf8, 0x0e, 0x7f, 0x72}
};
static block_cipher_test_vector_128_t const gift128n_3 = {
    "Test Vector 3",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0xb2, 0x3e, 0x1f, 0xb4, 0xfd, 0xd8, 0xc0, 0x88,    /* ciphertext */
     0xd3, 0x72, 0xe8, 0xbe, 0xf3, 0x43, 0x06, 0x02}
};

static uint32_t gift128t_tweak_value = 0;

static void gift128t_encrypt_wrapper
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128t_encrypt(ks, output, input, gift128t_tweak_value);
}

static void gift128t_decrypt_wrapper
    (const gift128n_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128t_decrypt(ks, output, input, gift128t_tweak_value);
}

/* Information block for the TweGIFT-128 block cipher (tweakable version) */
static block_cipher_t const gift128t = {
    "TweGIFT-128",
    sizeof(gift128n_key_schedule_t),
    (block_cipher_init_t)gift128n_init,
    (block_cipher_encrypt_t)gift128t_encrypt_wrapper,
    (block_cipher_decrypt_t)gift128t_decrypt_wrapper
};

static void gift128t_encrypt_wrapper_masked
    (const gift128n_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128t_encrypt_masked(ks, output, input, gift128t_tweak_value);
}

static void gift128t_decrypt_wrapper_masked
    (const gift128n_masked_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input)
{
    gift128t_decrypt_masked(ks, output, input, gift128t_tweak_value);
}

/* Information block for the TweGIFT-128 block cipher (tweakable version) */
static block_cipher_t const gift128t_masked = {
    "TweGIFT-128-masked",
    sizeof(gift128n_masked_key_schedule_t),
    (block_cipher_init_t)gift128n_init_masked,
    (block_cipher_encrypt_t)gift128t_encrypt_wrapper_masked,
    (block_cipher_decrypt_t)gift128t_decrypt_wrapper_masked
};

/* Test vectors generated by the TweGIFT-128 reference implementation
 * in the ESTATE submission */
static block_cipher_test_vector_128_t const gift128t_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x92, 0xFF, 0xB6, 0xCE, 0x36, 0x5A, 0xB1, 0x68,    /* ciphertext */
     0xF6, 0xD3, 0x8A, 0x38, 0x38, 0xD7, 0x0B, 0xCD}
    /* tweak = 0 */
};
static block_cipher_test_vector_128_t const gift128t_2 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* plaintext */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0xC8, 0xAE, 0x66, 0x59, 0xE8, 0xF1, 0x63, 0x62,    /* ciphertext */
     0xD1, 0xC6, 0xAB, 0xC4, 0x63, 0x09, 0x06, 0x1F}
    /* tweak = 11 */
};
static block_cipher_test_vector_128_t const gift128t_3 = {
    "Test Vector 2",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x23, 0x02, 0x80, 0xCD, 0x95, 0x78, 0xBB, 0xB6,    /* ciphertext */
     0xC5, 0x9B, 0xD0, 0x2E, 0x96, 0x32, 0x96, 0x2F}
    /* tweak = 4 */
};
static block_cipher_test_vector_128_t const gift128t_4 = {
    "Test Vector 4",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x4E, 0x1F, 0xCB, 0xC8, 0x7A, 0x54, 0x72, 0x79,    /* ciphertext */
     0x9C, 0x61, 0x77, 0x4F, 0xA4, 0x03, 0x16, 0xED}
    /* tweak = 0 */
};

void test_gift128(void)
{
    test_block_cipher_start(&gift128b);
    test_block_cipher_128(&gift128b, &gift128b_1);
    test_block_cipher_128(&gift128b, &gift128b_2);
    test_block_cipher_128(&gift128b, &gift128b_3);
    test_block_cipher_128(&gift128b, &gift128b_4);
    test_block_cipher_128(&gift128b, &gift128b_5);
    test_block_cipher_end(&gift128b);

    test_block_cipher_start(&gift128n);
    test_block_cipher_128(&gift128n, &gift128n_1);
    test_block_cipher_128(&gift128n, &gift128n_2);
    test_block_cipher_128(&gift128n, &gift128n_3);
    test_block_cipher_end(&gift128n);

    test_block_cipher_start(&gift128t);
    gift128t_tweak_value = GIFT128T_TWEAK_0;
    test_block_cipher_128(&gift128t, &gift128t_1);
    gift128t_tweak_value = GIFT128T_TWEAK_11;
    test_block_cipher_128(&gift128t, &gift128t_2);
    gift128t_tweak_value = GIFT128T_TWEAK_4;
    test_block_cipher_128(&gift128t, &gift128t_3);
    /* Check that encrypting with tweak = 0 is the same as untweaked GIFT-n */
    gift128t_tweak_value = GIFT128T_TWEAK_0;
    test_block_cipher_128(&gift128t, &gift128t_4);
    test_block_cipher_128(&gift128n, &gift128t_4);
    test_block_cipher_end(&gift128t);
}

void test_gift128_masked(void)
{
    test_block_cipher_start(&gift128b_masked);
    test_block_cipher_128(&gift128b_masked, &gift128b_1);
    test_block_cipher_128(&gift128b_masked, &gift128b_2);
    test_block_cipher_128(&gift128b_masked, &gift128b_3);
    test_block_cipher_128(&gift128b_masked, &gift128b_4);
    test_block_cipher_128(&gift128b_masked, &gift128b_5);
    test_block_cipher_end(&gift128b_masked);

    test_block_cipher_start(&gift128n_masked);
    test_block_cipher_128(&gift128n_masked, &gift128n_1);
    test_block_cipher_128(&gift128n_masked, &gift128n_2);
    test_block_cipher_128(&gift128n_masked, &gift128n_3);
    test_block_cipher_end(&gift128n_masked);

    test_block_cipher_start(&gift128t_masked);
    gift128t_tweak_value = GIFT128T_TWEAK_0;
    test_block_cipher_128(&gift128t_masked, &gift128t_1);
    gift128t_tweak_value = GIFT128T_TWEAK_11;
    test_block_cipher_128(&gift128t_masked, &gift128t_2);
    gift128t_tweak_value = GIFT128T_TWEAK_4;
    test_block_cipher_128(&gift128t_masked, &gift128t_3);
    /* Check that encrypting with tweak = 0 is the same as untweaked GIFT-n */
    gift128t_tweak_value = GIFT128T_TWEAK_0;
    test_block_cipher_128(&gift128t_masked, &gift128t_4);
    test_block_cipher_128(&gift128n_masked, &gift128t_4);
    test_block_cipher_end(&gift128t_masked);
}
