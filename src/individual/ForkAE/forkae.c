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

#include "forkae.h"
#include "internal-forkskinny.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const forkae_paef_64_192_cipher = {
    "PAEF-ForkSkinny-64-192",
    FORKAE_PAEF_64_192_KEY_SIZE,
    FORKAE_PAEF_64_192_NONCE_SIZE,
    FORKAE_PAEF_64_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_64_192_aead_encrypt,
    forkae_paef_64_192_aead_decrypt
};

aead_cipher_t const forkae_paef_128_192_cipher = {
    "PAEF-ForkSkinny-128-192",
    FORKAE_PAEF_128_192_KEY_SIZE,
    FORKAE_PAEF_128_192_NONCE_SIZE,
    FORKAE_PAEF_128_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_128_192_aead_encrypt,
    forkae_paef_128_192_aead_decrypt
};

aead_cipher_t const forkae_paef_128_256_cipher = {
    "PAEF-ForkSkinny-128-256",
    FORKAE_PAEF_128_256_KEY_SIZE,
    FORKAE_PAEF_128_256_NONCE_SIZE,
    FORKAE_PAEF_128_256_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_128_256_aead_encrypt,
    forkae_paef_128_256_aead_decrypt
};

aead_cipher_t const forkae_paef_128_288_cipher = {
    "PAEF-ForkSkinny-128-288",
    FORKAE_PAEF_128_288_KEY_SIZE,
    FORKAE_PAEF_128_288_NONCE_SIZE,
    FORKAE_PAEF_128_288_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_paef_128_288_aead_encrypt,
    forkae_paef_128_288_aead_decrypt
};

aead_cipher_t const forkae_saef_128_192_cipher = {
    "SAEF-ForkSkinny-128-192",
    FORKAE_SAEF_128_192_KEY_SIZE,
    FORKAE_SAEF_128_192_NONCE_SIZE,
    FORKAE_SAEF_128_192_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_saef_128_192_aead_encrypt,
    forkae_saef_128_192_aead_decrypt
};

aead_cipher_t const forkae_saef_128_256_cipher = {
    "SAEF-ForkSkinny-128-256",
    FORKAE_SAEF_128_256_KEY_SIZE,
    FORKAE_SAEF_128_256_NONCE_SIZE,
    FORKAE_SAEF_128_256_TAG_SIZE,
    AEAD_FLAG_NONE,
    forkae_saef_128_256_aead_encrypt,
    forkae_saef_128_256_aead_decrypt
};

/* PAEF-ForkSkinny-64-192 */
#define FORKAE_ALG_NAME forkae_paef_64_192
#define FORKAE_BLOCK_SIZE 8
#define FORKAE_NONCE_SIZE FORKAE_PAEF_64_192_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 2
#define FORKAE_TWEAKEY_SIZE 24
#define FORKAE_BLOCK_FUNC forkskinny_64_192
#include "internal-forkae-paef.h"

/* PAEF-ForkSkinny-128-192 */
#define FORKAE_ALG_NAME forkae_paef_128_192
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_PAEF_128_192_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 2
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-paef.h"

/* PAEF-ForkSkinny-128-256 */
#define FORKAE_ALG_NAME forkae_paef_128_256
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_PAEF_128_256_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 2
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-paef.h"

/* PAEF-ForkSkinny-128-288 */
#define FORKAE_ALG_NAME forkae_paef_128_288
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_PAEF_128_288_NONCE_SIZE
#define FORKAE_COUNTER_SIZE 7
#define FORKAE_TWEAKEY_SIZE 48
#define FORKAE_BLOCK_FUNC forkskinny_128_384
#include "internal-forkae-paef.h"

/* SAEF-ForkSkinny-128-192 */
#define FORKAE_ALG_NAME forkae_saef_128_192
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_SAEF_128_192_NONCE_SIZE
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_TWEAKEY_REDUCED_SIZE 24
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-saef.h"

/* SAEF-ForkSkinny-128-256 */
#define FORKAE_ALG_NAME forkae_saef_128_256
#define FORKAE_BLOCK_SIZE 16
#define FORKAE_NONCE_SIZE FORKAE_SAEF_128_256_NONCE_SIZE
#define FORKAE_TWEAKEY_SIZE 32
#define FORKAE_TWEAKEY_REDUCED_SIZE 32
#define FORKAE_BLOCK_FUNC forkskinny_128_256
#include "internal-forkae-saef.h"
