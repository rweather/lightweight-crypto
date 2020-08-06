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

#include "pyjamask-masked.h"
#include "internal-pyjamask-m.h"

aead_cipher_t const pyjamask_masked_96_cipher = {
    "Pyjamask-96-AEAD-Masked",
    PYJAMASK_96_MASKED_KEY_SIZE,
    PYJAMASK_96_MASKED_NONCE_SIZE,
    PYJAMASK_96_MASKED_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    pyjamask_masked_96_aead_encrypt,
    pyjamask_masked_96_aead_decrypt
};

#define OCB_ALG_NAME pyjamask_masked_96
#define OCB_BLOCK_SIZE 12
#define OCB_NONCE_SIZE PYJAMASK_96_MASKED_NONCE_SIZE
#define OCB_TAG_SIZE PYJAMASK_96_MASKED_TAG_SIZE
#define OCB_KEY_SCHEDULE pyjamask_masked_96_key_schedule_t
#define OCB_SETUP_KEY pyjamask_masked_96_setup_key
#define OCB_ENCRYPT_BLOCK pyjamask_masked_96_encrypt
#define OCB_DECRYPT_BLOCK pyjamask_masked_96_decrypt
#include "internal-ocb.h"
