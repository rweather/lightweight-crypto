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

#include "pyjamask.h"
#include "internal-pyjamask.h"

aead_cipher_t const pyjamask_masked_96_cipher = {
    "Pyjamask-96-AEAD-Masked",
    PYJAMASK_96_KEY_SIZE,
    PYJAMASK_96_NONCE_SIZE,
    PYJAMASK_96_TAG_SIZE,
    AEAD_FLAG_NONE,
    pyjamask_masked_96_aead_encrypt,
    pyjamask_masked_96_aead_decrypt
};

/* Double a value in GF(96) */
static void pyjamask_96_double_l
    (unsigned char out[12], const unsigned char in[12])
{
    unsigned index;
    unsigned char mask = (unsigned char)(((signed char)in[0]) >> 7);
    for (index = 0; index < 11; ++index)
        out[index] = (in[index] << 1) | (in[index + 1] >> 7);
    out[11] = (in[11] << 1) ^ (mask & 0x41);
    out[10] ^= (mask & 0x06);
}

#define OCB_ALG_NAME pyjamask_masked_96
#define OCB_BLOCK_SIZE 12
#define OCB_NONCE_SIZE PYJAMASK_96_NONCE_SIZE
#define OCB_TAG_SIZE PYJAMASK_96_TAG_SIZE
#define OCB_KEY_SCHEDULE pyjamask_masked_key_schedule_t
#define OCB_SETUP_KEY pyjamask_masked_setup_key
#define OCB_ENCRYPT_BLOCK pyjamask_masked_96_encrypt
#define OCB_DECRYPT_BLOCK pyjamask_masked_96_decrypt
#define OCB_DOUBLE_L pyjamask_96_double_l
#include "internal-ocb.h"
