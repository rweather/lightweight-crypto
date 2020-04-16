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

#ifndef GENAVR_GEN_H
#define GENAVR_GEN_H

#include "code.h"

// Information about a test vector for a block cipher.
typedef struct
{
    const char *name;
    unsigned char key[48];
    unsigned key_len;
    unsigned char plaintext[16];
    unsigned char ciphertext[16];

} block_cipher_test_vector_t;

// CHAM-128 and CHAM-64 block ciphers.
void gen_cham128_encrypt(Code &code);
void gen_cham64_encrypt(Code &code);
bool test_cham128_encrypt(Code &code);
bool test_cham64_encrypt(Code &code);

// GIFT-64 block cipher.
void gen_gift64n_setup_key(Code &code);
void gen_gift64n_encrypt(Code &code);
void gen_gift64n_decrypt(Code &code);
void gen_gift64t_encrypt(Code &code);
void gen_gift64t_decrypt(Code &code);
bool test_gift64n_setup_key(Code &code);
bool test_gift64n_encrypt(Code &code);
bool test_gift64n_decrypt(Code &code);
bool test_gift64t_encrypt(Code &code);
bool test_gift64t_decrypt(Code &code);

// Keccak permutation.
void gen_keccakp_200_permutation(Code &code);
void gen_keccakp_400_permutation(Code &code);
bool test_keccakp_200_permutation(Code &code);
bool test_keccakp_400_permutation(Code &code);

// SPARKLE permutation.
void gen_sparkle256_permutation(Code &code);
void gen_sparkle384_permutation(Code &code);
void gen_sparkle512_permutation(Code &code);
bool test_sparkle256_permutation(Code &code);
bool test_sparkle384_permutation(Code &code);
bool test_sparkle512_permutation(Code &code);

// SPECK-64 block cipher.
void gen_speck64_encrypt(Code &code);
bool test_speck64_encrypt(Code &code);

// TinyJAMBU permutation.
void gen_tinyjambu_permutation(Code &code);
bool test_tinyjambu_permutation(Code &code);

#endif
