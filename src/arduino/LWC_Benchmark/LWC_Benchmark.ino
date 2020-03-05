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

#include "benchmark.h"

int my_cipher_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    // Put code here to encrypt with your cipher.
    return -1;
}

int my_cipher_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    // Put code here to decrypt with your cipher.
    return -1;
}

// Populate this structure with information about your cipher.
aead_cipher_t const my_cipher = {
    "MyCipher",
    16,                     // Key size in bytes
    12,                     // Nonce size in bytes
    8,                      // Tag size in bytes
    AEAD_FLAG_NONE,
    my_cipher_aead_encrypt,
    my_cipher_aead_decrypt
};

void setup()
{
    // Set up the serial port.
    Serial.begin(9600);
    Serial.println();

    // Set up the performance framework and collect ChaChaPoly timings.
    perfSetup();

    // Run performance tests on the specific algorithm of interest.
    perfCipher(&my_cipher);
}

void loop()
{
    // Nothing to do here - everything is done in setup().
}
