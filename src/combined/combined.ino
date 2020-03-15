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

/*
This example runs lightweight cryptography tests on Arduino platforms.

Because this example links in the entire library and all algorithms,
it is only suitable for use on Arduino platforms with large amounts
of flash memory.
*/

#include "aead-common.h"
#include "ace.h"
#include "ascon128.h"
#include "comet.h"
#include "drygascon.h"
#include "elephant.h"
#include "estate.h"
#include "forkae.h"
#include "gift-cofb.h"
#include "gimli24.h"
#include "grain128.h"
#include "hyena.h"
#include "isap.h"
#include "knot.h"
#include "lotus-locus.h"
#include "orange.h"
#include "oribatida.h"
#include "photon-beetle.h"
#include "pyjamask.h"
#include "romulus.h"
#include "saturnin.h"
#include "skinny-aead.h"
#include "skinny-hash.h"
#include "sparkle.h"
#include "spix.h"
#include "spoc.h"
#include "spook.h"
#include "subterranean.h"
#include "sundae-gift.h"
#include "tinyjambu.h"
#include "wage.h"
#include "xoodyak.h"
#include "internal-blake2s.h"
#include "internal-chachapoly.h"

#if defined(ESP8266)
extern "C" void system_soft_wdt_feed(void);
#define crypto_feed_watchdog() system_soft_wdt_feed()
#else
#define crypto_feed_watchdog() do { ; } while (0)
#endif

#if defined(__AVR__)
#define DEFAULT_PERF_LOOPS 200
#define DEFAULT_PERF_LOOPS_16 200
#define DEFAULT_PERF_HASH_LOOPS 100
#else
#define DEFAULT_PERF_LOOPS 1000
#define DEFAULT_PERF_LOOPS_16 3000
#define DEFAULT_PERF_HASH_LOOPS 1000
#endif

static int PERF_LOOPS = DEFAULT_PERF_LOOPS;
static int PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16;
static int PERF_HASH_LOOPS = DEFAULT_PERF_HASH_LOOPS;

#define MAX_DATA_SIZE 128
#define MAX_TAG_SIZE 32

static unsigned char const key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};
static unsigned char const nonce[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
static unsigned char plaintext[MAX_DATA_SIZE];
static unsigned char ciphertext[MAX_DATA_SIZE + MAX_TAG_SIZE];

static unsigned long encrypt_128_time = 0;
static unsigned long encrypt_16_time = 0;
static unsigned long decrypt_128_time = 0;
static unsigned long decrypt_16_time = 0;
static unsigned long encrypt_128_ref = 0;
static unsigned long encrypt_16_ref = 0;
static unsigned long decrypt_128_ref = 0;
static unsigned long decrypt_16_ref = 0;
static unsigned long hash_1024_time = 0;
static unsigned long hash_128_time = 0;
static unsigned long hash_16_time = 0;
static unsigned long hash_1024_ref = 0;
static unsigned long hash_128_ref = 0;
static unsigned long hash_16_ref = 0;

static void print_x(double value)
{
    if (value < 0.005)
        Serial.print(value, 4);
    else
        Serial.print(value);
}

void perfCipherEncrypt128(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 128, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_128_time = elapsed;

    if (encrypt_128_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_128_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt128(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 128, 0, 0, 0, nonce, key);

    Serial.print("   decrypt 128 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS; ++count) {
        cipher->decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_128_time = elapsed;

    if (decrypt_128_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_128_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (128.0 * PERF_LOOPS));
    Serial.print("us per byte, ");
    Serial.print((128.0 * PERF_LOOPS * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherEncrypt16(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, 16, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_16_time = elapsed;

    if (encrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecrypt16(const aead_cipher_t *cipher)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, 16, 0, 0, 0, nonce, key);

    Serial.print("   decrypt  16 byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_16_time = elapsed;

    if (decrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (16.0 * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((16.0 * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipher(const aead_cipher_t *cipher)
{
    crypto_feed_watchdog();
    Serial.print(cipher->name);
    Serial.print(':');
    Serial.println();

    perfCipherEncrypt128(cipher);
    perfCipherDecrypt128(cipher);
    perfCipherEncrypt16(cipher);
    perfCipherDecrypt16(cipher);

    if (encrypt_128_ref != 0) {
        unsigned long ref_avg = encrypt_128_ref + decrypt_128_ref +
                                encrypt_16_ref  + decrypt_16_ref;
        unsigned long time_avg = encrypt_128_time + decrypt_128_time +
                                 encrypt_16_time  + decrypt_16_time;
        Serial.print("   average ... ");
        print_x(((double)ref_avg) / time_avg);
        Serial.print("x");
        Serial.println();
    }

    Serial.println();
}

// Variant on perfCipherEncrypt16 for algorithms that cannot do
// 16 bytes on a short packet; e.g. SATURNIN-Short is limited to 15.
void perfCipherEncryptShort(const aead_cipher_t *cipher, unsigned size)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;

    Serial.print("   encrypt  ");
    Serial.print(size);
    Serial.print(" byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->encrypt
            (ciphertext, &len, plaintext, size, 0, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    encrypt_16_time = elapsed;

    if (encrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)encrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (((double)size) * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((((double)size) * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherDecryptShort(const aead_cipher_t *cipher, unsigned size)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long clen;
    unsigned long long plen;
    int count;

    for (count = 0; count < MAX_DATA_SIZE; ++count)
        plaintext[count] = (unsigned char)count;
    cipher->encrypt(ciphertext, &clen, plaintext, size, 0, 0, 0, nonce, key);

    Serial.print("   decrypt  ");
    Serial.print(size);
    Serial.print(" byte packets ... ");

    start = micros();
    for (count = 0; count < PERF_LOOPS_16; ++count) {
        cipher->decrypt
            (plaintext, &plen, 0, ciphertext, clen, 0, 0, nonce, key);
    }
    elapsed = micros() - start;
    decrypt_16_time = elapsed;

    if (decrypt_16_ref != 0 && elapsed != 0) {
        print_x(((double)decrypt_16_ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (((double)size) * PERF_LOOPS_16));
    Serial.print("us per byte, ");
    Serial.print((((double)size) * PERF_LOOPS_16 * 1000000.0) / elapsed);
    Serial.println(" bytes per second");
}

void perfCipherShort(const aead_cipher_t *cipher, unsigned size)
{
    crypto_feed_watchdog();
    Serial.print(cipher->name);
    Serial.print(':');
    Serial.println();

    perfCipherEncryptShort(cipher, size);
    perfCipherDecryptShort(cipher, size);

    if (encrypt_16_ref != 0) {
        unsigned long ref_avg = encrypt_16_ref  + decrypt_16_ref;
        unsigned long time_avg = encrypt_16_time  + decrypt_16_time;
        Serial.print("   average ... ");
        print_x(((double)ref_avg) / time_avg);
        Serial.print("x");
        Serial.println();
    }

    Serial.println();
}

static unsigned char hash_buffer[1024];

unsigned long perfHash_N
    (const aead_hash_algorithm_t *hash_alg, int size, unsigned long ref)
{
    unsigned long start;
    unsigned long elapsed;
    unsigned long long len;
    int count, loops;

    for (count = 0; count < size; ++count)
        hash_buffer[count] = (unsigned char)count;

    Serial.print("   hash ");
    if (size < 1000) {
        if (size < 100)
            Serial.print("  ");
        else
            Serial.print(" ");
    }
    Serial.print(size);
    Serial.print(" bytes ... ");

    // Adjust the number of loops to do more loops on smaller sizes.
    if (size < 1024)
        loops = PERF_HASH_LOOPS * 4;
    else
        loops = PERF_HASH_LOOPS;

    start = micros();
    for (count = 0; count < loops; ++count) {
        hash_alg->hash(ciphertext, plaintext, size);
    }
    elapsed = micros() - start;

    if (ref != 0 && elapsed != 0) {
        print_x(((double)ref) / elapsed);
        Serial.print("x, ");
    }

    Serial.print(elapsed / (((double)size) * loops));
    Serial.print("us per byte, ");
    Serial.print((1000000.0 * size * loops) / elapsed);
    Serial.println(" bytes per second");

    return elapsed;
}

void perfHash(const aead_hash_algorithm_t *hash_alg)
{
    crypto_feed_watchdog();
    Serial.print(hash_alg->name);
    Serial.print(':');
    Serial.println();

    hash_1024_time = perfHash_N(hash_alg, 1024, hash_1024_ref);
    hash_128_time = perfHash_N(hash_alg, 128, hash_128_ref);
    hash_16_time = perfHash_N(hash_alg, 16, hash_16_ref);

    if (hash_16_ref != 0) {
        double avg = ((double)hash_1024_ref) / hash_1024_time;
        avg += ((double)hash_128_ref) / hash_128_time;
        avg += ((double)hash_16_ref) / hash_16_time;
        avg /= 3.0;
        Serial.print("   average ... ");
        print_x(avg);
        Serial.print("x");
        Serial.println();
    }

    Serial.println();
}

void setup()
{
    Serial.begin(9600);
    Serial.println();

    // Test ChaChaPoly and BLAKE2s first to get the reference time
    // for other algorithms.
    perfCipher(&internal_chachapoly_cipher);
    encrypt_128_ref = encrypt_128_time;
    decrypt_128_ref = decrypt_128_time;
    encrypt_16_ref = encrypt_16_time;
    decrypt_16_ref = decrypt_16_time;
    perfHash(&internal_blake2s_hash_algorithm);
    hash_1024_ref = hash_1024_time;
    hash_128_ref = hash_128_time;
    hash_16_ref = hash_16_time;

    // Run performance tests on the NIST AEAD algorithms.
    perfCipher(&ace_cipher);
    perfCipher(&ascon128_cipher);
    perfCipher(&ascon128a_cipher);
    perfCipher(&ascon80pq_cipher);
    perfCipher(&comet_128_cham_cipher);
    perfCipher(&comet_64_cham_cipher);
    perfCipher(&comet_64_speck_cipher);
    perfCipher(&drygascon128_cipher);
    perfCipher(&drygascon256_cipher);
    perfCipher(&estate_twegift_cipher);
    perfCipher(&forkae_paef_64_192_cipher);
    perfCipher(&forkae_paef_128_192_cipher);
    perfCipher(&forkae_paef_128_256_cipher);
    perfCipher(&forkae_paef_128_288_cipher);
    perfCipher(&forkae_saef_128_192_cipher);
    perfCipher(&forkae_saef_128_256_cipher);
    perfCipher(&gift_cofb_cipher);
    perfCipher(&gimli24_cipher);
    perfCipher(&grain128_aead_cipher);
    perfCipher(&hyena_cipher);
    perfCipher(&knot_aead_128_256_cipher);
    perfCipher(&knot_aead_128_384_cipher);
    perfCipher(&knot_aead_192_384_cipher);
    perfCipher(&knot_aead_256_512_cipher);
    perfCipher(&lotus_aead_cipher);
    perfCipher(&locus_aead_cipher);
    perfCipher(&orange_zest_cipher);
    perfCipher(&oribatida_256_cipher);
    perfCipher(&oribatida_192_cipher);
    perfCipher(&pyjamask_128_cipher);
    perfCipher(&pyjamask_96_cipher);
    perfCipher(&romulus_n1_cipher);
    perfCipher(&romulus_n2_cipher);
    perfCipher(&romulus_n3_cipher);
    perfCipher(&romulus_m1_cipher);
    perfCipher(&romulus_m2_cipher);
    perfCipher(&romulus_m3_cipher);
    perfCipher(&saturnin_cipher);
    perfCipherShort(&saturnin_short_cipher, 15);
    perfCipher(&schwaemm_256_128_cipher);
    perfCipher(&schwaemm_192_192_cipher);
    perfCipher(&schwaemm_128_128_cipher);
    perfCipher(&schwaemm_256_256_cipher);
    perfCipher(&skinny_aead_m1_cipher);
    perfCipher(&skinny_aead_m2_cipher);
    perfCipher(&skinny_aead_m3_cipher);
    perfCipher(&skinny_aead_m4_cipher);
    perfCipher(&skinny_aead_m5_cipher);
    perfCipher(&skinny_aead_m6_cipher);
    perfCipher(&spix_cipher);
    perfCipher(&spoc_128_cipher);
    perfCipher(&spoc_64_cipher);
    perfCipher(&spook_128_512_su_cipher);
    perfCipher(&spook_128_384_su_cipher);
    perfCipher(&spook_128_512_mu_cipher);
    perfCipher(&spook_128_384_mu_cipher);
    perfCipher(&subterranean_cipher);
    perfCipher(&sundae_gift_0_cipher);
    perfCipher(&sundae_gift_64_cipher);
    perfCipher(&sundae_gift_96_cipher);
    perfCipher(&sundae_gift_128_cipher);
    perfCipher(&tiny_jambu_128_cipher);
    perfCipher(&tiny_jambu_192_cipher);
    perfCipher(&tiny_jambu_256_cipher);
    perfCipher(&wage_cipher);
    perfCipher(&xoodyak_cipher);

    // Run performance tests on the NIST hash algorithms.
    perfHash(&ace_hash_algorithm);
    perfHash(&ascon_hash_algorithm);
    perfHash(&drygascon128_hash_algorithm);
    perfHash(&drygascon256_hash_algorithm);
    perfHash(&esch_256_hash_algorithm);
    perfHash(&esch_384_hash_algorithm);
    perfHash(&gimli24_hash_algorithm);
    perfHash(&knot_hash_256_256_algorithm);
    perfHash(&knot_hash_256_384_algorithm);
    perfHash(&knot_hash_384_384_algorithm);
    perfHash(&knot_hash_512_512_algorithm);
    perfHash(&orangish_hash_algorithm);
    perfHash(&photon_beetle_hash_algorithm);
    perfHash(&saturnin_hash_algorithm);
    perfHash(&skinny_tk2_hash_algorithm);
    perfHash(&skinny_tk3_hash_algorithm);
    perfHash(&subterranean_hash_algorithm);
    perfHash(&xoodyak_hash_algorithm);

    // Algorithms that are very slow.  Adjust loop counters and do them last.
    encrypt_128_ref /= 10;
    decrypt_128_ref /= 10;
    encrypt_16_ref /= 10;
    decrypt_16_ref /= 10;
    PERF_LOOPS = DEFAULT_PERF_LOOPS / 10;
    PERF_LOOPS_16 = DEFAULT_PERF_LOOPS_16 / 10;
    perfCipher(&dumbo_cipher);
    perfCipher(&jumbo_cipher);
    perfCipher(&delirium_cipher);
    perfCipher(&isap_ascon_128a_cipher);
    perfCipher(&isap_ascon_128_cipher);
    perfCipher(&isap_keccak_128a_cipher);
    perfCipher(&isap_keccak_128_cipher);
    perfCipher(&photon_beetle_128_cipher);
    perfCipher(&photon_beetle_32_cipher);
    perfCipher(&pyjamask_masked_128_cipher);
    perfCipher(&pyjamask_masked_96_cipher);
}

void loop()
{
}
