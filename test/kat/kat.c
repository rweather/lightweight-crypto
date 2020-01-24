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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include "aead-common.h"
#include "ascon128.h"
#include "comet.h"
#include "estate.h"
#include "gift-cofb.h"
#include "gimli24.h"
#include "hyena.h"
#include "isap.h"
#include "pyjamask.h"
#include "saturnin.h"
#include "sparkle.h"
#include "skinny-aead.h"
#include "sundae-gift.h"
#include "tinyjambu.h"

/* List of all AEAD ciphers that we can run KAT tests for */
static const aead_cipher_t *const ciphers[] = {
    &ascon128_cipher,
    &ascon128a_cipher,
    &ascon80pq_cipher,
    &comet_128_cham_cipher,
    &comet_64_cham_cipher,
    &comet_64_speck_cipher,
    &estate_twegift_cipher,
    &gift_cofb_cipher,
    &gimli24_cipher,
    &hyena_cipher,
    &isap_keccak_128a_cipher,
    &isap_ascon_128a_cipher,
    &isap_keccak_128_cipher,
    &isap_ascon_128_cipher,
    &pyjamask_128_cipher,
    &pyjamask_96_cipher,
    &pyjamask_masked_128_cipher,
    &pyjamask_masked_96_cipher,
    &saturnin_cipher,
    &saturnin_short_cipher,
    &schwaemm_256_128_cipher,
    &schwaemm_192_192_cipher,
    &schwaemm_128_128_cipher,
    &schwaemm_256_256_cipher,
    &skinny_aead_m1_cipher,
    &skinny_aead_m2_cipher,
    &skinny_aead_m3_cipher,
    &skinny_aead_m4_cipher,
    &skinny_aead_m5_cipher,
    &skinny_aead_m6_cipher,
    &sundae_gift_0_cipher,
    &sundae_gift_64_cipher,
    &sundae_gift_96_cipher,
    &sundae_gift_128_cipher,
    &tiny_jambu_128_cipher,
    &tiny_jambu_192_cipher,
    &tiny_jambu_256_cipher,
    0
};

/* List of all hash algorithms that we can run KAT tests for */
static const aead_hash_algorithm_t *const hashes[] = {
    &ascon_hash_algorithm,
    &ascon_xof_algorithm,
    &esch_256_hash_algorithm,
    &esch_384_hash_algorithm,
    &gimli24_hash_algorithm,
    &saturnin_hash_algorithm,
    0
};

/* Dynamically-allocated test string that was converted from hexadecimal */
typedef struct {
    size_t size;
    unsigned char data[1];
} test_string_t;

/* Create a test string from a hexadecimal string */
static test_string_t *create_test_string(const char *in)
{
    int value;
    int nibble;
    int phase;
    test_string_t *out;
    out = (test_string_t *)malloc(sizeof(test_string_t) + (strlen(in) / 2));
    if (!out)
        exit(2);
    out->size = 0;
    value = 0;
    phase = 0;
    while (*in != '\0') {
        int ch = *in++;
        if (ch >= '0' && ch <= '9')
            nibble = ch - '0';
        else if (ch >= 'A' && ch <= 'F')
            nibble = ch - 'A' + 10;
        else if (ch >= 'a' && ch <= 'f')
            nibble = ch - 'a' + 10;
        else
            continue; /* skip whitespace and other separators */
        if (!phase) {
            value = nibble << 4;
            phase = 1;
        } else {
            out->data[(out->size)++] = value | nibble;
            phase = 0;
        }
    }
    return out;
}

/* Frees a dynamically-allocated test string */
#define free_test_string(str) (free((str)))

/* Maximum number of parameters to a KAT vector */
#define MAX_TEST_PARAMS 16

/* All parameters for a KAT vector */
typedef struct
{
    int test_number;
    char names[MAX_TEST_PARAMS][16];
    test_string_t *values[MAX_TEST_PARAMS];
    size_t count;

} test_vector_t;

/* Reads a dynamically-allocated KAT vector from an input file */
static int test_vector_read(test_vector_t *vec, FILE *file)
{
    char buffer[8192];
    memset(vec, 0, sizeof(test_vector_t));
    while (fgets(buffer, sizeof(buffer), file)) {
        if (buffer[0] == '\n' || buffer[0] == '\r' || buffer[0] == '\0') {
            /* Blank line terminates the vector unless it is the first line */
            if (vec->count > 0)
                return 1;
        } else if (!strncmp(buffer, "Count = ", 8)) {
            /* Number of the test rather than a vector parameter */
            vec->test_number = atoi(buffer + 8);
        } else if (buffer[0] >= 'A' && buffer[0] <= 'Z' && vec->count < MAX_TEST_PARAMS) {
            /* Name = Value test string */
            const char *eq = strchr(buffer, '=');
            if (eq) {
                int posn = eq - buffer;
                while (posn > 0 && buffer[posn - 1] == ' ')
                    --posn;
                if (posn > 15)
                    posn = 15;
                memcpy(vec->names[vec->count], buffer, posn);
                vec->names[vec->count][posn] = '\0';
                vec->values[vec->count] = create_test_string(eq + 1);
                ++(vec->count);
            }
        }
    }
    return vec->count > 0;
}

/* Frees a dynamically-allocated KAT vector */
static void test_vector_free(test_vector_t *vec)
{
    size_t index;
    for (index = 0; index < vec->count; ++index)
        free_test_string(vec->values[index]);
    memset(vec, 0, sizeof(test_vector_t));
}

/* Gets a parameter from a test vector, NULL if parameter is not present */
static test_string_t *get_test_string
    (const test_vector_t *vec, const char *name)
{
    size_t index;
    for (index = 0; index < vec->count; ++index) {
        if (!strcmp(vec->names[index], name))
            return vec->values[index];
    }
    fprintf(stderr, "Could not find '%s' in test vector %d\n",
            name, vec->test_number);
    exit(3);
    return 0;
}

/* Print an error for a failed test */
static void test_print_error
    (const char *alg, const test_vector_t *vec, const char *format, ...)
{
    va_list va;
    printf("%s [%d]: ", alg, vec->test_number);
    va_start(va, format);
    vprintf(format, va);
    va_end(va);
    printf("\n");
}

static void test_print_hex
    (const char *tag, const unsigned char *data, unsigned long long len)
{
    printf("%s =", tag);
    while (len > 0) {
        printf(" %02x", data[0]);
        ++data;
        --len;
    }
    printf("\n");
}

static int test_compare
    (const unsigned char *actual, const unsigned char *expected,
     unsigned long long len)
{
    int cmp = memcmp(actual, expected, (size_t)len);
    if (cmp == 0)
        return 1;
    printf("\n");
    test_print_hex("actual  ", actual, len);
    test_print_hex("expected", expected, len);
    return 0;
}

/* Determine if the contents of a buffer is all-zero bytes or not */
static int test_all_zeroes(const unsigned char *buf, unsigned long long len)
{
    while (len > 0) {
        if (*buf++ != 0)
            return 0;
        --len;
    }
    return 1;
}

/* Test a cipher algorithm on a specific test vector */
static int test_cipher_inner
    (const aead_cipher_t *alg, const test_vector_t *vec)
{
    const test_string_t *key;
    const test_string_t *nonce;
    const test_string_t *plaintext;
    const test_string_t *ciphertext;
    const test_string_t *ad;
    unsigned char *temp1;
    unsigned char *temp2;
    unsigned long long len;
    int result;

    /* Get the parameters for the test */
    key = get_test_string(vec, "Key");
    nonce = get_test_string(vec, "Nonce");
    plaintext = get_test_string(vec, "PT");
    ciphertext = get_test_string(vec, "CT");
    ad = get_test_string(vec, "AD");
    if (key->size != alg->key_len) {
        test_print_error(alg->name, vec, "incorrect key size in test data");
        return 0;
    }
    if (nonce->size != alg->nonce_len) {
        test_print_error(alg->name, vec, "incorrect nonce size in test data");
        return 0;
    }
    /* Check doesn't work for SATURNIN-Short - disable it.
    if (ciphertext->size != (plaintext->size + alg->tag_len)) {
        test_print_error(alg->name, vec, "incorrect tag size in test data");
        return 0;
    }*/

    /* Allocate temporary buffers */
    temp1 = malloc(ciphertext->size);
    if (!temp1)
        exit(2);
    temp2 = malloc(ciphertext->size);
    if (!temp2)
        exit(2);

    /* Test encryption */
    memset(temp1, 0xAA, ciphertext->size);
    len = 0xBADBEEF;
    result = (*(alg->encrypt))
        (temp1, &len, plaintext->data, plaintext->size,
         ad->data, ad->size, 0, nonce->data, key->data);
    if (result != 0 || len != ciphertext->size ||
            !test_compare(temp1, ciphertext->data, len)) {
        test_print_error(alg->name, vec, "encryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test in-place encryption */
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp1, plaintext->data, plaintext->size);
    len = 0xBADBEEF;
    result = (*(alg->encrypt))
        (temp1, &len, temp1, plaintext->size,
         ad->size ? ad->data : 0, ad->size, 0, nonce->data, key->data);
    if (result != 0 || len != ciphertext->size ||
            !test_compare(temp1, ciphertext->data, len)) {
        test_print_error(alg->name, vec, "in-place encryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test decryption */
    memset(temp1, 0xAA, ciphertext->size);
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, 0, ciphertext->data, ciphertext->size,
         ad->data, ad->size, nonce->data, key->data);
    if (result != 0 || len != plaintext->size ||
            !test_compare(temp1, plaintext->data, len)) {
        test_print_error(alg->name, vec, "decryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test in-place decryption */
    memcpy(temp1, ciphertext->data, ciphertext->size);
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, 0, temp1, ciphertext->size,
         ad->data, ad->size, nonce->data, key->data);
    if (result != 0 || len != plaintext->size ||
            !test_compare(temp1, plaintext->data, len)) {
        test_print_error(alg->name, vec, "in-place decryption failed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* Test decryption with a failed tag check */
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp2, ciphertext->data, ciphertext->size);
    temp2[0] ^= 0x01; /* Corrupt the first byte of the ciphertext */
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, 0, temp2, ciphertext->size,
         ad->data, ad->size, nonce->data, key->data);
    if (result != -1) {
        test_print_error(alg->name, vec, "corrupt ciphertext check failed");
        free(temp1);
        free(temp2);
        return 0;
    }
    if (!test_all_zeroes(temp1, plaintext->size)) {
        test_print_error(alg->name, vec, "plaintext not destroyed");
        free(temp1);
        free(temp2);
        return 0;
    }
    memset(temp1, 0xAA, ciphertext->size);
    memcpy(temp2, ciphertext->data, ciphertext->size);
    temp2[plaintext->size] ^= 0x01; /* Corrupt first byte of the tag */
    len = 0xBADBEEF;
    result = (*(alg->decrypt))
        (temp1, &len, 0, temp2, ciphertext->size,
         ad->data, ad->size, nonce->data, key->data);
    if (result != -1) {
        test_print_error(alg->name, vec, "corrupt tag check failed");
        free(temp1);
        free(temp2);
        return 0;
    }
    if (!test_all_zeroes(temp1, plaintext->size)) {
        test_print_error(alg->name, vec, "plaintext not destroyed");
        free(temp1);
        free(temp2);
        return 0;
    }

    /* All tests passed for this test vector */
    free(temp1);
    free(temp2);
    return 1;
}

/* Test a cipher algorithm */
static int test_cipher(const aead_cipher_t *alg, FILE *file)
{
    test_vector_t vec;
    int success = 0;
    int fail = 0;
    while (test_vector_read(&vec, file)) {
        if (test_cipher_inner(alg, &vec))
            ++success;
        else
            ++fail;
        test_vector_free(&vec);
    }
    printf("%s: %d tests succeeded, %d tests failed\n",
           alg->name, success, fail);
    return fail != 0;
}

/* Test a hash algorithm on a specific test vector */
static int test_hash_inner
    (const aead_hash_algorithm_t *alg, const test_vector_t *vec)
{
    unsigned char out[alg->hash_len];
    void *state;
    const test_string_t *msg;
    const test_string_t *md;
    int result;
    size_t index;
    size_t inc;

    /* Get the parameters for the test */
    msg = get_test_string(vec, "Msg");
    md = get_test_string(vec, "MD");
    if (md->size != alg->hash_len) {
        test_print_error(alg->name, vec, "incorrect hash size in test data");
        return 0;
    }

    /* Hash the input message with the all-in-one function */
    memset(out, 0xAA, alg->hash_len);
    result = (*(alg->hash))(out, msg->data, msg->size);
    if (result != 0) {
        test_print_error(alg->name, vec, "all-in-one hash returned %d", result);
        return 0;
    }
    if (!test_compare(out, md->data, md->size)) {
        test_print_error(alg->name, vec, "all-in-one hash failed");
        return 0;
    }

    /*#define ADVANCE_INC(inc)    (++(inc))*/
    #define ADVANCE_INC(inc)    ((inc) *= 2)

    /* Do we have incremental hash functions? */
    state = malloc(alg->state_size);
    if (!state)
        exit(2);
    if (alg->init && alg->update && alg->finalize) {
        /* Incremental hashing with single finalize step */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->update))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, alg->hash_len);
            (*(alg->finalize))(state, out);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental hash failed");
                free(state);
                return 0;
            }
        }
    }
    if (alg->init && alg->absorb && alg->squeeze) {
        /* Incremental absorb with all-in-one squeeze output */
        for (inc = 1; inc <= msg->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            for (index = 0; index < msg->size; index += inc) {
                size_t temp = msg->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->absorb))(state, msg->data + index, temp);
            }
            memset(out, 0xAA, alg->hash_len);
            (*(alg->squeeze))(state, out, alg->hash_len);
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental absorb failed");
                free(state);
                return 0;
            }
        }

        /* All-in-one absorb with incremental squeeze output */
        for (inc = 1; inc <= md->size; ADVANCE_INC(inc)) {
            (*(alg->init))(state);
            (*(alg->absorb))(state, msg->data, msg->size);
            memset(out, 0xAA, alg->hash_len);
            for (index = 0; index < md->size; index += inc) {
                size_t temp = md->size - index;
                if (temp > inc)
                    temp = inc;
                (*(alg->squeeze))(state, out + index, temp);
            }
            if (!test_compare(out, md->data, md->size)) {
                test_print_error(alg->name, vec, "incremental squeeze failed");
                free(state);
                return 0;
            }
        }
    }
    free(state);

    /* All tests passed for this test vector */
    return 1;
}

/* Test a hash algorithm */
static int test_hash(const aead_hash_algorithm_t *alg, FILE *file)
{
    test_vector_t vec;
    int success = 0;
    int fail = 0;
    while (test_vector_read(&vec, file)) {
        if (test_hash_inner(alg, &vec))
            ++success;
        else
            ++fail;
        test_vector_free(&vec);
    }
    printf("%s: %d tests succeeded, %d tests failed\n",
           alg->name, success, fail);
    return fail != 0;
}

int main(int argc, char *argv[])
{
    int index;
    int exit_val;
    FILE *file;

    /* Check that we have all command-line arguments that we need */
    if (argc < 3) {
        fprintf(stderr, "Usage: %s Algorithm KAT-file\n", argv[0]);
        return 1;
    }

    /* Open the KAT input file */
    if ((file = fopen(argv[2], "r")) == NULL) {
        perror(argv[2]);
        return 1;
    }

    /* Look for a cipher with the specified name */
    for (index = 0; ciphers[index] != 0; ++index) {
        if (!strcmp(ciphers[index]->name, argv[1])) {
            exit_val = test_cipher(ciphers[index], file);
            fclose(file);
            return exit_val;
        }
    }

    /* Look for a hash algorithm with the specified name */
    for (index = 0; hashes[index] != 0; ++index) {
        if (!strcmp(hashes[index]->name, argv[1])) {
            exit_val = test_hash(hashes[index], file);
            fclose(file);
            return exit_val;
        }
    }

    /* Unknown algorithm name */
    fclose(file);
    fprintf(stderr, "Unknown algorithm '%s'\n", argv[1]);
    return 1;
}
