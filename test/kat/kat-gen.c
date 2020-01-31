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

#include "aead-common.h"
#include "algorithms.h"
#include "gimli24.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

/* Command-line parameters */
static int min_ad = 0;
static int max_ad = 32;
static int min_pt = 0;
static int max_pt = 32;
static int min_msg = 0;
static int max_msg = 1024;
static const char *alg_name = 0;
static const char *output_filename = 0;
static const aead_cipher_t *alg_cipher = 0;
static const aead_hash_algorithm_t *alg_hash = 0;

/* State of the RNG for generating input vectors */
static int rng_active = 0;
static gimli24_hash_state_t rng_state;

/**
 * \brief Initializes the pseudo random number generator.
 *
 * \param seed User-provided seed or NULL for a seed based on the time.
 */
static void rng_init(const char *seed)
{
    rng_active = 1;
    gimli24_hash_init(&rng_state);
    if (seed) {
        /* Absorb the user-supplied seed as-is */
        gimli24_hash_absorb(&rng_state, (unsigned char *)seed, strlen(seed));
    } else {
        /* Hash the current time to produce a 32-bit seed value */
        unsigned char data[4];
        char new_seed[16];
        unsigned long value;
#if defined(CLOCK_REALTIME)
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        gimli24_hash_absorb(&rng_state, (unsigned char *)&ts, sizeof(ts));
#else
        time_t t = time(0);
        gimli24_hash_absorb(&rng_state, (unsigned char *)&t, sizeof(t));
#endif
        gimli24_hash_squeeze(&rng_state, data, sizeof(data));
        value = ((unsigned long)(data[0])) |
               (((unsigned long)(data[1])) << 8) |
               (((unsigned long)(data[2])) << 16) |
               (((unsigned long)(data[3])) << 24);
        snprintf(new_seed, sizeof(new_seed), "%lu", value);
        printf("SEED: %lu\n", value);
        gimli24_hash_init(&rng_state);
        gimli24_hash_absorb
            (&rng_state, (unsigned char *)new_seed, strlen(new_seed));
    }
}

/**
 * \brief Generates random data that is suitable for KAT vectors.
 *
 * \param data Buffer to fill with random data.
 * \param size Number of bytes to generate.
 */
static void rng_generate(unsigned char *data, unsigned size)
{
    if (rng_active) {
        /* Squeeze more random data out of the Gimli state */
        gimli24_hash_squeeze(&rng_state, data, size);
    } else {
        /* No RNG, so always return 0 .. size-1 as the "random" data */
        unsigned index;
        for (index = 0; index < size; ++index)
            data[index] = (unsigned char)index;
    }
}

/**
 * \brief Parses a numeric option.
 *
 * \param name1 The name of the option from the command-line.
 * \param name2 The name of the option we are looking for.
 * \param value The value to return if \a name1 is the same as \a name2.
 *
 * \return Non-zero if the option was parsed or zero if \a name1 is
 * not the same as \a name2.
 */
static int parse_option(const char *name1, const char *name2, int *value)
{
    size_t len = strlen(name2);
    if (strlen(name1) <= len)
        return 0;
    if (strncmp(name1, name2, len) != 0 || name1[len] != '=')
        return 0;
    *value = atoi(name1 + len + 1);
    if (*value < 0)
        *value = 0; /* Sanity check */
    else if (*value > 100000)
        *value = 100000; /* Sanity check */
    return 1;
}

/**
 * \brief Parses the command-line parameters.
 *
 * \param argc Number of arguments.
 * \param argv Array of arguments.
 *
 * \return Non-zero if the command-line parameters are ok, 0 on error.
 */
static int parse_command_line(int argc, char **argv)
{
    /* Process options first */
    while (argc > 1 && !strncmp(argv[1], "--", 2)) {
        const char *name = argv[1] + 2;
        ++argv;
        --argc;
        if (*name == '\0') /* "--" on its own terminates the options */
            break;
        if (parse_option(name, "min-ad", &min_ad))
            continue;
        if (parse_option(name, "max-ad", &max_ad))
            continue;
        if (parse_option(name, "min-pt", &min_pt))
            continue;
        if (parse_option(name, "max-pt", &max_pt))
            continue;
        if (parse_option(name, "min-msg", &min_msg))
            continue;
        if (parse_option(name, "max-msg", &max_msg))
            continue;
        if (!strcmp(name, "random")) {
            rng_init(0);
            continue;
        } else if (!strncmp(name, "random=", 7)) {
            rng_init(name + 7);
            continue;
        }
        if (strcmp(name, "help") != 0)
            fprintf(stderr, "Unknown option '--%s'\n", name);
        return 0;
    }

    /* All we should have left is the algorithm name and filename */
    if (argc != 3)
        return 0;
    alg_name = argv[1];
    output_filename = argv[2];

    /* Look up the algorithm; is it a cipher or a hash? */
    alg_cipher = find_cipher(alg_name);
    if (!alg_cipher) {
        alg_hash = find_hash_algorithm(alg_name);
        if (!alg_hash) {
            fprintf(stderr, "Unknown algorithm name '%s'\n", alg_name);
            return 0;
        }
    }

    /* Done */
    return 1;
}

/**
 * \brief Prints usage information for this program.
 *
 * \param progname Name of the program from the argv[0] argument.
 */
static void usage(const char *progname)
{
    fprintf(stderr, "Usage: %s [options] ALGORITHM FILE\n\n", progname);

    fprintf(stderr, "Options:\n");
    fprintf(stderr, "    --min-ad=SIZE\n");
    fprintf(stderr, "        Set the minimum associated data size, default is 0.\n\n");

    fprintf(stderr, "    --max-ad=SIZE\n");
    fprintf(stderr, "        Set the maximum associated data size, default is 32.\n\n");

    fprintf(stderr, "    --min-pt=SIZE\n");
    fprintf(stderr, "        Set the minimum plaintext message size, default is 0.\n\n");

    fprintf(stderr, "    --max-pt=SIZE\n");
    fprintf(stderr, "        Set the maximum plaintext message size, default is 32.\n\n");

    fprintf(stderr, "    --min-msg=SIZE\n");
    fprintf(stderr, "        Set the minimum message size for hash inputs, default is 0.\n\n");

    fprintf(stderr, "    --max-msg=SIZE\n");
    fprintf(stderr, "        Set the maximum message size for hash inputs, default is 1024.\n\n");

    fprintf(stderr, "    --random\n");
    fprintf(stderr, "    --random=SEED\n");
    fprintf(stderr, "        Randomize the key, nonce, plaintext, and hash input for each\n");
    fprintf(stderr, "        KAT vector based on the given SEED.  The same random data will\n");
    fprintf(stderr, "        be generated each time for a given SEED to allow reproducibility.\n");
    fprintf(stderr, "        If the SEED is omitted, then a seed based on the current system\n");
    fprintf(stderr, "        time will be generated and written to stdout.\n");

    print_algorithm_names();
}

static void write_hex
    (FILE *file, const char *name, const unsigned char *data, int len)
{
    fprintf(file, "%s = ", name);
    while (len > 0) {
        fprintf(file, "%02X", data[0]);
        ++data;
        --len;
    }
    fprintf(file, "\n");
}

/**
 * \brief Generate Known Answer Tests for an AEAD encryption algorithm.
 *
 * \param alg Meta-information about the algorithm.
 * \param file Output file to write the test vectors to.
 */
static void generate_kats_for_cipher(const aead_cipher_t *alg, FILE *file)
{
    int count = 1;
    int pt_len, ad_len;
    unsigned long long clen;

    /* Allocate space for the temporary buffers we will need */
    unsigned char *key = (unsigned char *)malloc(alg->key_len);
    unsigned char *nonce = (unsigned char *)malloc(alg->nonce_len);
    unsigned char *ad = (unsigned char *)malloc(max_ad);
    unsigned char *pt = (unsigned char *)malloc(max_pt);
    unsigned char *ct = (unsigned char *)malloc(max_pt + alg->tag_len);
    if (!key || !nonce || !ad || !pt || !ct) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    /* Generate the KAT vectors */
    for (pt_len = min_pt; pt_len <= max_pt; ++pt_len) {
        for (ad_len = min_ad; ad_len <= max_ad; ++ad_len) {
            /* Generate the vectors for this test */
            rng_generate(key, alg->key_len);
            rng_generate(nonce, alg->nonce_len);
            rng_generate(ad, ad_len);
            rng_generate(pt, pt_len);

            /* Produce the ciphertext output */
            (*(alg->encrypt))
                (ct, &clen, pt, pt_len, ad, ad_len, 0, nonce, key);

            /* Write out the results */
            fprintf(file, "Count = %d\n", count++);
            write_hex(file, "Key", key, alg->key_len);
            write_hex(file, "Nonce", nonce, alg->nonce_len);
            write_hex(file, "PT", pt, pt_len);
            write_hex(file, "AD", ad, ad_len);
            write_hex(file, "CT", ct, clen);
            fprintf(file, "\n");
        }
    }

    /* Clean up */
    free(key);
    free(nonce);
    free(ad);
    free(pt);
    free(ct);
}

/**
 * \brief Generate Known Answer Tests for a hash algorithm.
 *
 * \param alg Meta-information about the algorithm.
 * \param file Output file to write the test vectors to.
 */
static void generate_kats_for_hash(const aead_hash_algorithm_t *alg, FILE *file)
{
    int count = 1;
    int msg_len;

    /* Allocate space for the temporary buffers we will need */
    unsigned char *state = (unsigned char *)malloc(alg->state_size);
    unsigned char *msg = (unsigned char *)malloc(max_msg);
    unsigned char *hash = (unsigned char *)malloc(alg->hash_len);
    if (!state || !msg || !hash) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    /* Generate the KAT vectors */
    for (msg_len = min_msg; msg_len <= max_msg; ++msg_len) {
        /* Generate the vectors for this test */
        rng_generate(msg, msg_len);

        /* Produce the hash output */
        (*(alg->hash))(hash, msg, msg_len);

        /* Write out the results */
        fprintf(file, "Count = %d\n", count++);
        write_hex(file, "Msg", msg, msg_len);
        write_hex(file, "MD", hash, alg->hash_len);
        fprintf(file, "\n");
    }

    /* Clean up */
    free(state);
    free(msg);
    free(hash);
}

int main(int argc, char *argv[])
{
    FILE *file;

    /* Parse the command-line */
    if (!parse_command_line(argc, argv)) {
        usage(argv[0]);
        return 1;
    }

    /* Open the output file */
    if ((file = fopen(output_filename, "w")) == NULL) {
        perror(output_filename);
        return 1;
    }

    /* Generate the KAT vectors for the algorithm */
    if (alg_cipher)
        generate_kats_for_cipher(alg_cipher, file);
    else if (alg_hash)
        generate_kats_for_hash(alg_hash, file);

    /* Clean up and exit */
    fclose(file);
    return 0;
}
