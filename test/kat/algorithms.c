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

#include "algorithms.h"
#include "ascon128.h"
#include "comet.h"
#include "estate.h"
#include "gift-cofb.h"
#include "gimli24.h"
#include "hyena.h"
#include "isap.h"
#include "knot.h"
#include "lotus-locus.h"
#include "pyjamask.h"
#include "saturnin.h"
#include "sparkle.h"
#include "skinny-aead.h"
#include "spook.h"
#include "sundae-gift.h"
#include "tinyjambu.h"
#include "xoodyak.h"
#include <string.h>
#include <stdio.h>

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
    &knot_aead_128_256_cipher,
    &knot_aead_128_384_cipher,
    &knot_aead_192_384_cipher,
    &knot_aead_256_512_cipher,
    &locus_aead_cipher,
    &lotus_aead_cipher,
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
    &spook_128_512_su_cipher,
    &spook_128_384_su_cipher,
    &spook_128_512_mu_cipher,
    &spook_128_384_mu_cipher,
    &sundae_gift_0_cipher,
    &sundae_gift_64_cipher,
    &sundae_gift_96_cipher,
    &sundae_gift_128_cipher,
    &tiny_jambu_128_cipher,
    &tiny_jambu_192_cipher,
    &tiny_jambu_256_cipher,
    &xoodyak_cipher,
    0
};

/* List of all hash algorithms that we can run KAT tests for */
static const aead_hash_algorithm_t *const hashes[] = {
    &ascon_hash_algorithm,
    &ascon_xof_algorithm,
    &esch_256_hash_algorithm,
    &esch_384_hash_algorithm,
    &gimli24_hash_algorithm,
    &knot_hash_256_256_algorithm,
    &knot_hash_256_384_algorithm,
    &knot_hash_384_384_algorithm,
    &knot_hash_512_512_algorithm,
    &saturnin_hash_algorithm,
    &xoodyak_hash_algorithm,
    0
};

const aead_cipher_t *find_cipher(const char *name)
{
    int index;
    for (index = 0; ciphers[index] != 0; ++index) {
        if (!strcmp(ciphers[index]->name, name))
            return ciphers[index];
    }
    return 0;
}

const aead_hash_algorithm_t *find_hash_algorithm(const char *name)
{
    int index;
    for (index = 0; hashes[index] != 0; ++index) {
        if (!strcmp(hashes[index]->name, name))
            return hashes[index];
    }
    return 0;
}

void print_algorithm_names(void)
{
    int index;
    fprintf(stderr, "\nCiphers:\n");
    for (index = 0; ciphers[index] != 0; ++index)
        fprintf(stderr, "    %s\n", ciphers[index]->name);
    fprintf(stderr, "\nHash Algorithms:\n");
    for (index = 0; hashes[index] != 0; ++index)
        fprintf(stderr, "    %s\n", hashes[index]->name);
}
