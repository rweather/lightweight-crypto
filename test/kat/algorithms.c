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
#include "ace.h"
#include "ascon128.h"
#include "ascon128-masked.h"
#include "comet.h"
#include "drygascon.h"
#include "elephant.h"
#include "estate.h"
#include "forkae.h"
#include "gift-cofb.h"
#include "gift-cofb-masked.h"
#include "gimli24.h"
#include "gimli24-masked.h"
#include "grain128.h"
#include "hyena.h"
#include "isap.h"
#include "knot.h"
#include "lotus-locus.h"
#include "orange.h"
#include "oribatida.h"
#include "photon-beetle.h"
#include "pyjamask.h"
#include "pyjamask-masked.h"
#include "romulus.h"
#include "saturnin.h"
#include "sparkle.h"
#include "skinny-aead.h"
#include "skinny-hash.h"
#include "spix.h"
#include "spoc.h"
#include "spook.h"
#include "spook-masked.h"
#include "subterranean.h"
#include "sundae-gift.h"
#include "tinyjambu.h"
#include "tinyjambu-masked.h"
#include "wage.h"
#include "xoodyak.h"
#include <string.h>
#include <stdio.h>

/* List of all AEAD ciphers that we can run KAT tests for */
static const aead_cipher_t *const ciphers[] = {
    &ace_cipher,
    &ascon128_cipher,
    &ascon128a_cipher,
    &ascon80pq_cipher,
    &ascon128_masked_cipher,
    &ascon128a_masked_cipher,
    &ascon80pq_masked_cipher,
    &comet_128_cham_cipher,
    &comet_64_cham_cipher,
    &comet_64_speck_cipher,
    &drygascon128_cipher,
    &drygascon256_cipher,
    &dumbo_cipher,
    &jumbo_cipher,
    &delirium_cipher,
    &estate_twegift_cipher,
    &forkae_paef_64_192_cipher,
    &forkae_paef_128_192_cipher,
    &forkae_paef_128_256_cipher,
    &forkae_paef_128_288_cipher,
    &forkae_saef_128_192_cipher,
    &forkae_saef_128_256_cipher,
    &gift_cofb_cipher,
    &gift_cofb_masked_cipher,
    &gimli24_cipher,
    &gimli24_masked_cipher,
    &grain128_aead_cipher,
    &hyena_v1_cipher,
    &hyena_v2_cipher,
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
    &orange_zest_cipher,
    &oribatida_256_cipher,
    &oribatida_192_cipher,
    &photon_beetle_128_cipher,
    &photon_beetle_32_cipher,
    &pyjamask_128_cipher,
    &pyjamask_96_cipher,
    &pyjamask_masked_128_cipher,
    &pyjamask_masked_96_cipher,
    &romulus_m1_cipher,
    &romulus_m2_cipher,
    &romulus_m3_cipher,
    &romulus_n1_cipher,
    &romulus_n2_cipher,
    &romulus_n3_cipher,
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
    &spix_cipher,
    &spoc_128_cipher,
    &spoc_64_cipher,
    &spook_128_512_su_cipher,
    &spook_128_384_su_cipher,
    &spook_128_512_mu_cipher,
    &spook_128_384_mu_cipher,
    &spook_128_512_su_masked_cipher,
    &spook_128_384_su_masked_cipher,
    &spook_128_512_mu_masked_cipher,
    &spook_128_384_mu_masked_cipher,
    &subterranean_cipher,
    &sundae_gift_0_cipher,
    &sundae_gift_64_cipher,
    &sundae_gift_96_cipher,
    &sundae_gift_128_cipher,
    &tiny_jambu_128_cipher,
    &tiny_jambu_192_cipher,
    &tiny_jambu_256_cipher,
    &tiny_jambu_128_masked_cipher,
    &tiny_jambu_192_masked_cipher,
    &tiny_jambu_256_masked_cipher,
    &wage_cipher,
    &xoodyak_cipher,
    0
};

/* List of all hash algorithms that we can run KAT tests for */
static const aead_hash_algorithm_t *const hashes[] = {
    &ace_hash_algorithm,
    &ascon_hash_algorithm,
    &ascon_xof_algorithm,
    &drygascon128_hash_algorithm,
    &drygascon256_hash_algorithm,
    &esch_256_hash_algorithm,
    &esch_384_hash_algorithm,
    &gimli24_hash_algorithm,
    &knot_hash_256_256_algorithm,
    &knot_hash_256_384_algorithm,
    &knot_hash_384_384_algorithm,
    &knot_hash_512_512_algorithm,
    &orangish_hash_algorithm,
    &photon_beetle_hash_algorithm,
    &saturnin_hash_algorithm,
    &skinny_tk2_hash_algorithm,
    &skinny_tk3_hash_algorithm,
    &subterranean_hash_algorithm,
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

static void print_cipher_details(const aead_cipher_t *cipher)
{
    printf("%-30s %8u   %8u   %8u\n",
           cipher->name,
           cipher->key_len * 8,
           cipher->nonce_len * 8,
           cipher->tag_len * 8);
}

static void print_hash_details(const aead_hash_algorithm_t *hash)
{
    printf("%-30s %8u\n", hash->name, hash->hash_len * 8);
}

void print_algorithm_names(void)
{
    int index;
    printf("\nCipher                           Key Bits");
    printf("  Nonce Bits  Tag Bits\n");
    for (index = 0; ciphers[index] != 0; ++index)
        print_cipher_details(ciphers[index]);
    printf("\nHash Algorithm                   Hash Bits\n");
    for (index = 0; hashes[index] != 0; ++index)
        print_hash_details(hashes[index]);
}
