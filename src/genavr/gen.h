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

// ASCON permutation.
void gen_ascon_permutation(Code &code);
bool test_ascon_permutation(Code &code);

// CHAM-128 and CHAM-64 block ciphers.
void gen_cham128_encrypt(Code &code);
void gen_cham64_encrypt(Code &code);
bool test_cham128_encrypt(Code &code);
bool test_cham64_encrypt(Code &code);

// ForkSkinny block cipher.
#define FORKSKINNY_SBOX_COUNT 9
Sbox get_forkskinny_sbox(int num);
void gen_forkskinny128_256_rounds(Code &code);
void gen_forkskinny128_256_inv_rounds(Code &code);
void gen_forkskinny128_256_forward_tk(Code &code);
void gen_forkskinny128_256_reverse_tk(Code &code);
void gen_forkskinny128_384_rounds(Code &code);
void gen_forkskinny128_384_inv_rounds(Code &code);
void gen_forkskinny128_384_forward_tk(Code &code);
void gen_forkskinny128_384_reverse_tk(Code &code);
void gen_forkskinny64_192_rounds(Code &code);
void gen_forkskinny64_192_inv_rounds(Code &code);
void gen_forkskinny64_192_forward_tk(Code &code);
void gen_forkskinny64_192_reverse_tk(Code &code);
bool test_forkskinny128_256_rounds(Code &code);
bool test_forkskinny128_256_inv_rounds(Code &code);
bool test_forkskinny128_256_forward_tk(Code &code);
bool test_forkskinny128_256_reverse_tk(Code &code);
bool test_forkskinny128_384_rounds(Code &code);
bool test_forkskinny128_384_inv_rounds(Code &code);
bool test_forkskinny128_384_forward_tk(Code &code);
bool test_forkskinny128_384_reverse_tk(Code &code);
bool test_forkskinny64_192_rounds(Code &code);
bool test_forkskinny64_192_inv_rounds(Code &code);
bool test_forkskinny64_192_forward_tk(Code &code);
bool test_forkskinny64_192_reverse_tk(Code &code);

// GASCON permutation and DrySPONGE helper functions.
void gen_gascon128_core_round(Code &code);
void gen_gascon128_permutation(Code &code);
void gen_drysponge128_g(Code &code);
void gen_gascon256_core_round(Code &code);
void gen_drysponge256_g(Code &code);
bool test_gascon128_core_round(Code &code);
bool test_gascon128_permutation(Code &code);
bool test_drysponge128_g(Code &code);
bool test_gascon256_core_round(Code &code);
bool test_drysponge256_g(Code &code);

// GIFT-128 block cipher (bit-sliced).
Sbox get_gift128_round_constants();
void gen_gift128b_setup_key(Code &code);
void gen_gift128b_encrypt(Code &code);
void gen_gift128b_encrypt_preloaded(Code &code);
void gen_gift128b_decrypt(Code &code);
void gen_gift128b_setup_key_alt(Code &code);
void gen_gift128b_encrypt_alt(Code &code);
void gen_gift128b_decrypt_alt(Code &code);
void gen_gift128n_setup_key(Code &code);
void gen_gift128n_encrypt(Code &code);
void gen_gift128n_decrypt(Code &code);
void gen_gift128t_encrypt(Code &code);
void gen_gift128t_decrypt(Code &code);
void gen_gift128n_encrypt_alt(Code &code);
void gen_gift128n_decrypt_alt(Code &code);
bool test_gift128b_setup_key(Code &code);
bool test_gift128n_setup_key(Code &code);
bool test_gift128b_encrypt(Code &code);
bool test_gift128b_encrypt_preloaded(Code &code);
bool test_gift128b_decrypt(Code &code);
bool test_gift128n_setup_key(Code &code);
bool test_gift128n_encrypt(Code &code);
bool test_gift128n_decrypt(Code &code);
bool test_gift128t_encrypt(Code &code);
bool test_gift128t_decrypt(Code &code);
bool test_gift128n_encrypt_alt(Code &code);
bool test_gift128n_decrypt_alt(Code &code);

// GIFT-128 block cipher (fix-sliced).
Sbox get_gift128_fs_round_constants();
void gen_gift128b_fs_setup_key(Code &code, int num_keys);
void gen_gift128b_fs_setup_key_alt(Code &code, int num_keys);
void gen_gift128n_fs_setup_key(Code &code, int num_keys);
void gen_gift128b_fs_encrypt(Code &code, int num_keys);
void gen_gift128b_fs_encrypt_alt(Code &code, int num_keys);
void gen_gift128b_fs_encrypt_preloaded(Code &code, int num_keys);
void gen_gift128n_fs_encrypt(Code &code, int num_keys);
void gen_gift128n_fs_encrypt_alt(Code &code, int num_keys);
void gen_gift128t_fs_encrypt(Code &code, int num_keys);
void gen_gift128b_fs_decrypt(Code &code, int num_keys);
void gen_gift128b_fs_decrypt_alt(Code &code, int num_keys);
void gen_gift128n_fs_decrypt(Code &code, int num_keys);
void gen_gift128n_fs_decrypt_alt(Code &code, int num_keys);
void gen_gift128t_fs_decrypt(Code &code, int num_keys);
bool test_gift128b_fs_setup_key(Code &code, int num_keys);
bool test_gift128n_fs_setup_key(Code &code, int num_keys);
bool test_gift128b_fs_encrypt(Code &code, int num_keys);
bool test_gift128b_fs_encrypt_preloaded(Code &code, int num_keys);
bool test_gift128n_fs_encrypt(Code &code, int num_keys);
bool test_gift128n_fs_encrypt_alt(Code &code, int num_keys);
bool test_gift128t_fs_encrypt(Code &code, int num_keys);
bool test_gift128b_fs_decrypt(Code &code, int num_keys);
bool test_gift128n_fs_decrypt(Code &code, int num_keys);
bool test_gift128n_fs_decrypt_alt(Code &code, int num_keys);
bool test_gift128t_fs_decrypt(Code &code, int num_keys);

// GIFT-64 block cipher.
void gen_gift64n_setup_key(Code &code);
void gen_gift64_setup_key_alt(Code &code);
void gen_gift64n_encrypt(Code &code);
void gen_gift64n_decrypt(Code &code);
void gen_gift64t_encrypt(Code &code);
void gen_gift64t_decrypt(Code &code);
void gen_gift64_encrypt_alt(Code &code);
void gen_gift64_decrypt_alt(Code &code);
bool test_gift64n_setup_key(Code &code);
bool test_gift64_setup_key_alt(Code &code);
bool test_gift64n_encrypt(Code &code);
bool test_gift64n_decrypt(Code &code);
bool test_gift64t_encrypt(Code &code);
bool test_gift64t_decrypt(Code &code);
bool test_gift64_encrypt_alt(Code &code);
bool test_gift64_decrypt_alt(Code &code);

// GIMLI-24 permutation.
void gen_gimli24_permutation(Code &code);
bool test_gimli24_permutation(Code &code);

// Grain-128 stream cipher.
void gen_grain128_core(Code &code);
void gen_grain128_preoutput(Code &code);
void gen_grain128_swap_word32(Code &code);
void gen_grain128_compute_tag(Code &code);
void gen_grain128_interleave(Code &code);
bool test_grain128_core(Code &code);
bool test_grain128_preoutput(Code &code);

// Keccak permutation.
void gen_keccakp_200_permutation(Code &code);
void gen_keccakp_400_permutation(Code &code);
bool test_keccakp_200_permutation(Code &code);
bool test_keccakp_400_permutation(Code &code);

// KNOT permutation.
Sbox get_knot_round_constants(int rc_bits);
void gen_knot256_permutation(Code &code, int rc_bits);
void gen_knot384_permutation(Code &code, int rc_bits);
void gen_knot512_permutation(Code &code, int rc_bits);
bool test_knot256_permutation(Code &code, int rc_bits);
bool test_knot384_permutation(Code &code, int rc_bits);
bool test_knot512_permutation(Code &code, int rc_bits);

// PHOTON-256 permutation.
void gen_photon256_permutation(Code &code);
bool test_photon256_permutation(Code &code);

// Pyjamask block cipher.
void gen_pyjamask_128_setup_key(Code &code);
void gen_pyjamask_128_encrypt(Code &code);
void gen_pyjamask_128_decrypt(Code &code);
void gen_pyjamask_96_setup_key(Code &code);
void gen_pyjamask_96_encrypt(Code &code);
void gen_pyjamask_96_decrypt(Code &code);
bool test_pyjamask_128_setup_key(Code &code);
bool test_pyjamask_128_encrypt(Code &code);
bool test_pyjamask_128_decrypt(Code &code);
bool test_pyjamask_96_setup_key(Code &code);
bool test_pyjamask_96_encrypt(Code &code);
bool test_pyjamask_96_decrypt(Code &code);

// Saturnin block cipher.
Sbox get_saturnin_round_constants();
void gen_saturnin_setup_key(Code &code);
void gen_saturnin_encrypt(Code &code);
void gen_saturnin_decrypt(Code &code);
bool test_saturnin_setup_key(Code &code);
bool test_saturnin_encrypt(Code &code);
bool test_saturnin_decrypt(Code &code);

// SimP permutation.
void gen_simp_256_permutation(Code &code);
void gen_simp_192_permutation(Code &code);
bool test_simp_256_permutation(Code &code);
bool test_simp_192_permutation(Code &code);

// SKINNY-128 block cipher.
#define SKINNY128_SBOX_COUNT 5
Sbox get_skinny128_sbox(int num);
void gen_skinny128_384_setup_key(Code &code);
void gen_skinny128_256_setup_key(Code &code);
void gen_skinny128_384_encrypt(Code &code);
void gen_skinny128_256_encrypt(Code &code);
void gen_skinny128_384_decrypt(Code &code);
void gen_skinny128_256_decrypt(Code &code);
bool test_skinny128_384_encrypt(Code &code);
bool test_skinny128_256_encrypt(Code &code);
bool test_skinny128_384_decrypt(Code &code);
bool test_skinny128_256_decrypt(Code &code);

// sLiSCP-light-192 permutation.
Sbox get_sliscp_light256_round_constants();
Sbox get_sliscp_light192_round_constants();
Sbox get_sliscp_light320_round_constants();
void gen_sliscp_light256_spix_permutation(Code &code);
void gen_sliscp_light256_spoc_permutation(Code &code);
void gen_sliscp_light256_swap_spix(Code &code);
void gen_sliscp_light256_swap_spoc(Code &code);
void gen_sliscp_light192_permutation(Code &code);
void gen_sliscp_light320_permutation(Code &code);
void gen_sliscp_light320_swap(Code &code);
bool test_sliscp_light256_spix_permutation(Code &code);
bool test_sliscp_light256_spoc_permutation(Code &code);
bool test_sliscp_light192_permutation(Code &code);
bool test_sliscp_light320_permutation(Code &code);

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

// Spongent-pi permutation.
Sbox get_spongent_sbox();
void gen_spongent160_permutation(Code &code);
void gen_spongent176_permutation(Code &code);
bool test_spongent160_permutation(Code &code);
bool test_spongent176_permutation(Code &code);

// Spook: Clyde-128 block cipher and Shadow permutation.
void gen_clyde128_encrypt(Code &code);
void gen_clyde128_decrypt(Code &code);
void gen_shadow512_permutation(Code &code);
void gen_shadow384_permutation(Code &code);
bool test_clyde128_encrypt(Code &code);
bool test_clyde128_decrypt(Code &code);
bool test_shadow512_permutation(Code &code);
bool test_shadow384_permutation(Code &code);

// Subterranean permutation.
void gen_subterranean_permutation(Code &code);
void gen_subterranean_absorb(Code &code, int count);
void gen_subterranean_extract(Code &code);
bool test_subterranean_permutation(Code &code);

// TinyJAMBU permutation.
void gen_tinyjambu_permutation(Code &code);
bool test_tinyjambu_permutation(Code &code);

// WAGE permutation.
Sbox get_wage_round_constants(int num);
void gen_wage_permutation(Code &code);
void gen_wage_absorb(Code &code);
void gen_wage_get_rate(Code &code);
void gen_wage_set_rate(Code &code);
bool test_wage_permutation(Code &code);

// Xoodoo permutation.
void gen_xoodoo_permutation(Code &code);
bool test_xoodoo_permutation(Code &code);

#endif
