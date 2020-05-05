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

#include "gen.h"
#include <iostream>
#include <cstring>

enum Mode
{
    Generate,
    Test
};

static void header(std::ostream &ostream)
{
    ostream << "#if defined(__AVR__)" << std::endl;
    ostream << "#include <avr/io.h>" << std::endl;
    ostream << "/* Automatically generated - do not edit */" << std::endl;
}

static void footer(std::ostream &ostream)
{
    ostream << std::endl;
    ostream << "#endif" << std::endl;
}

static bool ascon(enum Mode mode)
{
    Code code;
    gen_ascon_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_ascon_permutation(code)) {
            std::cout << "ASCON tests failed" << std::endl;
            return false;
        } else {
            std::cout << "ASCON tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool cham128(enum Mode mode)
{
    Code code;
    gen_cham128_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_cham128_encrypt(code)) {
            std::cout << "CHAM128-128 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "CHAM128-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool cham64(enum Mode mode)
{
    Code code;
    gen_cham64_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_cham64_encrypt(code)) {
            std::cout << "CHAM64-128 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "CHAM64-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gascon128_core(enum Mode mode)
{
    Code code;
    gen_gascon128_core_round(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gascon128_core_round(code)) {
            std::cout << "GASCON-128 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GASCON-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gascon128_g(enum Mode mode)
{
    Code code;
    gen_drysponge128_g(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_drysponge128_g(code)) {
            std::cout << "GASCON-128-G tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GASCON-128-G tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gascon128(enum Mode mode)
{
    bool ok = true;
    if (!gascon128_core(mode))
        ok = false;
    if (!gascon128_g(mode))
        ok = false;
    return ok;
}

static bool gascon256_core(enum Mode mode)
{
    Code code;
    gen_gascon256_core_round(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gascon256_core_round(code)) {
            std::cout << "GASCON-256 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GASCON-256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gascon256_g(enum Mode mode)
{
    Code code;
    gen_drysponge256_g(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_drysponge256_g(code)) {
            std::cout << "GASCON-256-G tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GASCON-256-G tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gascon256(enum Mode mode)
{
    bool ok = true;
    if (!gascon256_core(mode))
        ok = false;
    if (!gascon256_g(mode))
        ok = false;
    return ok;
}

static bool gift128b_setup_key(enum Mode mode)
{
    Code code;
    gen_gift128b_setup_key(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_setup_key(code)) {
            std::cout << "GIFT-128b key setup tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128b_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_encrypt(code)) {
            std::cout << "GIFT-128b encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_encrypt_block_preloaded(enum Mode mode)
{
    Code code;
    gen_gift128b_encrypt_preloaded(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_encrypt_preloaded(code)) {
            std::cout << "GIFT-128b preloaded encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b preloaded encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128b_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_decrypt(code)) {
            std::cout << "GIFT-128b decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b(enum Mode mode)
{
    bool ok = true;
    if (!gift128b_setup_key(mode))
        ok = false;
    if (!gift128b_encrypt_block(mode))
        ok = false;
    if (!gift128b_encrypt_block_preloaded(mode))
        ok = false;
    if (!gift128b_decrypt_block(mode))
        ok = false;
    return ok;
}

static bool gift128n_setup_key(enum Mode mode)
{
    Code code;
    gen_gift128n_setup_key(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128n_setup_key(code)) {
            std::cout << "GIFT-128n key setup tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128n_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_encrypt(code)) {
            std::cout << "GIFT-128n encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128n_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_decrypt(code)) {
            std::cout << "GIFT-128n decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128t_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_encrypt(code)) {
            std::cout << "TweGIFT-128 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "TweGIFT-128 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift128t_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_decrypt(code)) {
            std::cout << "TweGIFT-128 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "TweGIFT-128 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n(enum Mode mode)
{
    bool ok = true;
    if (!gift128n_setup_key(mode))
        ok = false;
    if (!gift128n_encrypt_block(mode))
        ok = false;
    if (!gift128n_decrypt_block(mode))
        ok = false;
    if (!gift128t_encrypt_block(mode))
        ok = false;
    if (!gift128t_decrypt_block(mode))
        ok = false;
    return ok;
}

static bool gift64_setup_key(enum Mode mode)
{
    Code code;
    gen_gift64n_setup_key(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64n_setup_key(code)) {
            std::cout << "GIFT-64 key setup tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-64 key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift64n_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64n_encrypt(code)) {
            std::cout << "GIFT-64 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-64 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift64n_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64n_decrypt(code)) {
            std::cout << "GIFT-64 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-64 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64t_encrypt_block(enum Mode mode)
{
    Code code;
    gen_gift64t_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64t_encrypt(code)) {
            std::cout << "TweGIFT-64 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "TweGIFT-64 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64t_decrypt_block(enum Mode mode)
{
    Code code;
    gen_gift64t_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64t_decrypt(code)) {
            std::cout << "TweGIFT-64 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "TweGIFT-64 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64(enum Mode mode)
{
    bool ok = true;
    if (!gift64_setup_key(mode))
        ok = false;
    if (!gift64_encrypt_block(mode))
        ok = false;
    if (!gift64_decrypt_block(mode))
        ok = false;
    if (!gift64t_encrypt_block(mode))
        ok = false;
    if (!gift64t_decrypt_block(mode))
        ok = false;
    return ok;
}

static bool gimli24(enum Mode mode)
{
    Code code;
    gen_gimli24_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gimli24_permutation(code)) {
            std::cout << "GIMLI-24 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "GIMLI-24 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool keccakp_200(enum Mode mode)
{
    Code code;
    gen_keccakp_200_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_keccakp_200_permutation(code)) {
            std::cout << "Keccak-p[200] tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Keccak-p[200] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool keccakp_400(enum Mode mode)
{
    Code code;
    gen_keccakp_400_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_keccakp_400_permutation(code)) {
            std::cout << "Keccak-p[400] tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Keccak-p[400] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask_96_setup_key(enum Mode mode)
{
    Code code;
    gen_pyjamask_96_setup_key(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_pyjamask_96_setup_key(code)) {
            std::cout << "Pyjamask-96 key setup tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Pyjamask-96 key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask_96_encrypt_block(enum Mode mode)
{
    Code code;
    gen_pyjamask_96_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_pyjamask_96_encrypt(code)) {
            std::cout << "Pyjamask-96 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Pyjamask-96 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask_96_decrypt_block(enum Mode mode)
{
    Code code;
    gen_pyjamask_96_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_pyjamask_96_decrypt(code)) {
            std::cout << "Pyjamask-96 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Pyjamask-96 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask_128_setup_key(enum Mode mode)
{
    Code code;
    gen_pyjamask_128_setup_key(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_pyjamask_128_setup_key(code)) {
            std::cout << "Pyjamask-128 key setup tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Pyjamask-128 key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask_128_encrypt_block(enum Mode mode)
{
    Code code;
    gen_pyjamask_128_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_pyjamask_128_encrypt(code)) {
            std::cout << "Pyjamask-128 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Pyjamask-128 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask_128_decrypt_block(enum Mode mode)
{
    Code code;
    gen_pyjamask_128_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_pyjamask_128_decrypt(code)) {
            std::cout << "Pyjamask-128 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Pyjamask-128 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool pyjamask(enum Mode mode)
{
    bool ok = true;
    if (!pyjamask_96_setup_key(mode))
        ok = false;
    if (!pyjamask_96_encrypt_block(mode))
        ok = false;
    if (!pyjamask_96_decrypt_block(mode))
        ok = false;
    if (!pyjamask_128_setup_key(mode))
        ok = false;
    if (!pyjamask_128_encrypt_block(mode))
        ok = false;
    if (!pyjamask_128_decrypt_block(mode))
        ok = false;
    return ok;
}

static void skinny128_sboxes(enum Mode mode)
{
    if (mode == Generate) {
        Code code;
        for (int index = 0; index < SKINNY128_SBOX_COUNT; ++index)
            code.sbox_write(std::cout, index, get_skinny128_sbox(index));
    }
}

static bool skinny128_384_setup_key(enum Mode mode)
{
    Code code;
    gen_skinny128_384_setup_key(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool skinny128_384_encrypt(enum Mode mode)
{
    Code code;
    gen_skinny128_384_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
        code.write_alias(std::cout, "skinny_128_384_encrypt_tk_full");
    } else {
        if (!test_skinny128_384_encrypt(code)) {
            std::cout << "SKINNY-128-384 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-384 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128_384_decrypt(enum Mode mode)
{
    Code code;
    gen_skinny128_384_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_skinny128_384_decrypt(code)) {
            std::cout << "SKINNY-128-384 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-384 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128_256_setup_key(enum Mode mode)
{
    Code code;
    gen_skinny128_256_setup_key(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool skinny128_256_encrypt(enum Mode mode)
{
    Code code;
    gen_skinny128_256_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
        code.write_alias(std::cout, "skinny_128_256_encrypt_tk_full");
    } else {
        if (!test_skinny128_256_encrypt(code)) {
            std::cout << "SKINNY-128-256 encrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-256 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128_256_decrypt(enum Mode mode)
{
    Code code;
    gen_skinny128_256_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_skinny128_256_decrypt(code)) {
            std::cout << "SKINNY-128-256 decrypt tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SKINNY-128-256 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool skinny128(enum Mode mode)
{
    bool ok = true;
    skinny128_sboxes(mode);
    if (!skinny128_384_setup_key(mode))
        ok = false;
    if (!skinny128_384_encrypt(mode))
        ok = false;
    if (!skinny128_384_decrypt(mode))
        ok = false;
    if (!skinny128_256_setup_key(mode))
        ok = false;
    if (!skinny128_256_encrypt(mode))
        ok = false;
    if (!skinny128_256_decrypt(mode))
        ok = false;
    return ok;
}

static bool speck64(enum Mode mode)
{
    Code code;
    gen_speck64_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_speck64_encrypt(code)) {
            std::cout << "SPECK-64 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SPECK-64 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sparkle256(enum Mode mode)
{
    Code code;
    gen_sparkle256_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sparkle256_permutation(code)) {
            std::cout << "SPARKLE-256 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SPARKLE-256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sparkle384(enum Mode mode)
{
    Code code;
    gen_sparkle384_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sparkle384_permutation(code)) {
            std::cout << "SPARKLE-384 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SPARKLE-384 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sparkle512(enum Mode mode)
{
    Code code;
    gen_sparkle512_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_sparkle512_permutation(code)) {
            std::cout << "SPARKLE-512 tests failed" << std::endl;
            return false;
        } else {
            std::cout << "SPARKLE-512 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spongent160(enum Mode mode)
{
    Code code;
    gen_spongent160_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_spongent_sbox());
        code.write(std::cout);
    } else {
        if (!test_spongent160_permutation(code)) {
            std::cout << "Spongent-pi[160] tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Spongent-pi[160] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spongent176(enum Mode mode)
{
    Code code;
    gen_spongent176_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_spongent176_permutation(code)) {
            std::cout << "Spongent-pi[176] tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Spongent-pi[176] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool tinyjambu(enum Mode mode)
{
    Code code;
    gen_tinyjambu_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_tinyjambu_permutation(code)) {
            std::cout << "TinyJAMBU tests failed" << std::endl;
            return false;
        } else {
            std::cout << "TinyJAMBU tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool xoodoo(enum Mode mode)
{
    Code code;
    gen_xoodoo_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_xoodoo_permutation(code)) {
            std::cout << "Xoodoo tests failed" << std::endl;
            return false;
        } else {
            std::cout << "Xoodoo tests succeeded" << std::endl;
        }
    }
    return true;
}

typedef bool (*gen_code)(enum Mode mode);

int main(int argc, char *argv[])
{
    bool generate = true;
    int exit_val = 0;
    gen_code gen1 = 0;
    gen_code gen2 = 0;
    gen_code gen3 = 0;

    if (argc > 1 && !strcmp(argv[1], "--test")) {
        generate = false;
    } else {
        if (argc <= 1) {
            fprintf(stderr, "Usage: %s algorithm-name\n", argv[0]);
            return 1;
        }
        if (!strcmp(argv[1], "ASCON")) {
            gen1 = ascon;
        } else if (!strcmp(argv[1], "CHAM")) {
            gen1 = cham128;
            gen2 = cham64;
        } else if (!strcmp(argv[1], "GASCON")) {
            gen1 = gascon128;
            gen2 = gascon256;
        } else if (!strcmp(argv[1], "GIFT-128b")) {
            gen1 = gift128b;
        } else if (!strcmp(argv[1], "GIFT-128n")) {
            gen1 = gift128n;
        } else if (!strcmp(argv[1], "GIFT-64")) {
            gen1 = gift64;
        } else if (!strcmp(argv[1], "GIMLI-24")) {
            gen1 = gimli24;
        } else if (!strcmp(argv[1], "Keccak")) {
            gen1 = keccakp_200;
            gen2 = keccakp_400;
        } else if (!strcmp(argv[1], "Pyjamask")) {
            gen1 = pyjamask;
        } else if (!strcmp(argv[1], "SKINNY-128")) {
            gen1 = skinny128;
        } else if (!strcmp(argv[1], "SPARKLE")) {
            gen1 = sparkle256;
            gen2 = sparkle384;
            gen3 = sparkle512;
        } else if (!strcmp(argv[1], "Spongent-pi")) {
            gen1 = spongent160;
            gen2 = spongent176;
        } else if (!strcmp(argv[1], "SPECK-64")) {
            gen1 = speck64;
        } else if (!strcmp(argv[1], "TinyJAMBU")) {
            gen1 = tinyjambu;
        } else if (!strcmp(argv[1], "Xoodoo")) {
            gen1 = xoodoo;
        }
    }

    if (generate) {
        header(std::cout);
        if (gen1)
            gen1(Generate);
        if (gen2)
            gen2(Generate);
        if (gen3)
            gen3(Generate);
        footer(std::cout);
    } else {
        if (!ascon(Test))
            exit_val = 1;
        if (!cham128(Test))
            exit_val = 1;
        if (!cham64(Test))
            exit_val = 1;
        if (!gascon128(Test))
            exit_val = 1;
        if (!gascon256(Test))
            exit_val = 1;
        if (!gift128b(Test))
            exit_val = 1;
        if (!gift128n(Test))
            exit_val = 1;
        if (!gift64(Test))
            exit_val = 1;
        if (!gimli24(Test))
            exit_val = 1;
        if (!keccakp_200(Test))
            exit_val = 1;
        if (!keccakp_400(Test))
            exit_val = 1;
        if (!pyjamask(Test))
            exit_val = 1;
        if (!skinny128(Test))
            exit_val = 1;
        if (!speck64(Test))
            exit_val = 1;
        if (!sparkle256(Test))
            exit_val = 1;
        if (!sparkle384(Test))
            exit_val = 1;
        if (!sparkle512(Test))
            exit_val = 1;
        if (!spongent160(Test))
            exit_val = 1;
        if (!spongent176(Test))
            exit_val = 1;
        if (!tinyjambu(Test))
            exit_val = 1;
        if (!xoodoo(Test))
            exit_val = 1;
    }

    return exit_val;
}
