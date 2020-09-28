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
            std::cout << "ASCON tests FAILED" << std::endl;
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
            std::cout << "CHAM128-128 tests FAILED" << std::endl;
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
            std::cout << "CHAM64-128 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "CHAM64-128 tests succeeded" << std::endl;
        }
    }
    return true;
}

static void forkskinny_sboxes(enum Mode mode)
{
    if (mode == Generate) {
        Code code;
        for (int index = 0; index < FORKSKINNY_SBOX_COUNT; ++index)
            code.sbox_write(std::cout, index, get_forkskinny_sbox(index));
    }
}

static bool forkskinny128_256_rounds(enum Mode mode)
{
    Code code;
    gen_forkskinny128_256_rounds(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_256_rounds(code)) {
            std::cout << "ForkSkinny-128-256-rounds tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-256-rounds tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_256_inv_rounds(enum Mode mode)
{
    Code code;
    gen_forkskinny128_256_inv_rounds(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_256_inv_rounds(code)) {
            std::cout << "ForkSkinny-128-256-inv-rounds tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-256-inv-rounds tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_256_forward_tk(enum Mode mode)
{
    Code code;
    gen_forkskinny128_256_forward_tk(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_256_forward_tk(code)) {
            std::cout << "ForkSkinny-128-256-forward-tk tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-256-forward-tk tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_256_reverse_tk(enum Mode mode)
{
    Code code;
    gen_forkskinny128_256_reverse_tk(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_256_reverse_tk(code)) {
            std::cout << "ForkSkinny-128-256-reverse-tk tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-256-reverse-tk tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_384_rounds(enum Mode mode)
{
    Code code;
    gen_forkskinny128_384_rounds(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_384_rounds(code)) {
            std::cout << "ForkSkinny-128-384-rounds tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-384-rounds tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_384_inv_rounds(enum Mode mode)
{
    Code code;
    gen_forkskinny128_384_inv_rounds(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_384_inv_rounds(code)) {
            std::cout << "ForkSkinny-128-384-inv-rounds tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-384-inv-rounds tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_384_forward_tk(enum Mode mode)
{
    Code code;
    gen_forkskinny128_384_forward_tk(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_384_forward_tk(code)) {
            std::cout << "ForkSkinny-128-384-forward-tk tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-384-forward-tk tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny128_384_reverse_tk(enum Mode mode)
{
    Code code;
    gen_forkskinny128_384_reverse_tk(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny128_384_reverse_tk(code)) {
            std::cout << "ForkSkinny-128-384-reverse-tk tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-128-384-reverse-tk tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny64_192_rounds(enum Mode mode)
{
    Code code;
    gen_forkskinny64_192_rounds(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny64_192_rounds(code)) {
            std::cout << "ForkSkinny-64-192-rounds tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-64-192-rounds tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny64_192_inv_rounds(enum Mode mode)
{
    Code code;
    gen_forkskinny64_192_inv_rounds(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny64_192_inv_rounds(code)) {
            std::cout << "ForkSkinny-64-192-inv-rounds tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-64-192-inv-rounds tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny64_192_forward_tk(enum Mode mode)
{
    Code code;
    gen_forkskinny64_192_forward_tk(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny64_192_forward_tk(code)) {
            std::cout << "ForkSkinny-64-192-forward-tk tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-64-192-forward-tk tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny64_192_reverse_tk(enum Mode mode)
{
    Code code;
    gen_forkskinny64_192_reverse_tk(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_forkskinny64_192_reverse_tk(code)) {
            std::cout << "ForkSkinny-64-192-reverse-tk tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "ForkSkinny-64-192-reverse-tk tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool forkskinny(enum Mode mode)
{
    bool ok = true;
    forkskinny_sboxes(mode);
    if (!forkskinny128_256_rounds(mode))
        ok = false;
    if (!forkskinny128_256_inv_rounds(mode))
        ok = false;
    if (!forkskinny128_256_forward_tk(mode))
        ok = false;
    if (!forkskinny128_256_reverse_tk(mode))
        ok = false;
    if (!forkskinny128_384_rounds(mode))
        ok = false;
    if (!forkskinny128_384_inv_rounds(mode))
        ok = false;
    if (!forkskinny128_384_forward_tk(mode))
        ok = false;
    if (!forkskinny128_384_reverse_tk(mode))
        ok = false;
    if (!forkskinny64_192_rounds(mode))
        ok = false;
    if (!forkskinny64_192_inv_rounds(mode))
        ok = false;
    if (!forkskinny64_192_forward_tk(mode))
        ok = false;
    if (!forkskinny64_192_reverse_tk(mode))
        ok = false;
    return ok;
}

static bool gascon128_core(enum Mode mode)
{
    Code code;
    gen_gascon128_core_round(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gascon128_core_round(code)) {
            std::cout << "GASCON-128 tests FAILED" << std::endl;
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
            std::cout << "GASCON-128-G tests FAILED" << std::endl;
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

static bool gascon128_full(enum Mode mode)
{
    Code code;
    gen_gascon128_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gascon128_permutation(code)) {
            std::cout << "GASCON-128 permutation tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GASCON-128 permutation tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gascon256_core(enum Mode mode)
{
    Code code;
    gen_gascon256_core_round(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gascon256_core_round(code)) {
            std::cout << "GASCON-256 tests FAILED" << std::endl;
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
            std::cout << "GASCON-256-G tests FAILED" << std::endl;
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
            std::cout << "GIFT-128b key setup tests FAILED" << std::endl;
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
            std::cout << "GIFT-128b encrypt tests FAILED" << std::endl;
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
            std::cout << "GIFT-128b preloaded encrypt tests FAILED" << std::endl;
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
            std::cout << "GIFT-128b decrypt tests FAILED" << std::endl;
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

static bool gift128b_setup_key_alt(enum Mode mode)
{
    Code code;
    gen_gift128b_setup_key_alt(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_setup_key(code)) {
            std::cout << "GIFT-128b-alt key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_encrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128b_encrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_encrypt(code)) {
            std::cout << "GIFT-128b-alt encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_decrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128b_decrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_decrypt(code)) {
            std::cout << "GIFT-128b-alt decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_encrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128n_encrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_encrypt_alt(code)) {
            std::cout << "GIFT-128n-alt encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_decrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift128n_decrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_decrypt_alt(code)) {
            std::cout << "GIFT-128n-alt decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128_alt(enum Mode mode)
{
    bool ok = true;
    if (!gift128b_setup_key_alt(mode))
        ok = false;
    if (!gift128b_encrypt_block_alt(mode))
        ok = false;
    if (!gift128b_decrypt_block_alt(mode))
        ok = false;
    if (!gift128n_encrypt_block_alt(mode))
        ok = false;
    if (!gift128n_decrypt_block_alt(mode))
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
            std::cout << "GIFT-128n key setup tests FAILED" << std::endl;
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
            std::cout << "GIFT-128n encrypt tests FAILED" << std::endl;
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
            std::cout << "GIFT-128n decrypt tests FAILED" << std::endl;
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
            std::cout << "TweGIFT-128 encrypt tests FAILED" << std::endl;
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
            std::cout << "TweGIFT-128 decrypt tests FAILED" << std::endl;
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

static bool gift128b_fs_setup_key(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_setup_key(code, num_keys);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_fs_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_setup_key(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_encrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs_encrypt_block_preloaded(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_encrypt_preloaded(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_encrypt_preloaded(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " preloaded encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " preloaded encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_decrypt(code, num_keys);
    if (mode == Generate) {
        if (num_keys != 80)
            code.sbox_write(std::cout, 1, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128b-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_fs(enum Mode mode, int num_keys)
{
    bool ok = true;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#include \"internal-gift128-config.h\"" << std::endl;
        std::cout << std::endl;
        std::cout << "#if GIFT128_VARIANT == ";
        if (num_keys == 4)
            std::cout << "GIFT128_VARIANT_TINY" << std::endl;
        else if (num_keys == 20)
            std::cout << "GIFT128_VARIANT_SMALL" << std::endl;
        else
            std::cout << "GIFT128_VARIANT_FULL" << std::endl;
    }
    if (!gift128b_fs_setup_key(mode, num_keys))
        ok = false;
    if (!gift128b_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128b_fs_encrypt_block_preloaded(mode, num_keys))
        ok = false;
    if (!gift128b_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#endif" << std::endl;
    }
    return ok;
}

static bool gift128b_fs_4(enum Mode mode)
{
    return gift128b_fs(mode, 4);
}

static bool gift128b_fs_20(enum Mode mode)
{
    return gift128b_fs(mode, 20);
}

static bool gift128b_fs_80(enum Mode mode)
{
    return gift128b_fs(mode, 80);
}

static bool gift128n_fs_setup_key(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_setup_key(code, num_keys);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_fs_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_setup_key(code, num_keys)) {
            std::cout << "GIFT-128n-fs-" << num_keys << " key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-fs-" << num_keys << " key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_encrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128n-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_decrypt(code, num_keys);
    if (mode == Generate) {
        if (num_keys != 80)
            code.sbox_write(std::cout, 1, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128n-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128t_fs_encrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128t-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128t-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128t_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128t_fs_decrypt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128t_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128t-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128t-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_fs(enum Mode mode, int num_keys)
{
    bool ok = true;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#include \"internal-gift128-config.h\"" << std::endl;
        std::cout << std::endl;
        std::cout << "#if GIFT128_VARIANT == ";
        if (num_keys == 4)
            std::cout << "GIFT128_VARIANT_TINY" << std::endl;
        else if (num_keys == 20)
            std::cout << "GIFT128_VARIANT_SMALL" << std::endl;
        else
            std::cout << "GIFT128_VARIANT_FULL" << std::endl;
    }
    if (!gift128n_fs_setup_key(mode, num_keys))
        ok = false;
    if (!gift128n_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128n_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (!gift128t_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128t_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (mode == Generate) {
        std::cout << std::endl;
        std::cout << "#endif" << std::endl;
    }
    return ok;
}

static bool gift128n_fs_4(enum Mode mode)
{
    return gift128n_fs(mode, 4);
}

static bool gift128n_fs_20(enum Mode mode)
{
    return gift128n_fs(mode, 20);
}

static bool gift128n_fs_80(enum Mode mode)
{
    return gift128n_fs(mode, 80);
}

static bool gift128b_alt_fs_setup_key(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_setup_key_alt(code, num_keys);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_gift128_fs_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_setup_key(code, num_keys)) {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_alt_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_encrypt_alt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_encrypt(code, num_keys)) {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128b_alt_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128b_fs_decrypt_alt(code, num_keys);
    if (mode == Generate) {
        if (num_keys != 80)
            code.sbox_write(std::cout, 1, get_gift128_round_constants());
        code.write(std::cout);
    } else {
        if (!test_gift128b_fs_decrypt(code, num_keys)) {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128b-alt-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_alt_fs_encrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_encrypt_alt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_encrypt_alt(code, num_keys)) {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128n_alt_fs_decrypt_block(enum Mode mode, int num_keys)
{
    Code code;
    gen_gift128n_fs_decrypt_alt(code, num_keys);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift128n_fs_decrypt_alt(code, num_keys)) {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-128n-alt-fs-" << num_keys << " decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift128_alt_fs(enum Mode mode, int num_keys)
{
    bool ok = true;
    if (!gift128b_alt_fs_setup_key(mode, num_keys))
        ok = false;
    if (!gift128b_alt_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128b_alt_fs_decrypt_block(mode, num_keys))
        ok = false;
    if (!gift128n_alt_fs_encrypt_block(mode, num_keys))
        ok = false;
    if (!gift128n_alt_fs_decrypt_block(mode, num_keys))
        ok = false;
    return ok;
}

static bool gift128_alt_fs_4(enum Mode mode)
{
    return gift128_alt_fs(mode, 4);
}

static bool gift128_alt_fs_20(enum Mode mode)
{
    return gift128_alt_fs(mode, 20);
}

static bool gift128_alt_fs_80(enum Mode mode)
{
    return gift128_alt_fs(mode, 80);
}

static bool gift64_setup_key(enum Mode mode)
{
    Code code;
    gen_gift64n_setup_key(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64n_setup_key(code)) {
            std::cout << "GIFT-64 key setup tests FAILED" << std::endl;
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
            std::cout << "GIFT-64 encrypt tests FAILED" << std::endl;
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
            std::cout << "GIFT-64 decrypt tests FAILED" << std::endl;
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
            std::cout << "TweGIFT-64 encrypt tests FAILED" << std::endl;
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
            std::cout << "TweGIFT-64 decrypt tests FAILED" << std::endl;
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

static bool gift64_setup_key_alt(enum Mode mode)
{
    Code code;
    gen_gift64_setup_key_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64_setup_key_alt(code)) {
            std::cout << "GIFT-64-alt key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-64-alt key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64_encrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift64_encrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64_encrypt_alt(code)) {
            std::cout << "GIFT-64-alt encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-64-alt encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64_decrypt_block_alt(enum Mode mode)
{
    Code code;
    gen_gift64_decrypt_alt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_gift64_decrypt_alt(code)) {
            std::cout << "GIFT-64-alt decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIFT-64-alt decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool gift64_alt(enum Mode mode)
{
    bool ok = true;
    if (!gift64_setup_key_alt(mode))
        ok = false;
    if (!gift64_encrypt_block_alt(mode))
        ok = false;
    if (!gift64_decrypt_block_alt(mode))
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
            std::cout << "GIMLI-24 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "GIMLI-24 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool grain128_core(enum Mode mode)
{
    Code code;
    gen_grain128_core(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_grain128_core(code)) {
            std::cout << "Grain-128 core tests FAILED" << std::endl;
            return false;
        } else {
                std::cout << "Grain-128 core tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool grain128_preoutput(enum Mode mode)
{
    Code code;
    gen_grain128_preoutput(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_grain128_preoutput(code)) {
            std::cout << "Grain-128 preoutput tests FAILED" << std::endl;
            return false;
        } else {
                std::cout << "Grain-128 preoutput tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool grain128_swap_word32(enum Mode mode)
{
    Code code;
    gen_grain128_swap_word32(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool grain128_compute_tag(enum Mode mode)
{
    Code code;
    gen_grain128_compute_tag(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool grain128_interleave(enum Mode mode)
{
    Code code;
    gen_grain128_interleave(code);
    if (mode == Generate)
        code.write(std::cout);
    return true;
}

static bool grain128(enum Mode mode)
{
    bool ok = true;
    if (!grain128_core(mode))
        ok = false;
    if (!grain128_preoutput(mode))
        ok = false;
    if (!grain128_swap_word32(mode))
        ok = false;
    if (!grain128_compute_tag(mode))
        ok = false;
    if (!grain128_interleave(mode))
        ok = false;
    return ok;
}

static bool keccakp_200(enum Mode mode)
{
    Code code;
    gen_keccakp_200_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_keccakp_200_permutation(code)) {
            std::cout << "Keccak-p[200] tests FAILED" << std::endl;
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
            std::cout << "Keccak-p[400] tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Keccak-p[400] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool knot256_6(enum Mode mode)
{
    Code code;
    gen_knot256_permutation(code, 6);
    if (mode == Generate) {
        code.sbox_write(std::cout, 6, get_knot_round_constants(6));
        code.write(std::cout);
    } else {
        if (!test_knot256_permutation(code, 6)) {
            std::cout << "KNOT-256-6 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "KNOT-256-6 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool knot256_7(enum Mode mode)
{
    Code code;
    gen_knot256_permutation(code, 7);
    if (mode == Generate) {
        code.sbox_write(std::cout, 7, get_knot_round_constants(7));
        code.write(std::cout);
    } else {/* not used
        if (!test_knot256_permutation(code, 7)) {
            std::cout << "KNOT-256-7 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "KNOT-256-7 tests succeeded" << std::endl;
        }*/
    }
    return true;
}

static bool knot256(enum Mode mode)
{
    if (!knot256_6(mode))
        return false;
    return knot256_7(mode);
}

static bool knot384(enum Mode mode)
{
    Code code;
    gen_knot384_permutation(code, 7);
    if (mode == Generate) {
        code.sbox_write(std::cout, 7, get_knot_round_constants(7));
        code.write(std::cout);
    } else {
        if (!test_knot384_permutation(code, 7)) {
            std::cout << "KNOT-384-7 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "KNOT-384-7 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool knot512_7(enum Mode mode)
{
    Code code;
    gen_knot512_permutation(code, 7);
    if (mode == Generate) {
        code.sbox_write(std::cout, 7, get_knot_round_constants(7));
        code.write(std::cout);
    } else { /* not used
        if (!test_knot512_permutation(code, 7)) {
            std::cout << "KNOT-512-7 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "KNOT-512-7 tests succeeded" << std::endl;
        } */
    }
    return true;
}

static bool knot512_8(enum Mode mode)
{
    Code code;
    gen_knot512_permutation(code, 8);
    if (mode == Generate) {
        code.sbox_write(std::cout, 8, get_knot_round_constants(8));
        code.write(std::cout);
    } else {
        if (!test_knot512_permutation(code, 8)) {
            std::cout << "KNOT-512-8 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "KNOT-512-8 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool knot512(enum Mode mode)
{
    if (!knot512_7(mode))
        return false;
    return knot512_8(mode);
}

static bool photon256(enum Mode mode)
{
    Code code;
    gen_photon256_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_photon256_permutation(code)) {
            std::cout << "PHOTON-256 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "PHOTON-256 tests succeeded" << std::endl;
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
            std::cout << "Pyjamask-96 key setup tests FAILED" << std::endl;
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
            std::cout << "Pyjamask-96 encrypt tests FAILED" << std::endl;
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
            std::cout << "Pyjamask-96 decrypt tests FAILED" << std::endl;
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
            std::cout << "Pyjamask-128 key setup tests FAILED" << std::endl;
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
            std::cout << "Pyjamask-128 encrypt tests FAILED" << std::endl;
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
            std::cout << "Pyjamask-128 decrypt tests FAILED" << std::endl;
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

static bool saturnin_setup_key(enum Mode mode)
{
    Code code;
    gen_saturnin_setup_key(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_saturnin_round_constants());
        code.write(std::cout);
    } else {
        if (!test_saturnin_setup_key(code)) {
            std::cout << "Saturnin key setup tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Saturnin key setup tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool saturnin_encrypt_block(enum Mode mode)
{
    Code code;
    gen_saturnin_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_saturnin_encrypt(code)) {
            std::cout << "Saturnin encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Saturnin encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool saturnin_decrypt_block(enum Mode mode)
{
    Code code;
    gen_saturnin_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_saturnin_decrypt(code)) {
            std::cout << "Saturnin decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Saturnin decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool saturnin(enum Mode mode)
{
    bool ok = true;
    if (!saturnin_setup_key(mode))
        ok = false;
    if (!saturnin_encrypt_block(mode))
        ok = false;
    if (!saturnin_decrypt_block(mode))
        ok = false;
    return ok;
}

static bool simp256(enum Mode mode)
{
    Code code;
    gen_simp_256_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_simp_256_permutation(code)) {
            std::cout << "SimP-256 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SimP-256 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool simp192(enum Mode mode)
{
    Code code;
    gen_simp_192_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_simp_192_permutation(code)) {
            std::cout << "SimP-192 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "SimP-192 tests succeeded" << std::endl;
        }
    }
    return true;
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
            std::cout << "SKINNY-128-384 encrypt tests FAILED" << std::endl;
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
            std::cout << "SKINNY-128-384 decrypt tests FAILED" << std::endl;
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
            std::cout << "SKINNY-128-256 encrypt tests FAILED" << std::endl;
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
            std::cout << "SKINNY-128-256 decrypt tests FAILED" << std::endl;
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

static bool sliscp256_spix(enum Mode mode)
{
    Code code;
    gen_sliscp_light256_spix_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_sliscp_light256_round_constants());
        code.write(std::cout);
        Code code2;
        gen_sliscp_light256_swap_spix(code2);
        code2.write(std::cout);
    } else {
        if (!test_sliscp_light256_spix_permutation(code)) {
            std::cout << "sLiSCP-light-256-SPIX tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "sLiSCP-light-256-SPIX tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sliscp256_spoc(enum Mode mode)
{
    Code code;
    gen_sliscp_light256_spoc_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_sliscp_light256_round_constants());
        code.write(std::cout);
        Code code2;
        gen_sliscp_light256_swap_spoc(code2);
        code2.write(std::cout);
    } else {
        if (!test_sliscp_light256_spoc_permutation(code)) {
            std::cout << "sLiSCP-light-256-SpoC tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "sLiSCP-light-256-SpoC tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sliscp192(enum Mode mode)
{
    Code code;
    gen_sliscp_light192_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_sliscp_light192_round_constants());
        code.write(std::cout);
    } else {
        if (!test_sliscp_light192_permutation(code)) {
            std::cout << "sLiSCP-light-192 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "sLiSCP-light-192 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool sliscp320(enum Mode mode)
{
    Code code;
    gen_sliscp_light320_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_sliscp_light320_round_constants());
        code.write(std::cout);
        Code code2;
        gen_sliscp_light320_swap(code2);
        code2.write(std::cout);
    } else {
        if (!test_sliscp_light320_permutation(code)) {
            std::cout << "sLiSCP-light-320 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "sLiSCP-light-320 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool speck64(enum Mode mode)
{
    Code code;
    gen_speck64_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_speck64_encrypt(code)) {
            std::cout << "SPECK-64 tests FAILED" << std::endl;
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
            std::cout << "SPARKLE-256 tests FAILED" << std::endl;
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
            std::cout << "SPARKLE-384 tests FAILED" << std::endl;
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
            std::cout << "SPARKLE-512 tests FAILED" << std::endl;
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
            std::cout << "Spongent-pi[160] tests FAILED" << std::endl;
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
            std::cout << "Spongent-pi[176] tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spongent-pi[176] tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spook_clyde128_encrypt(enum Mode mode)
{
    Code code;
    gen_clyde128_encrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_clyde128_encrypt(code)) {
            std::cout << "Spook/Clyde-128 encrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spook/Clyde-128 encrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spook_clyde128_decrypt(enum Mode mode)
{
    Code code;
    gen_clyde128_decrypt(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_clyde128_decrypt(code)) {
            std::cout << "Spook/Clyde-128 decrypt tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spook/Clyde-128 decrypt tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spook_shadow512(enum Mode mode)
{
    Code code;
    gen_shadow512_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_shadow512_permutation(code)) {
            std::cout << "Spook/Shadow-512 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spook/Shadow-512 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spook_shadow384(enum Mode mode)
{
    Code code;
    gen_shadow384_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);
    } else {
        if (!test_shadow384_permutation(code)) {
            std::cout << "Spook/Shadow-384 tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Spook/Shadow-384 tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool spook(enum Mode mode)
{
    bool ok = true;
    if (!spook_clyde128_encrypt(mode))
        ok = false;
    if (!spook_clyde128_decrypt(mode))
        ok = false;
    if (!spook_shadow512(mode))
        ok = false;
    if (!spook_shadow384(mode))
        ok = false;
    return ok;
}

static bool subterranean(enum Mode mode)
{
    Code code;
    gen_subterranean_permutation(code);
    if (mode == Generate) {
        code.write(std::cout);

        Code code2;
        gen_subterranean_absorb(code2, 1);
        code2.write(std::cout);

        Code code3;
        gen_subterranean_absorb(code3, 4);
        code3.write(std::cout);

        Code code4;
        gen_subterranean_extract(code4);
        code4.write(std::cout);
    } else {
        if (!test_subterranean_permutation(code)) {
            std::cout << "Subterranean tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "Subterranean tests succeeded" << std::endl;
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
            std::cout << "TinyJAMBU tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "TinyJAMBU tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool wage(enum Mode mode)
{
    Code code;
    gen_wage_permutation(code);
    if (mode == Generate) {
        code.sbox_write(std::cout, 0, get_wage_round_constants(0));
        code.sbox_write(std::cout, 1, get_wage_round_constants(1));
        code.write(std::cout);
    } else {
        if (!test_wage_permutation(code)) {
            std::cout << "WAGE tests FAILED" << std::endl;
            return false;
        } else {
            std::cout << "WAGE tests succeeded" << std::endl;
        }
    }
    return true;
}

static bool wage_helpers(enum Mode mode)
{
    if (mode == Generate) {
        Code code;
        gen_wage_absorb(code);
        code.write(std::cout);

        Code code2;
        gen_wage_get_rate(code2);
        code2.write(std::cout);

        Code code3;
        gen_wage_set_rate(code3);
        code3.write(std::cout);
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
            std::cout << "Xoodoo tests FAILED" << std::endl;
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
        } else if (!strcmp(argv[1], "ForkSkinny")) {
            gen1 = forkskinny;
        } else if (!strcmp(argv[1], "GASCON")) {
            gen1 = gascon128;
            gen2 = gascon256;
        } else if (!strcmp(argv[1], "GASCON-Full")) {
            gen1 = gascon128_full;
        } else if (!strcmp(argv[1], "GIFT-128b")) {
            gen1 = gift128b;
        } else if (!strcmp(argv[1], "GIFT-128n")) {
            gen1 = gift128n;
        } else if (!strcmp(argv[1], "GIFT-128-alt")) {
            gen1 = gift128_alt;
        } else if (!strcmp(argv[1], "GIFT-128b-fs-4")) {
            gen1 = gift128b_fs_4;
        } else if (!strcmp(argv[1], "GIFT-128b-fs-20")) {
            gen1 = gift128b_fs_20;
        } else if (!strcmp(argv[1], "GIFT-128b-fs-80")) {
            gen1 = gift128b_fs_80;
        } else if (!strcmp(argv[1], "GIFT-128n-fs-4")) {
            gen1 = gift128n_fs_4;
        } else if (!strcmp(argv[1], "GIFT-128n-fs-20")) {
            gen1 = gift128n_fs_20;
        } else if (!strcmp(argv[1], "GIFT-128n-fs-80")) {
            gen1 = gift128n_fs_80;
        } else if (!strcmp(argv[1], "GIFT-128-alt-fs-4")) {
            gen1 = gift128_alt_fs_4;
        } else if (!strcmp(argv[1], "GIFT-128-alt-fs-20")) {
            gen1 = gift128_alt_fs_20;
        } else if (!strcmp(argv[1], "GIFT-128-alt-fs-80")) {
            gen1 = gift128_alt_fs_80;
        } else if (!strcmp(argv[1], "GIFT-64")) {
            gen1 = gift64;
        } else if (!strcmp(argv[1], "GIFT-64-alt")) {
            gen1 = gift64_alt;
        } else if (!strcmp(argv[1], "GIMLI-24")) {
            gen1 = gimli24;
        } else if (!strcmp(argv[1], "Grain-128")) {
            gen1 = grain128;
        } else if (!strcmp(argv[1], "Keccak")) {
            gen1 = keccakp_200;
            gen2 = keccakp_400;
        } else if (!strcmp(argv[1], "KNOT-256")) {
            gen1 = knot256;
        } else if (!strcmp(argv[1], "KNOT-384")) {
            gen1 = knot384;
        } else if (!strcmp(argv[1], "KNOT-512")) {
            gen1 = knot512;
        } else if (!strcmp(argv[1], "PHOTON-256")) {
            gen1 = photon256;
        } else if (!strcmp(argv[1], "Pyjamask")) {
            gen1 = pyjamask;
        } else if (!strcmp(argv[1], "Saturnin")) {
            gen1 = saturnin;
        } else if (!strcmp(argv[1], "SimP")) {
            gen1 = simp256;
            gen2 = simp192;
        } else if (!strcmp(argv[1], "SKINNY-128")) {
            gen1 = skinny128;
        } else if (!strcmp(argv[1], "sLiSCP-light-256-SPIX")) {
            gen1 = sliscp256_spix;
        } else if (!strcmp(argv[1], "sLiSCP-light-256-SpoC")) {
            gen1 = sliscp256_spoc;
        } else if (!strcmp(argv[1], "sLiSCP-light-192")) {
            gen1 = sliscp192;
        } else if (!strcmp(argv[1], "sLiSCP-light-320")) {
            gen1 = sliscp320;
        } else if (!strcmp(argv[1], "SPARKLE")) {
            gen1 = sparkle256;
            gen2 = sparkle384;
            gen3 = sparkle512;
        } else if (!strcmp(argv[1], "Spongent-pi")) {
            gen1 = spongent160;
            gen2 = spongent176;
        } else if (!strcmp(argv[1], "SPECK-64")) {
            gen1 = speck64;
        } else if (!strcmp(argv[1], "Spook")) {
            gen1 = spook;
        } else if (!strcmp(argv[1], "Subterranean")) {
            gen1 = subterranean;
        } else if (!strcmp(argv[1], "TinyJAMBU")) {
            gen1 = tinyjambu;
        } else if (!strcmp(argv[1], "WAGE")) {
            gen1 = wage;
            gen2 = wage_helpers;
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
        if (!forkskinny(Test))
            exit_val = 1;
        if (!gascon128(Test))
            exit_val = 1;
        if (!gascon256(Test))
            exit_val = 1;
        if (!gascon128_full(Test))
            exit_val = 1;
        if (!gift128b(Test))
            exit_val = 1;
        if (!gift128_alt(Test))
            exit_val = 1;
        if (!gift128n(Test))
            exit_val = 1;
        if (!gift128b_fs_4(Test))
            exit_val = 1;
        if (!gift128b_fs_20(Test))
            exit_val = 1;
        if (!gift128b_fs_80(Test))
            exit_val = 1;
        if (!gift128n_fs_4(Test))
            exit_val = 1;
        if (!gift128n_fs_20(Test))
            exit_val = 1;
        if (!gift128n_fs_80(Test))
            exit_val = 1;
        if (!gift128_alt_fs_4(Test))
            exit_val = 1;
        if (!gift128_alt_fs_20(Test))
            exit_val = 1;
        if (!gift128_alt_fs_80(Test))
            exit_val = 1;
        if (!gift64(Test))
            exit_val = 1;
        if (!gift64_alt(Test))
            exit_val = 1;
        if (!gimli24(Test))
            exit_val = 1;
        if (!grain128(Test))
            exit_val = 1;
        if (!keccakp_200(Test))
            exit_val = 1;
        if (!keccakp_400(Test))
            exit_val = 1;
        if (!knot256(Test))
            exit_val = 1;
        if (!knot384(Test))
            exit_val = 1;
        if (!knot512(Test))
            exit_val = 1;
        if (!photon256(Test))
            exit_val = 1;
        if (!pyjamask(Test))
            exit_val = 1;
        if (!saturnin(Test))
            exit_val = 1;
        if (!simp256(Test))
            exit_val = 1;
        if (!simp192(Test))
            exit_val = 1;
        if (!skinny128(Test))
            exit_val = 1;
        if (!sliscp256_spix(Test))
            exit_val = 1;
        if (!sliscp256_spoc(Test))
            exit_val = 1;
        if (!sliscp192(Test))
            exit_val = 1;
        if (!sliscp320(Test))
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
        if (!spook(Test))
            exit_val = 1;
        if (!subterranean(Test))
            exit_val = 1;
        if (!tinyjambu(Test))
            exit_val = 1;
        if (!wage(Test))
            exit_val = 1;
        if (!xoodoo(Test))
            exit_val = 1;
    }

    return exit_val;
}
