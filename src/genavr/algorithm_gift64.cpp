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
#include <cstring>

/* Round constants for GIFT-64 */
static unsigned char const GIFT64_RC[28] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B
};

class Gift64State
{
public:
    Gift64State(Code &code, bool decrypt = false);

    // 16-bit registers that hold the state.
    Reg s0, s1, s2, s3;

    // 16-bit registers that hold the last two words of the key schedule.
    Reg k6, k7;

    // Temporaries.
    Reg t1, t2;

    void sub_cells(Code &code);
    void inv_sub_cells(Code &code);
    void perm_bits(Code &code, bool inverse = false);
    void rotate_key(Code &code, int round);
    void inv_rotate_key(Code &code, int round);
};

Gift64State::Gift64State(Code &code, bool decrypt)
{
    // Allocate the temporaries (first needs to be in high registers).
    t1 = code.allocateHighReg(2);
    t2 = code.allocateReg(2);

    // Allocate registers for the state.
    s0 = code.allocateReg(2);
    s1 = code.allocateReg(2);
    s2 = code.allocateReg(2);
    s3 = code.allocateReg(2);

    // Allocate registers for the key schedule.
    k6 = code.allocateReg(2);
    k7 = code.allocateReg(2);

    // Copy the key schedule into local variable storage.
    if (!decrypt) {
        code.ldz(k6, 0);
        code.ldz(k7, 2);
        code.sty(k6, 0);
        code.sty(k7, 2);
        code.ldz(k6, 4);
        code.ldz(k7, 6);
        code.sty(k6, 4);
        code.sty(k7, 6);
        code.ldz(k6, 8);
        code.ldz(k7, 10);
        code.sty(k6, 8);
        code.sty(k7, 10);
        code.ldz(k6, 12);   // Leave the last two words in k6 and k7.
        code.ldz(k7, 14);
    } else {
        // For decryption we also need to fast-forward the key schedule
        // to the end by rotating the words of the key schedule.
        code.ldz(k6, 0);
        code.ldz(k7, 2);
        code.rol(k6, 12);
        code.ror(k7, 14);
        code.sty(k6, 0);
        code.sty(k7, 2);
        code.ldz(k6, 4);
        code.ldz(k7, 6);
        code.rol(k6, 12);
        code.ror(k7, 14);
        code.sty(k6, 4);
        code.sty(k7, 6);
        code.ldz(k6, 8);
        code.ldz(k7, 10);
        code.rol(k6, 12);
        code.ror(k7, 14);
        code.sty(k6, 8);
        code.sty(k7, 10);
        code.ldz(k6, 12);
        code.ldz(k7, 14);
        code.rol(k6, 12);
        code.ror(k7, 14);
    }
}

void Gift64State::sub_cells(Code &code)
{
    // s1 ^= s0 & s2;
    code.move(t1, s0);
    code.logand(t1, s2);
    code.logxor(s1, t1);

    // s0 ^= s1 & s3;
    code.move(t1, s3);
    code.logand(t1, s1);
    code.logxor(s0, t1);

    // s2 ^= s0 | s1;
    code.move(t1, s0);
    code.logor(t1, s1);
    code.logxor(s2, t1);

    // s3 ^= s2;
    code.logxor(s3, s2);

    // s1 ^= s3;
    code.logxor(s1, s3);

    // s3 ^= 0xFFFFU;
    code.lognot(s3);

    // s2 ^= s0 & s1;
    code.move(t1, s0);
    code.move(t2, s1);
    code.logand(t2, t1);
    code.logxor(s2, t2);

    // swap(s0, s3);
    code.move(s0, s3);
    code.move(s3, t1);
}

void Gift64State::inv_sub_cells(Code &code)
{
    // swap(s0, s3);
    code.move(t1, s3);
    code.move(s3, s0);
    code.move(s0, t1);

    // s2 ^= s0 & s1;
    code.logand(t1, s1);
    code.logxor(s2, t1);

    // s3 ^= 0xFFFFU;
    code.lognot(s3);

    // s1 ^= s3;
    code.logxor(s1, s3);

    // s3 ^= s2;
    code.logxor(s3, s2);

    // s2 ^= s0 | s1;
    code.move(t1, s0);
    code.move(t2, s1);
    code.logor(t1, t2);
    code.logxor(s2, t1);

    // s0 ^= s1 & s3;
    code.logand(t2, s3);
    code.logxor(s0, t2);

    // s1 ^= s0 & s2;
    code.move(t1, s0);
    code.logand(t1, s2);
    code.logxor(s1, t1);
}

void Gift64State::perm_bits(Code &code, bool inverse)
{
    // Permutations to apply to the state words.
    static unsigned char const P0[16] =
        {0, 12, 8, 4, 1, 13, 9, 5, 2, 14, 10, 6, 3, 15, 11, 7};
    static unsigned char const P1[16] =
        {4, 0, 12, 8, 5, 1, 13, 9, 6, 2, 14, 10, 7, 3, 15, 11};
    static unsigned char const P2[16] =
        {8, 4, 0, 12, 9, 5, 1, 13, 10, 6, 2, 14, 11, 7, 3, 15};
    static unsigned char const P3[16] =
        {12, 8, 4, 0, 13, 9, 5, 1, 14, 10, 6, 2, 15, 11, 7, 3};

    // Apply the permutations bit by bit.  The mask and shift approach
    // from the 32-bit implementation uses more instructions than simply
    // moving the bits around one at a time.
    code.bit_permute(s0, P0, 16, inverse);
    code.bit_permute(s1, P1, 16, inverse);
    code.bit_permute(s2, P2, 16, inverse);
    code.bit_permute(s3, P3, 16, inverse);
}

void Gift64State::rotate_key(Code &code, int round)
{
    int curr_offset;
    int next_offset;
    switch (round % 4) {
    case 0: default:
        curr_offset = 12;
        next_offset = 8;
        break;
    case 1:
        curr_offset = 8;
        next_offset = 4;
        break;
    case 2:
        curr_offset = 4;
        next_offset = 0;
        break;
    case 3:
        curr_offset = 0;
        next_offset = 12;
        break;
    }
    code.rol(k6, 4);
    code.ror(k7, 2);
    code.sty(k6, curr_offset);
    code.sty(k7, curr_offset + 2);
    code.ldy(k6, next_offset);
    code.ldy(k7, next_offset + 2);
}

void Gift64State::inv_rotate_key(Code &code, int round)
{
    int curr_offset;
    int next_offset;
    switch (round % 4) {
    case 0: default:
        curr_offset = 12;
        next_offset = 8;
        break;
    case 1:
        curr_offset = 8;
        next_offset = 4;
        break;
    case 2:
        curr_offset = 4;
        next_offset = 0;
        break;
    case 3:
        curr_offset = 0;
        next_offset = 12;
        break;
    }
    code.sty(k6, next_offset);
    code.sty(k7, next_offset + 2);
    code.ldy(k6, curr_offset);
    code.ldy(k7, curr_offset + 2);
    code.ror(k6, 4);
    code.rol(k7, 2);
}

/**
 * \brief Generates the AVR code for the gift64n key setup function.
 *
 * \param code The code block to generate into.
 */
void gen_gift64n_setup_key(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("gift64n_init", 0);
    code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Copy the key into the key schedule structure and rearrange:
    //      ks->k[0] = le_load_word32(key + 12);
    //      ks->k[1] = le_load_word32(key + 8);
    //      ks->k[2] = le_load_word32(key + 4);
    //      ks->k[3] = le_load_word32(key);
    Reg temp = code.allocateReg(4);
    code.ldx(temp, POST_INC);
    code.stz(temp, 12);
    code.ldx(temp, POST_INC);
    code.stz(temp, 8);
    code.ldx(temp, POST_INC);
    code.stz(temp, 4);
    code.ldx(temp, POST_INC);
    code.stz(temp, 0);
}

/**
 * \brief Load the 64-bit input state from X and convert into bit-sliced form.
 *
 * \param code The code block to generate into.
 * \param s State register information.
 */
static void gen_load_state(Code &code, Gift64State &s)
{
    int word, bit;
    for (word = 0; word < 4; ++word) {
        code.ldx(s.t1, POST_INC);
        for (bit = 0; bit < 16; ++bit) {
            Reg dst;
            switch (bit % 4) {
            case 0: default:    dst = s.s0; break;
            case 1:             dst = s.s1; break;
            case 2:             dst = s.s2; break;
            case 3:             dst = s.s3; break;
            }
            code.bit_get(s.t1, bit);
            code.bit_put(dst, (bit / 4) + (word * 4));
        }
    }
}

/**
 * \brief Store the 64-bit input state to X and convert from bit-sliced form.
 *
 * \param code The code block to generate into.
 * \param s State register information.
 */
static void gen_store_state(Code &code, Gift64State &s)
{
    int word, bit;
    for (word = 0; word < 4; ++word) {
        for (bit = 0; bit < 16; ++bit) {
            Reg src;
            switch (bit % 4) {
            case 0: default:    src = s.s0; break;
            case 1:             src = s.s1; break;
            case 2:             src = s.s2; break;
            case 3:             src = s.s3; break;
            }
            code.bit_get(src, (bit / 4) + (word * 4));
            code.bit_put(s.t1, bit);
        }
        code.stx(s.t1, POST_INC);
    }
}

/**
 * \brief Generates the AVR code for the GIFT-64 encryption function.
 *
 * \param code The code block to generate into.
 * \param has_tweak Set to true if we are generating the tweakable version.
 */
static void gen_gift64_encrypt(Code &code, bool has_tweak)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (!has_tweak)
        code.prologue_encrypt_block("gift64n_encrypt", 16);
    else
        tweak = code.prologue_encrypt_block_with_tweak("gift64t_encrypt", 16);

    // Allocate the registers that we need and load the key schedule.
    Gift64State s(code);

    // Load the state and convert into bit-sliced form.
    gen_load_state(code, s);

    // Perform all encryption rounds.  The bulk of the round is in a
    // subroutine with the outer loop unrolled to deal with rotating
    // the key schedule and the round constants.
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (int round = 0; round < 28; ++round) {
        code.call(subroutine);
        code.move(s.t1, 0x8000 ^ GIFT64_RC[round]);
        code.logxor(s.s3, s.t1);
        if (has_tweak && ((round + 1) % 4) == 0 && round < 27) {
            // Tweak is a single byte, but we need to XOR into a 16-bit word.
            code.logxor(Reg(s.s2, 0, 1), tweak);
            code.logxor(Reg(s.s2, 1, 1), tweak);
        }
        if (round != 27) {
            // Rotate the key schedule on all rounds except the last.
            s.rotate_key(code, round);
        }
    }
    code.jmp(end_label);
    code.label(subroutine);
    s.sub_cells(code);
    s.perm_bits(code);
    code.logxor(s.s0, s.k6);
    code.logxor(s.s1, s.k7);
    code.ret();

    // Store the state to the output and convert into nibble form.
    code.label(end_label);
    code.load_output_ptr();
    gen_store_state(code, s);
}

/**
 * \brief Generates the AVR code for the GIFT-64 decryption function.
 *
 * \param code The code block to generate into.
 * \param has_tweak Set to true if we are generating the tweakable version.
 */
static void gen_gift64_decrypt(Code &code, bool has_tweak)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (!has_tweak)
        code.prologue_decrypt_block("gift64n_decrypt", 16);
    else
        tweak = code.prologue_decrypt_block_with_tweak("gift64t_decrypt", 16);

    // Allocate the registers that we need and load the key schedule.
    Gift64State s(code, true);

    // Load the state and convert into bit-sliced form.
    gen_load_state(code, s);

    // Perform all decryption rounds.  The bulk of the round is in a
    // subroutine with the outer loop unrolled to deal with rotating
    // the key schedule and the round constants.
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (int round = 28; round > 0; --round) {
        s.inv_rotate_key(code, round - 1);
        code.move(s.t1, 0x8000 ^ GIFT64_RC[round - 1]);
        code.logxor(s.s3, s.t1);
        if (has_tweak && (round % 4) == 0 && round != 28) {
            // Tweak is a single byte, but we need to XOR into a 16-bit word.
            code.logxor(Reg(s.s2, 0, 1), tweak);
            code.logxor(Reg(s.s2, 1, 1), tweak);
        }
        code.call(subroutine);
    }
    code.jmp(end_label);
    code.label(subroutine);
    code.logxor(s.s0, s.k6);
    code.logxor(s.s1, s.k7);
    s.perm_bits(code, true);
    s.inv_sub_cells(code);
    code.ret();

    // Store the state to the output and convert into nibble form.
    code.label(end_label);
    code.load_output_ptr();
    gen_store_state(code, s);
}

void gen_gift64n_encrypt(Code &code)
{
    gen_gift64_encrypt(code, false);
}

void gen_gift64n_decrypt(Code &code)
{
    gen_gift64_decrypt(code, false);
}

void gen_gift64t_encrypt(Code &code)
{
    gen_gift64_encrypt(code, true);
}

void gen_gift64t_decrypt(Code &code)
{
    gen_gift64_decrypt(code, true);
}

/* Test vectors for GIFT-64 */
static block_cipher_test_vector_t const gift64n_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   /* plaintext */
    {0xac, 0x75, 0xf7, 0x34, 0xef, 0xc3, 0x2b, 0xf6}    /* ciphertext */
};
static block_cipher_test_vector_t const gift64n_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},   /* plaintext */
    {0x4b, 0x1f, 0xc1, 0xef, 0xfe, 0xe1, 0x87, 0x4e}    /* ciphertext */
};
static block_cipher_test_vector_t const gift64n_3 = {
    "Test Vector 3",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0x08, 0x2d, 0xad, 0xcc, 0x6a, 0xe6, 0x3c, 0x64}    /* ciphertext */
};

// Set up the key schedule which is a word-reversed version of the input key.
static void gift64n_setup
    (unsigned char schedule[16], const block_cipher_test_vector_t *test)
{
    memcpy(schedule, test->key + 12, 4);
    memcpy(schedule + 4, test->key + 8, 4);
    memcpy(schedule + 8, test->key + 4, 4);
    memcpy(schedule + 12, test->key, 4);
}

static bool test_gift64n_setup_key
    (Code &code, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[16];
    unsigned char expected[16];

    // Set up the key schedule.
    code.exec_setup_key(schedule, sizeof(schedule),
                        test->key, test->key_len);

    // We expect the words to be reversed, but otherwise copied as-is.
    gift64n_setup(expected, test);
    if (memcmp(schedule, expected, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_gift64n_setup_key(Code &code)
{
    if (!test_gift64n_setup_key(code, &gift64n_1))
        return false;
    if (!test_gift64n_setup_key(code, &gift64n_2))
        return false;
    if (!test_gift64n_setup_key(code, &gift64n_3))
        return false;
    return true;
}

static bool test_gift64n_encrypt
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char output[8];
    gift64n_setup(schedule, test);
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            test->plaintext, 8, tweak);
    if (memcmp(output, test->ciphertext, 8) != 0)
        return false;
    return true;
}

bool test_gift64n_encrypt(Code &code)
{
    if (!test_gift64n_encrypt(code, &gift64n_1))
        return false;
    if (!test_gift64n_encrypt(code, &gift64n_2))
        return false;
    if (!test_gift64n_encrypt(code, &gift64n_3))
        return false;
    return true;
}

static bool test_gift64n_decrypt
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char output[8];
    gift64n_setup(schedule, test);
    code.exec_decrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            test->ciphertext, 8, tweak);
    if (memcmp(output, test->plaintext, 8) != 0)
        return false;
    return true;
}

bool test_gift64n_decrypt(Code &code)
{
    if (!test_gift64n_decrypt(code, &gift64n_1))
        return false;
    if (!test_gift64n_decrypt(code, &gift64n_2))
        return false;
    if (!test_gift64n_decrypt(code, &gift64n_3))
        return false;
    return true;
}

static block_cipher_test_vector_t const gift64t_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},   /* plaintext */
    {0xb6, 0x6a, 0x7a, 0x0d, 0x14, 0xb1, 0x74, 0x0a}    /* ciphertext */
    /* tweak = 11 */
};
static block_cipher_test_vector_t const gift64t_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},   /* plaintext */
    {0x88, 0xb0, 0xf8, 0x78, 0xe0, 0x27, 0xe5, 0x8b}    /* ciphertext */
    /* tweak = 4 */
};
static block_cipher_test_vector_t const gift64t_3 = {
    "Test Vector 3",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0x55, 0x09, 0xa7, 0x40, 0x1b, 0x1e, 0x29, 0x61}    /* ciphertext */
    /* tweak = 9 */
};
static block_cipher_test_vector_t const gift64t_4 = {
    "Test Vector 4",
    {0xbd, 0x91, 0x73, 0x1e, 0xb6, 0xbc, 0x27, 0x13,    /* key */
     0xa1, 0xf9, 0xf6, 0xff, 0xc7, 0x50, 0x44, 0xe7},
    16,                                                 /* key_len */
    {0xc4, 0x50, 0xc7, 0x72, 0x7a, 0x9b, 0x8a, 0x7d},   /* plaintext */
    {0x08, 0x2d, 0xad, 0xcc, 0x6a, 0xe6, 0x3c, 0x64}    /* ciphertext */
    /* tweak = 0 */
};

bool test_gift64t_encrypt(Code &code)
{
    if (!test_gift64n_encrypt(code, &gift64t_1, 0x4b4b))
        return false;
    if (!test_gift64n_encrypt(code, &gift64t_2, 0xb4b4))
        return false;
    if (!test_gift64n_encrypt(code, &gift64t_3, 0x9999))
        return false;
    if (!test_gift64n_encrypt(code, &gift64t_4, 0x0000))
        return false;
    return true;
}

bool test_gift64t_decrypt(Code &code)
{
    if (!test_gift64n_decrypt(code, &gift64t_1, 0x4b4b))
        return false;
    if (!test_gift64n_decrypt(code, &gift64t_2, 0xb4b4))
        return false;
    if (!test_gift64n_decrypt(code, &gift64t_3, 0x9999))
        return false;
    if (!test_gift64n_decrypt(code, &gift64t_4, 0x0000))
        return false;
    return true;
}
