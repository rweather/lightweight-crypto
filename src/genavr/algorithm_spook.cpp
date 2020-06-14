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

/**
 * \brief Number of steps in the Clyde-128 block cipher.
 *
 * This is also the number of steps in the Shadow-512 and Shadow-384
 * permutations.
 */
#define CLYDE128_STEPS 6

/**
 * \brief Round constants for the steps of Clyde-128.
 */
static uint8_t const rc[CLYDE128_STEPS][8] = {
    {1, 0, 0, 0, 0, 1, 0, 0},
    {0, 0, 1, 0, 0, 0, 0, 1},
    {1, 1, 0, 0, 0, 1, 1, 0},
    {0, 0, 1, 1, 1, 1, 0, 1},
    {1, 0, 1, 0, 0, 1, 0, 1},
    {1, 1, 1, 0, 0, 1, 1, 1}
};

// Generate code for the Clyde-128 S-box.
static void gen_clyde128_sbox
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2,
     const Reg &s3, const Reg &c, const Reg &d)
{
    // c = (s0 & s1) ^ s2;
    code.move(c, s0);
    code.logand(c, s1);
    code.logxor(c, s2);

    // d = (s3 & s0) ^ s1;
    code.move(d, s3);
    code.logand(d, s0);
    code.logxor(d, s1);

    // s2 = (c & d) ^ s3;
    code.move(s2, c);
    code.logand(s2, d);
    code.logxor(s2, s3);

    // s3 = (c & s3) ^ s0;
    code.logand(s3, c);
    code.logxor(s3, s0);

    // s0 = d;
    code.move(s0, d);

    // s1 = c;
    code.move(s1, c);
}

// Generate code for the inverse of the Clyde-128 S-box.
static void gen_clyde128_inv_sbox
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2,
     const Reg &s3, const Reg &c, const Reg &d)
{
    // d = (s0 & s1) ^ s2;
    code.move(d, s0);
    code.logand(d, s1);
    code.logxor(d, s2);

    // c = (s1 & d) ^ s3;
    code.move(c, s1);
    code.logand(c, d);
    code.logxor(c, s3);

    // s3 = d;
    code.move(s3, d);

    // d = (d & c) ^ s0;
    code.logand(d, c);
    code.logxor(d, s0);

    // s2 = (c & d) ^ s1;
    code.move(s2, c);
    code.logand(s2, d);
    code.logxor(s2, s1);

    // s0 = c;
    code.move(s0, c);

    // s1 = d;
    code.move(s1, d);
}

// Generate code for the Clyde-128 L-box.
static void gen_clyde128_lbox
    (Code &code, const Reg &x, const Reg &y, const Reg &c, const Reg &d)
{
    // c = x ^ rightRotate12(x);
    code.move(c, x.shuffle(1, 2, 3, 0));
    code.ror(c, 4);
    code.logxor(c, x);

    // d = y ^ rightRotate12(y);
    code.move(d, y.shuffle(1, 2, 3, 0));
    code.ror(d, 4);
    code.logxor(d, y);

    // c ^= rightRotate3(c);
    Reg t = code.allocateReg(4);
    code.move(t, c);
    code.ror(t, 3);
    code.logxor(c, t);

    // d ^= rightRotate3(d);
    code.move(t, d);
    code.ror(t, 3);
    code.logxor(d, t);
    code.releaseReg(t);

    // x = c ^ leftRotate15(x);
    code.rol(x, 15);
    code.logxor(x, c);

    // y = d ^ leftRotate15(y);
    code.rol(y, 15);
    code.logxor(y, d);

    // c = x ^ leftRotate1(x);
    code.move(c, x);
    code.rol(c, 1);
    code.logxor(c, x);

    // d = y ^ leftRotate1(y);
    code.move(d, y);
    code.rol(d, 1);
    code.logxor(d, y);

    // x ^= leftRotate6(d);
    t = code.allocateReg(4);
    code.move(t, d.shuffle(3, 0, 1, 2));
    code.ror(t, 2);
    code.logxor(x, t);

    // y ^= leftRotate7(c);
    code.move(t, c.shuffle(3, 0, 1, 2));
    code.ror(t, 1);
    code.logxor(y, t);
    code.releaseReg(t);

    // x ^= rightRotate15(c);
    t = c.shuffle(2, 3, 0, 1);
    code.rol(t, 1);
    code.logxor(x, t);

    // y ^= rightRotate15(d);
    t = d.shuffle(2, 3, 0, 1);
    code.rol(t, 1);
    code.logxor(y, t);
}

// Generate code for the inverse of the Clyde-128 L-box.
static void gen_clyde128_inv_lbox
    (Code &code, const Reg &x, const Reg &y, const Reg &c, const Reg &d)
{
    // c = x ^ leftRotate7(x);
    code.move(c, x.shuffle(3, 0, 1, 2));
    code.ror(c, 1);
    code.logxor(c, x);

    // d = y ^ leftRotate7(y);
    code.move(d, y.shuffle(3, 0, 1, 2));
    code.ror(d, 1);
    code.logxor(d, y);

    // x ^= leftRotate1(c);
    Reg t = code.allocateReg(4);
    code.move(t, c);
    code.rol(t, 1);
    code.logxor(x, t);

    // y ^= leftRotate1(d);
    code.move(t, d);
    code.rol(t, 1);
    code.logxor(y, t);
    code.releaseReg(t);

    // x ^= leftRotate12(c);
    code.rol(c, 4);
    code.logxor(x, c.shuffle(3, 0, 1, 2));

    // y ^= leftRotate12(d);
    code.rol(d, 4);
    code.logxor(y, d.shuffle(3, 0, 1, 2));

    // c = x ^ leftRotate1(x);
    code.move(c, x);
    code.rol(c, 1);
    code.logxor(c, x);

    // d = y ^ leftRotate1(y);
    code.move(d, y);
    code.rol(d, 1);
    code.logxor(d, y);

    // x ^= leftRotate6(d);
    t = code.allocateReg(4);
    code.move(t, d.shuffle(3, 0, 1, 2));
    code.ror(t, 2);
    code.logxor(x, t);

    // y ^= leftRotate7(c);
    code.move(t, c.shuffle(3, 0, 1, 2));
    code.ror(t, 1);
    code.logxor(y, t);
    code.releaseReg(t);

    // c ^= leftRotate15(x);
    code.ror(x, 1);
    code.logxor(c, x.shuffle(2, 3, 0, 1));

    // d ^= leftRotate15(y);
    code.ror(y, 1);
    code.logxor(d, y.shuffle(2, 3, 0, 1));

    // x = rightRotate16(c);
    code.move(x, c.shuffle(2, 3, 0, 1));

    // y = rightRotate16(d);
    code.move(y, d.shuffle(2, 3, 0, 1));
}

/**
 * \brief Generates the AVR code for the Clyde-128 encryption function.
 *
 * \param code The code block to generate into.
 */
void gen_clyde128_encrypt(Code &code)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local storage.
    code.prologue_encrypt_block("clyde128_encrypt", 16);
    Reg tweak_ptr = code.arg(2);
    code.setFlag(Code::TempR0);
    code.setFlag(Code::TempR1);

    // Load the input into s0, s1, s2, s3.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);
    code.ldx(s0, POST_INC);
    code.ldx(s1, POST_INC);
    code.ldx(s2, POST_INC);
    code.ldx(s3, POST_INC);

    // Add the key to the state.
    code.ldz_xor(s0, 0);
    code.ldz_xor(s1, 4);
    code.ldz_xor(s2, 8);
    code.ldz_xor(s3, 12);

    // Load the tweak into local variables on the stack.
    // We also XOR the tweak into the state.
    code.move(Reg::x_ptr(), tweak_ptr);
    code.releaseReg(tweak_ptr);
    Reg c = code.allocateReg(4);
    Reg d = code.allocateReg(4);
    code.ldx(c, POST_INC);
    code.stlocal(c, 0);
    code.logxor(s0, c);
    code.ldx(c, POST_INC);
    code.stlocal(c, 4);
    code.logxor(s1, c);
    code.ldx(c, POST_INC);
    code.stlocal(c, 8);
    code.logxor(s2, c);
    code.ldx(c, POST_INC);
    code.stlocal(c, 12);
    code.logxor(s3, c);
    code.setFlag(Code::TempX);

    // Perform all rounds in pairs.  We unroll the outer loop to deal
    // with the round constants and put the bulk of the code in subroutines.
    unsigned char slbox_subroutine = 0;
    unsigned char update_subroutine = 0;
    unsigned char end_label = 0;
    for (int step = 0; step < CLYDE128_STEPS; ++step) {
        code.call(slbox_subroutine);
        if (rc[step][0])
            code.logxor(s0, 1);
        if (rc[step][1])
            code.logxor(s1, 1);
        if (rc[step][2])
            code.logxor(s2, 1);
        if (rc[step][3])
            code.logxor(s3, 1);
        code.call(slbox_subroutine);
        if (rc[step][4])
            code.logxor(s0, 1);
        if (rc[step][5])
            code.logxor(s1, 1);
        if (rc[step][6])
            code.logxor(s2, 1);
        if (rc[step][7])
            code.logxor(s3, 1);
        code.call(update_subroutine);
    }
    code.jmp(end_label);

    // Output the sbox/lbox subroutine.
    code.label(slbox_subroutine);
    gen_clyde128_sbox(code, s0, s1, s2, s3, c, d);
    gen_clyde128_lbox(code, s0, s1, c, d);
    gen_clyde128_lbox(code, s2, s3, c, d);
    code.ret();

    // Update the tweakey and add it to the state.
    code.label(update_subroutine);
    // c = t2; d = t0; c ^= d; t2 = d; t0 = c;
    code.ldlocal(c, 8);
    code.ldlocal(d, 0);
    code.logxor(c, d);
    code.stlocal(d, 8);
    code.stlocal(c, 0);
    // s0 ^= c; s2 ^= d;
    code.logxor(s0, c);
    code.logxor(s2, d);
    // c = t3; d = t1; c ^= d; t3 = d; t1 = c;
    code.ldlocal(c, 12);
    code.ldlocal(d, 4);
    code.logxor(c, d);
    code.stlocal(d, 12);
    code.stlocal(c, 4);
    // s1 ^= c; s3 ^= d;
    code.logxor(s1, c);
    code.logxor(s3, d);
    // s0 ^= k0; s1 ^= k1; s2 ^= k2; s3 ^= k3;
    code.ldz_xor(s0, 0);
    code.ldz_xor(s1, 4);
    code.ldz_xor(s2, 8);
    code.ldz_xor(s3, 12);
    code.ret();

    // End of the function.  Write the state to the output buffer.
    code.label(end_label);
    code.load_output_ptr();
    code.stx(s0, POST_INC);
    code.stx(s1, POST_INC);
    code.stx(s2, POST_INC);
    code.stx(s3, POST_INC);
}

/**
 * \brief Generates the AVR code for the Clyde-128 decryption function.
 *
 * \param code The code block to generate into.
 */
void gen_clyde128_decrypt(Code &code)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local storage.
    code.prologue_encrypt_block("clyde128_decrypt", 16);
    Reg tweak_ptr = code.arg(2);
    code.setFlag(Code::TempR0);
    code.setFlag(Code::TempR1);

    // Load the input into s0, s1, s2, s3.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);
    code.ldx(s0, POST_INC);
    code.ldx(s1, POST_INC);
    code.ldx(s2, POST_INC);
    code.ldx(s3, POST_INC);

    // Load the tweak into local variables on the stack.
    code.move(Reg::x_ptr(), tweak_ptr);
    code.releaseReg(tweak_ptr);
    Reg c = code.allocateReg(4);
    Reg d = code.allocateReg(4);
    code.ldx(c, POST_INC);
    code.stlocal(c, 0);
    code.ldx(c, POST_INC);
    code.stlocal(c, 4);
    code.ldx(c, POST_INC);
    code.stlocal(c, 8);
    code.ldx(c, POST_INC);
    code.stlocal(c, 12);
    code.setFlag(Code::TempX);

    // Perform all rounds in pairs.  We unroll the outer loop to deal
    // with the round constants and put the bulk of the code in subroutines.
    unsigned char slbox_subroutine = 0;
    unsigned char update_subroutine = 0;
    unsigned char end_label = 0;
    for (int step = CLYDE128_STEPS - 1; step >= 0; --step) {
        code.call(update_subroutine);
        if (rc[step][4])
            code.logxor(s0, 1);
        if (rc[step][5])
            code.logxor(s1, 1);
        if (rc[step][6])
            code.logxor(s2, 1);
        if (rc[step][7])
            code.logxor(s3, 1);
        code.call(slbox_subroutine);
        if (rc[step][0])
            code.logxor(s0, 1);
        if (rc[step][1])
            code.logxor(s1, 1);
        if (rc[step][2])
            code.logxor(s2, 1);
        if (rc[step][3])
            code.logxor(s3, 1);
        code.call(slbox_subroutine);
    }
    code.jmp(end_label);

    // Output the sbox/lbox subroutine.
    code.label(slbox_subroutine);
    gen_clyde128_inv_lbox(code, s0, s1, c, d);
    gen_clyde128_inv_lbox(code, s2, s3, c, d);
    gen_clyde128_inv_sbox(code, s0, s1, s2, s3, c, d);
    code.ret();

    // Add the tweakey to the state and update it.
    code.label(update_subroutine);
    // s0 ^= k0 ^ t0;
    // s1 ^= k1 ^ t1;
    // s2 ^= k2 ^ t2;
    // s3 ^= k3 ^ t3;
    code.ldz_xor(s0, 0);
    code.ldz_xor(s1, 4);
    code.ldz_xor(s2, 8);
    code.ldz_xor(s3, 12);
    // c = t2 ^ t0; t0 = t2; t2 = c;
    code.ldlocal(c, 0);
    code.ldlocal(d, 8);
    code.logxor(s0, c);
    code.logxor(s2, d);
    code.logxor(c, d);
    code.stlocal(d, 0);
    code.stlocal(c, 8);
    // c = t3 ^ t1; t1 = t3; t3 = c;
    code.ldlocal(c, 4);
    code.ldlocal(d, 12);
    code.logxor(s1, c);
    code.logxor(s3, d);
    code.logxor(c, d);
    code.stlocal(d, 4);
    code.stlocal(c, 12);
    code.ret();

    // End of the function.  Add the tweakkey to the state one last time.
    code.label(end_label);
    code.ldz_xor(s0, 0);
    code.ldz_xor(s1, 4);
    code.ldz_xor(s2, 8);
    code.ldz_xor(s3, 12);
    code.ldlocal_xor(s0, 0);
    code.ldlocal_xor(s1, 4);
    code.ldlocal_xor(s2, 8);
    code.ldlocal_xor(s3, 12);

    // Write the state to the output buffer.
    code.load_output_ptr();
    code.stx(s0, POST_INC);
    code.stx(s1, POST_INC);
    code.stx(s2, POST_INC);
    code.stx(s3, POST_INC);
}

static void gen_shadow_permutation(Code &code, int num_bundles)
{
    // We don't need the Y register, so use it for temporaries instead.
    code.setFlag(Code::TempY);

    // Allocate the registers that we need.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);
    Reg c = code.allocateReg(4);
    Reg d = code.allocateReg(4);

    // Perform all rounds in pairs.  We unroll the outer loop to deal
    // with the round constants and put the bulk of the code in subroutines.
    unsigned char sbox_subroutine = 0;
    unsigned char lbox_subroutine = 0;
    unsigned char diffuse_subroutine = 0;
    unsigned char end_label = 0;
    for (int step = 0; step < CLYDE128_STEPS; ++step) {
        // Apply the S-box and L-box to all bundles.
        for (int bundle = 0; bundle < num_bundles; ++bundle) {
            code.ldz(s0, bundle * 16);
            code.ldz(s1, bundle * 16 + 4);
            code.ldz(s2, bundle * 16 + 8);
            code.ldz(s3, bundle * 16 + 12);
            code.call(sbox_subroutine);
            code.call(lbox_subroutine);
            if (rc[step][0])
                code.logxor(s0, 1 << bundle);
            if (rc[step][1])
                code.logxor(s1, 1 << bundle);
            if (rc[step][2])
                code.logxor(s2, 1 << bundle);
            if (rc[step][3])
                code.logxor(s3, 1 << bundle);
            code.call(sbox_subroutine);
            code.stz(s0, bundle * 16);
            code.stz(s1, bundle * 16 + 4);
            code.stz(s2, bundle * 16 + 8);
            code.stz(s3, bundle * 16 + 12);
        }

        // Apply the diffusion layer to the rows of the state.
        code.call(diffuse_subroutine);

        // Add round constants to all bundles again.
        for (int bundle = 0; bundle < num_bundles; ++bundle) {
            Reg temp = Reg(s0, 0, 1);
            if (rc[step][4]) {
                code.ldz(temp, bundle * 16);
                code.logxor(temp, 1 << bundle);
                code.stz(temp, bundle * 16);
            }
            if (rc[step][5]) {
                code.ldz(temp, bundle * 16 + 4);
                code.logxor(temp, 1 << bundle);
                code.stz(temp, bundle * 16 + 4);
            }
            if (rc[step][6]) {
                code.ldz(temp, bundle * 16 + 8);
                code.logxor(temp, 1 << bundle);
                code.stz(temp, bundle * 16 + 8);
            }
            if (rc[step][7]) {
                code.ldz(temp, bundle * 16 + 12);
                code.logxor(temp, 1 << bundle);
                code.stz(temp, bundle * 16 + 12);
            }
        }
    }
    code.jmp(end_label);

    // Output the sbox and lbox subroutines.
    code.label(sbox_subroutine);
    gen_clyde128_sbox(code, s0, s1, s2, s3, c, d);
    code.ret();
    code.label(lbox_subroutine);
    gen_clyde128_lbox(code, s0, s1, c, d);
    gen_clyde128_lbox(code, s2, s3, c, d);
    code.ret();

    // Output the subroutine for the diffusion layer.
    code.label(diffuse_subroutine);
    for (int row = 0; row < 4; ++row) {
        if (num_bundles == 4) {
            // Diffusion layer for Shadow-512.
            code.ldz(s0, row * 4);
            code.ldz(s1, row * 4 + 16);
            code.ldz(s2, row * 4 + 32);
            code.ldz(s3, row * 4 + 48);
            code.move(c, s0);
            code.logxor(c, s1);
            code.move(d, s2);
            code.logxor(d, s3);
            code.logxor(s0, d);
            code.logxor(s1, d);
            code.logxor(s2, c);
            code.logxor(s3, c);
            code.stz(s1, row * 4);
            code.stz(s0, row * 4 + 16);
            code.stz(s3, row * 4 + 32);
            code.stz(s2, row * 4 + 48);
        } else {
            // Diffusion layer for Shadow-384.
            code.ldz(s0, row * 4);
            code.ldz(s1, row * 4 + 16);
            code.ldz(s2, row * 4 + 32);
            code.logxor(s1, s0);
            code.stz(s1, row * 4 + 32);
            code.logxor(s1, s2);
            code.stz(s1, row * 4);
            code.logxor(s0, s2);
            code.stz(s0, row * 4 + 16);
        }
    }
    code.ret();

    // End of the function.
    code.label(end_label);
}

void gen_shadow512_permutation(Code &code)
{
    code.prologue_permutation("shadow512", 0);
    gen_shadow_permutation(code, 4);
}

void gen_shadow384_permutation(Code &code)
{
    code.prologue_permutation("shadow384", 0);
    gen_shadow_permutation(code, 3);
}

// Test vector for Clyde-128 generated with the reference implementation.
static block_cipher_test_vector_t const clyde128_1 = {
    "Test Vector 1",
    {0xc6, 0x5a, 0xf8, 0xdd, 0xcf, 0x9d, 0x4a, 0x70,    /* key + tweak */
     0xb7, 0x20, 0x2e, 0x95, 0x9b, 0x4b, 0xfd, 0xb7,
     0x9c, 0xc9, 0x76, 0xbd, 0x0c, 0x21, 0x48, 0x4c,
     0x9d, 0x19, 0xf9, 0x27, 0xb1, 0xaa, 0x3f, 0xe1},
    32,                                                 /* key_len */
    {0xd0, 0x84, 0x40, 0x22, 0x36, 0x80, 0x40, 0x4f,    /* plaintext */
     0xa2, 0x09, 0xb2, 0x1c, 0xf7, 0xff, 0x86, 0xa6},
    {0x6b, 0x73, 0xfa, 0x3e, 0x9a, 0x5a, 0x89, 0x95,    /* ciphertext */
     0x2c, 0xd2, 0x9d, 0x3e, 0xe2, 0x03, 0x85, 0x01}
};

bool test_clyde128_encrypt(Code &code)
{
    unsigned char output[16];
    code.exec_encrypt_block_with_tweak_ptr
        (clyde128_1.key, 16, output, 16, clyde128_1.plaintext, 16,
         clyde128_1.key + 16, 16);
    return !memcmp(output, clyde128_1.ciphertext, 16);
}

bool test_clyde128_decrypt(Code &code)
{
    unsigned char output[16];
    code.exec_encrypt_block_with_tweak_ptr
        (clyde128_1.key, 16, output, 16, clyde128_1.ciphertext, 16,
         clyde128_1.key + 16, 16);
    return !memcmp(output, clyde128_1.plaintext, 16);
}

// Test vectors for Shadow-512/384 generated with reference implementation.
static unsigned char const shadow512_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
};
static unsigned char const shadow512_output[] = {
    0x68, 0x3f, 0xa9, 0xf9, 0x00, 0xf6, 0x58, 0xa2,
    0x71, 0x66, 0xe2, 0xcc, 0x1b, 0xb4, 0x0d, 0xf8,
    0x32, 0xd2, 0x70, 0xf8, 0xc0, 0x10, 0x88, 0xbf,
    0xeb, 0x92, 0x43, 0x2f, 0x0d, 0xb2, 0xe6, 0x9c,
    0x73, 0xc6, 0x4d, 0x2a, 0x3c, 0xf3, 0x28, 0x49,
    0xbc, 0x6e, 0xe1, 0xbe, 0x09, 0x2a, 0x42, 0x68,
    0xad, 0x56, 0xf0, 0x78, 0xcb, 0x2b, 0x87, 0x92,
    0x44, 0x77, 0xcc, 0x15, 0xcd, 0x56, 0x52, 0x38,
};
static unsigned char const shadow384_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
};
static unsigned char const shadow384_output[] = {
    0x28, 0x14, 0xfc, 0x1a, 0x79, 0xc9, 0x8e, 0x3d,
    0xcb, 0xb7, 0x11, 0xce, 0x0f, 0xce, 0xf8, 0xdb,
    0xfb, 0x3b, 0xd3, 0x45, 0xae, 0xac, 0x78, 0x43,
    0xeb, 0xcc, 0xb3, 0x1c, 0x41, 0xd9, 0x9d, 0x47,
    0xc6, 0xe7, 0xc6, 0xcc, 0x87, 0x82, 0xe3, 0x9c,
    0x4b, 0x40, 0xb1, 0xdf, 0xda, 0x96, 0x43, 0xb2,
};

bool test_shadow512_permutation(Code &code)
{
    unsigned char state[64];
    memcpy(state, shadow512_input, 64);
    code.exec_permutation(state, 64);
    return !memcmp(shadow512_output, state, 64);
}

bool test_shadow384_permutation(Code &code)
{
    unsigned char state[48];
    memcpy(state, shadow384_input, 48);
    code.exec_permutation(state, 48);
    return !memcmp(shadow384_output, state, 48);
}
