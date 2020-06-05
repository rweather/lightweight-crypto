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

Sbox get_sliscp_light256_round_constants()
{
    /* Interleaved rc0, rc1, sc0, and sc1 values for each round */
    static unsigned char const sliscp_light256_RC[18 * 4] = {
        0x0f, 0x47, 0x08, 0x64, 0x04, 0xb2, 0x86, 0x6b,
        0x43, 0xb5, 0xe2, 0x6f, 0xf1, 0x37, 0x89, 0x2c,
        0x44, 0x96, 0xe6, 0xdd, 0x73, 0xee, 0xca, 0x99,
        0xe5, 0x4c, 0x17, 0xea, 0x0b, 0xf5, 0x8e, 0x0f,
        0x47, 0x07, 0x64, 0x04, 0xb2, 0x82, 0x6b, 0x43,
        0xb5, 0xa1, 0x6f, 0xf1, 0x37, 0x78, 0x2c, 0x44,
        0x96, 0xa2, 0xdd, 0x73, 0xee, 0xb9, 0x99, 0xe5,
        0x4c, 0xf2, 0xea, 0x0b, 0xf5, 0x85, 0x0f, 0x47,
        0x07, 0x23, 0x04, 0xb2, 0x82, 0xd9, 0x43, 0xb5
    };
    return Sbox(sliscp_light256_RC, sizeof(sliscp_light256_RC));
}

Sbox get_sliscp_light192_round_constants()
{
    /* Interleaved rc0, rc1, sc0, and sc1 values for each round */
    static unsigned char const sliscp_light192_RC[18 * 4] = {
        0x07, 0x27, 0x08, 0x29, 0x04, 0x34, 0x0c, 0x1d,
        0x06, 0x2e, 0x0a, 0x33, 0x25, 0x19, 0x2f, 0x2a,
        0x17, 0x35, 0x38, 0x1f, 0x1c, 0x0f, 0x24, 0x10,
        0x12, 0x08, 0x36, 0x18, 0x3b, 0x0c, 0x0d, 0x14,
        0x26, 0x0a, 0x2b, 0x1e, 0x15, 0x2f, 0x3e, 0x31,
        0x3f, 0x38, 0x01, 0x09, 0x20, 0x24, 0x21, 0x2d,
        0x30, 0x36, 0x11, 0x1b, 0x28, 0x0d, 0x39, 0x16,
        0x3c, 0x2b, 0x05, 0x3d, 0x22, 0x3e, 0x27, 0x03,
        0x13, 0x01, 0x34, 0x02, 0x1a, 0x21, 0x2e, 0x23
    };
    return Sbox(sliscp_light192_RC, sizeof(sliscp_light192_RC));
}

Sbox get_sliscp_light320_round_constants()
{
    /* Interleaved rc0, rc1, rc2, sc0, sc1, and sc2 values for each round */
    static unsigned char const sliscp_light320_RC[16 * 6] = {
        0x07, 0x53, 0x43, 0x50, 0x28, 0x14, 0x0a, 0x5d,
        0xe4, 0x5c, 0xae, 0x57, 0x9b, 0x49, 0x5e, 0x91,
        0x48, 0x24, 0xe0, 0x7f, 0xcc, 0x8d, 0xc6, 0x63,
        0xd1, 0xbe, 0x32, 0x53, 0xa9, 0x54, 0x1a, 0x1d,
        0x4e, 0x60, 0x30, 0x18, 0x22, 0x28, 0x75, 0x68,
        0x34, 0x9a, 0xf7, 0x6c, 0x25, 0xe1, 0x70, 0x38,
        0x62, 0x82, 0xfd, 0xf6, 0x7b, 0xbd, 0x96, 0x47,
        0xf9, 0x9d, 0xce, 0x67, 0x71, 0x6b, 0x76, 0x40,
        0x20, 0x10, 0xaa, 0x88, 0xa0, 0x4f, 0x27, 0x13,
        0x2b, 0xdc, 0xb0, 0xbe, 0x5f, 0x2f, 0xe9, 0x8b,
        0x09, 0x5b, 0xad, 0xd6, 0xcf, 0x59, 0x1e, 0xe9,
        0x74, 0xba, 0xb7, 0xc6, 0xad, 0x7f, 0x3f, 0x1f
    };
    return Sbox(sliscp_light320_RC, sizeof(sliscp_light320_RC));
}

// Apply a single round of the Simeck block operation.
static void simeck_round
    (Code &code, const Reg &x, const Reg &y, const Reg &rc)
{
    // y ^= leftRotate1(x);
    Reg temp = code.allocateReg(x.size());
    code.move(temp, x);
    code.rol(temp, 1);
    code.logxor(y, temp);

    // y ^= leftRotate5(x) & x;
    code.rol(temp, 4);
    code.logand(temp, x);
    code.logxor(y, temp);
    code.releaseReg(temp);

    // y ^= 0xFFFFFFFE ^ (rc & 1); rc >>= 1;
    code.lognot(Reg(y, 1, y.size() - 1));
    temp = code.allocateHighReg(1);
    code.move(temp, 0xFF);
    code.onereg(Insn::LSR, rc.reg(0));
    code.onereg(Insn::ROL, temp.reg(0));
    code.logxor(y, temp);
    code.releaseReg(temp);
}

// Encrypts a 64-bit block with the 8 round version of Simeck-64.
static void simeck64_box
    (Code &code, const Reg &x, const Reg &y, const Reg &round, const Reg &rc)
{
    // Load the round constant bits for this Simeck-64 block operation.
    code.sbox_lookup(rc, round);
    code.inc(round);

    // Apply the 8 rounds.
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
}

// Encrypts a 64-bit block with the 8 round version of Simeck-64.
// This version is used when registers are in short supply.
static void simeck64_box
    (Code &code, const Reg &x, const Reg &y, const Reg &round)
{
    // Load the round constant bits for this Simeck-64 block operation.
    // We reuse the "round" register for the rc value.
    Reg rc = code.allocateReg(1);
    code.sbox_lookup(rc, round);
    code.inc(round);
    code.push(round);
    code.move(round, rc);
    code.releaseReg(rc);
    rc = round;

    // Apply the 8 rounds.
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);

    // Restore the round counter.
    code.pop(round);
}

// Encrypts a 48-bit block with the 6 round version of Simeck-48.
static void simeck48_box
    (Code &code, const Reg &x, const Reg &y, const Reg &round, const Reg &rc)
{
    // Load the round constant bits for this Simeck-48 block operation.
    code.sbox_lookup(rc, round);
    code.inc(round);

    // Apply the 6 rounds.
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
    simeck_round(code, x, y, rc);
    simeck_round(code, y, x, rc);
}

static void gen_sliscp_light256_permutation
    (Code &code, const char *name, bool is_spix)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg rounds;
    if (is_spix)
        rounds = code.prologue_permutation_with_count(name, 16);
    else
        code.prologue_permutation(name, 16);

    // Load four words of the input state into registers and the other
    // four words are stored into local variables.  At the end of this,
    // x2, x3, x6, and x7 will end up in registers.
    Reg x2 = code.allocateReg(4);
    Reg x3 = code.allocateReg(4);
    Reg x6 = code.allocateReg(4);
    Reg x7 = code.allocateReg(4);
    if (is_spix) {
        // Input byte order is for SPIX.
        code.ldz(x2.reversed(), 0);     // x0
        code.ldz(x3.reversed(), 4);     // x1
        code.ldz(x6.reversed(), 16);    // x4
        code.ldz(x7.reversed(), 20);    // x5
        code.stlocal(x2, 0);
        code.stlocal(x3, 4);
        code.stlocal(x6, 8);
        code.stlocal(x7, 12);
        code.ldz(x2.reversed(), 8);     // x2
        code.ldz(x3.reversed(), 24);    // x3
        code.ldz(x6.reversed(), 12);    // x6
        code.ldz(x7.reversed(), 28);    // x7
    } else {
        // Input byte order is for SpoC-128.
        code.ldz(x2.reversed(), 0);     // x0
        code.ldz(x3.reversed(), 4);     // x1
        code.ldz(x6.reversed(), 8);     // x4
        code.ldz(x7.reversed(), 12);    // x5
        code.stlocal(x2, 0);
        code.stlocal(x3, 4);
        code.stlocal(x6, 8);
        code.stlocal(x7, 12);
        code.ldz(x2.reversed(), 16);    // x2
        code.ldz(x3.reversed(), 20);    // x3
        code.ldz(x6.reversed(), 24);    // x6
        code.ldz(x7.reversed(), 28);    // x7
    }

    // Save Z and set up the pointer to the RC table.
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_sliscp_light256_round_constants());

    // Top of the round loop.
    unsigned char top_label = 0;
    Reg round = Reg(Reg::z_ptr(), 0, 1); // Low byte of Z.
    Reg rc = code.allocateReg(1);
    code.move(round, 0);
    code.label(top_label);

    // Apply Simeck-64 to two of the 64-bit sub-blocks.
    simeck64_box(code, x2, x3, round, rc);
    simeck64_box(code, x6, x7, round, rc);

    // Mix the sub-blocks and apply step constants.
    Reg t0 = code.allocateReg(4);
    code.ldlocal(t0, 0);                // t0 = (x0 ^ 0xFFFFFFFFU) ^ x2;
    code.lognot(t0);
    code.logxor(t0, x2);
    code.stlocal(x2, 0);                // x0 = x2;
    code.ldlocal(x2, 8);                // x2 = (x4 ^ 0xFFFFFFFFU) ^ x6;
    code.lognot(x2);
    code.logxor(x2, x6);
    code.stlocal(x6, 8);                // x4 = x6;
    code.move(x6, t0);                  // x6 = t0;
    code.ldlocal(t0, 4);                // x1 ^= 0xFFFFFF00U ^ rc[2];
    code.lognot(Reg(t0, 1, 3));
    code.sbox_lookup(rc, round);
    code.logxor(t0, rc);
    code.inc(round);
    code.logxor(t0, x3);                // t0 = x1 ^ x3;
    code.stlocal(x3, 4);                // x1 = x3;
    code.ldlocal(x3, 12);               // x5 ^= 0xFFFFFF00U ^ rc[3];
    code.lognot(Reg(x3, 1, 3));
    code.sbox_lookup(rc, round);
    code.logxor(x3, rc);
    code.inc(round);
    code.logxor(x3, x7);                // x3 = x5 ^ x7;
    code.stlocal(x7, 12);               // x5 = x7;
    code.move(x7, t0);                  // x7 = t0;
    code.releaseReg(t0);

    // Bottom of the round loop.
    if (is_spix) {
        code.dec(rounds);
        code.brne(top_label);
    } else {
        code.compare_and_loop(round, 18 * 4, top_label);
    }

    // Restore Z and save the state back.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    if (is_spix) {
        // Output byte order is for SPIX.
        code.stz(x2.reversed(), 8);     // x2
        code.stz(x3.reversed(), 24);    // x3
        code.stz(x6.reversed(), 12);    // x6
        code.stz(x7.reversed(), 28);    // x7
        code.ldlocal(x2, 0);
        code.ldlocal(x3, 4);
        code.ldlocal(x6, 8);
        code.ldlocal(x7, 12);
        code.stz(x2.reversed(), 0);     // x0
        code.stz(x3.reversed(), 4);     // x1
        code.stz(x6.reversed(), 16);    // x4
        code.stz(x7.reversed(), 20);    // x5
    } else {
        // Output byte order is for SpoC-128.
        code.stz(x2.reversed(), 16);    // x2
        code.stz(x3.reversed(), 20);    // x3
        code.stz(x6.reversed(), 24);    // x6
        code.stz(x7.reversed(), 28);    // x7
        code.ldlocal(x2, 0);
        code.ldlocal(x3, 4);
        code.ldlocal(x6, 8);
        code.ldlocal(x7, 12);
        code.stz(x2.reversed(), 0);     // x0
        code.stz(x3.reversed(), 4);     // x1
        code.stz(x6.reversed(), 8);     // x4
        code.stz(x7.reversed(), 12);    // x5
    }
}

void gen_sliscp_light256_spix_permutation(Code &code)
{
    gen_sliscp_light256_permutation
        (code, "sliscp_light256_permute_spix", true);
}

void gen_sliscp_light256_spoc_permutation(Code &code)
{
    gen_sliscp_light256_permutation
        (code, "sliscp_light256_permute_spoc", false);
}

void gen_sliscp_light256_swap_spix(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("sliscp_light256_swap_spix", 0);
    code.setFlag(Code::NoLocals);

    // Swap bytes 12..15 with 24..27.
    Reg t1 = code.allocateReg(4);
    Reg t2 = code.allocateReg(4);
    code.ldz(t1, 12);
    code.ldz(t2, 24);
    code.stz(t1, 24);
    code.stz(t2, 12);
}

void gen_sliscp_light256_swap_spoc(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("sliscp_light256_swap_spoc", 0);
    code.setFlag(Code::NoLocals);

    // Swap bytes 8..15 with 16..23.
    Reg t1 = code.allocateReg(4);
    Reg t2 = code.allocateReg(4);
    code.ldz(t1, 8);
    code.ldz(t2, 16);
    code.stz(t1, 16);
    code.stz(t2, 8);
    code.ldz(t1, 12);
    code.ldz(t2, 20);
    code.stz(t1, 20);
    code.stz(t2, 12);
}

void gen_sliscp_light192_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("sliscp_light192_permute", 0);
    code.setFlag(Code::TempY);
    code.setFlag(Code::TempR0);
    code.setFlag(Code::TempR1);

    // Load the state up into 48-bit registers.
    Reg x0 = code.allocateReg(3);
    Reg x1 = code.allocateReg(3);
    Reg x2 = code.allocateReg(3);
    Reg x3 = code.allocateReg(3);
    Reg x4 = code.allocateReg(3);
    Reg x5 = code.allocateReg(3);
    Reg x6 = code.allocateReg(3);
    Reg x7 = code.allocateReg(3);
    code.ldz(x0.reversed(), 0);
    code.ldz(x1.reversed(), 3);
    code.ldz(x2.reversed(), 6);
    code.ldz(x3.reversed(), 9);
    code.ldz(x4.reversed(), 12);
    code.ldz(x5.reversed(), 15);
    code.ldz(x6.reversed(), 18);
    code.ldz(x7.reversed(), 21);

    // Save Z and set up the pointer to the RC table.
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_sliscp_light192_round_constants());

    // Top of the round loop.
    unsigned char top_label = 0;
    Reg round = code.allocateHighReg(1);
    Reg rc = code.allocateReg(1);
    code.move(round, 0);
    code.label(top_label);

    // Apply Simeck-48 to two of the 48-bit sub-blocks.
    simeck48_box(code, x2, x3, round, rc);
    simeck48_box(code, x6, x7, round, rc);

    // Add step constants.
    code.lognot(x0);                // x0 ^= 0x00FFFFFFU;
    code.lognot(Reg(x1, 1, 2));     // x1 ^= 0x00FFFF00U ^ rc[2];
    code.sbox_lookup(rc, round);
    code.logxor(x1, rc);
    code.inc(round);
    code.lognot(x4);                // x4 ^= 0x00FFFFFFU;
    code.lognot(Reg(x5, 1, 2));     // x5 ^= 0x00FFFF00U ^ rc[3];
    code.sbox_lookup(rc, round);
    code.logxor(x5, rc);
    code.inc(round);

    // Mix the sub-blocks.
    Reg t0 = code.allocateReg(4);
    code.move(t0, x0);              // t0 = x0 ^ x2;
    code.logxor(t0, x2);
    code.move(x0, x2);              // x0 = x2;
    code.move(x2, x4);              // x2 = x4 ^ x6;
    code.logxor(x2, x6);
    code.move(x4, x6);              // x4 = x6;
    code.move(x6, t0);              // x6 = t0;
    code.move(t0, x1);              // t0 = x1 ^ x3;
    code.logxor(t0, x3);
    code.move(x1, x3);              // x1 = x3;
    code.move(x3, x5);              // x3 = x5 ^ x7;
    code.logxor(x3, x7);
    code.move(x5, x7);              // x5 = x7;
    code.move(x7, t0);              // x7 = t0;
    code.releaseReg(t0);

    // Bottom of the round loop.
    code.compare_and_loop(round, 18 * 4, top_label);

    // Restore Z and save the state back.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(x0.reversed(), 0);
    code.stz(x1.reversed(), 3);
    code.stz(x2.reversed(), 6);
    code.stz(x3.reversed(), 9);
    code.stz(x4.reversed(), 12);
    code.stz(x5.reversed(), 15);
    code.stz(x6.reversed(), 18);
    code.stz(x7.reversed(), 21);
}

void gen_sliscp_light320_permutation(Code &code)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("sliscp_light320_permute", 16);
    code.setFlag(Code::TempR0);
    code.setFlag(Code::TempR1);

    // Load six words of the input state into registers and the other
    // four words are stored into local variables.  At the end of this,
    // x0, x1, x4, x5, x8, and x9 will end up in registers.
    Reg x0 = code.allocateReg(4);
    Reg x1 = code.allocateReg(4);
    Reg x4 = code.allocateReg(4);
    Reg x5 = code.allocateReg(4);
    Reg x8 = code.allocateReg(4);
    Reg x9 = code.allocateReg(4);
    code.ldz(x0.reversed(), 8);     // x2
    code.ldz(x1.reversed(), 12);    // x3
    code.ldz(x4.reversed(), 24);    // x6
    code.ldz(x5.reversed(), 28);    // x7
    code.stlocal(x0, 0);
    code.stlocal(x1, 4);
    code.stlocal(x4, 8);
    code.stlocal(x5, 12);
    code.ldz(x0.reversed(), 0);     // x0
    code.ldz(x1.reversed(), 16);    // x1
    code.ldz(x4.reversed(), 4);     // x4
    code.ldz(x5.reversed(), 20);    // x5
    code.ldz(x8.reversed(), 32);    // x8
    code.ldz(x9.reversed(), 36);    // x9

    // Save Z and set up the pointer to the RC table.
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_sliscp_light320_round_constants());

    // Top of the round loop.
    unsigned char top_label = 0;
    Reg round = Reg(Reg::z_ptr(), 0, 1); // Low byte of Z.
    code.move(round, 0);
    code.label(top_label);

    // Apply Simeck-64 to three of the 64-bit sub-blocks.
    simeck64_box(code, x0, x1, round);
    simeck64_box(code, x4, x5, round);
    simeck64_box(code, x8, x9, round);

    // Mix the blocks and apply step constants.
    Reg t0 = code.allocateReg(4);
    Reg rc = Reg(t0, 3, 1);
    code.ldlocal(t0, 0);                // x2 ^= x4;
    code.logxor(t0, x4);
    code.lognot(t0);                    // x2 ^= 0xFFFFFFFFU;
    code.stlocal(t0, 0);
    code.ldlocal(t0, 4);                // x3 ^= x5;
    code.logxor(t0, x5);
    code.lognot(Reg(t0, 1, 3));         // x3 ^= 0xFFFFFF00U ^ rc[3];
    code.stlocal(Reg(t0, 1, 3), 5);
    code.sbox_lookup(rc, round);
    code.inc(round);
    code.logxor(Reg(t0, 0, 1), rc);
    code.stlocal(Reg(t0, 0, 1), 4);
    code.ldlocal(t0, 8);                // x6 ^= x8;
    code.logxor(t0, x8);
    code.lognot(t0);                    // x6 ^= 0xFFFFFFFFU;
    code.stlocal(t0, 8);
    code.ldlocal(t0, 12);               // x7 ^= x9;
    code.logxor(t0, x9);
    code.lognot(Reg(t0, 1, 3));         // x7 ^= 0xFFFFFF00U ^ rc[4];
    code.stlocal(Reg(t0, 1, 3), 13);
    code.sbox_lookup(rc, round);
    code.inc(round);
    code.logxor(Reg(t0, 0, 1), rc);
    code.stlocal(Reg(t0, 0, 1), 12);
    code.logxor(x8, x0);                // x8 ^= x0;
    code.lognot(x8);                    // x8 ^= 0xFFFFFFFFU;
    code.logxor(x9, x1);                // x9 ^= x1;
    code.lognot(Reg(x9, 1, 3));         // x9 ^= 0xFFFFFF00U ^ rc[5];
    code.sbox_lookup(rc, round);
    code.inc(round);
    code.logxor(x9, rc);

    // Rotate the sub-blocks.
    code.move(t0, x8);                  // t0 = x8;
    code.ldlocal(x8, 0);                // x8 = x2;
    code.stlocal(x4, 0);                // x2 = x4;
    code.move(x4, x0);                  // x4 = x0;
    code.ldlocal(x0, 8);                // x0 = x6;
    code.stlocal(t0, 8);                // x6 = t0;
    code.move(t0, x9);                  // t0 = x9;
    code.ldlocal(x9, 4);                // x9 = x3;
    code.stlocal(x5, 4);                // x3 = x5;
    code.move(x5, x1);                  // x5 = x1;
    code.ldlocal(x1, 12);               // x1 = x7;
    code.stlocal(t0, 12);               // x7 = t0;
    code.releaseReg(t0);

    // Bottom of the round loop.
    code.compare_and_loop(round, 16 * 6, top_label);

    // Restore Z and save the state back.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(x0.reversed(), 0);
    code.stz(x1.reversed(), 16);
    code.stz(x4.reversed(), 4);
    code.stz(x5.reversed(), 20);
    code.stz(x8.reversed(), 32);
    code.stz(x9.reversed(), 36);
    code.ldlocal(x0, 0);                // x2
    code.ldlocal(x1, 4);                // x3
    code.ldlocal(x4, 8);                // x6
    code.ldlocal(x5, 12);               // x7
    code.stz(x0.reversed(), 8);
    code.stz(x1.reversed(), 12);
    code.stz(x4.reversed(), 24);
    code.stz(x5.reversed(), 28);
}

void gen_sliscp_light320_swap(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("sliscp_light320_swap", 0);
    code.setFlag(Code::NoLocals);

    // Swap bytes 4..7 with 16..19.
    Reg t1 = code.allocateReg(4);
    Reg t2 = code.allocateReg(4);
    code.ldz(t1, 4);
    code.ldz(t2, 16);
    code.stz(t1, 16);
    code.stz(t2, 4);
}

static void sliscp_light256_spix_swap(unsigned char state[32])
{
    // Swap bytes 12..15 with 24..27.
    for (int index = 12; index < 16; ++index) {
        unsigned char temp = state[index];
        state[index] = state[index + 12];
        state[index + 12] = temp;
    }
}

bool test_sliscp_light256_spix_permutation(Code &code)
{
    static unsigned char const output[32] = {
        0xc1, 0x4f, 0xd3, 0x2f, 0xdd, 0x8c, 0x4f, 0x91,
        0x3d, 0x7c, 0xd3, 0x7c, 0xe4, 0xc0, 0xfc, 0x40,
        0x47, 0x57, 0x72, 0x47, 0xa9, 0x07, 0xf4, 0x6a,
        0xb9, 0x29, 0x67, 0x03, 0xc6, 0x78, 0x8a, 0x4c
    };
    unsigned char state[32];
    memset(state, 0, sizeof(state));
    code.exec_permutation(state, 32, 18);
    sliscp_light256_spix_swap(state);
    return !memcmp(output, state, 32);
}

static void sliscp_light256_spoc_swap(unsigned char state[32])
{
    // Swap bytes 8..15 with 16..23.
    for (int index = 8; index < 16; ++index) {
        unsigned char temp = state[index];
        state[index] = state[index + 8];
        state[index + 8] = temp;
    }
}

bool test_sliscp_light256_spoc_permutation(Code &code)
{
    static unsigned char const output[32] = {
        0xc1, 0x4f, 0xd3, 0x2f, 0xdd, 0x8c, 0x4f, 0x91,
        0x3d, 0x7c, 0xd3, 0x7c, 0xe4, 0xc0, 0xfc, 0x40,
        0x47, 0x57, 0x72, 0x47, 0xa9, 0x07, 0xf4, 0x6a,
        0xb9, 0x29, 0x67, 0x03, 0xc6, 0x78, 0x8a, 0x4c
    };
    unsigned char state[32];
    memset(state, 0, sizeof(state));
    code.exec_permutation(state, 32);
    sliscp_light256_spoc_swap(state);
    return !memcmp(output, state, 32);
}

bool test_sliscp_light192_permutation(Code &code)
{
    static unsigned char const output[24] = {
        0x2d, 0xca, 0xca, 0x34, 0x66, 0xfa, 0x12, 0x6d,
        0x47, 0xf0, 0xe1, 0x42, 0x29, 0xa1, 0x1a, 0x0b,
        0x5d, 0x4c, 0x7f, 0x70, 0x2d, 0x8a, 0x46, 0x4d
    };
    unsigned char state[24];
    memset(state, 0, sizeof(state));
    code.exec_permutation(state, 24);
    return !memcmp(output, state, 24);
}

static void sliscp_light320_swap(unsigned char state[40])
{
    // Swap bytes 4..7 with 16..19.
    for (int index = 4; index < 8; ++index) {
        unsigned char temp = state[index];
        state[index] = state[index + 12];
        state[index + 12] = temp;
    }
}

bool test_sliscp_light320_permutation(Code &code)
{
    static unsigned char const input[40] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    static unsigned char const output[40] = {
        0xba, 0xc2, 0xcf, 0xa0, 0x9d, 0x50, 0xb3, 0x93,
        0x99, 0x2d, 0xac, 0x9e, 0x4c, 0x59, 0x4f, 0xbc,
        0x40, 0xe7, 0x18, 0x61, 0x08, 0x2d, 0xc7, 0x47,
        0xf2, 0x43, 0x88, 0x3a, 0x1b, 0xac, 0x45, 0xdb,
        0xa6, 0x13, 0x83, 0x1c, 0x7b, 0x12, 0xd7, 0xb3
    };
    unsigned char state[40];
    memcpy(state, input, 40);
    sliscp_light320_swap(state);
    code.exec_permutation(state, 40);
    sliscp_light320_swap(state);
    return !memcmp(output, state, 40);
}
