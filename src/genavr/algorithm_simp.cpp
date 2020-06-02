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

void gen_simp_256_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg steps = code.prologue_permutation_with_count("simp_256_permute", 0);
    code.setFlag(Code::TempY);

    // Temporary registers.
    Reg t0 = code.allocateReg(8);
    Reg t1 = code.allocateReg(8);

    // Load the round constants into "z".
    Reg z = code.allocateReg(8);
    code.move(z, 0x3369F885192C0EF5ULL);

    // Top of the outer round loop.
    unsigned char top_label1 = 0;
    code.label(top_label1);

    // Top of the inner round loop.
    unsigned char top_label2 = 0;
    Reg round = code.allocateHighReg(1);
    code.move(round, 34 / 2);
    code.label(top_label2);

    // Perform the rounds two at a time.
    // t1 = x3 ^ (leftRotate1_64(x2) & leftRotate8_64(x2)) ^
    //      leftRotate2_64(x2) ^ x1;
    // x3 = t1;
    code.ldz(t0.reversed(), 16); // t0 = x2
    code.move(t1, t0.shuffle(7, 0, 1, 2, 3, 4, 5, 6));
    code.rol(t0, 1);            // t1 = leftRotate1_64(x2) & leftRotate8_64(x2)
    code.logand(t1, t0);
    code.rol(t0, 1);            // t1 ^= leftRotate2_64(x2)
    code.logxor(t1, t0);
    code.ldz_xor(t1.reversed(), 8);     // t1 ^= x1
    code.ldz_xor_in(t1.reversed(), 24); // t1 ^= x3; x3 = t1

    // t0 = x1 ^ rightRotate3_64(x0) ^ rightRotate4_64(x0) ^
    //      0xFFFFFFFFFFFFFFFCULL ^ (z & 1);
    // x1 = t0;
    code.ldz(t0.reversed(), 0); // t0 = rightRotate3_64(x0)
    code.ror(t0, 3);
    code.move(t1, t0);          // t0 ^= rightRotate4_64(64)
    code.ror(t1, 1);
    code.logxor(t0, t1);
    code.logxor(t0, 0xFFFFFFFFFFFFFFFCULL);
    // t0 ^= (z & 1); z = (z >> 1) | (z << 61);
    code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
    code.bit_get(z, 0);
    code.lsr(z, 1);
    code.bit_put(z, 61);
    code.bitop(Insn::BLD, TEMP_REG, 0);
    code.tworeg(Insn::EOR, t0.reg(0), TEMP_REG);
    code.ldz_xor_in(t0.reversed(), 8); // t0 ^= x1; x1 = t0

    // x2 = x2 ^ (leftRotate1_64(t1) & leftRotate8_64(t1)) ^
    //      leftRotate2_64(t1) ^ x0;
    code.ldz(t1.reversed(), 24);        // t1 = x3
    code.move(t0, t1.shuffle(7, 0, 1, 2, 3, 4, 5, 6));
    code.rol(t1, 1);            // t0 = leftRotate1_64(t1) & leftRotate8_64(t1)
    code.logand(t0, t1);
    code.rol(t1, 1);            // t0 ^= leftRotate2_64(t1)
    code.logxor(t0, t1);
    code.ldz_xor(t0.reversed(), 0);     // t0 ^= x0
    code.ldz_xor_in(t0.reversed(), 16); // x2 ^= t0

    // x0 = x0 ^ rightRotate3_64(t0) ^ rightRotate4_64(t0) ^
    //      0xFFFFFFFFFFFFFFFCULL ^ (z & 1);
    code.ldz(t0.reversed(), 8); // t0 = x1
    code.ror(t0, 3);            // t1 = rightRotate3_64(t0)
    code.move(t1, t0);
    code.ror(t0, 1);            // t1 ^= rightRotate4_64(t0)
    code.logxor(t1, t0);
    code.logxor(t1, 0xFFFFFFFFFFFFFFFCULL);
    // t0 ^= (z & 1); z = (z >> 1) | (z << 61);
    code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
    code.bit_get(z, 0);
    code.lsr(z, 1);
    code.bit_put(z, 61);
    code.bitop(Insn::BLD, TEMP_REG, 0);
    code.tworeg(Insn::EOR, t1.reg(0), TEMP_REG);
    code.ldz_xor_in(t1.reversed(), 0); // x0 ^= t1

    // Bottom of the inner round loop.
    code.dec(round);
    code.brne(top_label2);

    // Bottom of the outer round loop.
    unsigned char end_label = 0;
    code.dec(steps);
    code.breq(end_label);
    code.ldz(t0, 0);        // Swap the top and bottom halves of the state.
    code.ldz(t1, 16);
    code.stz(t1, 0);
    code.stz(t0, 16);
    code.ldz(t0, 8);
    code.ldz(t1, 24);
    code.stz(t1, 8);
    code.stz(t0, 24);
    code.jmp(top_label1);
    code.label(end_label);
}

void gen_simp_192_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg steps = code.prologue_permutation_with_count("simp_192_permute", 0);
    code.setFlag(Code::NoLocals);

    // Temporary registers.
    Reg t0 = code.allocateReg(6);
    Reg t1 = code.allocateReg(6);

    // Load the round constants into "z".
    Reg z = code.allocateReg(8);
    code.move(z, 0x3369F885192C0EF5ULL);

    // Top of the outer round loop.
    unsigned char top_label1 = 0;
    code.label(top_label1);

    // Top of the inner round loop.
    unsigned char top_label2 = 0;
    Reg round = code.allocateHighReg(1);
    code.move(round, 26 / 2);
    code.label(top_label2);

    // Perform the rounds two at a time.
    // t1 = x3 ^ (leftRotate1_48(x2) & leftRotate8_48(x2)) ^
    //      leftRotate2_48(x2) ^ x1;
    // x3 = t1;
    code.ldz(t0.reversed(), 12); // t0 = x2
    code.move(t1, t0.shuffle(5, 0, 1, 2, 3, 4));
    code.rol(t0, 1);            // t1 = leftRotate1_48(x2) & leftRotate8_48(x2)
    code.logand(t1, t0);
    code.rol(t0, 1);            // t1 ^= leftRotate2_48(x2)
    code.logxor(t1, t0);
    code.ldz_xor(t1.reversed(), 6);     // t1 ^= x1
    code.ldz_xor_in(t1.reversed(), 18); // t1 ^= x3; x3 = t1

    // t0 = x1 ^ rightRotate3_48(x0) ^ rightRotate4_48(x0) ^
    //      0xFFFFFFFFFFFCULL ^ (z & 1);
    // x1 = t0;
    code.ldz(t0.reversed(), 0); // t0 = rightRotate3_48(x0)
    code.ror(t0, 3);
    code.move(t1, t0);          // t0 ^= rightRotate4_48(64)
    code.ror(t1, 1);
    code.logxor(t0, t1);
    code.logxor(t0, 0xFFFFFFFFFFFCULL);
    // t0 ^= (z & 1); z = (z >> 1) | (z << 61);
    code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
    code.bit_get(z, 0);
    code.lsr(z, 1);
    code.bit_put(z, 61);
    code.bitop(Insn::BLD, TEMP_REG, 0);
    code.tworeg(Insn::EOR, t0.reg(0), TEMP_REG);
    code.ldz_xor_in(t0.reversed(), 6); // t0 ^= x1; x1 = t0

    // x2 = x2 ^ (leftRotate1_48(t1) & leftRotate8_48(t1)) ^
    //      leftRotate2_48(t1) ^ x0;
    code.ldz(t1.reversed(), 18);        // t1 = x3
    code.move(t0, t1.shuffle(5, 0, 1, 2, 3, 4));
    code.rol(t1, 1);            // t0 = leftRotate1_48(t1) & leftRotate8_48(t1)
    code.logand(t0, t1);
    code.rol(t1, 1);            // t0 ^= leftRotate2_48(t1)
    code.logxor(t0, t1);
    code.ldz_xor(t0.reversed(), 0);     // t0 ^= x0
    code.ldz_xor_in(t0.reversed(), 12); // x2 ^= t0

    // x0 = x0 ^ rightRotate3_48(t0) ^ rightRotate4_48(t0) ^
    //      0xFFFFFFFFFFFCULL ^ (z & 1);
    code.ldz(t0.reversed(), 6); // t0 = x1
    code.ror(t0, 3);            // t1 = rightRotate3_48(t0)
    code.move(t1, t0);
    code.ror(t0, 1);            // t1 ^= rightRotate4_48(t0)
    code.logxor(t1, t0);
    code.logxor(t1, 0xFFFFFFFFFFFCULL);
    // t0 ^= (z & 1); z = (z >> 1) | (z << 61);
    code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
    code.bit_get(z, 0);
    code.lsr(z, 1);
    code.bit_put(z, 61);
    code.bitop(Insn::BLD, TEMP_REG, 0);
    code.tworeg(Insn::EOR, t1.reg(0), TEMP_REG);
    code.ldz_xor_in(t1.reversed(), 0); // x0 ^= t1

    // Bottom of the inner round loop.
    code.dec(round);
    code.brne(top_label2);

    // Bottom of the outer round loop.
    unsigned char end_label = 0;
    code.dec(steps);
    code.breq(end_label);
    code.ldz(t0, 0);        // Swap the top and bottom halves of the state.
    code.ldz(t1, 12);
    code.stz(t1, 0);
    code.stz(t0, 12);
    code.ldz(t0, 6);
    code.ldz(t1, 18);
    code.stz(t1, 6);
    code.stz(t0, 18);
    code.jmp(top_label1);
    code.label(end_label);
}

// Test vectors for SimP generated with the Oribatida reference code.
static unsigned char const simp_192_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};
static unsigned char const simp_192_output[] = {
    0xd8, 0x01, 0x34, 0xd1, 0xb6, 0xc1, 0xf9, 0xfc,
    0x05, 0x73, 0xa5, 0x1f, 0x01, 0xfe, 0x06, 0x8b,
    0xa3, 0xd2, 0xf7, 0xd3, 0x61, 0x7b, 0x87, 0x29
};
static unsigned char const simp_256_input[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char const simp_256_output[] = {
    0x5a, 0xb3, 0x47, 0xab, 0x9a, 0x01, 0x6f, 0xe0,
    0x3b, 0xad, 0x26, 0xb4, 0x5b, 0x43, 0xa1, 0xb0,
    0x67, 0x1d, 0xe4, 0x17, 0x6e, 0x2a, 0x33, 0x07,
    0x93, 0x81, 0xae, 0xca, 0xae, 0x63, 0xda, 0x3d
};

bool test_simp_256_permutation(Code &code)
{
    unsigned char state[32];
    memcpy(state, simp_256_input, 32);
    code.exec_permutation(state, 32, 4);
    return !memcmp(simp_256_output, state, 32);
}

bool test_simp_192_permutation(Code &code)
{
    unsigned char state[24];
    memcpy(state, simp_192_input, 24);
    code.exec_permutation(state, 24, 4);
    return !memcmp(simp_192_output, state, 24);
}
