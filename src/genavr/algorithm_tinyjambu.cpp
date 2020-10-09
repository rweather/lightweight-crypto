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

static void shift_left_4regs
    (Code &code, unsigned char r0, unsigned char r1,
     unsigned char r2, unsigned char r3)
{
    code.onereg(Insn::LSL, r0);
    code.onereg(Insn::ROL, r1);
    code.onereg(Insn::ROL, r2);
    code.onereg(Insn::ROL, r3);
}

static void shift_left_5regs
    (Code &code, unsigned char r0, unsigned char r1,
     unsigned char r2, unsigned char r3, unsigned char r4)
{
    code.onereg(Insn::LSL, r0);
    code.onereg(Insn::ROL, r1);
    code.onereg(Insn::ROL, r2);
    code.onereg(Insn::ROL, r3);
    code.onereg(Insn::ROL, r4);
}

static void gen_tinyjambu_steps_32
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3,
     int koffset)
{
    // Allocate some temporary working registers.  After the allocations
    // in the gen_tinyjambu_permutation() function we have 7 left spare.
    Reg temp = code.allocateReg(7);
    Reg t = Reg(temp, 0, 4);
    Reg u = Reg(temp, 4, 3);

    // t1 = (s1 >> 15) | (s2 << 17);
    // s0 ^= t1;
    code.move(Reg(temp, 2, 2), Reg(s1, 2, 2));
    code.move(Reg(temp, 4, 2), Reg(s2, 0, 2));
    code.move(Reg(temp, 1, 1), Reg(s1, 1, 1));
    code.lsl(Reg(temp, 1, 5), 1);
    code.logxor(s0, Reg(temp, 2, 4));

    // t2 = (s2 >> 6)  | (s3 << 26);
    // t3 = (s2 >> 21) | (s3 << 11);
    // s0 ^= ~(t2 & t3);
    code.move(Reg(t, 0, 3), Reg(s2, 1, 3));
    code.move(Reg(t, 3, 1), Reg(s3, 0, 1));
    code.tworeg(Insn::MOV, TEMP_REG, s2.reg(0));
    shift_left_5regs(code, TEMP_REG, t.reg(0), t.reg(1), t.reg(2), t.reg(3));
    shift_left_5regs(code, TEMP_REG, t.reg(0), t.reg(1), t.reg(2), t.reg(3));
    // Getting low on registers, so divide t3 into two parts,
    // then AND the parts into t2 one at a time.
    code.move(Reg(u, 0, 1), Reg(s2, 3, 1));
    code.tworeg(Insn::MOV, TEMP_REG, s2.reg(2));
    code.move(Reg(u, 1, 2), Reg(s3, 0, 2));
    shift_left_4regs(code, TEMP_REG, u.reg(0), u.reg(1), u.reg(2));
    shift_left_4regs(code, TEMP_REG, u.reg(0), u.reg(1), u.reg(2));
    shift_left_4regs(code, TEMP_REG, u.reg(0), u.reg(1), u.reg(2));
    code.logand(Reg(t, 0, 3), u);
    code.move(Reg(u, 0, 2), Reg(s3, 1, 2));
    code.lsl(Reg(u, 0, 2), 3);
    code.logand(Reg(t, 3, 1), Reg(u, 1, 1));
    code.lognot(t);
    code.logxor(s0, t);

    // t4 = (s2 >> 27) | (s3 << 5);
    // s0 ^= t4;
    code.move(Reg(temp, 2, 4), s3);
    code.move(Reg(temp, 1, 1), Reg(s2, 3, 1));
    code.lsr(Reg(temp, 1, 5), 3);
    code.logxor(s0, Reg(temp, 1, 4));

    // s0 ^= k[koffset];
    code.ldz_xor(s0, koffset * 4);

    // Release the temporary working registers.
    code.releaseReg(temp);
}

/**
 * \brief Generates the AVR code for the TinyJAMBU permutation.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param key_words Number of words in the key: 4, 6, or 8.
 */
static void gen_tinyjambu_permutation
    (Code &code, const char *name, int key_words)
{
    // Set up the function prologue.  X points to the state and Z to the key.
    Reg rounds;
    code.prologue_tinyjambu(name, rounds);
    code.setFlag(Code::NoLocals);

    // Load the 128-bit state from X into registers.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);
    code.ldx(s0, POST_INC);
    code.ldx(s1, POST_INC);
    code.ldx(s2, POST_INC);
    code.ldx(s3, POST_INC);

    // Perform all permutation rounds.  Each round has 128 steps
    // but it may be unrolled 2 or 3 times based on the key size.
    unsigned char top_label = 0;
    unsigned char end_label = 0;
    code.label(top_label);

    // Unroll the inner part of the loop.
    int inner_rounds;
    if (key_words == 4)
        inner_rounds = 1;
    else if (key_words == 6)
        inner_rounds = 3;
    else
        inner_rounds = 2;
    for (int inner = 0; inner < inner_rounds; ++inner) {
        // Perform the 128 steps of this inner round, 32 at a time.
        int koffset = inner * 4;
        gen_tinyjambu_steps_32(code, s0, s1, s2, s3, koffset % key_words);
        gen_tinyjambu_steps_32(code, s1, s2, s3, s0, (koffset + 1) % key_words);
        gen_tinyjambu_steps_32(code, s2, s3, s0, s1, (koffset + 2) % key_words);
        gen_tinyjambu_steps_32(code, s3, s0, s1, s2, (koffset + 3) % key_words);

        // Check for early bail-out between the inner rounds.
        if (inner < (inner_rounds - 1)) {
            code.dec(rounds);
            code.breq(end_label);
        }
    }

    // Decrement the round counter at the bottom of the round loop.
    code.dec(rounds);
    code.brne(top_label);

    // Store the 128-bit state in the registers back to X.
    code.label(end_label);
    code.stx(s3, PRE_DEC);
    code.stx(s2, PRE_DEC);
    code.stx(s1, PRE_DEC);
    code.stx(s0, PRE_DEC);
}

/**
 * \brief Generates the AVR code for the TinyJAMBU-128 permutation.
 *
 * \param code The code block to generate into.
 */
void gen_tinyjambu128_permutation(Code &code)
{
    gen_tinyjambu_permutation(code, "tiny_jambu_permutation_128", 4);
}

/**
 * \brief Generates the AVR code for the TinyJAMBU-192 permutation.
 *
 * \param code The code block to generate into.
 */
void gen_tinyjambu192_permutation(Code &code)
{
    gen_tinyjambu_permutation(code, "tiny_jambu_permutation_192", 6);
}

/**
 * \brief Generates the AVR code for the TinyJAMBU-256 permutation.
 *
 * \param code The code block to generate into.
 */
void gen_tinyjambu256_permutation(Code &code)
{
    gen_tinyjambu_permutation(code, "tiny_jambu_permutation_256", 8);
}

bool test_tinyjambu128_permutation(Code &code)
{
    static unsigned char const input[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static unsigned char const key[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    static unsigned char const output[16] = {
        0x75, 0x5b, 0x02, 0xd9, 0x11, 0xc7, 0xa7, 0xde,
        0x5c, 0xfe, 0x2b, 0xc4, 0x16, 0x50, 0x1e, 0x36
    };
    unsigned char state[16];
    memcpy(state, input, 16);
    code.exec_tinyjambu(state, 16, key, 16, 1024);
    return !memcmp(output, state, 16);
}

bool test_tinyjambu192_permutation(Code &code)
{
    static unsigned char const input[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static unsigned char const key[24] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xa5, 0xb4, 0x87, 0x96, 0xe1, 0xf0, 0xc3, 0xd2
    };
    static unsigned char const output[16] = {
        0xda, 0xd4, 0x03, 0xeb, 0x42, 0x43, 0x89, 0x14,
        0x4d, 0xba, 0xd7, 0xb0, 0xa6, 0x53, 0x5b, 0x02
    };
    unsigned char state[16];
    memcpy(state, input, 16);
    code.exec_tinyjambu(state, 16, key, 24, 1152);
    return !memcmp(output, state, 16);
}

bool test_tinyjambu256_permutation(Code &code)
{
    static unsigned char const input[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    static unsigned char const key[32] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0xa5, 0xb4, 0x87, 0x96, 0xe1, 0xf0, 0xc3, 0xd2,
        0x2d, 0x3c, 0x0f, 0x1e, 0x69, 0x78, 0x4b, 0x5a
    };
    static unsigned char const output[16] = {
        0x53, 0xf2, 0x66, 0xf0, 0xed, 0x13, 0xcf, 0xa8,
        0xb9, 0x2e, 0x6f, 0xd4, 0x4a, 0x5e, 0x4c, 0xbd
    };
    unsigned char state[16];
    memcpy(state, input, 16);
    code.exec_tinyjambu(state, 16, key, 32, 1280);
    return !memcmp(output, state, 16);
}
