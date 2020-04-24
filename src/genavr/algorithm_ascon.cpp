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

// Offset of a byte in the ASCON state in big-endian byte order.
#define ASCON_BYTE(word, byte) ((word) * 8 + 7 - (byte))

// Offset of a word in the ASCON state.  Points to the high byte.
#define ASCON_WORD(word) ((word) * 8)

static void ascon_substitute
    (Code &code, int offset, const Reg &x2, const Reg &x4)
{
    // Allocate and load the registers for x0, x1, and x3.
    // The x2 and x4 values have already been loaded by the calling function.
    Reg x0 = code.allocateReg(1);
    Reg x1 = code.allocateReg(1);
    Reg x3 = code.allocateReg(1);
    code.ldz(x0, ASCON_BYTE(0, offset));
    code.ldz(x1, ASCON_BYTE(1, offset));
    code.ldz(x3, ASCON_BYTE(3, offset));

    // We need some temporary registers as well.
    Reg t0 = code.allocateReg(1);
    Reg t1 = code.allocateReg(1);
    Reg t2 = code.allocateReg(1);
    Reg t3 = code.allocateReg(1);
    Reg t4 = code.allocateReg(1);

    // x0 ^= x4;   x4 ^= x3;   x2 ^= x1;
    code.logxor(x0, x4);
    code.logxor(x4, x3);
    code.logxor(x2, x1);

    // t0 = ~x0;   t1 = ~x1;   t2 = ~x2;   t3 = ~x3;   t4 = ~x4;
    code.move(t0, x0);
    code.move(t1, x1);
    code.move(t2, x2);
    code.move(t3, x3);
    code.move(t4, x4);
    code.lognot(t0);
    code.lognot(t1);
    code.lognot(t2);
    code.lognot(t3);
    code.lognot(t4);

    // t0 &= x1;   t1 &= x2;   t2 &= x3;   t3 &= x4;   t4 &= x0;
    code.logand(t0, x1);
    code.logand(t1, x2);
    code.logand(t2, x3);
    code.logand(t3, x4);
    code.logand(t4, x0);

    // x0 ^= t1;   x1 ^= t2;   x2 ^= t3;   x3 ^= t4;   x4 ^= t0;
    code.logxor(x0, t1);
    code.logxor(x1, t2);
    code.logxor(x2, t3);
    code.logxor(x3, t4);
    code.logxor(x4, t0);

    // x1 ^= x0;   x0 ^= x4;   x3 ^= x2;   x2 = ~x2;
    code.logxor(x1, x0);
    code.logxor(x0, x4);
    code.logxor(x3, x2);
    code.lognot(x2);

    // Write x0, x1, x3, and x4 back to the state.  We keep x2 in a
    // register in preparation for the diffusion step that follows.
    code.stz(x0, ASCON_BYTE(0, offset));
    code.stz(x1, ASCON_BYTE(1, offset));
    code.stz(x3, ASCON_BYTE(3, offset));
    code.stz(x4, ASCON_BYTE(4, offset));

    // Release all registers except x2 and x4.
    code.releaseReg(x0);
    code.releaseReg(x1);
    code.releaseReg(x3);
    code.releaseReg(t0);
    code.releaseReg(t1);
    code.releaseReg(t2);
    code.releaseReg(t3);
    code.releaseReg(t4);
}

static void ascon_diffuse
    (Code &code, const Reg &x, int word, int shift1, int shift2)
{
    // Compute "x ^= (x >>> shift1) ^ (x >>> shift2)".
    Reg t = code.allocateReg(8);
    if (word != 2)
        code.ldz(x.reversed(), ASCON_WORD(word));
    code.move(t, x);
    code.ror(t, shift1);
    code.logxor(t, x);
    code.ror(x, shift2);
    code.logxor(x, t);
    if (word != 2 && word != 4)
        code.stz(x.reversed(), ASCON_WORD(word));
    code.releaseReg(t);
}

void gen_ascon_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg round = code.prologue_permutation_with_count("ascon_permute", 0);
    code.setFlag(Code::NoLocals); // Don't need Y, so no point creating locals.

    // Compute "round = ((0x0F - round) << 4) | round" to convert the
    // first round number into a round constant.
    Reg temp = code.allocateHighReg(1);
    code.move(temp, 0x0F);
    code.sub(temp, round);
    code.onereg(Insn::SWAP, temp.reg(0));
    code.logor(round, temp);
    code.releaseReg(temp);

    // We keep "x2" and "x4" in registers between rounds so preload them.
    Reg x2 = code.allocateReg(8);
    Reg x4 = code.allocateReg(8);
    code.ldz(x2.reversed(), ASCON_WORD(2));
    code.ldz(x4.reversed(), ASCON_WORD(4));

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // XOR the round constant with the low byte of "x2".
    code.logxor(x2, round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index)
        ascon_substitute(code, index, Reg(x2, index, 1), Reg(x4, index, 1));

    // Perform the linear diffusion layer on each of the state words.
    // We spilled "x4" out to the state during the substitution layer,
    // so we can use that as a temporary register.  We diffuse the "x4"
    // row last so that it is ready in registers for the next round.
    ascon_diffuse(code, x4, 0, 19, 28);
    ascon_diffuse(code, x4, 1, 61, 39);
    ascon_diffuse(code, x2, 2,  1,  6);
    ascon_diffuse(code, x4, 3, 10, 17);
    ascon_diffuse(code, x4, 4,  7, 41);

    // Bottom of the round loop.  Adjust the round constant and
    // check to see if we have reached the final round.
    code.sub(round, 0x0F);
    code.compare_and_loop(round, 0x3C, top_label);

    // Store "x2" and "x4" back to the state memory.
    code.stz(x2.reversed(), ASCON_WORD(2));
    code.stz(x4.reversed(), ASCON_WORD(4));
}

bool test_ascon_permutation(Code &code)
{
    static unsigned char const input[40] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
    };
    static unsigned char const output_12[40] = {
        0x06, 0x05, 0x87, 0xe2, 0xd4, 0x89, 0xdd, 0x43,
        0x1c, 0xc2, 0xb1, 0x7b, 0x0e, 0x3c, 0x17, 0x64,
        0x95, 0x73, 0x42, 0x53, 0x18, 0x44, 0xa6, 0x74,
        0x96, 0xb1, 0x71, 0x75, 0xb4, 0xcb, 0x68, 0x63,
        0x29, 0xb5, 0x12, 0xd6, 0x27, 0xd9, 0x06, 0xe5
    };
    static unsigned char const output_8[40] = {
        0x83, 0x0d, 0x26, 0x0d, 0x33, 0x5f, 0x3b, 0xed,
        0xda, 0x0b, 0xba, 0x91, 0x7b, 0xcf, 0xca, 0xd7,
        0xdd, 0x0d, 0x88, 0xe7, 0xdc, 0xb5, 0xec, 0xd0,
        0x89, 0x2a, 0x02, 0x15, 0x1f, 0x95, 0x94, 0x6e,
        0x3a, 0x69, 0xcb, 0x3c, 0xf9, 0x82, 0xf6, 0xf7
    };
    unsigned char state[40];
    int ok;
    memcpy(state, input, 40);
    code.exec_permutation(state, 40, 0);
    ok = !memcmp(output_12, state, 40);
    memcpy(state, input, 40);
    code.exec_permutation(state, 40, 4);
    return ok && !memcmp(output_8, state, 40);
}
