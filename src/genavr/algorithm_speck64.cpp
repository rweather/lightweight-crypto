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

static void gen_speck64_round
    (Code &code, Reg &x, const Reg &y, const Reg &round,
     const Reg &s, const Reg &l, bool third = false)
{
    // x = (rightRotate8(x) + y) ^ s;
    //
    // We rotate x right by 8 bits by rearranging the registers and then
    // keep that rotation as the new x for the next round.  After 4 rounds,
    // the rotation order will return to the original position.
    //
    // However, we do the rounds in groups of 3 in the calling function so
    // we would get misaligned every 3 rounds without some kind of correction.
    // To correct things we actually rotate x by 8 bits every 3 rounds.
    x = Reg(x, 1, 4);
    code.add(x, y);
    code.logxor(x, s);

    // y = leftRotate3(y) ^ x;
    code.rol(y, 3);
    code.logxor(y, x);

    // Perform the correction on x's rotation position every 3 rounds.
    if (third) {
        code.rol(x, 8);
        x = Reg(x, 1, 4);
    }

    // l_out = (s + rightRotate8(l_in)) ^ round;
    // s = leftRotate3(s) ^ l_out;
    //
    // Note: l_out and l_in occupy the same location.  We replace what
    // used to be l_in with the new value of l_out.
    unsigned char l0 = l.reg(0);
    unsigned char l1 = l.reg(1);
    unsigned char l2 = l.reg(2);
    unsigned char l3 = l.reg(3);
    unsigned char l4 = TEMP_REG;
    code.tworeg(Insn::MOV, l4, l0);
    code.tworeg(Insn::MOV, l0, l1);
    code.tworeg(Insn::ADD, l0, s.reg(0));
    code.tworeg(Insn::MOV, l1, l2);
    code.tworeg(Insn::ADC, l1, s.reg(1));
    code.tworeg(Insn::MOV, l2, l3);
    code.tworeg(Insn::ADC, l2, s.reg(2));
    code.tworeg(Insn::MOV, l3, l4);
    code.tworeg(Insn::ADC, l3, s.reg(3));
    code.logxor(l, round);
    code.rol(s, 3);
    code.logxor(s, l);

    // Increment the round number.
    code.inc(round);
}

/**
 * \brief Generates the AVR code for the SPECK-64-128 block cipher.
 *
 * \param code The code block to generate into.
 */
void gen_speck64_encrypt(Code &code)
{
    // Set up the function prologue with zero bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is reserved.
    code.prologue_encrypt_block("speck64_128_encrypt", 0);

    // Load the key into the key schedule words s, l0, l1, l2.
    Reg s  = code.allocateReg(4);
    Reg l0 = code.allocateReg(4);
    Reg l1 = code.allocateReg(4);
    Reg l2 = code.allocateReg(4);
    code.ldz(s,  0);
    code.ldz(l0, 4);
    code.ldz(l1, 8);
    code.ldz(l2, 12);

    // We can now use Z for temporaries.
    code.setFlag(Code::TempZ);

    // Load the input state.
    Reg x = code.allocateReg(4);
    Reg y = code.allocateReg(4);
    code.ldx(y, POST_INC);
    code.ldx(x, POST_INC);

    // Perform all 27 encryption rounds, 3 at a time.
    Reg round = code.allocateHighReg(1);
    code.move(round, 0);
    unsigned char top_label = 0;
    code.label(top_label);
    gen_speck64_round(code, x, y, round, s, l0);
    gen_speck64_round(code, x, y, round, s, l1);
    gen_speck64_round(code, x, y, round, s, l2, true);
    code.compare_and_loop(round, 27, top_label);

    // Write the state to the output buffer.
    code.load_output_ptr();
    code.stx(y, POST_INC);
    code.stx(x, POST_INC);
}

// Test vector for SPECK-64-128.
static block_cipher_test_vector_t const speck64_128_1 = {
    "Test Vector 1",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF},   /* plaintext */
    {0x71, 0xB0, 0x8A, 0xE3, 0xA2, 0x0A, 0x94, 0x96}    /* ciphertext */
};

bool test_speck64_encrypt(Code &code)
{
    unsigned char output[8];
    code.exec_encrypt_block(speck64_128_1.key, speck64_128_1.key_len,
                            output, 8, speck64_128_1.plaintext, 8);
    return !memcmp(output, speck64_128_1.ciphertext, 8);
}
