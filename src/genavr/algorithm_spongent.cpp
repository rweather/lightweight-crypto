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
 * \brief Gets the S-box table to use with Spongent-pi permutations.
 *
 * \return The S-box table.
 */
Sbox get_spongent_sbox()
{
    static unsigned char const sbox[256] = {
        0xee, 0xed, 0xeb, 0xe0, 0xe2, 0xe1, 0xe4, 0xef, 0xe7, 0xea, 0xe8, 0xe5,
        0xe9, 0xec, 0xe3, 0xe6, 0xde, 0xdd, 0xdb, 0xd0, 0xd2, 0xd1, 0xd4, 0xdf,
        0xd7, 0xda, 0xd8, 0xd5, 0xd9, 0xdc, 0xd3, 0xd6, 0xbe, 0xbd, 0xbb, 0xb0,
        0xb2, 0xb1, 0xb4, 0xbf, 0xb7, 0xba, 0xb8, 0xb5, 0xb9, 0xbc, 0xb3, 0xb6,
        0x0e, 0x0d, 0x0b, 0x00, 0x02, 0x01, 0x04, 0x0f, 0x07, 0x0a, 0x08, 0x05,
        0x09, 0x0c, 0x03, 0x06, 0x2e, 0x2d, 0x2b, 0x20, 0x22, 0x21, 0x24, 0x2f,
        0x27, 0x2a, 0x28, 0x25, 0x29, 0x2c, 0x23, 0x26, 0x1e, 0x1d, 0x1b, 0x10,
        0x12, 0x11, 0x14, 0x1f, 0x17, 0x1a, 0x18, 0x15, 0x19, 0x1c, 0x13, 0x16, 
        0x4e, 0x4d, 0x4b, 0x40, 0x42, 0x41, 0x44, 0x4f, 0x47, 0x4a, 0x48, 0x45,
        0x49, 0x4c, 0x43, 0x46, 0xfe, 0xfd, 0xfb, 0xf0, 0xf2, 0xf1, 0xf4, 0xff,
        0xf7, 0xfa, 0xf8, 0xf5, 0xf9, 0xfc, 0xf3, 0xf6, 0x7e, 0x7d, 0x7b, 0x70,
        0x72, 0x71, 0x74, 0x7f, 0x77, 0x7a, 0x78, 0x75, 0x79, 0x7c, 0x73, 0x76, 
        0xae, 0xad, 0xab, 0xa0, 0xa2, 0xa1, 0xa4, 0xaf, 0xa7, 0xaa, 0xa8, 0xa5,
        0xa9, 0xac, 0xa3, 0xa6, 0x8e, 0x8d, 0x8b, 0x80, 0x82, 0x81, 0x84, 0x8f,
        0x87, 0x8a, 0x88, 0x85, 0x89, 0x8c, 0x83, 0x86, 0x5e, 0x5d, 0x5b, 0x50,
        0x52, 0x51, 0x54, 0x5f, 0x57, 0x5a, 0x58, 0x55, 0x59, 0x5c, 0x53, 0x56, 
        0x9e, 0x9d, 0x9b, 0x90, 0x92, 0x91, 0x94, 0x9f, 0x97, 0x9a, 0x98, 0x95,
        0x99, 0x9c, 0x93, 0x96, 0xce, 0xcd, 0xcb, 0xc0, 0xc2, 0xc1, 0xc4, 0xcf,
        0xc7, 0xca, 0xc8, 0xc5, 0xc9, 0xcc, 0xc3, 0xc6, 0x3e, 0x3d, 0x3b, 0x30,
        0x32, 0x31, 0x34, 0x3f, 0x37, 0x3a, 0x38, 0x35, 0x39, 0x3c, 0x33, 0x36, 
        0x6e, 0x6d, 0x6b, 0x60, 0x62, 0x61, 0x64, 0x6f, 0x67, 0x6a, 0x68, 0x65,
        0x69, 0x6c, 0x63, 0x66 
    };
    return Sbox(sbox, sizeof(sbox));
}

// Update the LFSR's for the round constants rc0 and rc1.
// We could use a table for this but it is annoying to switch Z
// back and forth between the S-box table and the RC table.
static void spongent_update_lfsr(Code &code, const Reg &rc0, const Reg &rc1)
{
    // rc0 = (rc0 << 1) ^ ((rc0 & 0x40) >> 6) ^ ((rc0 & 0x20) >> 5);
    // rc0 &= 0x7F;
    code.lsl(rc0, 1);
    code.bit_get(rc0, 7);
    code.bit_put(rc0, 0);
    code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
    code.bit_get(rc0, 6);
    code.bitop(Insn::BLD, TEMP_REG, 0);
    code.tworeg(Insn::EOR, rc0.reg(0), TEMP_REG);
    code.logand(rc0, 0x7F);

    // rc1 = (rc1 >> 1) ^ ((rc1 & 0x02) << 6) ^ ((rc1 & 0x04) << 5);
    // rc1 &= 0xFE;
    code.lsr(rc1, 1);
    code.bit_get(rc1, 0);
    code.bit_put(rc1, 7);
    code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
    code.bit_get(rc1, 1);
    code.bitop(Insn::BLD, TEMP_REG, 7);
    code.tworeg(Insn::EOR, rc1.reg(0), TEMP_REG);
    code.logand(rc1, 0xFE);
}

/**
 * \brief Generates the AVR code for the Spongent-pi[160] permutation.
 *
 * \param code The code block to generate into.
 */
void gen_spongent160_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output but we also
    // need to use Z for S-box lookups.
    code.prologue_permutation("spongent160_permute", 0);
    code.setFlag(Code::TempY);
    code.clearFlag(Code::TempX);

    // We will need some high registers later for round counters and constants.
    Reg round = code.allocateHighReg(1);
    Reg rc0 = code.allocateHighReg(1);
    Reg rc1 = code.allocateHighReg(1);

    // Allocate 20 bytes for the core state and load it from Z.
    Reg S = code.allocateReg(20);
    code.ldz(S, 0);

    // Copy Z to the X register and then set up the S-box pointer in Z.
    code.move(Reg::x_ptr(), Reg::z_ptr());
    code.sbox_setup(0, get_spongent_sbox());

    // Perform all 80 rounds of Spongent-pi[160].  Top of the loop.
    unsigned char top_label = 0;
    code.move(round, 80);
    code.move(rc0, 0x75);
    code.move(rc1, 0xAE);
    code.label(top_label);

    // Add the round constants to the front and back of the state and update.
    code.logxor(Reg(S, 0, 1), rc0);
    code.logxor(Reg(S, 19, 1), rc1);
    spongent_update_lfsr(code, rc0, rc1);

    // Apply the S-box to every byte in the state.
    code.sbox_lookup(S, S);

    // Permute the bits of the state.  Bit i is moved to (40 * i) % 159
    // for all bits except the last which is left where it is.
    // The permutation is annoying: the most efficient method is to
    // move all of the bits one at a time to their destination.
    unsigned char perm[160];
    for (int i = 0; i < 159; ++i)
        perm[i] = (40 * i) % 159;
    perm[159] = 159;
    code.bit_permute(S, perm, 160);

    // Bottom of the round loop.
    code.dec(round);
    code.brne(top_label);

    // Restore RAMPZ from the stack and then store the state back to X.
    code.sbox_cleanup();
    code.stx(S, POST_INC);
}

/**
 * \brief Generates the AVR code for the Spongent-pi[176] permutation.
 *
 * \param code The code block to generate into.
 */
void gen_spongent176_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output but we also
    // need to use Z for S-box lookups.
    code.prologue_permutation("spongent176_permute", 0);
    code.setFlag(Code::TempY);
    code.clearFlag(Code::TempX);

    // We will need some high registers later for round counters and constants.
    Reg round = code.allocateHighReg(1);
    Reg rc0 = code.allocateHighReg(1);
    Reg rc1 = code.allocateHighReg(1);

    // Allocate 22 bytes for the core state and load it from Z.
    Reg S = code.allocateReg(22);
    code.ldz(S, 0);

    // Copy Z to the X register and then set up the S-box pointer in Z.
    code.move(Reg::x_ptr(), Reg::z_ptr());
    code.sbox_setup(0, get_spongent_sbox());

    // Perform all 90 rounds of Spongent-pi[160].  Top of the loop.
    unsigned char top_label = 0;
    code.move(round, 90);
    code.move(rc0, 0x45);
    code.move(rc1, 0xA2);
    code.label(top_label);

    // Add the round constants to the front and back of the state and update.
    code.logxor(Reg(S, 0, 1), rc0);
    code.logxor(Reg(S, 21, 1), rc1);
    spongent_update_lfsr(code, rc0, rc1);

    // Apply the S-box to every byte in the state.
    code.sbox_lookup(S, S);

    // Permute the bits of the state.  Bit i is moved to (44 * i) % 175
    // for all bits except the last which is left where it is.
    // The permutation is annoying: the most efficient method is to
    // move all of the bits one at a time to their destination.
    unsigned char perm[176];
    for (int i = 0; i < 175; ++i)
        perm[i] = (44 * i) % 175;
    perm[175] = 175;
    code.bit_permute(S, perm, 175);

    // Bottom of the round loop.
    code.dec(round);
    code.brne(top_label);

    // Restore RAMPZ from the stack and then store the state back to X.
    code.sbox_cleanup();
    code.stx(S, POST_INC);
}

bool test_spongent160_permutation(Code &code)
{
    static unsigned char const input[20] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13
    };
    static unsigned char const output[20] = {
        0x7c, 0x80, 0x0e, 0xdf, 0x9a, 0x56, 0x0d, 0xf7,
        0xcc, 0x19, 0xf1, 0xa2, 0x26, 0x2c, 0x7d, 0x73,
        0x26, 0x7b, 0xf7, 0x7b
    };
    unsigned char state[20];
    memcpy(state, input, 20);
    code.exec_permutation(state, 20);
    return !memcmp(output, state, 20);
}

bool test_spongent176_permutation(Code &code)
{
    static unsigned char const input[22] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15
    };
    static unsigned char const output[22] = {
        0xd2, 0x69, 0x76, 0xeb, 0x35, 0x34, 0xb5, 0x85,
        0xcd, 0xd0, 0x61, 0xe7, 0xc6, 0xe4, 0x9b, 0x5b,
        0xee, 0xd9, 0xe8, 0xd8, 0x66, 0x26
    };
    unsigned char state[22];
    memcpy(state, input, 22);
    code.exec_permutation(state, 22);
    return !memcmp(output, state, 22);
}
