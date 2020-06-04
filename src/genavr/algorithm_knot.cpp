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

// Round constants for the KNOT-256, KNOT-384, and KNOT-512 permutations.
static uint8_t const rc6[52] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x21, 0x03, 0x06, 0x0c, 0x18, 0x31, 0x22,
    0x05, 0x0a, 0x14, 0x29, 0x13, 0x27, 0x0f, 0x1e, 0x3d, 0x3a, 0x34, 0x28,
    0x11, 0x23, 0x07, 0x0e, 0x1c, 0x39, 0x32, 0x24, 0x09, 0x12, 0x25, 0x0b,
    0x16, 0x2d, 0x1b, 0x37, 0x2e, 0x1d, 0x3b, 0x36, 0x2c, 0x19, 0x33, 0x26,
    0x0d, 0x1a, 0x35, 0x2a
};
static uint8_t const rc7[104] = {
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x41, 0x03, 0x06, 0x0c, 0x18, 0x30,
    0x61, 0x42, 0x05, 0x0a, 0x14, 0x28, 0x51, 0x23, 0x47, 0x0f, 0x1e, 0x3c,
    0x79, 0x72, 0x64, 0x48, 0x11, 0x22, 0x45, 0x0b, 0x16, 0x2c, 0x59, 0x33,
    0x67, 0x4e, 0x1d, 0x3a, 0x75, 0x6a, 0x54, 0x29, 0x53, 0x27, 0x4f, 0x1f,
    0x3e, 0x7d, 0x7a, 0x74, 0x68, 0x50, 0x21, 0x43, 0x07, 0x0e, 0x1c, 0x38,
    0x71, 0x62, 0x44, 0x09, 0x12, 0x24, 0x49, 0x13, 0x26, 0x4d, 0x1b, 0x36,
    0x6d, 0x5a, 0x35, 0x6b, 0x56, 0x2d, 0x5b, 0x37, 0x6f, 0x5e, 0x3d, 0x7b,
    0x76, 0x6c, 0x58, 0x31, 0x63, 0x46, 0x0d, 0x1a, 0x34, 0x69, 0x52, 0x25,
    0x4b, 0x17, 0x2e, 0x5d, 0x3b, 0x77, 0x6e, 0x5c
};
static uint8_t const rc8[140] = {
    0x01, 0x02, 0x04, 0x08, 0x11, 0x23, 0x47, 0x8e, 0x1c, 0x38, 0x71, 0xe2,
    0xc4, 0x89, 0x12, 0x25, 0x4b, 0x97, 0x2e, 0x5c, 0xb8, 0x70, 0xe0, 0xc0,
    0x81, 0x03, 0x06, 0x0c, 0x19, 0x32, 0x64, 0xc9, 0x92, 0x24, 0x49, 0x93,
    0x26, 0x4d, 0x9b, 0x37, 0x6e, 0xdc, 0xb9, 0x72, 0xe4, 0xc8, 0x90, 0x20,
    0x41, 0x82, 0x05, 0x0a, 0x15, 0x2b, 0x56, 0xad, 0x5b, 0xb6, 0x6d, 0xda,
    0xb5, 0x6b, 0xd6, 0xac, 0x59, 0xb2, 0x65, 0xcb, 0x96, 0x2c, 0x58, 0xb0,
    0x61, 0xc3, 0x87, 0x0f, 0x1f, 0x3e, 0x7d, 0xfb, 0xf6, 0xed, 0xdb, 0xb7,
    0x6f, 0xde, 0xbd, 0x7a, 0xf5, 0xeb, 0xd7, 0xae, 0x5d, 0xba, 0x74, 0xe8,
    0xd1, 0xa2, 0x44, 0x88, 0x10, 0x21, 0x43, 0x86, 0x0d, 0x1b, 0x36, 0x6c,
    0xd8, 0xb1, 0x63, 0xc7, 0x8f, 0x1e, 0x3c, 0x79, 0xf3, 0xe7, 0xce, 0x9c,
    0x39, 0x73, 0xe6, 0xcc, 0x98, 0x31, 0x62, 0xc5, 0x8b, 0x16, 0x2d, 0x5a,
    0xb4, 0x69, 0xd2, 0xa4, 0x48, 0x91, 0x22, 0x45
};

Sbox get_knot_round_constants(int rc_bits)
{
    if (rc_bits == 6)
        return Sbox(rc6, sizeof(rc6));
    else if (rc_bits == 7)
        return Sbox(rc7, sizeof(rc7));
    else
        return Sbox(rc8, sizeof(rc8));
}

/**
 * \brief Generates the KNOT permutation for AVR.
 *
 * \param code Code object to generate into.
 * \param name Name of the function to generate.
 * \param rc_bits Number of bits for the round constant table: 6, 7, or 8.
 * \param row_size Size of each row in bytes.
 * \param shift_row2 Shift count for row 2 in the linear diffusion layer.
 * \param shift_row3 Shift count for row 3 in the linear diffusion layer.
 */
static void gen_knot_permutation
    (Code &code, const char *name, int rc_bits,
     int row_size, int shift_row2, int shift_row3)
{
    int index;

    // Macros to help find the start of a row or a particular row byte.
    #define ROW(row) \
        (row_size == 8 ? (((row) - 1) * row_size) : ((row) * row_size))
    #define ROW_BYTE(row, index) (ROW((row)) + (index))

    // Set up the function prologue with 6 rows of local variable space.
    Reg rounds = code.prologue_permutation_with_count(name, ROW(6));

    // Create the temporary registers that we will need later.
    Reg a0_word;
    if (row_size == 8) {
        // KNOT-256 has enough spare AVR registers that we can hold one
        // of the rows in registers continuously rather than on the stack.
        a0_word = code.allocateReg(row_size);
    }
    Reg a1 = code.allocateReg(1);
    Reg a2 = code.allocateReg(1);
    Reg a3 = code.allocateReg(1);
    Reg b1 = code.allocateReg(1);
    Reg b2_word = code.allocateReg(row_size);
    Reg b3 = code.allocateReg(1);
    Reg t1 = code.allocateReg(1);
    Reg t3 = code.allocateReg(1);
    Reg t6 = code.allocateReg(1);

    // Copy the permutation state to the stack because we need Z
    // to point at the round constant table.
    if (row_size == 8) {
        code.ldz(a0_word, 0);
    } else {
        code.ldz(b2_word, 0);
        code.stlocal(b2_word, ROW(0));
    }
    code.ldz(b2_word, row_size);
    code.stlocal(b2_word, ROW(1));
    code.ldz(b2_word, row_size * 2);
    code.stlocal(b2_word, ROW(2));
    code.ldz(b2_word, row_size * 3);
    code.stlocal(b2_word, ROW(3));

    // Save Z on the stack and then point it at the round constant table.
    code.push(Reg::z_ptr());
    code.sbox_setup(rc_bits, get_knot_round_constants(rc_bits));

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // Add the round constant to the low byte of the first word in the state.
    if (row_size == 8) {
        code.sbox_lookup(a1, Reg(Reg::z_ptr(), 0, 1));
        code.logxor(Reg(a0_word, 0, 1), a1);
        code.inc(Reg(Reg::z_ptr(), 0, 1));
    } else {
        code.ldlocal(t1, ROW_BYTE(0, 0));
        code.sbox_lookup(a1, Reg(Reg::z_ptr(), 0, 1));
        code.logxor(t1, a1);
        code.inc(Reg(Reg::z_ptr(), 0, 1));
    }

    // Substitution layer, performed byte by byte to reduce the number
    // of registers that we need to have active at once.  At the end of
    // this the "b1" value and "b3" values are on the stack and the
    // "b2" value is in a register ready for the linear diffusion layer.
    for (index = 0; index < row_size; ++index) {
        Reg b2 = Reg(b2_word, index, 1);

        // Load the row bytes into registers; a0 is already in a register.
        code.ldlocal(a1, ROW_BYTE(1, index));
        code.ldlocal(a2, ROW_BYTE(2, index));
        code.ldlocal(a3, ROW_BYTE(3, index));

        // t1 = ~(a0);
        if (row_size == 8)
            code.move(t1, Reg(a0_word, index, 1));
        code.lognot(t1);

        // t3 = (a2) ^ ((a1) & t1);
        code.move(t3, a1);
        code.logand(t3, t1);
        code.logxor(t3, a2);

        // (b3) = (a3) ^ t3;
        code.move(b3, a3);
        code.logxor(b3, t3);
        code.stlocal(b3, ROW_BYTE(5, index));

        // t6 = (a3) ^ t1;
        code.move(t6, a3);
        code.logxor(t6, t1);

        // (b2) = ((a1) | (a2)) ^ t6;
        code.move(b2, a1);
        code.logor(b2, a2);
        code.logxor(b2, t6);

        // t1 = (a1) ^ (a3);
        code.move(t1, a1);
        code.logxor(t1, a3);

        // (a0) = t1 ^ (t3 & t6);
        if (row_size == 8) {
            Reg a0 = Reg(a0_word, index, 1);
            code.move(a0, t3);
            code.logand(a0, t6);
            code.logxor(a0, t1);
        } else {
            code.move(b1, t3);
            code.logand(b1, t6);
            code.logxor(b1, t1);
            code.stlocal(b1, ROW_BYTE(0, index));
        }

        // (b1) = t3 ^ ((b2) & t1);
        code.move(b1, b2);
        code.logand(b1, t1);
        code.logxor(b1, t3);
        code.stlocal(b1, ROW_BYTE(4, index));

        // Load the a0 value for the next iteration.
        if (index != (row_size - 1) && row_size != 8)
            code.ldlocal(t1, ROW_BYTE(0, index + 1));
    }

    // Linear diffusion layer.  Row 2 is rotated left by 8 or 16
    // which can be done with a simple byte shuffle.
    unsigned char pattern[row_size];
    for (index = 0; index < row_size; ++index)
        pattern[index] = (index + row_size - shift_row2 / 8) % row_size;
    code.stlocal(b2_word.shuffle(pattern), ROW(2));

    // Row 1 is always rotated left by 1 bit.
    code.ldlocal(b2_word, ROW(4));
    code.rol(b2_word, 1);
    code.stlocal(b2_word, ROW(1));

    // Row 3 is rotated left by either 25 or 55.  Both of these can
    // be decomposed into a rotation by 1 bit followed by a byte shuffle.
    code.ldlocal(b2_word, ROW(5));
    if (shift_row3 == 25) {
        code.rol(b2_word, 1);
        --shift_row3;
    } else {
        code.ror(b2_word, 1);
        ++shift_row3;
    }
    for (index = 0; index < row_size; ++index)
        pattern[index] = (index + row_size - shift_row3 / 8) % row_size;
    code.stlocal(b2_word.shuffle(pattern), ROW(3));

    // Bottom of the round loop.
    code.dec(rounds);
    code.brne(top_label);

    // Restore Z and copy the permutation state from the stack back to memory.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    if (row_size == 8) {
        code.stz(a0_word, 0);
    } else {
        code.ldlocal(b2_word, ROW(0));
        code.stz(b2_word, 0);
    }
    code.ldlocal(b2_word, ROW(1));
    code.stz(b2_word, row_size);
    code.ldlocal(b2_word, ROW(2));
    code.stz(b2_word, row_size * 2);
    code.ldlocal(b2_word, ROW(3));
    code.stz(b2_word, row_size * 3);
}

void gen_knot256_permutation(Code &code, int rc_bits)
{
    if (rc_bits == 6)
        gen_knot_permutation(code, "knot256_permute_6", rc_bits, 8, 8, 25);
    else if (rc_bits == 7)
        gen_knot_permutation(code, "knot256_permute_7", rc_bits, 8, 8, 25);
    else if (rc_bits == 8)
        gen_knot_permutation(code, "knot256_permute_8", rc_bits, 8, 8, 25);
}

void gen_knot384_permutation(Code &code, int rc_bits)
{
    if (rc_bits == 6)
        gen_knot_permutation(code, "knot384_permute_6", rc_bits, 12, 8, 55);
    else if (rc_bits == 7)
        gen_knot_permutation(code, "knot384_permute_7", rc_bits, 12, 8, 55);
    else
        gen_knot_permutation(code, "knot384_permute_8", rc_bits, 12, 8, 55);
}

void gen_knot512_permutation(Code &code, int rc_bits)
{
    if (rc_bits == 6)
        gen_knot_permutation(code, "knot512_permute_6", rc_bits, 16, 16, 25);
    else if (rc_bits == 7)
        gen_knot_permutation(code, "knot512_permute_7", rc_bits, 16, 16, 25);
    else
        gen_knot_permutation(code, "knot512_permute_8", rc_bits, 16, 16, 25);
}

// KNOT permutation test vectors generated with the reference implementation.
#define knot256_rounds 52
static unsigned char knot256_in[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char knot256_out[32] = {
    0x0c, 0x86, 0x01, 0xe9, 0x7f, 0x59, 0x30, 0xfd,
    0xe2, 0x3c, 0x45, 0xa6, 0x03, 0x05, 0x7f, 0x85,
    0x0e, 0xa5, 0x6d, 0x6e, 0xc5, 0x84, 0x67, 0xd3,
    0xa4, 0x25, 0xe7, 0x35, 0xa3, 0x85, 0x66, 0x09
};
#define knot384_rounds 76
static unsigned char knot384_in[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static unsigned char knot384_out[48] = {
    0xca, 0x10, 0x72, 0x70, 0xbd, 0x88, 0x9f, 0xa0,
    0x89, 0xd2, 0xd1, 0x09, 0xf7, 0x65, 0x8e, 0xe1,
    0x0d, 0x2a, 0xd7, 0xc8, 0x79, 0x4f, 0x59, 0xb9,
    0x16, 0x87, 0x64, 0xba, 0x1a, 0xed, 0x86, 0x83,
    0xf2, 0x9b, 0x82, 0x80, 0x9e, 0x83, 0x2e, 0xf2,
    0xca, 0x1c, 0x93, 0xe9, 0xf6, 0xf7, 0x52, 0x40
};
#define knot512_rounds 140
static unsigned char knot512_in[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
};
static unsigned char knot512_out[64] = {
    0x03, 0xbb, 0x5f, 0x54, 0xea, 0x9b, 0x15, 0x76,
    0xef, 0x12, 0xdd, 0x18, 0x52, 0x1a, 0x9d, 0x89,
    0xd6, 0x5d, 0xd3, 0x7d, 0xec, 0xb7, 0x47, 0xc7,
    0x4a, 0x67, 0xfe, 0x31, 0x13, 0x9d, 0x0c, 0x54,
    0x00, 0x72, 0x4e, 0xba, 0x05, 0x34, 0x3b, 0x3f,
    0x1e, 0xb2, 0x79, 0x66, 0x73, 0x33, 0x32, 0x35,
    0x8a, 0x61, 0xba, 0xd9, 0x62, 0x72, 0xf9, 0xb7,
    0xb3, 0x43, 0xdd, 0xc7, 0x66, 0x59, 0xee, 0x7d
};

bool test_knot256_permutation(Code &code, int rc_bits)
{
    if (rc_bits != 6)
        return false;
    unsigned char state[32];
    memcpy(state, knot256_in, 32);
    code.exec_permutation(state, 32, knot256_rounds);
    return !memcmp(knot256_out, state, 32);
}

bool test_knot384_permutation(Code &code, int rc_bits)
{
    if (rc_bits != 7)
        return false;
    unsigned char state[48];
    memcpy(state, knot384_in, 48);
    code.exec_permutation(state, 48, knot384_rounds);
    return !memcmp(knot384_out, state, 48);
}

bool test_knot512_permutation(Code &code, int rc_bits)
{
    if (rc_bits != 8)
        return false;
    unsigned char state[64];
    memcpy(state, knot512_in, 64);
    code.exec_permutation(state, 64, knot512_rounds);
    return !memcmp(knot512_out, state, 64);
}
