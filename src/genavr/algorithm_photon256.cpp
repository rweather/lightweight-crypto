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

// Number of rounds in the PHOTON-256 permutation in bit-sliced form.
#define PHOTON256_ROUNDS 12

// Round constants for PHOTON-256.
static uint32_t const photon256_rc[PHOTON256_ROUNDS] = {
    0x96d2f0e1, 0xb4f0d2c3, 0xf0b49687, 0x692d0f1e,
    0x5a1e3c2d, 0x3c785a4b, 0xe1a58796, 0x4b0f2d3c,
    0x1e5a7869, 0xa5e1c3d2, 0xd296b4a5, 0x2d694b5a
};

// GF(^4) matrix to multiply by to mix the columns.
static unsigned char photon256_mix_matrix[8][8] = {
    { 2,  4,  2, 11,  2,  8,  5,  6},
    {12,  9,  8, 13,  7,  7,  5,  2},
    { 4,  4, 13, 13,  9,  4, 13,  9},
    { 1,  6,  5,  1, 12, 13, 15, 14},
    {15, 12,  9, 13, 14,  5, 14, 13},
    { 9, 14,  5, 15,  4, 12,  9,  6},
    {12,  2,  2, 10,  3,  1,  1, 14},
    {15,  1, 13, 10,  5, 10,  2,  3}
};

// Loads a 128-bit value and converts it into bit-sliced form.
static void photon256_to_sliced_128
    (Code &code, int offset, const Reg &s0, const Reg &s1,
     const Reg &s2, const Reg &s3, const Reg &t0)
{
    int word, bit;
    for (word = 0; word < 4; ++word) {
        code.ldz(t0, offset + word * 4);
        for (bit = 0; bit < 32; ++bit) {
            Reg dst;
            switch (bit % 4) {
            case 0: default:    dst = s0; break;
            case 1:             dst = s1; break;
            case 2:             dst = s2; break;
            case 3:             dst = s3; break;
            }
            code.bit_get(t0, bit);
            code.bit_put(dst, (bit / 4) + (word * 8));
        }
    }
}

// Converts a 128-bit value from bit-sliced form and stores it.
static void photon256_from_sliced_128
    (Code &code, int offset, const Reg &s0, const Reg &s1,
     const Reg &s2, const Reg &s3, const Reg &t0)
{
    int word, bit;
    for (word = 0; word < 4; ++word) {
        for (bit = 0; bit < 32; ++bit) {
            Reg src;
            switch (bit % 4) {
            case 0: default:    src = s0; break;
            case 1:             src = s1; break;
            case 2:             src = s2; break;
            case 3:             src = s3; break;
            }
            code.bit_get(src, (bit / 4) + (word * 8));
            code.bit_put(t0, bit);
        }
        code.stz(t0, offset + word * 4);
    }
}

// Applies the PHOTON-256 S-box to the state one byte at a time
static void photon256_sbox_byte
    (Code &code, const Reg &x0, const Reg &x1, const Reg &x2,
     const Reg &x3, const Reg &t1)
{
    // Need another temporary.
    Reg t2 = code.allocateReg(x0.size());

    // x1 ^= x2;
    code.logxor(x1, x2);

    // x3 ^= (x2 & x1);
    code.logxor_and(x3, x2, x1);

    // t1 = x3;
    code.move(t1, x3);

    // x3 = (x3 & x1) ^ x2;
    code.logand(x3, x1);
    code.logxor(x3, x2);

    // t2 = x3;
    code.move(t2, x3);

    // x3 ^= x0;
    code.logxor(x3, x0);

    // x3 = ~(x3);
    code.lognot(x3);

    // x2 = x3;
    code.move(x2, x3);

    // t2 |= x0;
    code.logor(t2, x0);

    // x0 ^= t1;
    code.logxor(x0, t1);

    // x1 ^= x0;
    code.logxor(x1, x0);

    // x2 |= x1;
    code.logor(x2, x1);

    // x2 ^= t1;
    code.logxor(x2, t1);

    // x1 ^= t2;
    code.logxor(x1, t2);

    // x3 ^= x1;
    code.logxor(x3, x1);

    // Release the extra temporary.
    code.releaseReg(t2);
}

// Applies the PHOTON-256 S-box to the state in bit-sliced form.
static void photon256_sbox
    (Code &code, const Reg &x0, const Reg &x1, const Reg &x2,
     const Reg &x3, const Reg &t1)
{
    for (int index = 0; index < x0.size(); ++index) {
        photon256_sbox_byte
            (code, Reg(x0, index, 1), Reg(x1, index, 1),
             Reg(x2, index, 1), Reg(x3, index, 1), Reg(t1, index, 1));
    }
}

// Loads the top half of the PHOTON-256 state into registers from Z.
static void photon256_load_top
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    code.ldz(s0, 0);
    code.ldz(s1, 4);
    code.ldz(s2, 8);
    code.ldz(s3, 12);
}

// Loads the bottom half of the PHOTON-256 state into registers from Z.
static void photon256_load_bottom
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    code.ldz(s0, 16);
    code.ldz(s1, 20);
    code.ldz(s2, 24);
    code.ldz(s3, 28);
}

// Stores the top half of the PHOTON-256 state from registers to Y.
static void photon256_store_top
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    code.stlocal(s0, 0);
    code.stlocal(s1, 4);
    code.stlocal(s2, 8);
    code.stlocal(s3, 12);
}

// Stores the bottom half of the PHOTON-256 state from registers to Y.
static void photon256_store_bottom
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    code.stlocal(s0, 16);
    code.stlocal(s1, 20);
    code.stlocal(s2, 24);
    code.stlocal(s3, 28);
}

// Loads the left half of the PHOTON-256 state into registers from Y.
static void photon256_load_left
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    for (int col = 0; col < 4; ++col) {
        code.ldlocal(Reg(s0, col, 1), col * 4);
        code.ldlocal(Reg(s1, col, 1), col * 4 + 1);
        code.ldlocal(Reg(s2, col, 1), col * 4 + 2);
        code.ldlocal(Reg(s3, col, 1), col * 4 + 3);
    }
}

// Loads the right half of the PHOTON-256 state into registers from Y.
static void photon256_load_right
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    for (int col = 0; col < 4; ++col) {
        code.ldlocal(Reg(s0, col, 1), col * 4 + 16);
        code.ldlocal(Reg(s1, col, 1), col * 4 + 17);
        code.ldlocal(Reg(s2, col, 1), col * 4 + 18);
        code.ldlocal(Reg(s3, col, 1), col * 4 + 19);
    }
}

// Loads a specific row of the PHOTON-256 state from Z.
static void photon256_load_row(Code &code, const Reg &s0, int row)
{
    if (row >= 4)
        row += 12;
    for (int col = 0; col < 4; ++col)
        code.ldz(Reg(s0, col, 1), col * 4 + row);
}

// Stores a specific row of the PHOTON-256 state to Z.
static void photon256_store_row(Code &code, const Reg &s0, int row)
{
    if (row >= 4)
        row += 12;
    for (int col = 0; col < 4; ++col)
        code.stz(Reg(s0, col, 1), col * 4 + row);
}

// Applies the round constant to one half of the PHOTON-256 state.
static void photon256_apply_rc
    (Code &code, const Reg &x0, const Reg &x1, const Reg &x2,
     const Reg &x3, const Reg &t1, const Reg &rc, bool bottom = false)
{
    #define LSR_BYTES() \
        do { \
            code.lsr(Reg(rc, 0, 1), 1); \
            code.lsr(Reg(rc, 1, 1), 1); \
            code.lsr(Reg(rc, 2, 1), 1); \
            code.lsr(Reg(rc, 3, 1), 1); \
        } while (0)
    code.move(t1, rc);
    code.logand(t1, 0x01010101U);
    code.logxor(x0, t1);
    LSR_BYTES();
    code.move(t1, rc);
    code.logand(t1, 0x01010101U);
    code.logxor(x1, t1);
    LSR_BYTES();
    code.move(t1, rc);
    code.logand(t1, 0x01010101U);
    code.logxor(x2, t1);
    LSR_BYTES();
    if (bottom) {
        code.logxor(x3, rc);
    } else {
        code.move(t1, rc);
        code.logand(t1, 0x01010101U);
        code.logxor(x3, t1);
        LSR_BYTES();
    }
}

// Set "out" to "out ^= MUL(value, in)" using the GF(^4) field of PHOTON-256.
static void photon256_field_multiply
    (Code &code, const Reg &out, const Reg &in,
     unsigned value, bool first = false)
{
    Reg temp = code.allocateReg(4);
    for (int bit = 0; bit < 4; ++bit) {
        if (value & 1) {
            if (bit == 0) {
                if (first)
                    code.move(out, in);
                else
                    code.logxor(out, in);
            } else {
                if (first)
                    code.move(out, temp);
                else
                    code.logxor(out, temp);
            }
            first = false;
        }
        value >>= 1;
        if (value == 0)
            break;
        if (bit == 0)
            code.move(temp, in);
        temp = temp.shuffle(3, 0, 1, 2);
        code.logxor(Reg(temp, 1, 1), Reg(temp, 0, 1));
    }
    code.releaseReg(temp);
}

// Mixes the columns of the PHOTON-256 state in bit-sliced form.
static void photon256_mix_columns
    (Code &code, const Reg &x0, const Reg &x1, const Reg &x2,
     const Reg &x3, const Reg &t1)
{
    // Load the left half of the state.
    photon256_load_left(code, x0, x1, x2, x3);

    // Perform the left half of the matrix multiplication.
    for (int row = 0; row < 8; ++row) {
        photon256_field_multiply
            (code, t1, x0, photon256_mix_matrix[row][0], true);
        photon256_field_multiply
            (code, t1, x1, photon256_mix_matrix[row][1]);
        photon256_field_multiply
            (code, t1, x2, photon256_mix_matrix[row][2]);
        photon256_field_multiply
            (code, t1, x3, photon256_mix_matrix[row][3]);
        photon256_store_row(code, t1, row);
    }

    // Load the right half of the state.
    photon256_load_right(code, x0, x1, x2, x3);

    // Perform the right half of the matrix multiplication.
    for (int row = 0; row < 8; ++row) {
        photon256_load_row(code, t1, row);
        photon256_field_multiply
            (code, t1, x0, photon256_mix_matrix[row][4]);
        photon256_field_multiply
            (code, t1, x1, photon256_mix_matrix[row][5]);
        photon256_field_multiply
            (code, t1, x2, photon256_mix_matrix[row][6]);
        photon256_field_multiply
            (code, t1, x3, photon256_mix_matrix[row][7]);
        photon256_store_row(code, t1, row);
    }
}

void gen_photon256_permutation(Code &code)
{
    int col;

    // Set up the function prologue with 32 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("photon256_permute", 32);

    // Allocate the registers we will need later.
    Reg t0 = code.allocateHighReg(4);
    Reg rc = code.allocateHighReg(4);
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);

    // Convert the input state into bit-sliced form in-place.
    // Leave the top-most row in s0, s1, s2, s3 before each iteration.
    photon256_to_sliced_128(code, 16, s0, s1, s2, s3, t0);
    code.stz(s0, 16);
    code.stz(s1, 20);
    code.stz(s2, 24);
    code.stz(s3, 28);
    photon256_to_sliced_128(code, 0, s0, s1, s2, s3, t0);

    // Top of the round loop.  We unroll the outer loop to deal
    // with the round constants, with the rest in a subroutine.
    unsigned char end_label = 0;
    unsigned char subroutine = 0;
    for (int round = 0; round < PHOTON256_ROUNDS; ++round) {
        code.move(rc, photon256_rc[round]);
        code.call(subroutine);
    }
    code.jmp(end_label);

    // Start of the subroutine.
    code.label(subroutine);

    // Add the round constants in "rc" to the top half of the state.
    photon256_apply_rc(code, s0, s1, s2, s3, t0, rc);

    // Apply the S-box to the top half of the state.
    photon256_sbox(code, s0, s1, s2, s3, t0);

    // Rotate the rows of the top half by 0..3 bit positions and store.
    for (col = 1; col < 4; ++col) {
        code.ror(Reg(s0, col, 1), col);
        code.ror(Reg(s1, col, 1), col);
        code.ror(Reg(s2, col, 1), col);
        code.ror(Reg(s3, col, 1), col);
    }
    photon256_store_top(code, s0, s1, s2, s3);

    // Add the round constants in "rc" to the bottom half of the state.
    photon256_load_bottom(code, s0, s1, s2, s3);
    photon256_apply_rc(code, s0, s1, s2, s3, t0, rc, true);

    // Can now reuse "rc" for other purposes.
    code.releaseReg(rc);

    // Apply the S-box to the bottom half of the state.
    photon256_sbox(code, s0, s1, s2, s3, t0);

    // Rotate the rows of the bottom half by 4..7 bit positions and store.
    for (col = 0; col < 4; ++col) {
        code.ror(Reg(s0, col, 1), col + 4);
        code.ror(Reg(s1, col, 1), col + 4);
        code.ror(Reg(s2, col, 1), col + 4);
        code.ror(Reg(s3, col, 1), col + 4);
    }
    photon256_store_bottom(code, s0, s1, s2, s3);

    // Mix the columns.
    photon256_mix_columns(code, s0, s1, s2, s3, t0);

    // Reload the top half of the state for the next round.
    photon256_load_top(code, s0, s1, s2, s3);

    // End of the subroutine.
    code.ret();

    // Convert the state from bit-sliced form back into regular form in-place.
    code.label(end_label);
    photon256_from_sliced_128(code, 0, s0, s1, s2, s3, t0);
    photon256_load_bottom(code, s0, s1, s2, s3);
    photon256_from_sliced_128(code, 16, s0, s1, s2, s3, t0);
}

bool test_photon256_permutation(Code &code)
{
    static unsigned char const input[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static unsigned char const output[] = {
        0x25, 0x5e, 0x27, 0x0d, 0x37, 0xe9, 0x0d, 0x76,
        0xbc, 0xa8, 0x38, 0x53, 0x65, 0xba, 0xae, 0x7d,
        0x4a, 0xcc, 0x71, 0x33, 0x8f, 0x26, 0x5b, 0x0c,
        0x1b, 0x52, 0x09, 0x3f, 0x4d, 0x48, 0xee, 0xf9
    };
    unsigned char state[32];
    memcpy(state, input, 32);
    code.exec_permutation(state, 32);
    return !memcmp(output, state, 32);
}
