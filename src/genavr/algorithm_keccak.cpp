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

static void rho_pi_200
    (Code &code, const Reg &out_reg, int rotate, const Reg &in_reg)
{
    code.rol(in_reg, rotate);
    code.move(out_reg, in_reg);
}

/**
 * \brief Generates the AVR code for the Keccak-p[200] permutation.
 *
 * \param code The code block to generate into.
 */
void gen_keccakp_200_permutation(Code &code)
{
    static uint8_t const RC[18] = {
        0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01, 0x81, 0x09,
        0x8A, 0x88, 0x09, 0x0A, 0x8B, 0x8B, 0x89, 0x03,
        0x02, 0x80
    };
    int round, index, index2;

    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("keccakp_200_permute", 0);
    code.setFlag(Code::TempY);

    // Allocate 25 bytes for the core state and load it from Z.
    Reg A = code.allocateReg(25);
    code.ldz(A, 0);

    // Push Z on the stack so we can use it for temporaries.
    code.push(Reg::z_ptr());
    code.setFlag(Code::TempZ);

    // Allocate 5 bytes for the "C" array.  We force C[0] to be a high
    // register because we need one for loading round constants below.
    Reg C[5];
    C[0] = code.allocateHighReg(1);
    C[1] = code.allocateReg(1);
    C[2] = code.allocateReg(1);
    C[3] = code.allocateReg(1);
    C[4] = code.allocateReg(1);

    // Unroll the outer loop to handle round constants with an inner
    // subroutine to handle the bulk of the permutation.
    #define state_A(row, col) (Reg(A, (row) * 5 + (col), 1))
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (round = 0; round < 18; ++round) {
        code.call(subroutine);
        code.move(C[0], RC[round]);
        code.logxor(state_A(0, 0), C[0]);
    }
    code.jmp(end_label);

    // Step mapping theta.
    code.label(subroutine);
    for (index = 0; index < 5; ++index) {
        code.move(C[index], state_A(0, index));
        code.logxor(C[index], state_A(1, index));
        code.logxor(C[index], state_A(2, index));
        code.logxor(C[index], state_A(3, index));
        code.logxor(C[index], state_A(4, index));
    }
    for (index = 0; index < 5; ++index) {
        code.tworeg(Insn::MOV, TEMP_REG, C[(index + 1) % 5].reg(0));
        code.onereg(Insn::LSL, TEMP_REG); // Left rotate by 1 bit.
        code.tworeg(Insn::ADC, TEMP_REG, ZERO_REG);
        code.tworeg(Insn::EOR, TEMP_REG, C[(index + 4) % 5].reg(0));
        for (index2 = 0; index2 < 5; ++index2)
            code.tworeg(Insn::EOR, state_A(index2, index).reg(0), TEMP_REG);
    }

    // Step mappings rho and pi combined into a single step.
    code.move(C[0], state_A(0, 1));
    rho_pi_200(code, state_A(0, 1), 4, state_A(1, 1));
    rho_pi_200(code, state_A(1, 1), 4, state_A(1, 4));
    rho_pi_200(code, state_A(1, 4), 5, state_A(4, 2));
    rho_pi_200(code, state_A(4, 2), 7, state_A(2, 4));
    rho_pi_200(code, state_A(2, 4), 2, state_A(4, 0));
    rho_pi_200(code, state_A(4, 0), 6, state_A(0, 2));
    rho_pi_200(code, state_A(0, 2), 3, state_A(2, 2));
    rho_pi_200(code, state_A(2, 2), 1, state_A(2, 3));
    rho_pi_200(code, state_A(2, 3), 0, state_A(3, 4));
    rho_pi_200(code, state_A(3, 4), 0, state_A(4, 3));
    rho_pi_200(code, state_A(4, 3), 1, state_A(3, 0));
    rho_pi_200(code, state_A(3, 0), 3, state_A(0, 4));
    rho_pi_200(code, state_A(0, 4), 6, state_A(4, 4));
    rho_pi_200(code, state_A(4, 4), 2, state_A(4, 1));
    rho_pi_200(code, state_A(4, 1), 7, state_A(1, 3));
    rho_pi_200(code, state_A(1, 3), 5, state_A(3, 1));
    rho_pi_200(code, state_A(3, 1), 4, state_A(1, 0));
    rho_pi_200(code, state_A(1, 0), 4, state_A(0, 3));
    rho_pi_200(code, state_A(0, 3), 5, state_A(3, 3));
    rho_pi_200(code, state_A(3, 3), 7, state_A(3, 2));
    rho_pi_200(code, state_A(3, 2), 2, state_A(2, 1));
    rho_pi_200(code, state_A(2, 1), 6, state_A(1, 2));
    rho_pi_200(code, state_A(1, 2), 3, state_A(2, 0));
    code.rol(C[0], 1);
    code.move(state_A(2, 0), C[0]);

    // Step mapping chi.
    for (index = 0; index < 5; ++index) {
        code.move(C[0], state_A(index, 0));
        code.move(C[1], state_A(index, 1));
        code.move(C[2], state_A(index, 2));
        code.move(C[3], state_A(index, 3));
        code.move(C[4], state_A(index, 4));
        for (index2 = 0; index2 < 5; ++index2) {
            Reg s = state_A(index, index2);
            code.move(s, C[(index2 + 2) % 5]);
            code.logand_not(s, C[(index2 + 1) % 5]);
            code.logxor(s, C[index2]);
        }
    }

    // End of the inner subroutine.
    code.ret();

    // Restore Z from the stack and store the "A" state back again.
    code.label(end_label);
    code.pop(Reg::z_ptr());
    code.stz(A, 0);
}

static void rho_pi_400
    (Code &code, const Reg *A, const Reg &temp,
     int out_posn, int rotate, int in_posn)
{
    if (out_posn < 10) {
        if (in_posn < 10)
            code.move(A[out_posn / 2], A[in_posn / 2]);
        else
            code.ldz(A[out_posn / 2], in_posn);
        code.rol(A[out_posn / 2], rotate);
    } else {
        if (in_posn < 10)
            code.move(temp, A[in_posn / 2]);
        else
            code.ldz(temp, in_posn);
        code.rol(temp, rotate);
        code.stz(temp, out_posn);
    }
}

/**
 * \brief Generates the AVR code for the Keccak-p[400] permutation.
 *
 * \param code The code block to generate into.
 */
void gen_keccakp_400_permutation(Code &code)
{
    static uint16_t const RC[20] = {
        0x0001, 0x8082, 0x808A, 0x8000, 0x808B, 0x0001, 0x8081, 0x8009,
        0x008A, 0x0088, 0x8009, 0x000A, 0x808B, 0x008B, 0x8089, 0x8003,
        0x8002, 0x0080, 0x800A, 0x000A
    };
    int round, index, index2;

    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg rounds = code.prologue_permutation_with_count("keccakp_400_permute", 0);
    code.setFlag(Code::NoLocals); // Don't need local variables or Y.

    // We cannot hold the entire 50-byte state in registers at once so we
    // deal with the data one 10-byte row or column at a time.  Between
    // rounds, the first row of the state is cached in A[0..4] to reduce
    // the amount of data movement to and from memory.
    Reg C[5];
    C[0] = code.allocateReg(2);
    C[1] = code.allocateReg(2);
    C[2] = code.allocateReg(2);
    C[3] = code.allocateReg(2);
    C[4] = code.allocateReg(2);
    Reg A[5];
    A[0] = code.allocateReg(2);
    A[1] = code.allocateReg(2);
    A[2] = code.allocateReg(2);
    A[3] = code.allocateReg(2);
    A[4] = code.allocateReg(2);
    Reg D = code.allocateReg(2);

    // Unroll the outer loop to handle round constants with an inner
    // subroutine to handle the bulk of the permutation.
    #define posn_A(row, col) ((row) * 10 + (col) * 2)
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    code.ldz(A[0], posn_A(0, 0)); // Pre-load the first row into registers.
    code.ldz(A[1], posn_A(0, 1));
    code.ldz(A[2], posn_A(0, 2));
    code.ldz(A[3], posn_A(0, 3));
    code.ldz(A[4], posn_A(0, 4));
    for (round = 0; round < 20; ++round) {
        // Skip this round if it is before the starting round.
        unsigned char next_label = 0;
        code.compare(rounds, 20 - round);
        code.brcs(next_label);

        // Perform the bulk of the round by calling the subroutine.
        code.call(subroutine);

        // XOR the round constant into A[0][0] which is still in a register.
        code.logxor(A[0], RC[round]);
        code.label(next_label);
    }
    code.jmp(end_label);

    // Step mapping theta.
    code.label(subroutine);
    for (index = 0; index < 5; ++index) {
        code.move(C[index], A[index]);
        code.ldz_xor(C[index], posn_A(1, index));
        code.ldz_xor(C[index], posn_A(2, index));
        code.ldz_xor(C[index], posn_A(3, index));
        code.ldz_xor(C[index], posn_A(4, index));
    }
    for (index = 0; index < 5; ++index) {
        code.move(D, C[(index + 1) % 5]);
        code.rol(D, 1);
        code.logxor(D, C[(index + 4) % 5]);
        for (index2 = 0; index2 < 5; ++index2) {
            if (index2 == 0)
                code.logxor(A[index], D);
            else
                code.ldz_xor_in(D, posn_A(index2, index));
        }
    }

    // Step mappings rho and pi combined into a single step.
    code.move(D, A[1]); // D = A[0][1]
    rho_pi_400(code, A, C[0], posn_A(0, 1), 12, posn_A(1, 1));
    rho_pi_400(code, A, C[0], posn_A(1, 1),  4, posn_A(1, 4));
    rho_pi_400(code, A, C[0], posn_A(1, 4), 13, posn_A(4, 2));
    rho_pi_400(code, A, C[0], posn_A(4, 2),  7, posn_A(2, 4));
    rho_pi_400(code, A, C[0], posn_A(2, 4),  2, posn_A(4, 0));
    rho_pi_400(code, A, C[0], posn_A(4, 0), 14, posn_A(0, 2));
    rho_pi_400(code, A, C[0], posn_A(0, 2), 11, posn_A(2, 2));
    rho_pi_400(code, A, C[0], posn_A(2, 2),  9, posn_A(2, 3));
    rho_pi_400(code, A, C[0], posn_A(2, 3),  8, posn_A(3, 4));
    rho_pi_400(code, A, C[0], posn_A(3, 4),  8, posn_A(4, 3));
    rho_pi_400(code, A, C[0], posn_A(4, 3),  9, posn_A(3, 0));
    rho_pi_400(code, A, C[0], posn_A(3, 0), 11, posn_A(0, 4));
    rho_pi_400(code, A, C[0], posn_A(0, 4), 14, posn_A(4, 4));
    rho_pi_400(code, A, C[0], posn_A(4, 4),  2, posn_A(4, 1));
    rho_pi_400(code, A, C[0], posn_A(4, 1),  7, posn_A(1, 3));
    rho_pi_400(code, A, C[0], posn_A(1, 3), 13, posn_A(3, 1));
    rho_pi_400(code, A, C[0], posn_A(3, 1),  4, posn_A(1, 0));
    rho_pi_400(code, A, C[0], posn_A(1, 0), 12, posn_A(0, 3));
    rho_pi_400(code, A, C[0], posn_A(0, 3),  5, posn_A(3, 3));
    rho_pi_400(code, A, C[0], posn_A(3, 3), 15, posn_A(3, 2));
    rho_pi_400(code, A, C[0], posn_A(3, 2), 10, posn_A(2, 1));
    rho_pi_400(code, A, C[0], posn_A(2, 1),  6, posn_A(1, 2));
    rho_pi_400(code, A, C[0], posn_A(1, 2),  3, posn_A(2, 0));
    code.rol(D, 1);
    code.stz(D, posn_A(2, 0));

    // Step mapping chi.
    for (index = 0; index < 5; ++index) {
        if (index == 0) {
            code.move(C[0], A[0]);
            code.move(C[1], A[1]);
            code.move(C[2], A[2]);
            code.move(C[3], A[3]);
            code.move(C[4], A[4]);
        } else {
            code.ldz(C[0], posn_A(index, 0));
            code.ldz(C[1], posn_A(index, 1));
            code.ldz(C[2], posn_A(index, 2));
            code.ldz(C[3], posn_A(index, 3));
            code.ldz(C[4], posn_A(index, 4));
        }
        for (index2 = 0; index2 < 5; ++index2) {
            if (index == 0) {
                code.move(A[index2], C[(index2 + 2) % 5]);
                code.logand_not(A[index2], C[(index2 + 1) % 5]);
                code.logxor(A[index2], C[index2]);
            } else {
                code.move(D, C[(index2 + 2) % 5]);
                code.logand_not(D, C[(index2 + 1) % 5]);
                code.logxor(D, C[index2]);
                code.stz(D, posn_A(index, index2));
            }
        }
    }

    // End of the inner subroutine.
    code.ret();

    // First row is still in registers, so store it back.
    code.label(end_label);
    code.stz(A[0], posn_A(0, 0));
    code.stz(A[1], posn_A(0, 1));
    code.stz(A[2], posn_A(0, 2));
    code.stz(A[3], posn_A(0, 3));
    code.stz(A[4], posn_A(0, 4));
}

bool test_keccakp_200_permutation(Code &code)
{
    static unsigned char const input[25] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18
    };
    static unsigned char const output[25] = {
        0x7f, 0x03, 0x40, 0xbd, 0x5e, 0xf9, 0xa9, 0xce,
        0x6c, 0x77, 0xd1, 0x41, 0xea, 0x91, 0x23, 0x77,
        0x2d, 0x83, 0xf0, 0x40, 0xbf, 0x23, 0x1c, 0xa5,
        0x1c
    };
    unsigned char state[25];
    memcpy(state, input, 25);
    code.exec_permutation(state, 25);
    return !memcmp(output, state, 25);
}

bool test_keccakp_400_permutation(Code &code)
{
    static unsigned char const input[50] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31
    };
    static unsigned char const output[50] = {
        0x4f, 0x12, 0x06, 0x0e, 0x11, 0x27, 0x48, 0x1e,
        0x58, 0xdf, 0x3c, 0x9f, 0xef, 0x2e, 0x02, 0xaf,
        0xf4, 0xfc, 0x03, 0xd8, 0x32, 0x95, 0x7a, 0x54,
        0xac, 0xbc, 0xbe, 0x22, 0x51, 0x4e, 0x5c, 0xcb,
        0x0f, 0x58, 0x95, 0xdd, 0x1f, 0x37, 0xe8, 0x3a,
        0x23, 0x49, 0x82, 0x2c, 0xde, 0x5c, 0xaa, 0x77,
        0x7d, 0x54
    };
    unsigned char state[50];
    memcpy(state, input, 50);
    code.exec_permutation(state, 50, 20);
    return !memcmp(output, state, 50);
}
