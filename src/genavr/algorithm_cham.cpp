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

// XOR the round constant into the second byte of a register.
static void logxor_shifted_8(Code &code, const Reg &reg, const Reg &round)
{
    Reg reg2(reg, 1, 1);
    code.logxor(reg2, round);
}

static void gen_cham_double_round
    (Code &code, const Reg &x0, const Reg& x1, const Reg &x2,
     const Reg &temp, const Reg &round, unsigned ks_offset)
{
    // x0 = leftRotate8((x0 ^ round)       + (leftRotate1(x1) ^ k[0]));
    // x1 = leftRotate1((x1 ^ (round + 1)) + (leftRotate8(x2) ^ k[1]));
    // We assume that x0 is rotated left by 8 on input and that x2
    // should be left rotated by 8 on output.
    logxor_shifted_8(code, x0, round); // x0 is already pre-rotated by 8.
    code.move(temp, x1);
    code.rol(temp, 1);
    code.ldlocal_xor(temp, ks_offset * x0.size());
    code.add(Reg(x0, 1, 4), temp);
    code.inc(round);
    code.logxor(x1, round);
    code.rol(x2, 8);
    code.ldlocal(temp, (ks_offset + 1) * x0.size());
    code.logxor(temp, x2);
    code.add(x1, temp);
    code.rol(x1, 1);
    code.inc(round);
}

/**
 * \brief Generates the AVR code for the CHAM-128-128 block cipher.
 *
 * \param code The code block to generate into.
 */
void gen_cham128_encrypt(Code &code)
{
    // Set up the function prologue with 32 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is the key schedule.
    code.prologue_encrypt_block("cham128_128_encrypt", 32);

    // Get some temporary registers to hold the state.  We put x0 and x1
    // into high registers so that we can reduce the number of registers
    // that need to be call-saved.
    Reg x0 = code.allocateHighReg(4);
    Reg x1 = code.allocateHighReg(4);
    Reg x2 = code.allocateReg(4);
    Reg x3 = code.allocateReg(4);

    // Create the key schedule in local variables on the stack.
    for (unsigned offset = 0; offset < 4; ++offset) {
        code.ldz(x0, offset * 4);       // x0 = K[offset * 4]
        code.move(x1, x0);              // x1 = x0
        code.move(x3, x0);              // x3 = leftRotate1(x0)
        code.rol(x3, 1);
        code.logxor(x0, x3);            // x0 ^= x3
        code.move(x2, x0);              // x2 = x0 = (x0 ^ leftRotate1(x0))
        code.logxor(x0, Reg(x1, 3, 4)); // x0 ^= leftRotate8(x1)
        code.stlocal(x0, offset * 4);
        code.rol(x3, 2);                // x3 = leftRotate11(x1)
        code.logxor(x2, Reg(x3, 3, 4)); // x2 ^= x3
        code.stlocal(x2, (offset ^ 0x05) * 4);
    }

    // Print the contents of the key schedule in diagnostic mode.
    if (code.hasFlag(Code::Print)) {
        code.print("Key : ");
        code.ldlocal(x0, 0);
        code.ldlocal(x1, 4);
        code.ldlocal(x2, 8);
        code.ldlocal(x3, 12);
        code.print(x0);
        code.print(x1);
        code.print(x2);
        code.print(x3);
        code.ldlocal(x0, 16);
        code.ldlocal(x1, 20);
        code.ldlocal(x2, 24);
        code.ldlocal(x3, 28);
        code.println();
        code.print("      ");
        code.print(x0);
        code.print(x1);
        code.print(x2);
        code.print(x3);
        code.println();
    }

    // We no longer need the Z register so allow it to be used for temporaries.
    code.setFlag(Code::TempZ);

    // Unpack the input state into 32-bit registers x0, x1, x2, and x3.
    // We also load x0 in a way that pre-rotates it left by 8 bits.
    Reg x0_rotated = Reg(x0, 1, 4);
    code.ldx(x0_rotated, POST_INC);
    code.ldx(x1, POST_INC);
    code.ldx(x2, POST_INC);
    code.ldx(x3, POST_INC);

    // Perform 80 rounds, eight at a time.
    Reg round = code.allocateHighReg(1);
    Reg temp = code.allocateReg(4);
    code.move(round, 0);

    // Label at the top of the loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // Print the state at the start of this round.
    code.print(round);
    code.print(" : ");
    code.print(x0_rotated);
    code.print(x1);
    code.print(x2);
    code.print(x3);
    code.println();

    // Perform the eight rounds for this iteration.
    gen_cham_double_round(code, x0, x1, x2, temp, round, 0);
    gen_cham_double_round(code, x2, x3, x0, temp, round, 2);
    gen_cham_double_round(code, x0, x1, x2, temp, round, 4);
    gen_cham_double_round(code, x2, x3, x0, temp, round, 6);

    // Loop back if round != 80.
    code.compare_and_loop(round, 80, top_label);

    // Print the state at the end of the encryption process.
    code.print(round);
    code.print(" : ");
    code.print(x0_rotated);
    code.print(x1);
    code.print(x2);
    code.print(x3);
    code.println();

    // Pack the state into the output buffer after rotating x0 back by 8 bits.
    code.load_output_ptr();
    code.stx(x0_rotated, POST_INC);
    code.stx(x1, POST_INC);
    code.stx(x2, POST_INC);
    code.stx(x3, POST_INC);
}

/**
 * \brief Generates the AVR code for the CHAM-64-128 block cipher.
 *
 * \param code The code block to generate into.
 */
void gen_cham64_encrypt(Code &code)
{
    // Set up the function prologue with 32 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is the key schedule.
    code.prologue_encrypt_block("cham64_128_encrypt", 32);

    // Get some temporary registers to hold the state.  We put them
    // all into high registers so that we can reduce the number of
    // registers that need to be call-saved.
    Reg x0 = code.allocateHighReg(2);
    Reg x1 = code.allocateHighReg(2);
    Reg x2 = code.allocateHighReg(2);
    Reg x3 = code.allocateHighReg(2);

    // Create the key schedule in local variables on the stack.
    for (unsigned offset = 0; offset < 8; ++offset) {
        code.ldz(x0, offset * 2);       // x0 = K[offset * 4]
        code.move(x1, x0);              // x1 = x0
        code.move(x3, x0);              // x3 = leftRotate1(x0)
        code.rol(x3, 1);
        code.logxor(x0, x3);            // x0 ^= x3
        code.move(x2, x0);              // x2 = x0 = (x0 ^ leftRotate1(x0))
        code.logxor(x0, Reg(x1, 1, 2)); // x0 ^= leftRotate8(x1)
        code.stlocal(x0, offset * 2);
        code.rol(x3, 2);                // x3 = leftRotate11(x1)
        code.logxor(x2, Reg(x3, 1, 2)); // x2 ^= x3
        code.stlocal(x2, (offset ^ 0x09) * 2);
    }

    // We no longer need the Z register so allow it to be used for temporaries.
    code.setFlag(Code::TempZ);

    // Unpack the input state into 16-bit registers x0, x1, x2, and x3.
    // We also load x0 in a way that pre-rotates it left by 8 bits.
    Reg x0_rotated = Reg(x0, 1, 2);
    code.ldx(x0_rotated, POST_INC);
    code.ldx(x1, POST_INC);
    code.ldx(x2, POST_INC);
    code.ldx(x3, POST_INC);

    // Perform 80 rounds, 16 at a time.
    Reg temp = code.allocateHighReg(2);
    Reg round = code.allocateHighReg(1);
    code.move(round, 0);

    // Label at the top of the loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // Perform the 16 rounds for this iteration.
    gen_cham_double_round(code, x0, x1, x2, temp, round, 0);
    gen_cham_double_round(code, x2, x3, x0, temp, round, 2);
    gen_cham_double_round(code, x0, x1, x2, temp, round, 4);
    gen_cham_double_round(code, x2, x3, x0, temp, round, 6);
    gen_cham_double_round(code, x0, x1, x2, temp, round, 8);
    gen_cham_double_round(code, x2, x3, x0, temp, round, 10);
    gen_cham_double_round(code, x0, x1, x2, temp, round, 12);
    gen_cham_double_round(code, x2, x3, x0, temp, round, 14);

    // Loop back if round != 80.
    code.compare_and_loop(round, 80, top_label);

    // Pack the state into the output buffer after rotating x0 back by 8 bits.
    code.load_output_ptr();
    code.stx(x0_rotated, POST_INC);
    code.stx(x1, POST_INC);
    code.stx(x2, POST_INC);
    code.stx(x3, POST_INC);
}

// Test vector for CHAM-128-128 from the original CHAM paper.
static block_cipher_test_vector_t const cham128_128_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    16,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* plaintext */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    {0x34, 0x60, 0x74, 0xc3, 0xc5, 0x00, 0x57, 0xb5,    /* ciphertext */
     0x32, 0xec, 0x64, 0x8d, 0xf7, 0x32, 0x93, 0x48}
};

// Test vector for CHAM-64-128 from the original CHAM paper.
static block_cipher_test_vector_t const cham64_128_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f},
    16,                                                 /* key_len */
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},   /* plaintext */
    {0x3c, 0x45, 0xbc, 0x63, 0xfa, 0xdc, 0x4e, 0xbf}    /* ciphertext */
};

bool test_cham128_encrypt(Code &code)
{
    unsigned char output[16];
    code.exec_encrypt_block(cham128_128_1.key, cham128_128_1.key_len,
                            output, 16, cham128_128_1.plaintext, 16);
    return !memcmp(output, cham128_128_1.ciphertext, 16);
}

bool test_cham64_encrypt(Code &code)
{
    unsigned char output[8];
    code.exec_encrypt_block(cham64_128_1.key, cham64_128_1.key_len,
                            output, 8, cham64_128_1.plaintext, 8);
    return !memcmp(output, cham64_128_1.ciphertext, 8);
}
