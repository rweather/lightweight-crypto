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

// Number of rounds for the Pyjamask cipher.
#define PYJAMASK_ROUNDS 14

// Performs a circulant binary matrix multiplication.
static void pyjamask_matrix_multiply(Code &code, uint32_t x, const Reg &y)
{
    int bit;
    Reg temp = code.allocateHighReg(4);
    Reg result = code.allocateReg(4);
    for (bit = 31; bit >= 0; --bit) {
        code.tworeg(Insn::MOV, TEMP_REG, ZERO_REG);
        code.lsl(Reg(y, bit / 8, 1), 1);
        code.tworeg(Insn::SBC, TEMP_REG, ZERO_REG);
        if (bit == 31) {
            code.move(result, x);
            code.tworeg(Insn::AND, result.reg(0), TEMP_REG);
            code.tworeg(Insn::AND, result.reg(1), TEMP_REG);
            code.tworeg(Insn::AND, result.reg(2), TEMP_REG);
            code.tworeg(Insn::AND, result.reg(3), TEMP_REG);
        } else {
            code.move(temp, x);
            code.tworeg(Insn::AND, temp.reg(0), TEMP_REG);
            code.tworeg(Insn::AND, temp.reg(1), TEMP_REG);
            code.tworeg(Insn::AND, temp.reg(2), TEMP_REG);
            code.tworeg(Insn::AND, temp.reg(3), TEMP_REG);
            code.logxor(result, temp);
        }
        x = (x >> 1) | (x << 31);
    }
    code.move(y, result);
    code.releaseReg(temp);
    code.releaseReg(result);
}

#if 0

// By reversing the arguments, we can get a version of Pyjamask that is 2x
// faster than using the multiplication code above.  It is not clear from
// the specification as to whether we should do this or if there is some
// security implication on the side channel protection in doing so.
static void pyjamask_matrix_multiply(Code &code, uint32_t x, const Reg &y)
{
    int bit, count, first;
    Reg result = code.allocateReg(4);
    count = 0;
    first = 1;
    for (bit = 31; bit >= 0; --bit) {
        if ((x & (((uint32_t)1) << bit)) != 0) {
            code.ror(y, count);
            if (first)
                code.move(result, y);
            else
                code.logxor(result, y);
            count = 0;
            first = 0;
        }
        ++count;
    }
    code.move(y, result);
    code.releaseReg(result);
}

#endif

/**
 * \brief Generates the AVR code for the Pyjamask key setup function.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param variant 128 or 96 for the variant to generate.
 *
 * Pyjamask-128 generates 4 round keys for each round and Pyjamask-96
 * generates 3 round keys for each round.
 */
static void gen_pyjamask_setup_key(Code &code, const char *name, int variant)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key(name, 0);
    code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Load the words of the key.
    Reg k0 = code.allocateReg(4);
    Reg k1 = code.allocateReg(4);
    Reg k2 = code.allocateReg(4);
    Reg k3 = code.allocateReg(4);
    code.ldx(k0.reversed(), POST_INC);
    code.ldx(k1.reversed(), POST_INC);
    code.ldx(k2.reversed(), POST_INC);
    code.ldx(k3.reversed(), POST_INC);
    code.setFlag(Code::TempX);

    // The first round key is the same as the key itself.
    code.stz(k0, POST_INC);
    code.stz(k1, POST_INC);
    code.stz(k2, POST_INC);
    if (variant == 128)
        code.stz(k3, POST_INC);

    // Derive the rest of the round keys.
    unsigned char top_label = 0;
    Reg round = code.allocateHighReg(1);
    code.move(round, 0);
    code.label(top_label);

    // Mix the columns.
    Reg temp = code.allocateReg(4);
    code.move(temp, k0);
    code.logxor(temp, k1);
    code.logxor(temp, k2);
    code.logxor(temp, k3);
    code.logxor(k0, temp);
    code.logxor(k1, temp);
    code.logxor(k2, temp);
    code.logxor(k3, temp);
    code.releaseReg(temp);

    // Mix the rows and add the round constants.
    pyjamask_matrix_multiply(code, 0xb881b9caU, k0);
    code.logxor(k0, 0x00000080U);
    code.logxor(k0, round);
    code.ror(k1, 8);
    code.logxor(k1, 0x00006a00U);
    code.ror(k2, 15);
    code.logxor(k2, 0x003f0000U);
    code.ror(k3, 18);
    code.logxor(k3, 0x24000000U);

    // Write the round key to the schedule and loop.
    code.stz(k0, POST_INC);
    code.stz(k1, POST_INC);
    code.stz(k2, POST_INC);
    if (variant == 128)
        code.stz(k3, POST_INC);
    code.inc(round);
    code.compare_and_loop(round, PYJAMASK_ROUNDS, top_label);
}

// XOR the Pyjamask state with the round key and advance the Z pointer.
static void pyjmask_xor_round_key
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2,
     const Reg &s3, unsigned char offset)
{
    Reg temp = code.allocateReg(4);
    if (offset == POST_INC) {
        code.ldz(temp, POST_INC);
        code.logxor(s0, temp);
        code.ldz(temp, POST_INC);
        code.logxor(s1, temp);
        code.ldz(temp, POST_INC);
        code.logxor(s2, temp);
        if (s3.size() != 0) {
            code.ldz(temp, POST_INC);
            code.logxor(s3, temp);
        }
    } else {
        if (s3.size() != 0) {
            code.ldz(temp, PRE_DEC);
            code.logxor(s3, temp);
        }
        code.ldz(temp, PRE_DEC);
        code.logxor(s2, temp);
        code.ldz(temp, PRE_DEC);
        code.logxor(s1, temp);
        code.ldz(temp, PRE_DEC);
        code.logxor(s0, temp);
    }
    code.releaseReg(temp);
}

/**
 * \brief Generates the AVR code for the Pyjamask encryption function.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param variant 128 or 96 for the variant to generate.
 */
static void gen_pyjamask_encrypt(Code &code, const char *name, int variant)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X will point to the input and Z points to the key schedule.
    code.prologue_encrypt_block(name, 0);
    //code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Load the 96-bit or 128-bit input into registers.
    Reg s0, s1, s2, s3;
    s0 = code.allocateReg(4);
    s1 = code.allocateReg(4);
    s2 = code.allocateReg(4);
    code.ldx(s0.reversed(), POST_INC);
    code.ldx(s1.reversed(), POST_INC);
    code.ldx(s2.reversed(), POST_INC);
    if (variant == 128) {
        s3 = code.allocateReg(4);
        code.ldx(s3.reversed(), POST_INC);
    }

    // We can now use the X register for temporaries.
    code.setFlag(Code::TempX);

    // Top of the round loop.
    unsigned char top_label = 0;
    Reg round = code.allocateHighReg(1);
    code.move(round, PYJAMASK_ROUNDS);
    code.label(top_label);

    // Add the round key to the state.
    pyjmask_xor_round_key(code, s0, s1, s2, s3, POST_INC);

    // Apply the Pyjamask sbox.
    if (variant == 128) {
        code.logxor(s0, s3);                // s0 ^= s3;
        code.logxor_and(s3, s0, s1);        // s3 ^= s0 & s1;
        code.logxor_and(s0, s1, s2);        // s0 ^= s1 & s2;
        code.logxor_and(s1, s2, s3);        // s1 ^= s2 & s3;
        code.logxor_and(s2, s0, s3);        // s2 ^= s0 & s3;
        code.logxor(s2, s1);                // s2 ^= s1;
        code.logxor(s1, s0);                // s1 ^= s0;
        code.lognot(s3);                    // s3 = ~s3;
        code.logxor(s2, s3);                // s2 ^= s3;
        code.logxor(s3, s2);                // s3 ^= s2;
        code.logxor(s2, s3);                // s2 ^= s3;
    } else {
        code.logxor(s0, s1);                // s0 ^= s1;
        code.logxor(s1, s2);                // s1 ^= s2;
        code.logxor_and(s2, s0, s1);        // s2 ^= s0 & s1;
        code.logxor_and(s0, s1, s2);        // s0 ^= s1 & s2;
        code.logxor_and(s1, s0, s2);        // s1 ^= s0 & s2;
        code.logxor(s2, s0);                // s2 ^= s0;
        code.lognot(s2);                    // s2 = ~s2;
        code.logxor(s1, s0);                // s1 ^= s0;
        code.logxor(s0, s1);                // s0 ^= s1;
    }

    // Mix the rows of the state.
    pyjamask_matrix_multiply(code, 0xa3861085U, s0);
    pyjamask_matrix_multiply(code, 0x63417021U, s1);
    pyjamask_matrix_multiply(code, 0x692cf280U, s2);
    if (variant == 128)
        pyjamask_matrix_multiply(code, 0x48a54813U, s3);

    // Bottom of the round loop.
    code.dec(round);
    code.brne(top_label);

    // Mix in the key one last time.
    pyjmask_xor_round_key(code, s0, s1, s2, s3, POST_INC);

    // Store the state registers to the 96-bit or 128-bit output buffer.
    code.load_output_ptr();
    code.stx(s0.reversed(), POST_INC);
    code.stx(s1.reversed(), POST_INC);
    code.stx(s2.reversed(), POST_INC);
    if (variant == 128)
        code.stx(s3.reversed(), POST_INC);
}

/**
 * \brief Generates the AVR code for the Pyjamask decryption function.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param variant 128 or 96 for the variant to generate.
 */
static void gen_pyjamask_decrypt(Code &code, const char *name, int variant)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X will point to the input and Z points to the key schedule.
    code.prologue_encrypt_block(name, 0);
    //code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Load the 96-bit or 128-bit input into registers.
    Reg s0, s1, s2, s3;
    s0 = code.allocateReg(4);
    s1 = code.allocateReg(4);
    s2 = code.allocateReg(4);
    code.ldx(s0.reversed(), POST_INC);
    code.ldx(s1.reversed(), POST_INC);
    code.ldx(s2.reversed(), POST_INC);
    if (variant == 128) {
        s3 = code.allocateReg(4);
        code.ldx(s3.reversed(), POST_INC);
    }

    // We can now use the X register for temporaries.
    code.setFlag(Code::TempX);

    // Mix in the last round key.
    code.add_ptr_z((PYJAMASK_ROUNDS + 1) * (variant / 8));
    pyjmask_xor_round_key(code, s0, s1, s2, s3, PRE_DEC);

    // Top of the round loop.
    unsigned char top_label = 0;
    Reg round = code.allocateHighReg(1);
    code.move(round, PYJAMASK_ROUNDS);
    code.label(top_label);

    // Inverse mix of the rows in the state.
    pyjamask_matrix_multiply(code, 0x2037a121U, s0);
    pyjamask_matrix_multiply(code, 0x108ff2a0U, s1);
    pyjamask_matrix_multiply(code, 0x9054d8c0U, s2);
    if (variant == 128)
        pyjamask_matrix_multiply(code, 0x3354b117U, s3);

    // Apply the inverse of the Pyjamask sbox.
    if (variant == 128) {
        code.logxor(s2, s3);                // s2 ^= s3;
        code.logxor(s3, s2);                // s3 ^= s2;
        code.logxor(s2, s3);                // s2 ^= s3;
        code.lognot(s3);                    // s3 = ~s3;
        code.logxor(s1, s0);                // s1 ^= s0;
        code.logxor(s2, s1);                // s2 ^= s1;
        code.logxor_and(s2, s0, s3);        // s2 ^= s0 & s3;
        code.logxor_and(s1, s2, s3);        // s1 ^= s2 & s3;
        code.logxor_and(s0, s1, s2);        // s0 ^= s1 & s2;
        code.logxor_and(s3, s0, s1);        // s3 ^= s0 & s1;
        code.logxor(s0, s3);                // s0 ^= s3;
    } else {
        code.logxor(s0, s1);                // s0 ^= s1;
        code.logxor(s1, s0);                // s1 ^= s0;
        code.lognot(s2);                    // s2 = ~s2;
        code.logxor(s2, s0);                // s2 ^= s0;
        code.logxor_and(s1, s0, s2);        // s1 ^= s0 & s2;
        code.logxor_and(s0, s1, s2);        // s0 ^= s1 & s2;
        code.logxor_and(s2, s0, s1);        // s2 ^= s0 & s1;
        code.logxor(s1, s2);                // s1 ^= s2;
        code.logxor(s0, s1);                // s0 ^= s1;
    }

    // Add the round key to the state.
    pyjmask_xor_round_key(code, s0, s1, s2, s3, PRE_DEC);

    // Bottom of the round loop.
    code.dec(round);
    code.brne(top_label);

    // Store the state registers to the 96-bit or 128-bit output buffer.
    code.load_output_ptr();
    code.stx(s0.reversed(), POST_INC);
    code.stx(s1.reversed(), POST_INC);
    code.stx(s2.reversed(), POST_INC);
    if (variant == 128)
        code.stx(s3.reversed(), POST_INC);
}

void gen_pyjamask_128_setup_key(Code &code)
{
    gen_pyjamask_setup_key(code, "pyjamask_128_setup_key", 128);
}

void gen_pyjamask_128_encrypt(Code &code)
{
    gen_pyjamask_encrypt(code, "pyjamask_128_encrypt", 128);
}

void gen_pyjamask_128_decrypt(Code &code)
{
    gen_pyjamask_decrypt(code, "pyjamask_128_decrypt", 128);
}

void gen_pyjamask_96_setup_key(Code &code)
{
    gen_pyjamask_setup_key(code, "pyjamask_96_setup_key", 96);
}

void gen_pyjamask_96_encrypt(Code &code)
{
    gen_pyjamask_encrypt(code, "pyjamask_96_encrypt", 96);
}

void gen_pyjamask_96_decrypt(Code &code)
{
    gen_pyjamask_decrypt(code, "pyjamask_96_decrypt", 96);
}

/* Test vectors for the Pyjamask block cipher from the specification */
static block_cipher_test_vector_t const pyjamask_128_1 = {
    "Test Vector 1",
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* key */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    16,                                                 /* key_len */
    {0x50, 0x79, 0x6a, 0x61, 0x6d, 0x61, 0x73, 0x6b,    /* plaintext */
     0x2d, 0x31, 0x32, 0x38, 0x3a, 0x29, 0x3a, 0x29},
    {0x48, 0xf1, 0x39, 0xa1, 0x09, 0xbd, 0xd9, 0xc0,    /* ciphertext */
     0x72, 0x6e, 0x82, 0x61, 0xf8, 0xd6, 0x8e, 0x7d}
};
static block_cipher_test_vector_t const pyjamask_96_1 = {
    "Test Vector 1",
    {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,    /* key */
     0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
    16,                                                 /* key_len */
    {0x50, 0x79, 0x6a, 0x61, 0x6d, 0x61, 0x73, 0x6b,    /* plaintext */
     0x39, 0x36, 0x3a, 0x29},
    {0xca, 0x9c, 0x6e, 0x1a, 0xbb, 0xde, 0x4e, 0xdc,    /* ciphertext */
     0x27, 0x07, 0x3d, 0xa6}
};

// Expanded version of the Pyjamask-128 key schedule.
static unsigned char pyjamask_128_ks[] = {
    0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44, 0xbb, 0xaa, 0x99, 0x88,
    0xff, 0xee, 0xdd, 0xcc, 0x30, 0x3a, 0x0b, 0x81, 0x66, 0x3f, 0x44, 0x77,
    0x33, 0x11, 0x48, 0x55, 0x37, 0xf3, 0xbf, 0x5f, 0xdf, 0x1a, 0x30, 0x1e,
    0xd8, 0x96, 0x8b, 0x34, 0xe1, 0x53, 0xfc, 0xec, 0xc1, 0x68, 0x19, 0xe1,
    0xae, 0x0a, 0x51, 0x5e, 0x21, 0xbf, 0x13, 0xff, 0x45, 0x97, 0xb2, 0xc9,
    0x91, 0xb1, 0xf9, 0xd3, 0x26, 0xd5, 0xda, 0x18, 0x2c, 0x70, 0x44, 0x7a,
    0x76, 0xe5, 0x03, 0x08, 0x3c, 0x9a, 0xb2, 0x2c, 0x8d, 0x40, 0x5c, 0x53,
    0xaa, 0x01, 0x3c, 0x6c, 0x58, 0x9c, 0x53, 0x7e, 0xa7, 0x1a, 0x1f, 0x74,
    0xa3, 0xfa, 0x96, 0x77, 0xc6, 0x7a, 0x59, 0x72, 0xfe, 0x96, 0x3f, 0xb7,
    0x4c, 0xd0, 0x5f, 0xd3, 0x5b, 0x92, 0x60, 0x77, 0xbc, 0x9c, 0x13, 0x11,
    0x20, 0xad, 0x6c, 0xa0, 0xbc, 0xec, 0xa6, 0x21, 0x7c, 0x0c, 0x45, 0x71,
    0xd3, 0xc0, 0xf6, 0xc7, 0xab, 0x8f, 0x89, 0xc4, 0x87, 0xf1, 0xf1, 0xcc,
    0x8b, 0x6e, 0x69, 0x04, 0x72, 0x57, 0x79, 0x50, 0x84, 0xf4, 0x6f, 0x7a,
    0x8e, 0x1c, 0xc1, 0xb4, 0xf5, 0x2a, 0xbf, 0x7c, 0x86, 0xad, 0xca, 0x81,
    0xa2, 0xc1, 0xd0, 0x4a, 0x9f, 0x4b, 0x5f, 0xd7, 0x11, 0x19, 0x16, 0x3d,
    0xa0, 0x5a, 0xe1, 0xc8, 0x55, 0x54, 0xe7, 0x99, 0xe9, 0x6d, 0xb4, 0x75,
    0x8b, 0x16, 0xad, 0x76, 0x20, 0x2f, 0xd1, 0xad, 0x86, 0x00, 0x8e, 0x5c,
    0x04, 0x1b, 0xf9, 0x21, 0x8e, 0x26, 0xec, 0x35, 0x0d, 0xb0, 0x0b, 0x09,
    0x0a, 0xf5, 0x60, 0x45, 0xfc, 0x61, 0x4b, 0xaa, 0x7a, 0xb7, 0xf7, 0xce,
    0xb2, 0xad, 0xda, 0x78, 0x59, 0x2d, 0xc0, 0xee, 0x61, 0x5e, 0xe2, 0xfc,
};

// Expanded version of the Pyjamask-96 key schedule.
static unsigned char pyjamask_96_ks[] = {
    0x33, 0x22, 0x11, 0x00, 0x77, 0x66, 0x55, 0x44, 0xbb, 0xaa, 0x99, 0x88,
    0x30, 0x3a, 0x0b, 0x81, 0x66, 0x3f, 0x44, 0x77, 0x33, 0x11, 0x48, 0x55,
    0xdf, 0x1a, 0x30, 0x1e, 0xd8, 0x96, 0x8b, 0x34, 0xe1, 0x53, 0xfc, 0xec,
    0xae, 0x0a, 0x51, 0x5e, 0x21, 0xbf, 0x13, 0xff, 0x45, 0x97, 0xb2, 0xc9,
    0x26, 0xd5, 0xda, 0x18, 0x2c, 0x70, 0x44, 0x7a, 0x76, 0xe5, 0x03, 0x08,
    0x8d, 0x40, 0x5c, 0x53, 0xaa, 0x01, 0x3c, 0x6c, 0x58, 0x9c, 0x53, 0x7e,
    0xa3, 0xfa, 0x96, 0x77, 0xc6, 0x7a, 0x59, 0x72, 0xfe, 0x96, 0x3f, 0xb7,
    0x5b, 0x92, 0x60, 0x77, 0xbc, 0x9c, 0x13, 0x11, 0x20, 0xad, 0x6c, 0xa0,
    0x7c, 0x0c, 0x45, 0x71, 0xd3, 0xc0, 0xf6, 0xc7, 0xab, 0x8f, 0x89, 0xc4,
    0x8b, 0x6e, 0x69, 0x04, 0x72, 0x57, 0x79, 0x50, 0x84, 0xf4, 0x6f, 0x7a,
    0xf5, 0x2a, 0xbf, 0x7c, 0x86, 0xad, 0xca, 0x81, 0xa2, 0xc1, 0xd0, 0x4a,
    0x11, 0x19, 0x16, 0x3d, 0xa0, 0x5a, 0xe1, 0xc8, 0x55, 0x54, 0xe7, 0x99,
    0x8b, 0x16, 0xad, 0x76, 0x20, 0x2f, 0xd1, 0xad, 0x86, 0x00, 0x8e, 0x5c,
    0x8e, 0x26, 0xec, 0x35, 0x0d, 0xb0, 0x0b, 0x09, 0x0a, 0xf5, 0x60, 0x45,
    0x7a, 0xb7, 0xf7, 0xce, 0xb2, 0xad, 0xda, 0x78, 0x59, 0x2d, 0xc0, 0xee,
};

static bool test_pyjamask_128_setup_key
    (Code &code, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[240];
    code.exec_setup_key(schedule, sizeof(schedule),
                        test->key, test->key_len);
    if (memcmp(schedule, pyjamask_128_ks, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_pyjamask_128_setup_key(Code &code)
{
    if (!test_pyjamask_128_setup_key(code, &pyjamask_128_1))
        return false;
    return true;
}

bool test_pyjamask_128_encrypt(Code &code)
{
    unsigned char output[16];
    code.exec_encrypt_block(pyjamask_128_ks, sizeof(pyjamask_128_ks),
                            output, 16, pyjamask_128_1.plaintext, 16);
    return !memcmp(output, pyjamask_128_1.ciphertext, 16);
}

bool test_pyjamask_128_decrypt(Code &code)
{
    unsigned char output[16];
    code.exec_decrypt_block(pyjamask_128_ks, sizeof(pyjamask_128_ks),
                            output, 16, pyjamask_128_1.ciphertext, 16);
    return !memcmp(output, pyjamask_128_1.plaintext, 16);
}

static bool test_pyjamask_96_setup_key
    (Code &code, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[180];
    code.exec_setup_key(schedule, sizeof(schedule),
                        test->key, test->key_len);
    if (memcmp(schedule, pyjamask_96_ks, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_pyjamask_96_setup_key(Code &code)
{
    if (!test_pyjamask_96_setup_key(code, &pyjamask_96_1))
        return false;
    return true;
}

bool test_pyjamask_96_encrypt(Code &code)
{
    unsigned char output[12];
    code.exec_encrypt_block(pyjamask_96_ks, sizeof(pyjamask_96_ks),
                            output, 12, pyjamask_96_1.plaintext, 12);
    return !memcmp(output, pyjamask_96_1.ciphertext, 16);
}

bool test_pyjamask_96_decrypt(Code &code)
{
    unsigned char output[12];
    code.exec_decrypt_block(pyjamask_96_ks, sizeof(pyjamask_96_ks),
                            output, 12, pyjamask_96_1.ciphertext, 12);
    return !memcmp(output, pyjamask_96_1.plaintext, 12);
}
