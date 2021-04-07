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

// Extracts a 32-bit word from a bit position within a 128-bit state.
static Reg extract_word
    (Code &code, Reg &temp, int bit,
     const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3,
     bool copy = false)
{
    Reg w0, w1;

    // Handle the word-aligned and byte-aligned cases.
    switch (bit) {
    case 0:     w0 = s0;                                  break;
    case 8:     w0 = Reg(s1, 3, 1).append(Reg(s0, 0, 3)); break;
    case 16:    w0 = Reg(s1, 2, 2).append(Reg(s0, 0, 2)); break;
    case 24:    w0 = Reg(s1, 1, 3).append(Reg(s0, 0, 1)); break;
    case 32:    w0 = s1;                                  break;
    case 40:    w0 = Reg(s2, 3, 1).append(Reg(s1, 0, 3)); break;
    case 48:    w0 = Reg(s2, 2, 2).append(Reg(s1, 0, 2)); break;
    case 56:    w0 = Reg(s2, 1, 3).append(Reg(s1, 0, 1)); break;
    case 64:    w0 = s2;                                  break;
    case 72:    w0 = Reg(s3, 3, 1).append(Reg(s2, 0, 3)); break;
    case 80:    w0 = Reg(s3, 2, 2).append(Reg(s2, 0, 2)); break;
    case 88:    w0 = Reg(s3, 1, 3).append(Reg(s2, 0, 1)); break;
    case 96:    w0 = s3;                                  break;
    }
    if (w0.size() != 0) {
        // We can return the bytes as-is.
        if (copy) {
            temp = code.allocateReg(4);
            code.move(temp, w0);
            return temp;
        } else {
            temp = Reg();
            return w0;
        }
    }

    // Extract 5 bytes from across a word boundary and shift into position.
    temp = code.allocateReg(5);
    if (bit < 32) {
        w0 = s0;
        w1 = s1;
    } else if (bit < 64) {
        w0 = s1;
        w1 = s2;
    } else {
        w0 = s2;
        w1 = s3;
    }
    bit %= 32;
    code.move(Reg(temp, (bit / 8) + 1, 4 - (bit / 8)), w0);
    code.move(Reg(temp, 0, (bit / 8) + 1),
              Reg(w1, 3 - (bit / 8), (bit / 8) + 1));
    if ((bit % 8) <= 4) {
        code.lsl(temp, bit % 8);
        return Reg(temp, 1, 4);
    } else {
        code.lsr(temp, 8 - (bit % 8));
        return Reg(temp, 0, 4);
    }
}

// Extracts a 32-bit word from the Grain128 state and XOR's it with another.
static void xor_word
    (Code &code, const Reg &x, int bit,
     const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    Reg temp;
    Reg ext = extract_word(code, temp, bit, s0, s1, s2, s3);
    code.logxor(x, ext);
    code.releaseReg(temp);
}

// Extracts two 32-bit words from the Grain128 state, AND's them together
// and then XOR's the result with an output register.
static void xor_word_and_2
    (Code &code, const Reg &x, int bit1, int bit2,
     const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    Reg temp1, ext1;
    Reg temp2, ext2;
    ext1 = extract_word(code, temp1, bit1, s0, s1, s2, s3, true);
    ext2 = extract_word(code, temp2, bit2, s0, s1, s2, s3);
    code.logand(ext1, ext2);
    code.logxor(x, ext1);
    code.releaseReg(temp1);
    code.releaseReg(temp2);
}

// Extracts three 32-bit words from the Grain128 state, AND's them together
// and then XOR's the result with an output register.
static void xor_word_and_3
    (Code &code, const Reg &x, int bit1, int bit2, int bit3,
     const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    Reg temp1, ext1;
    Reg temp2, ext2;
    ext1 = extract_word(code, temp1, bit1, s0, s1, s2, s3, true);
    ext2 = extract_word(code, temp2, bit2, s0, s1, s2, s3);
    code.logand(ext1, ext2);
    code.releaseReg(temp2);
    ext2 = extract_word(code, temp2, bit3, s0, s1, s2, s3);
    code.logand(ext1, ext2);
    code.logxor(x, ext1);
    code.releaseReg(temp1);
    code.releaseReg(temp2);
}

// Extracts four 32-bit words from the Grain128 state, AND's them together
// and then XOR's the result with an output register.
static void xor_word_and_4
    (Code &code, const Reg &x, int bit1, int bit2, int bit3, int bit4,
     const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    Reg temp1, ext1;
    Reg temp2, ext2;
    ext1 = extract_word(code, temp1, bit1, s0, s1, s2, s3, true);
    ext2 = extract_word(code, temp2, bit2, s0, s1, s2, s3);
    code.logand(ext1, ext2);
    code.releaseReg(temp2);
    ext2 = extract_word(code, temp2, bit3, s0, s1, s2, s3);
    code.logand(ext1, ext2);
    code.releaseReg(temp2);
    ext2 = extract_word(code, temp2, bit4, s0, s1, s2, s3);
    code.logand(ext1, ext2);
    code.logxor(x, ext1);
    code.releaseReg(temp1);
    code.releaseReg(temp2);
}

void gen_grain128_core(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.  We also have
    // two 32-bit arguments x and x2 to deal with.
    code.prologue_permutation("grain128_core", 0);
    Reg args = code.arg(8);
    Reg x = Reg(args, 4, 4);
    Reg x2 = Reg(args, 0, 4);
    code.setFlag(Code::TempY);
    code.setFlag(Code::TempR0);
    code.setFlag(Code::TempR1);

    // Allocate registers for temporary values.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);

    // From the Grain-128AEAD specification, the LFSR feedback algorithm is:
    //
    //      s'[i] = s[i + 1]
    //      s'[127] = s[0] ^ s[7] ^ s[38] ^ s[70] ^ s[81] ^ s[96] ^ x
    //
    // The bits are numbered from the most significant bit in the first
    // word of the LFSR state.  Calculate the feedback bits 32 at a time.
    code.ldz(s0, 0);
    code.ldz(s1, 4);
    code.ldz(s2, 8);
    code.ldz(s3, 12);
    xor_word(code, x, 0, s0, s1, s2, s3);           // s[0]
    xor_word(code, x, 7, s0, s1, s2, s3);           // s[7]
    xor_word(code, x, 38, s0, s1, s2, s3);          // s[38]
    xor_word(code, x, 70, s0, s1, s2, s3);          // s[70]
    xor_word(code, x, 81, s0, s1, s2, s3);          // s[81]
    xor_word(code, x, 96, s0, s1, s2, s3);          // s[96]
    code.stz(s1, 0);
    code.stz(s2, 4);
    code.stz(s3, 8);
    code.stz(x, 12);
    code.logxor(x2, s0);
    code.releaseReg(x);

    // Perform the NFSR feedback algorithm from the specification:
    //
    //      b'[i] = b[i + 1]
    //      b'[127] = s[0] ^ b[0] ^ b[26] ^ b[56] ^ b[91] ^ b[96]
    //              ^ (b[3] & b[67]) ^ (b[11] & b[13]) ^ (b[17] & b[18])
    //              ^ (b[27] & b[59]) ^ (b[40] & b[48]) ^ (b[61] & b[65])
    //              ^ (b[68] & b[84]) ^ (b[22] & b[24] & b[25])
    //              ^ (b[70] & b[78] & b[82])
    //              ^ (b[88] & b[92] & b[93] & b[95]) ^ x2
    //
    // Once again, we calculate 32 feedback bits in parallel.
    code.ldz(s0, 16);
    code.ldz(s1, 20);
    code.ldz(s2, 24);
    code.ldz(s3, 28);
    xor_word(code, x2,  0, s0, s1, s2, s3);                   // b[0]
    xor_word(code, x2, 26, s0, s1, s2, s3);                   // b[26]
    xor_word(code, x2, 56, s0, s1, s2, s3);                   // b[56]
    xor_word(code, x2, 91, s0, s1, s2, s3);                   // b[91]
    xor_word(code, x2, 96, s0, s1, s2, s3);                   // b[96]
    xor_word_and_2(code, x2, 3, 67, s0, s1, s2, s3);          // b[3] & b[67]
    xor_word_and_2(code, x2, 11, 13, s0, s1, s2, s3);         // b[11] & b[13]
    xor_word_and_2(code, x2, 17, 18, s0, s1, s2, s3);         // b[17] & b[18]
    xor_word_and_2(code, x2, 27, 59, s0, s1, s2, s3);         // b[27] & b[59]
    xor_word_and_2(code, x2, 40, 48, s0, s1, s2, s3);         // b[40] & b[48]
    xor_word_and_2(code, x2, 61, 65, s0, s1, s2, s3);         // b[61] & b[65]
    xor_word_and_2(code, x2, 68, 84, s0, s1, s2, s3);         // b[68] & b[84]
    xor_word_and_3(code, x2, 22, 24, 25, s0, s1, s2, s3);     // b[68] & b[84] & b[25]
    xor_word_and_3(code, x2, 70, 78, 82, s0, s1, s2, s3);     // b[70] & b[78] & b[82]
    xor_word_and_4(code, x2, 88, 92, 93, 95, s0, s1, s2, s3); // b[88] & b[92] & b[93] & b[95]
    code.stz(s1, 16);
    code.stz(s2, 20);
    code.stz(s3, 24);
    code.stz(x2, 28);
}

void gen_grain128_preoutput(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.  We also have a
    // 32-bit return value to generate.
    code.prologue_permutation("grain128_preoutput", 0);
    code.setFlag(Code::TempY);
    code.setFlag(Code::TempR0);
    code.setFlag(Code::TempR1);
    Reg y = code.return_value(4);

    // From the Grain-128AEAD specification, each pre-output bit y is given by:
    //
    //      x[0..8] = b[12], s[8], s[13], s[20], b[95],
    //                s[42], s[60], s[79], s[94]
    //      h(x) = (x[0] & x[1]) ^ (x[2] & x[3]) ^ (x[4] & x[5])
    //           ^ (x[6] & x[7]) ^ (x[0] & x[4] & x[8])
    //      y = h(x) ^ s[93] ^ b[2] ^ b[15] ^ b[36] ^ b[45]
    //               ^ b[64] ^ b[73] ^ b[89]
    //
    // Calculate 32 pre-output bits in parallel.
    Reg x0 = code.allocateReg(5);
    code.ldz(Reg(x0, 2, 3), 16);
    code.ldz(Reg(x0, 0, 2), 22);
    code.lsl(x0, 4);
    code.releaseReg(Reg(x0, 0, 1));
    x0 = Reg(x0, 1, 4);
    Reg x4 = code.allocateReg(5);
    code.ldz(Reg(x4, 4, 1), 24);
    code.ldz(Reg(x4, 0, 4), 28);
    code.lsr(x4, 1);
    code.releaseReg(Reg(x4, 4, 1));
    x4 = Reg(x4, 0, 4);
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2, s3;
    code.ldz(s0, 0);
    code.ldz(s1, 4);
    code.move(Reg(y, 1, 3), s0);
    code.move(Reg(y, 0, 1), Reg(s1, 3, 1));
    code.logand(y, x0);
    xor_word_and_2(code, y, 13, 20, s0, s1, s2, s3);
    s2 = s0;
    s0 = Reg();
    code.ldz(s2, 8);
    Reg temp, ext;
    ext = extract_word(code, temp, 42, s0, s1, s2, s3, true);
    code.logand(ext, x4);
    code.logxor(y, ext);
    code.releaseReg(temp);
    ext = extract_word(code, temp, 60, s0, s1, s2, s3, true);
    s3 = s1;
    s1 = Reg();
    code.ldz(s3, 12);
    Reg temp2, ext2;
    ext2 = extract_word(code, temp2, 79, s0, s1, s2, s3);
    code.logand(ext, ext2);
    code.logxor(y, ext);
    code.releaseReg(temp2);
    code.releaseReg(temp);
    code.logand(x0, x4);
    ext = extract_word(code, temp, 94, s0, s1, s2, s3);
    code.logand(x0, ext);
    code.logxor(y, x0);
    code.releaseReg(temp);
    xor_word(code, y, 93, s0, s1, s2, s3);
    code.releaseReg(x0);
    code.releaseReg(x4);
    s0 = code.allocateReg(4);
    s1 = code.allocateReg(4);
    code.ldz(s0, 16);
    code.ldz(s1, 20);
    code.ldz(s2, 24);
    code.ldz(s3, 28);
    xor_word(code, y,  2, s0, s1, s2, s3);
    xor_word(code, y, 15, s0, s1, s2, s3);
    xor_word(code, y, 36, s0, s1, s2, s3);
    xor_word(code, y, 45, s0, s1, s2, s3);
    xor_word(code, y, 64, s0, s1, s2, s3);
    xor_word(code, y, 73, s0, s1, s2, s3);
    xor_word(code, y, 89, s0, s1, s2, s3);

    // Release the return register.  Reallocated in test_grain128_preoutput().
    code.releaseReg(y);
}

// Swaps the bits in every byte of a word.
static void swap_bits(Code &code, const Reg &x)
{
    Reg temp = code.allocateHighReg(1);
    for (int index = 0; index < x.size(); ++index) {
        Reg xbyte = Reg(x, index, 1);

        // bit_permute_step_simple(x, 0x55555555, 1);
        code.move(temp, xbyte);
        code.logand(temp, 0x55);
        code.lsl(temp, 1);
        code.lsr(xbyte, 1);
        code.logand(xbyte, 0x55);
        code.logor(xbyte, temp);

        // bit_permute_step_simple(tmp, 0x33333333, 2);
        code.move(temp, xbyte);
        code.logand(temp, 0x33);
        code.lsl(temp, 2);
        code.lsr(xbyte, 2);
        code.logand(xbyte, 0x33);
        code.logor(xbyte, temp);

        // bit_permute_step_simple(tmp, 0x0f0f0f0f, 4);
        code.rol(xbyte, 4);
    }
    code.releaseReg(temp);
}

void gen_grain128_swap_word32(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the input data, and we need a 32-bit return word.
    code.prologue_permutation("grain128_swap_word32", 0);
    code.setFlag(Code::NoLocals);
    Reg x = code.return_value(4);

    // Load the input and bit-swap it.
    code.ldz(x.reversed(), 0);
    swap_bits(code, x);
}

void gen_grain128_compute_tag(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("grain128_compute_tag", 0);
    code.setFlag(Code::NoLocals);

    // state->accum ^= state->sr;
    Reg accum = code.allocateHighReg(8);
    code.ldz(accum, 32);
    code.ldz_xor(accum, 40);
    code.stz(accum, 32);

    // Swap the bits in state->accum and write them to state->ks.
    swap_bits(code, accum);
    code.stz(accum.reversed(), 48);
}

void gen_grain128_interleave(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("grain128_interleave", 0);
    code.setFlag(Code::NoLocals);

    // Separate the even and odd bits in each 32-bit word.
    Reg x = code.allocateHighReg(4);
    for (int offset = 0; offset < 16; offset += 4) {
        code.ldz(x, offset);
        code.swapmove(x, 0x11111111, 3);
        code.swapmove(x, 0x03030303, 6);
        code.swapmove(x, 0x000f000f, 12);
        code.stz(x.shuffle(2, 3, 0, 1), offset);
    }
}

// Test vectors for the Grain-128 core and preoutput functions.
static unsigned char const grain128_input[32] = {
    0xfa, 0x5a, 0x8a, 0xec, 0x92, 0x16, 0x9c, 0xe4,
    0xaf, 0x7a, 0xfc, 0xe5, 0x72, 0x6f, 0xda, 0x9c,
    0x55, 0x8e, 0x94, 0x98, 0x6f, 0xcd, 0xa9, 0xa5,
    0xac, 0xfa, 0x2d, 0x6e, 0xd6, 0x73, 0xf6, 0x70
};
static unsigned char const grain128_output[32] = {
    0x6d, 0x5a, 0x24, 0x4f, 0x82, 0x8f, 0x5c, 0x60,
    0x9c, 0xc0, 0xd8, 0x96, 0x24, 0x7c, 0x19, 0xed,
    0x0b, 0xe8, 0x47, 0xb5, 0xd4, 0xa6, 0x27, 0x46,
    0xf4, 0xa5, 0xc4, 0x4b, 0x66, 0x42, 0x97, 0x65
};
static unsigned char const grain128_pre_output[4] = {
    0x4e, 0x8f, 0x5f, 0x86
};

bool test_grain128_core(Code &code)
{
    unsigned char state[32];
    memcpy(state, grain128_input, 32);
    for (unsigned round = 0; round < 8; ++round) {
        uint32_t x = round * 0x11111111U;
        uint32_t y = round * 0x55555555U;
        code.exec_permutation
            (state, 32, (x >> 16) & 0xFFFF, x & 0xFFFF,
             (y >> 16) & 0xFFFF, y & 0xFFFF);
    }
    return !memcmp(grain128_output, state, 32);
}

bool test_grain128_preoutput(Code &code)
{
    unsigned char state[32];
    Reg return_value = code.return_value(4);
    memcpy(state, grain128_output, 32);
    code.stz(return_value, 0); // Store the return value to the output buffer.
    code.exec_permutation(state, 32);
    return !memcmp(grain128_pre_output, state, 4);
}
