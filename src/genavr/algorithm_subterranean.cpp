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

// Bits where data is injected or extracted.
static unsigned short const duplex_bits[33] = {
    1, 176, 136, 35, 249, 134, 197, 234, 64, 213, 223, 184,
    2, 95, 15, 70, 241, 11, 137, 211, 128, 169, 189, 111, 4,
    190, 30, 140, 225, 22, 17, 165, 256
};
static unsigned short const duplex_bits_2[32] = {
    256, 81, 121, 222, 8, 123, 60, 23, 193, 44, 34, 73, 255,
    162, 242, 187, 16, 246, 120, 46, 129, 88, 68, 146, 253,
    67, 227, 117, 32, 235, 240, 92
};

void gen_subterranean_permutation(Code &code)
{
    // Set up the function prologue with 32 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("subterranean_round", 32);

    // Allocate temporary registers.
    Reg t0full = code.allocateHighReg(2);
    Reg t0 = Reg(t0full, 0, 1);
    Reg t1 = code.allocateReg(8);
    Reg t2 = code.allocateReg(8);
    Reg t3 = code.allocateReg(8);

    // Step chi, for each bit: s[i] = s[i] ^ (~(s[i+1]) & s[i+2])
    #define CHI(offset, size) \
        do { \
            Reg t1x = Reg(t1, 0, (size)); \
            Reg t2x = Reg(t2, 0, (size)); \
            Reg t3x = Reg(t3, 0, (size)); \
            Reg t1y = Reg(t1, 0, (size) - 1); \
            Reg t2y = Reg(t2, 0, (size) - 1); \
            Reg t3y = Reg(t3, 0, (size) - 1); \
            if ((size) == 5) { \
                code.ldz(Reg(t1x, 1, (size) - 2), (offset) + 1); \
                code.move(Reg(t1x, (size) - 1, 1), t0); \
            } else if ((offset) != 0) { \
                code.ldz(Reg(t1x, 1, (size) - 1), (offset) + 1); \
            } \
            code.move(t2x, t1x); \
            code.lsr(t2x, 1); \
            code.move(t3x, t2x); \
            code.lsr(t3x, 1); \
            code.lognot(t2y); \
            code.logand(t2y, t3y); \
            code.logxor(t1y, t2y); \
            if ((offset) == 0) { \
                /* Step iota */ \
                code.releaseReg(t3); /* Need a spare high register */ \
                code.logxor(Reg(t1, 0, 1), 0x01); \
                t3 = code.allocateReg(8); \
            } \
            code.stlocal(t1y, (offset)); \
            if ((size) == 8) { \
                /* Move the last byte of t1 down to the first */ \
                code.move(Reg(t1, 0, 1), Reg(t1, (size) - 1, 1)); \
            } \
        } while (0)
    code.ldz(t1, 0);
    code.move(t0, Reg(t1, 0, 1));   // t0 = (s[0..7] << 1) ^ s[256]
    code.lsl(t0, 1);
    code.ldz_xor(t0, 32);
    CHI(0, 8);                      // Apply chi 7 bytes at a time.
    CHI(7, 8);
    CHI(14, 8);
    CHI(21, 8);
    CHI(28, 5);
    code.move(Reg(t1, 0, 1), t0);   // t0 ^= (~(t0 >> 1)) & (t0 >> 2)
    code.lsr(Reg(t1, 0, 1), 1);
    code.move(Reg(t1, 1, 1), Reg(t1, 0, 1));
    code.lsr(Reg(t1, 1, 1), 1);
    code.lognot(Reg(t1, 0, 1));
    code.logand(Reg(t1, 0, 1), Reg(t1, 1, 1));
    code.logxor(t0, Reg(t1, 0, 1));
    code.logand(t0, 0x01);          // Reduce the final byte to 1 bit.

    // Step theta, for each bit: s[i] = s[i] ^ s[i + 3] ^ s[i + 8]
    #define THETA(offset, size) \
        do { \
            Reg t1x = Reg(t1, 0, (size)); \
            Reg t2x = Reg(t2, 0, (size)); \
            Reg t1y = Reg(t1, 0, (size) - 1); \
            Reg t2y = Reg(t2, 0, (size) - 1); \
            if ((size) == 5) { \
                code.ldlocal(Reg(t1x, 1, (size) - 2), (offset) + 1); \
                code.move(Reg(t1x, (size) - 1, 1), t0); \
            } else if ((offset) != 0) { \
                code.ldlocal(Reg(t1x, 1, (size) - 1), (offset) + 1); \
            } \
            code.move(t2x, t1x); \
            code.lsr(t2x, 3); \
            code.logxor(t1y, Reg(t1x, 1, (size) - 1)); \
            code.logxor(t1y, t2y); \
            code.stlocal(t1y, (offset)); \
            if ((size) == 8) { \
                /* Move the last byte of t1 down to the first */ \
                code.move(Reg(t1, 0, 1), Reg(t1, (size) - 1, 1)); \
            } \
        } while (0)
    code.ldlocal(t1, 0);
    code.move(Reg(t2, 0, 2), Reg(t1, 0, 2));
    code.lsl(Reg(t2, 0, 2), 1);
    code.logxor(t0, Reg(t2, 0, 1));
    code.move(Reg(t0full, 1, 1), Reg(t2, 1, 1));
    THETA(0, 8);                    // Apply theta 7 bytes at a time.
    THETA(7, 8);
    THETA(14, 8);
    THETA(21, 8);
    THETA(28, 5);
    code.move(Reg(t1, 0, 1), t0);   // t0 ^= (t0 >> 3) ^ (t0 >> 8);
    code.lsr(Reg(t1, 0, 1), 3);     // We only need the bit 0 in the result.
    code.logxor(t0, Reg(t0full, 1, 1));
    code.logxor(t0, Reg(t1, 0, 1));

    // Step pi, permute the entire state: s'[i] = s[(i * 12) % 257]

    // Invert pi to find the destination bit for each source bit.
    short dest_bit[257] = {0};
    for (int i = 0; i < 257; ++i)
        dest_bit[(i * 12) % 257] = i;

    // Allocate new registers so we can keep as much of the output
    // in registers as long as possible before flushing back to Z.
    code.releaseReg(t1);
    code.releaseReg(t2);
    code.releaseReg(t3);
    t1 = code.allocateReg(23);
    t2 = code.allocateReg(1);

    // Collect up the destination bits for the first 23 bytes of the output.
    int cached_i = -1;
    for (int i = 0; i < 257; ++i) {
        int j = dest_bit[i];
        if (j >= (23 * 8))
            continue;
        if (i == 256) {
            // Special case for the final bit of the input - it is in t0.
            code.bit_get(t0, 0);
            code.bit_put(t1, j);
            continue;
        }
        if (cached_i != (i / 8)) {
            cached_i = i / 8;
            code.ldlocal(t2, cached_i);
        }
        code.bit_get(t2, i % 8);
        code.bit_put(t1, j);
    }
    code.stz(t1, 0);

    // Collect up the destination bits for the last 10 bytes of the output.
    code.releaseReg(t1);
    t1 = code.allocateReg(10);
    code.move(Reg(t1, 9, 1), 0); // Last byte contains only 1 bit, clear others.
    for (int i = 0; i < 257; ++i) {
        int j = dest_bit[i] - 23 * 8;
        if (j < 0)
            continue;
        if (i == 256) {
            // Special case for the final bit of the input - it is in t0.
            code.bit_get(t0, 0);
            code.bit_put(t1, j);
            continue;
        }
        if (cached_i != (i / 8)) {
            cached_i = i / 8;
            code.ldlocal(t2, cached_i);
        }
        code.bit_get(t2, i % 8);
        code.bit_put(t1, j);
    }
    code.stz(t1, 23);
}

void gen_subterranean_absorb(Code &code, int count)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg arg;
    if (count == 1) {
        code.prologue_permutation("subterranean_absorb_1", 0);
        arg = code.arg(2);
        code.move(Reg(arg, 1, 1), 1); // 9th bit must be set to 1 for padding.
    } else {
        code.prologue_permutation("subterranean_absorb_word", 0);
        arg = code.arg(4);
    }
    code.setFlag(Code::NoLocals);

    // Invert the bit permutation so that we know which source
    // bit corresponds to each destination bit.
    short dest_bit[257];
    for (int i = 0; i < 257; ++i)
        dest_bit[i] = -1;
    for (int i = 0; i < 32; ++i) {
        if (count == 1 && i >= 9)
            break;
        dest_bit[duplex_bits[i]] = i;
    }

    // Iterate over all state bits and pick across the source bits.
    Reg temp = code.allocateReg(1);
    int cached_i = -1;
    int dirty_i = -1;
    for (int i = 0; i < 257; ++i) {
        int j = dest_bit[i];
        if (j < 0)
            continue;
        if (cached_i != (i / 8)) {
            cached_i = i / 8;
            if (dirty_i != -1)
                code.ldz_xor_in(temp, dirty_i);
            code.move(temp, 0);
            dirty_i = cached_i;
        }
        code.bit_get(arg, j);
        code.bit_put(temp, i % 8);
    }
    code.ldz_xor_in(temp, dirty_i);
}

void gen_subterranean_extract(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("subterranean_extract", 0);
    Reg word1 = code.return_value(4);
    Reg word2 = code.allocateReg(4);
    code.setFlag(Code::NoLocals);

    // Invert the bit permutation so that we know which extracted
    // bit corresponds to each state bit.
    short dest_bit[257];
    for (int i = 0; i < 257; ++i)
        dest_bit[i] = -1;
    for (int i = 0; i < 32; ++i) {
        dest_bit[duplex_bits[i]] = i;
        dest_bit[duplex_bits_2[i]] = 32 + i;
    }

    // Iterate over all state bits and pick across the bits we need.
    Reg temp = code.allocateReg(1);
    int cached_i = -1;
    for (int i = 0; i < 257; ++i) {
        int j = dest_bit[i];
        if (j < 0)
            continue;
        if (cached_i != (i / 8)) {
            cached_i = i / 8;
            code.ldz(temp, cached_i);
        }
        code.bit_get(temp, i % 8);
        if (j < 32)
            code.bit_put(word1, j);
        else
            code.bit_put(word2, j - 32);
    }

    // XOR the two 32-bit halves together to generate the result.
    code.logxor(word1, word2);
}

bool test_subterranean_permutation(Code &code)
{
    // Test vectors for Subterranean generated with the reference code.
    static unsigned char const input[] = {
        0x81, 0xbb, 0xd3, 0xe3, 0xa1, 0x9d, 0x4e, 0x80,
        0xac, 0x00, 0xfe, 0xf5, 0x8f, 0x22, 0x0f, 0xbc,
        0x1c, 0x84, 0x40, 0x37, 0x8f, 0x49, 0x43, 0x71,
        0x84, 0x69, 0x48, 0x31, 0x0b, 0xf0, 0xa5, 0x71,
        0x01
    };
    static unsigned char const output[] = {
        0xdb, 0xd1, 0x37, 0xe4, 0xaa, 0x4c, 0x09, 0x8d,
        0x5f, 0x85, 0x57, 0x2d, 0x72, 0x6c, 0x12, 0xd2,
        0x69, 0x52, 0xf0, 0x61, 0x47, 0x7e, 0x72, 0x1c,
        0x6b, 0x8a, 0xab, 0x94, 0x41, 0x56, 0xf0, 0x18,
        0x01
    };
    unsigned char state[33];
    memcpy(state, input, 33);
    for (int round = 0; round < 8; ++round) {
        code.exec_permutation(state, 33);
        state[0] ^= 0x02; // Emulate the "blank" function from the ref code.
    }
    return !memcmp(output, state, 33);
}
