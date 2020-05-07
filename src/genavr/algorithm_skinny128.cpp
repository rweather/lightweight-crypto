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
#include <iostream>

// S-box tables that are used by SKINNY-128.
#define SBOX_MAIN 0
#define SBOX_MAIN_INV 1
#define SBOX_LFSR2 2
#define SBOX_LFSR3 3
#define SBOX_RC 4

// S-box for SKINNY-128.
static unsigned char const sbox[256] = {
    0x65, 0x4c, 0x6a, 0x42, 0x4b, 0x63, 0x43, 0x6b, 0x55, 0x75, 0x5a, 0x7a,
    0x53, 0x73, 0x5b, 0x7b, 0x35, 0x8c, 0x3a, 0x81, 0x89, 0x33, 0x80, 0x3b,
    0x95, 0x25, 0x98, 0x2a, 0x90, 0x23, 0x99, 0x2b, 0xe5, 0xcc, 0xe8, 0xc1,
    0xc9, 0xe0, 0xc0, 0xe9, 0xd5, 0xf5, 0xd8, 0xf8, 0xd0, 0xf0, 0xd9, 0xf9,
    0xa5, 0x1c, 0xa8, 0x12, 0x1b, 0xa0, 0x13, 0xa9, 0x05, 0xb5, 0x0a, 0xb8,
    0x03, 0xb0, 0x0b, 0xb9, 0x32, 0x88, 0x3c, 0x85, 0x8d, 0x34, 0x84, 0x3d,
    0x91, 0x22, 0x9c, 0x2c, 0x94, 0x24, 0x9d, 0x2d, 0x62, 0x4a, 0x6c, 0x45,
    0x4d, 0x64, 0x44, 0x6d, 0x52, 0x72, 0x5c, 0x7c, 0x54, 0x74, 0x5d, 0x7d,
    0xa1, 0x1a, 0xac, 0x15, 0x1d, 0xa4, 0x14, 0xad, 0x02, 0xb1, 0x0c, 0xbc,
    0x04, 0xb4, 0x0d, 0xbd, 0xe1, 0xc8, 0xec, 0xc5, 0xcd, 0xe4, 0xc4, 0xed,
    0xd1, 0xf1, 0xdc, 0xfc, 0xd4, 0xf4, 0xdd, 0xfd, 0x36, 0x8e, 0x38, 0x82,
    0x8b, 0x30, 0x83, 0x39, 0x96, 0x26, 0x9a, 0x28, 0x93, 0x20, 0x9b, 0x29,
    0x66, 0x4e, 0x68, 0x41, 0x49, 0x60, 0x40, 0x69, 0x56, 0x76, 0x58, 0x78,
    0x50, 0x70, 0x59, 0x79, 0xa6, 0x1e, 0xaa, 0x11, 0x19, 0xa3, 0x10, 0xab,
    0x06, 0xb6, 0x08, 0xba, 0x00, 0xb3, 0x09, 0xbb, 0xe6, 0xce, 0xea, 0xc2,
    0xcb, 0xe3, 0xc3, 0xeb, 0xd6, 0xf6, 0xda, 0xfa, 0xd3, 0xf3, 0xdb, 0xfb,
    0x31, 0x8a, 0x3e, 0x86, 0x8f, 0x37, 0x87, 0x3f, 0x92, 0x21, 0x9e, 0x2e,
    0x97, 0x27, 0x9f, 0x2f, 0x61, 0x48, 0x6e, 0x46, 0x4f, 0x67, 0x47, 0x6f,
    0x51, 0x71, 0x5e, 0x7e, 0x57, 0x77, 0x5f, 0x7f, 0xa2, 0x18, 0xae, 0x16,
    0x1f, 0xa7, 0x17, 0xaf, 0x01, 0xb2, 0x0e, 0xbe, 0x07, 0xb7, 0x0f, 0xbf,
    0xe2, 0xca, 0xee, 0xc6, 0xcf, 0xe7, 0xc7, 0xef, 0xd2, 0xf2, 0xde, 0xfe,
    0xd7, 0xf7, 0xdf, 0xff
};
static unsigned char const sbox_inv[256] = {
    0xac, 0xe8, 0x68, 0x3c, 0x6c, 0x38, 0xa8, 0xec, 0xaa, 0xae, 0x3a, 0x3e,
    0x6a, 0x6e, 0xea, 0xee, 0xa6, 0xa3, 0x33, 0x36, 0x66, 0x63, 0xe3, 0xe6,
    0xe1, 0xa4, 0x61, 0x34, 0x31, 0x64, 0xa1, 0xe4, 0x8d, 0xc9, 0x49, 0x1d,
    0x4d, 0x19, 0x89, 0xcd, 0x8b, 0x8f, 0x1b, 0x1f, 0x4b, 0x4f, 0xcb, 0xcf,
    0x85, 0xc0, 0x40, 0x15, 0x45, 0x10, 0x80, 0xc5, 0x82, 0x87, 0x12, 0x17,
    0x42, 0x47, 0xc2, 0xc7, 0x96, 0x93, 0x03, 0x06, 0x56, 0x53, 0xd3, 0xd6,
    0xd1, 0x94, 0x51, 0x04, 0x01, 0x54, 0x91, 0xd4, 0x9c, 0xd8, 0x58, 0x0c,
    0x5c, 0x08, 0x98, 0xdc, 0x9a, 0x9e, 0x0a, 0x0e, 0x5a, 0x5e, 0xda, 0xde,
    0x95, 0xd0, 0x50, 0x05, 0x55, 0x00, 0x90, 0xd5, 0x92, 0x97, 0x02, 0x07,
    0x52, 0x57, 0xd2, 0xd7, 0x9d, 0xd9, 0x59, 0x0d, 0x5d, 0x09, 0x99, 0xdd,
    0x9b, 0x9f, 0x0b, 0x0f, 0x5b, 0x5f, 0xdb, 0xdf, 0x16, 0x13, 0x83, 0x86,
    0x46, 0x43, 0xc3, 0xc6, 0x41, 0x14, 0xc1, 0x84, 0x11, 0x44, 0x81, 0xc4,
    0x1c, 0x48, 0xc8, 0x8c, 0x4c, 0x18, 0x88, 0xcc, 0x1a, 0x1e, 0x8a, 0x8e,
    0x4a, 0x4e, 0xca, 0xce, 0x35, 0x60, 0xe0, 0xa5, 0x65, 0x30, 0xa0, 0xe5,
    0x32, 0x37, 0xa2, 0xa7, 0x62, 0x67, 0xe2, 0xe7, 0x3d, 0x69, 0xe9, 0xad,
    0x6d, 0x39, 0xa9, 0xed, 0x3b, 0x3f, 0xab, 0xaf, 0x6b, 0x6f, 0xeb, 0xef,
    0x26, 0x23, 0xb3, 0xb6, 0x76, 0x73, 0xf3, 0xf6, 0x71, 0x24, 0xf1, 0xb4,
    0x21, 0x74, 0xb1, 0xf4, 0x2c, 0x78, 0xf8, 0xbc, 0x7c, 0x28, 0xb8, 0xfc,
    0x2a, 0x2e, 0xba, 0xbe, 0x7a, 0x7e, 0xfa, 0xfe, 0x25, 0x70, 0xf0, 0xb5,
    0x75, 0x20, 0xb0, 0xf5, 0x22, 0x27, 0xb2, 0xb7, 0x72, 0x77, 0xf2, 0xf7,
    0x2d, 0x79, 0xf9, 0xbd, 0x7d, 0x29, 0xb9, 0xfd, 0x2b, 0x2f, 0xbb, 0xbf,
    0x7b, 0x7f, 0xfb, 0xff
};

Sbox get_skinny128_sbox(int num)
{
    switch (num) {
    case SBOX_MAIN: default: break;
    case SBOX_MAIN_INV:
        return Sbox(sbox_inv, sizeof(sbox_inv));
    case SBOX_LFSR2: {
        unsigned char lfsr2[256];
        for (int index = 0; index < 256; ++index) {
            lfsr2[index] = ((index << 1) & 0xFE) ^
                           (((index >> 7) ^ (index >> 5)) & 0x01);
        }
        return Sbox(lfsr2, sizeof(lfsr2)); }
    case SBOX_LFSR3: {
        unsigned char lfsr3[256];
        for (int index = 0; index < 256; ++index) {
            lfsr3[index] = ((index >> 1) & 0x7F) ^
                           (((index << 7) ^ (index << 1)) & 0x80);
        }
        return Sbox(lfsr3, sizeof(lfsr3)); }
    case SBOX_RC: {
        unsigned char rc_table[56 * 2];
        int rc = 0;
        for (int index = 0; index < 56; ++index) {
            // Generate the round constants and split into high and low nibbles.
            rc = (rc << 1) ^ ((rc >> 5) & 0x01) ^ ((rc >> 4) & 0x01) ^ 0x01;
            rc &= 0x3F;
            rc_table[index * 2]     = (rc & 0x0F);
            rc_table[index * 2 + 1] = ((rc >> 4) & 0x0F);
        }
        return Sbox(rc_table, sizeof(rc_table)); }
    }
    return Sbox(sbox, sizeof(sbox));
}

// Permutes the TK value at a specific local variable offset.  If "with_lfsr"
// is true, then also apply an LFSR to the first two output rows.
static void skinny128_permute_tk(Code &code, unsigned offset, bool with_lfsr)
{
    // PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
    // The caller implicitly swaps the two halves so we only need to
    // care about what used to be the second half - now the first.
    Reg row2 = code.allocateReg(4);
    Reg row3 = code.allocateReg(4);
    code.ldy(row2, offset);
    code.ldy(row3, offset + 4);
    if (with_lfsr) {
        code.sbox_lookup(row2, row2);
        code.sbox_lookup(row3, row3);
    }
    code.memory(Insn::ST_Y, row2.reg(1), offset);       // 9
    code.memory(Insn::ST_Y, row3.reg(3), offset + 1);   // 15
    code.memory(Insn::ST_Y, row2.reg(0), offset + 2);   // 8
    code.memory(Insn::ST_Y, row3.reg(1), offset + 3);   // 13
    code.memory(Insn::ST_Y, row2.reg(2), offset + 4);   // 10
    code.memory(Insn::ST_Y, row3.reg(2), offset + 5);   // 14
    code.memory(Insn::ST_Y, row3.reg(0), offset + 6);   // 12
    code.memory(Insn::ST_Y, row2.reg(3), offset + 7);   // 11
    code.releaseReg(row2);
    code.releaseReg(row3);
}

// Inverse permute the TK value at a specific local variable offset.
// If "with_lfsr" is true, then also apply an LFSR to the last two output rows.
static void skinny128_inv_permute_tk
    (Code &code, unsigned offset, bool with_lfsr)
{
    // PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1]
    // The caller implicitly swaps the two halves so we only need to
    // care about what used to be the first half - now the second.
    Reg row0 = code.allocateReg(4);
    Reg row1 = code.allocateReg(4);
    code.ldy(row0, offset);
    code.ldy(row1, offset + 4);
    if (with_lfsr) {
        code.sbox_lookup(row0, row0);
        code.sbox_lookup(row1, row1);
    }
    code.memory(Insn::ST_Y, row0.reg(2), offset);       // 2
    code.memory(Insn::ST_Y, row0.reg(0), offset + 1);   // 0
    code.memory(Insn::ST_Y, row1.reg(0), offset + 2);   // 4
    code.memory(Insn::ST_Y, row1.reg(3), offset + 3);   // 7
    code.memory(Insn::ST_Y, row1.reg(2), offset + 4);   // 6
    code.memory(Insn::ST_Y, row0.reg(3), offset + 5);   // 3
    code.memory(Insn::ST_Y, row1.reg(1), offset + 6);   // 5
    code.memory(Insn::ST_Y, row0.reg(1), offset + 7);   // 1
    code.releaseReg(row0);
    code.releaseReg(row1);
}

// Applies an LFSR repeatedly to all 16 bytes of a TK value.
static void skinny128_apply_lfsr(Code &code, int offset, int rounds)
{
    Reg round = code.allocateHighReg(1);
    Reg temp = code.allocateReg(8);
    unsigned char label;

    // Deal with the left half of the TK value.
    label = 0;
    code.move(round, rounds / 2);
    code.ldy(temp, offset);
    code.label(label);
    code.sbox_lookup(temp, temp);
    code.dec(round);
    code.brne(label);
    code.sty(temp, offset);

    // Deal with the right half of the TK value.
    label = 0;
    code.move(round, rounds / 2);
    code.ldy(temp, offset + 8);
    code.label(label);
    code.sbox_lookup(temp, temp);
    code.dec(round);
    code.brne(label);
    code.sty(temp, offset + 8);

    // Clean up.
    code.releaseReg(round);
    code.releaseReg(temp);
}

// Generate the SKINNY-128 key setup function.
static void gen_skinny128_setup_key(Code &code, const char *name, int ks_size)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key(name, 0);
    code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Copy all of the key bytes to the schedule.  We expand the schedule
    // on the fly so no need to do anything else but a copy.
    Reg temp = code.allocateReg(4);
    Reg size = code.allocateHighReg(1);
    unsigned char label = 0;
    code.move(size, ks_size / 4);
    code.label(label);
    code.ldx(temp, POST_INC);
    code.stz(temp, POST_INC);
    code.dec(size);
    code.brne(label);
}

// Generate the SKINNY-128 encryption function.  We assume that the key
// schedule is always "ks_size" bytes and expanded on the fly.
static void gen_skinny128_encrypt(Code &code, const char *name, int ks_size)
{
    // Set up the function prologue with ks_size bytes of local variables.
    // X will point to the input, Z points to the key, Y is local variables.
    code.prologue_encrypt_block(name, ks_size);

    // Allocate the registers that we need.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);

    // Copy the key schedule to local variables.
    for (int offset = 0; offset < ks_size; offset += 4) {
        code.ldz(s0, offset);
        code.sty(s0, offset);
    }

    // Load the input state from X into registers.
    code.ldx(s0, POST_INC);
    code.ldx(s1, POST_INC);
    code.ldx(s2, POST_INC);
    code.ldx(s3, POST_INC);

    // No longer need X so convert it into temporary registers.
    code.setFlag(Code::TempX);

    // Set up Z to point at the main S-box table.
    code.sbox_setup(SBOX_MAIN, get_skinny128_sbox(SBOX_MAIN));

    // Top of the round loop.  We unroll four rounds at a time to
    // reduce the permutation overhead from round to round.
    unsigned char top_label = 0;
    unsigned char end_label = 0;
    int rounds = (ks_size == 48) ? 56 : 48;
    Reg round = code.allocateHighReg(1);
    code.move(round, 0);
    code.label(top_label);

    // Execute the 4 unrolled inner rounds.
    int shift = 0;
    for (int inner = 0; inner < 4; ++inner) {
        // Apply the S-box to all bytes in the state.
        code.sbox_lookup(s0, s0);
        code.sbox_lookup(s1, s1);
        code.sbox_lookup(s2, s2);
        code.sbox_lookup(s3, s3);

        // XOR the round constant for this round.
        Reg rc = code.allocateReg(1);
        code.sbox_switch(SBOX_RC, get_skinny128_sbox(SBOX_RC));
        code.sbox_lookup(rc, round);
        code.logxor(s0, rc);
        code.inc(round);
        code.sbox_lookup(rc, round);
        code.logxor(s1, rc);
        code.inc(round);
        code.releaseReg(rc);
        code.logxor(s2, 2);

        // XOR the subkeys for this round.
        if (ks_size == 48) {
            code.ldy_xor(s0, shift + 0);    // TK1[0]
            code.ldy_xor(s0, shift + 16);   // TK2[0]
            code.ldy_xor(s0, shift + 32);   // TK3[0]
            code.ldy_xor(s1, shift + 4);    // TK1[1]
            code.ldy_xor(s1, shift + 20);   // TK2[1]
            code.ldy_xor(s1, shift + 36);   // TK3[1]
        } else {
            code.ldy_xor(s0, shift + 0);    // TK1[0]
            code.ldy_xor(s0, shift + 16);   // TK2[0]
            code.ldy_xor(s1, shift + 4);    // TK1[1]
            code.ldy_xor(s1, shift + 20);   // TK2[1]
        }

        // Shift the cells in the rows.
        code.rol(s1, 8);
        code.rol(s2, 16);
        code.rol(s3, 24);

        // Mix the columns.  This involves rotating the four words
        // of the state.  We do the rotation virtually.  After four
        // rounds the order will return to the original position.
        code.logxor(s1, s2);
        code.logxor(s2, s0);
        code.logxor(s3, s2);
        Reg t0 = s3;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = t0;

        // Bail out if this is the last round.  We only need to do this
        // on the last inner round out of the set of 4.
        if (inner == 3) {
            code.compare(round, rounds * 2);
            code.breq(end_label);
        }

        // Permute TK1, TK2, and TK3 for the next round.  Normally we would
        // need to swap the two halves, but we do that virtually and only
        // rearrange one of the halves.
        shift ^= 8;
        skinny128_permute_tk(code, shift, false);           // TK1
        code.sbox_switch(SBOX_LFSR2, get_skinny128_sbox(SBOX_LFSR2));
        skinny128_permute_tk(code, 16 + shift, true);       // TK2
        if (ks_size == 48) {
            code.sbox_switch(SBOX_LFSR3, get_skinny128_sbox(SBOX_LFSR3));
            skinny128_permute_tk(code, 32 + shift, true);   // TK3
        }

        // Reset the S-box pointer for the next round.
        code.sbox_switch(SBOX_MAIN, get_skinny128_sbox(SBOX_MAIN));
    }
    code.jmp(top_label);

    // Clean up and save the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    code.stx(s0, POST_INC);
    code.stx(s1, POST_INC);
    code.stx(s2, POST_INC);
    code.stx(s3, POST_INC);
}

// Generate the SKINNY-128 decryption function.  We assume that the key
// schedule is always "ks_size" bytes and expanded on the fly.
static void gen_skinny128_decrypt(Code &code, const char *name, int ks_size)
{
    // Set up the function prologue with ks_size bytes of local variables.
    // X will point to the input, Z points to the key, Y is local variables.
    code.prologue_decrypt_block(name, ks_size);

    // Allocate the registers that we need.
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);

    // Copy the key schedule to local variables and fast-forward it.
    // For SKINNY-128-384, we need to permute TK1, TK2, and TK3 by 8
    // rounds of permutations.  Not needed for SKINNY-128-256 because
    // the number of rounds is a multiple of 16.
    // PT*8 = [5, 6, 3, 2, 7, 0, 1, 4, 13, 14, 11, 10, 15, 8, 9, 12]
    for (int offset = 0; offset < ks_size; offset += 16) {
        code.ldz(s0, offset);
        code.ldz(s1, offset + 4);
        code.ldz(s2, offset + 8);
        code.ldz(s3, offset + 12);
        if (ks_size == 48) {
            // Apply the permutation as we store the TK value to locals.
            code.sty(Reg(s1, 1, 1), offset);        // 5
            code.sty(Reg(s1, 2, 1), offset + 1);    // 6
            code.sty(Reg(s0, 3, 1), offset + 2);    // 3
            code.sty(Reg(s0, 2, 1), offset + 3);    // 2
            code.sty(Reg(s1, 3, 1), offset + 4);    // 7
            code.sty(Reg(s0, 0, 1), offset + 5);    // 0
            code.sty(Reg(s0, 1, 1), offset + 6);    // 1
            code.sty(Reg(s1, 0, 1), offset + 7);    // 4
            code.sty(Reg(s3, 1, 1), offset + 8);    // 13
            code.sty(Reg(s3, 2, 1), offset + 9);    // 14
            code.sty(Reg(s2, 3, 1), offset + 10);   // 11
            code.sty(Reg(s2, 2, 1), offset + 11);   // 10
            code.sty(Reg(s3, 3, 1), offset + 12);   // 15
            code.sty(Reg(s2, 0, 1), offset + 13);   // 8
            code.sty(Reg(s2, 1, 1), offset + 14);   // 9
            code.sty(Reg(s3, 0, 1), offset + 15);   // 12
        } else {
            // Copy the value as-is for SKINNY-128-256.
            code.sty(s0, offset);
            code.sty(s1, offset + 4);
            code.sty(s2, offset + 8);
            code.sty(s3, offset + 12);
        }
    }

    // Load the input state from X into registers.
    code.ldx(s0, POST_INC);
    code.ldx(s1, POST_INC);
    code.ldx(s2, POST_INC);
    code.ldx(s3, POST_INC);

    // No longer need X so convert it into temporary registers.
    code.setFlag(Code::TempX);

    // Apply LFSR2 and LFSR3 to every byte of TK2 and TK3 "rounds / 2" times.
    // We set things up to leave the LFSR3 pointer in the Z register.
    int rounds = (ks_size == 48) ? 56 : 48;
    if (ks_size == 48) {
        code.sbox_setup(SBOX_LFSR2, get_skinny128_sbox(SBOX_LFSR2));
        skinny128_apply_lfsr(code, 16, rounds);
        code.sbox_switch(SBOX_LFSR3, get_skinny128_sbox(SBOX_LFSR3));
        skinny128_apply_lfsr(code, 32, rounds);
    } else {
        code.sbox_setup(SBOX_LFSR2, get_skinny128_sbox(SBOX_LFSR2));
        skinny128_apply_lfsr(code, 16, rounds);
        code.sbox_switch(SBOX_LFSR3, get_skinny128_sbox(SBOX_LFSR3));
    }

    // Top of the round loop.  We unroll four rounds at a time to
    // reduce the permutation overhead from round to round.
    unsigned char top_label = 0;
    unsigned char end_label = 0;
    Reg round = code.allocateHighReg(1);
    code.move(round, rounds * 2);
    code.label(top_label);

    // Execute the 4 unrolled inner rounds.
    int shift = 0;
    for (int inner = 0; inner < 4; ++inner) {
        // Inverse permutation of TK1, TK2, and TK3 for the next round.
        skinny128_inv_permute_tk(code, shift + 0, false);       // TK1
        skinny128_inv_permute_tk(code, shift + 16, true);       // TK2
        if (ks_size == 48) {
            code.sbox_switch(SBOX_LFSR2, get_skinny128_sbox(SBOX_LFSR2));
            skinny128_inv_permute_tk(code, shift + 32, true);   // TK3
        }
        shift ^= 8;

        // Inverse mix of the columns.  This involves rotating the four words
        // of the state.  We do the rotation virtually.  After four rounds
        // the order will return to the original position.
        Reg t0 = s3;
        s3 = s0;
        s0 = s1;
        s1 = s2;
        s2 = t0;
        code.logxor(s3, t0);
        code.logxor(s2, s0);
        code.logxor(s1, s2);

        // Inverse shift of the cells in the rows.
        code.ror(s1, 8);
        code.ror(s2, 16);
        code.ror(s3, 24);

        // XOR the subkeys for this round.
        if (ks_size == 48) {
            code.ldy_xor(s0, shift + 0);        // TK1[0]
            code.ldy_xor(s0, shift + 16);       // TK2[0]
            code.ldy_xor(s0, shift + 32);       // TK3[0]
            code.ldy_xor(s1, shift + 4);        // TK1[1]
            code.ldy_xor(s1, shift + 20);       // TK2[1]
            code.ldy_xor(s1, shift + 36);       // TK3[1]
        } else {
            code.ldy_xor(s0, shift + 0);        // TK1[0]
            code.ldy_xor(s0, shift + 16);       // TK2[0]
            code.ldy_xor(s1, shift + 4);        // TK1[1]
            code.ldy_xor(s1, shift + 20);       // TK2[1]
        }

        // XOR the round constant for this round.
        Reg rc = code.allocateReg(1);
        code.sbox_switch(SBOX_RC, get_skinny128_sbox(SBOX_RC));
        code.dec(round);
        code.sbox_lookup(rc, round);
        code.logxor(s1, rc);
        code.dec(round);
        code.sbox_lookup(rc, round);
        code.logxor(s0, rc);
        code.releaseReg(rc);
        code.logxor(s2, 2);

        // Apply the inverse of the S-box to all bytes in the state.
        code.sbox_switch(SBOX_MAIN_INV, get_skinny128_sbox(SBOX_MAIN_INV));
        code.sbox_lookup(s0, s0);
        code.sbox_lookup(s1, s1);
        code.sbox_lookup(s2, s2);
        code.sbox_lookup(s3, s3);

        // Test for the last round at the bottom of the inner loop.
        if (inner == 3) {
            code.compare(round, 0);
            code.breq(end_label);
        }

        // Reset the LFSR3 pointer for the next iteration.
        code.sbox_switch(SBOX_LFSR3, get_skinny128_sbox(SBOX_LFSR3));
    }
    code.jmp(top_label);

    // Clean up and save the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    code.stx(s0, POST_INC);
    code.stx(s1, POST_INC);
    code.stx(s2, POST_INC);
    code.stx(s3, POST_INC);
}

void gen_skinny128_384_setup_key(Code &code)
{
    gen_skinny128_setup_key(code, "skinny_128_384_init", 48);
}

void gen_skinny128_256_setup_key(Code &code)
{
    gen_skinny128_setup_key(code, "skinny_128_256_init", 32);
}

void gen_skinny128_384_encrypt(Code &code)
{
    gen_skinny128_encrypt(code, "skinny_128_384_encrypt", 48);
}

void gen_skinny128_256_encrypt(Code &code)
{
    gen_skinny128_encrypt(code, "skinny_128_256_encrypt", 32);
}

void gen_skinny128_384_decrypt(Code &code)
{
    gen_skinny128_decrypt(code, "skinny_128_384_decrypt", 48);
}

void gen_skinny128_256_decrypt(Code &code)
{
    gen_skinny128_decrypt(code, "skinny_128_256_decrypt", 32);
}

/* Test vectors for SKINNY-128 from https://eprint.iacr.org/2016/660.pdf */
static block_cipher_test_vector_t const skinny128_256_1 = {
    "Test Vector",
    {0x00, 0x9c, 0xec, 0x81, 0x60, 0x5d, 0x4a, 0xc1,    /* key */
     0xd2, 0xae, 0x9e, 0x30, 0x85, 0xd7, 0xa1, 0xf3,
     0x1a, 0xc1, 0x23, 0xeb, 0xfc, 0x00, 0xfd, 0xdc,
     0xf0, 0x10, 0x46, 0xce, 0xed, 0xdf, 0xca, 0xb3},
    32,                                                 /* key_len */
    {0x3a, 0x0c, 0x47, 0x76, 0x7a, 0x26, 0xa6, 0x8d,    /* plaintext */
     0xd3, 0x82, 0xa6, 0x95, 0xe7, 0x02, 0x2e, 0x25},
    {0xb7, 0x31, 0xd9, 0x8a, 0x4b, 0xde, 0x14, 0x7a,    /* ciphertext */
     0x7e, 0xd4, 0xa6, 0xf1, 0x6b, 0x9b, 0x58, 0x7f}
};
static block_cipher_test_vector_t const skinny128_384_1 = {
    "Test Vector",
    {0xdf, 0x88, 0x95, 0x48, 0xcf, 0xc7, 0xea, 0x52,    /* key */
     0xd2, 0x96, 0x33, 0x93, 0x01, 0x79, 0x74, 0x49,
     0xab, 0x58, 0x8a, 0x34, 0xa4, 0x7f, 0x1a, 0xb2,
     0xdf, 0xe9, 0xc8, 0x29, 0x3f, 0xbe, 0xa9, 0xa5,
     0xab, 0x1a, 0xfa, 0xc2, 0x61, 0x10, 0x12, 0xcd,
     0x8c, 0xef, 0x95, 0x26, 0x18, 0xc3, 0xeb, 0xe8},
    48,                                                 /* key_len */
    {0xa3, 0x99, 0x4b, 0x66, 0xad, 0x85, 0xa3, 0x45,    /* plaintext */
     0x9f, 0x44, 0xe9, 0x2b, 0x08, 0xf5, 0x50, 0xcb},
    {0x94, 0xec, 0xf5, 0x89, 0xe2, 0x01, 0x7c, 0x60,    /* ciphertext */
     0x1b, 0x38, 0xc6, 0x34, 0x6a, 0x10, 0xdc, 0xfa}
};

bool test_skinny128_384_encrypt(Code &code)
{
    unsigned char output[16];
    code.exec_encrypt_block(skinny128_384_1.key, skinny128_384_1.key_len,
                            output, 16, skinny128_384_1.plaintext, 16);
    return !memcmp(output, skinny128_384_1.ciphertext, 16);
}

bool test_skinny128_256_encrypt(Code &code)
{
    unsigned char output[16];
    code.exec_encrypt_block(skinny128_256_1.key, skinny128_256_1.key_len,
                            output, 16, skinny128_256_1.plaintext, 16);
    return !memcmp(output, skinny128_256_1.ciphertext, 16);
}

bool test_skinny128_384_decrypt(Code &code)
{
    unsigned char output[16];
    code.exec_decrypt_block(skinny128_384_1.key, skinny128_384_1.key_len,
                            output, 16, skinny128_384_1.ciphertext, 16);
    return !memcmp(output, skinny128_384_1.plaintext, 16);
}

bool test_skinny128_256_decrypt(Code &code)
{
    unsigned char output[16];
    code.exec_decrypt_block(skinny128_256_1.key, skinny128_256_1.key_len,
                            output, 16, skinny128_256_1.ciphertext, 16);
    return !memcmp(output, skinny128_256_1.plaintext, 16);
}
