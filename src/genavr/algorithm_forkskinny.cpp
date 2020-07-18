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

// S-box tables that are used by ForkSkinny.
#define SBOX128_MAIN 0
#define SBOX128_MAIN_INV 1
#define SBOX128_LFSR2 2
#define SBOX128_LFSR3 3
#define SBOX_RC 4
#define SBOX64_MAIN 5
#define SBOX64_MAIN_INV 6
#define SBOX64_LFSR2 7
#define SBOX64_LFSR3 8

// 7-bit round constants for all ForkSkinny block ciphers.
static unsigned char const RC[87] = {
    0x01, 0x03, 0x07, 0x0f, 0x1f, 0x3f, 0x7e, 0x7d,
    0x7b, 0x77, 0x6f, 0x5f, 0x3e, 0x7c, 0x79, 0x73,
    0x67, 0x4f, 0x1e, 0x3d, 0x7a, 0x75, 0x6b, 0x57,
    0x2e, 0x5c, 0x38, 0x70, 0x61, 0x43, 0x06, 0x0d,
    0x1b, 0x37, 0x6e, 0x5d, 0x3a, 0x74, 0x69, 0x53,
    0x26, 0x4c, 0x18, 0x31, 0x62, 0x45, 0x0a, 0x15,
    0x2b, 0x56, 0x2c, 0x58, 0x30, 0x60, 0x41, 0x02,
    0x05, 0x0b, 0x17, 0x2f, 0x5e, 0x3c, 0x78, 0x71,
    0x63, 0x47, 0x0e, 0x1d, 0x3b, 0x76, 0x6d, 0x5b,
    0x36, 0x6c, 0x59, 0x32, 0x64, 0x49, 0x12, 0x25,
    0x4a, 0x14, 0x29, 0x52, 0x24, 0x48, 0x10
};

// S-box tables for Skinny-64.
static unsigned char const sbox64[16] = {
    12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15
};
static unsigned char const sbox64_inv[16] = {
    3, 4, 6, 8, 12, 10, 1, 14, 9, 2, 5, 7, 0, 11, 13, 15
};

Sbox get_forkskinny_sbox(int num)
{
    switch (num) {
    case SBOX128_MAIN:
    case SBOX128_MAIN_INV:
    case SBOX128_LFSR2:
    case SBOX128_LFSR3:
    default:
        return get_skinny128_sbox(num);

    case SBOX64_MAIN: {
        unsigned char sb[256];
        for (int index = 0; index < 256; ++index) {
            sb[index] = sbox64[index & 0x0F] |
                       (sbox64[(index >> 4) & 0x0F] << 4);
        }
        return Sbox(sb, sizeof(sb)); }

    case SBOX64_MAIN_INV: {
        unsigned char sb[256];
        for (int index = 0; index < 256; ++index) {
            sb[index] = sbox64_inv[index & 0x0F] |
                       (sbox64_inv[(index >> 4) & 0x0F] << 4);
        }
        return Sbox(sb, sizeof(sb)); }

    case SBOX64_LFSR2: {
        unsigned char lfsr2[256];
        for (int index = 0; index < 256; ++index) {
            lfsr2[index] = ((index << 1) & 0xEE) ^
                           (((index >> 3) ^ (index >> 2)) & 0x11);
        }
        return Sbox(lfsr2, sizeof(lfsr2)); }

    case SBOX64_LFSR3: {
        unsigned char lfsr3[256];
        for (int index = 0; index < 256; ++index) {
            lfsr3[index] = ((index >> 1) & 0x77) ^
                           ((index ^ (index << 3)) & 0x88);
        }
        return Sbox(lfsr3, sizeof(lfsr3)); }

    case SBOX_RC: {
        unsigned char rc_table[87 * 2];
        for (int index = 0; index < 87; ++index) {
            int rc = RC[index];
            rc_table[index * 2] = (rc & 0x0F);
            rc_table[index * 2 + 1] = (rc & 0x70) >> 4;
        }
        return Sbox(rc_table, sizeof(rc_table)); }
    }
}

/**
 * \brief Forwards the tweakey using SKINNY-128's key schedule.
 *
 * \param code Code block to generate into.
 * \param name Name of the function to generate.
 * \param key_size Size of the key in bytes, 32 or 48.
 */
static void gen_forkskinny128_forward_tk
    (Code &code, const char *name, int key_size)
{
    int offset;

    // Set up the function prologue with 16 or 32 bytes of local variable
    // storage.  Z points to the state structure on input and output.
    Reg rounds = code.prologue_permutation_with_count(name, key_size - 16);

    // Copy the tweakey from the input to local variables and registers
    // because we need the Z register to point at the LFSR tables.
    Reg temp1 = code.allocateHighReg(4);
    Reg temp2 = code.allocateReg(4);
    Reg tk1_0 = code.allocateReg(4);
    Reg tk1_1 = code.allocateReg(4);
    Reg tk1_2 = code.allocateReg(4);
    Reg tk1_3 = code.allocateReg(4);
    code.ldz(tk1_0, 0);
    code.ldz(tk1_1, 4);
    code.ldz(tk1_2, 8);
    code.ldz(tk1_3, 12);
    for (offset = 16; offset < key_size; offset += 4) {
        code.ldz(temp1, offset);
        code.stlocal(temp1, offset - 16);
    }
    code.push(Reg::z_ptr());

    // Perform all forwarding rounds.
    unsigned char top_label = 0;
    code.sbox_setup(SBOX128_LFSR2, get_forkskinny_sbox(SBOX128_LFSR2));
    code.label(top_label);
    code.move(temp1, tk1_2);
    code.move(temp2, tk1_3);
    code.move(tk1_2, tk1_0);
    code.move(tk1_3, tk1_1);
    // Permute TK1
    code.move(Reg(tk1_0, 0, 1), Reg(temp1, 1, 1));      // 9
    code.move(Reg(tk1_0, 1, 1), Reg(temp2, 3, 1));      // 15
    code.move(Reg(tk1_0, 2, 1), Reg(temp1, 0, 1));      // 8
    code.move(Reg(tk1_0, 3, 1), Reg(temp2, 1, 1));      // 13
    code.move(Reg(tk1_1, 0, 1), Reg(temp1, 2, 1));      // 10
    code.move(Reg(tk1_1, 1, 1), Reg(temp2, 2, 1));      // 14
    code.move(Reg(tk1_1, 2, 1), Reg(temp2, 0, 1));      // 12
    code.move(Reg(tk1_1, 3, 1), Reg(temp1, 3, 1));      // 11
    // Permute TK2 and apply the LFSR.
    code.ldlocal(temp1, 8);
    code.ldlocal(temp2, 12);
    Reg temp3 = code.allocateReg(1);
    for (offset = 0; offset < 8; ++offset) {
        code.ldlocal(temp3, offset);
        code.stlocal(temp3, offset + 8);
    }
    code.sbox_lookup(temp1, temp1);
    code.sbox_lookup(temp2, temp2);
    code.stlocal(Reg(temp1, 1, 1), 0);      // 9
    code.stlocal(Reg(temp2, 3, 1), 1);      // 15
    code.stlocal(Reg(temp1, 0, 1), 2);      // 8
    code.stlocal(Reg(temp2, 1, 1), 3);      // 13
    code.stlocal(Reg(temp1, 2, 1), 4);      // 10
    code.stlocal(Reg(temp2, 2, 1), 5);      // 14
    code.stlocal(Reg(temp2, 0, 1), 6);      // 12
    code.stlocal(Reg(temp1, 3, 1), 7);      // 11
    // Permute TK3 and apply the LFSR.
    if (key_size == 48) {
        code.sbox_switch(SBOX128_LFSR3, get_forkskinny_sbox(SBOX128_LFSR3), temp1);
        code.ldlocal(temp1, 24);
        code.ldlocal(temp2, 28);
        for (offset = 16; offset < 24; ++offset) {
            code.ldlocal(temp3, offset);
            code.stlocal(temp3, offset + 8);
        }
        code.sbox_lookup(temp1, temp1);
        code.sbox_lookup(temp2, temp2);
        code.stlocal(Reg(temp1, 1, 1), 16);     // 9
        code.stlocal(Reg(temp2, 3, 1), 17);     // 15
        code.stlocal(Reg(temp1, 0, 1), 18);     // 8
        code.stlocal(Reg(temp2, 1, 1), 19);     // 13
        code.stlocal(Reg(temp1, 2, 1), 20);     // 10
        code.stlocal(Reg(temp2, 2, 1), 21);     // 14
        code.stlocal(Reg(temp2, 0, 1), 22);     // 12
        code.stlocal(Reg(temp1, 3, 1), 23);     // 11
        code.sbox_switch(SBOX128_LFSR2, get_forkskinny_sbox(SBOX128_LFSR2), temp1);
    }
    code.dec(rounds);
    code.brne(top_label);

    // Restore Z and copy the tweakey back to the state structure.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(tk1_0, 0);
    code.stz(tk1_1, 4);
    code.stz(tk1_2, 8);
    code.stz(tk1_3, 12);
    for (offset = 16; offset < key_size; offset += 4) {
        code.ldlocal(temp1, offset - 16);
        code.stz(temp1, offset);
    }
}

/**
 * \brief Reverses the tweakey using SKINNY-128's key schedule.
 *
 * \param code Code block to generate into.
 * \param name Name of the function to generate.
 * \param key_size Size of the key in bytes, 32 or 48.
 */
static void gen_forkskinny128_reverse_tk
    (Code &code, const char *name, int key_size)
{
    int offset;

    // Set up the function prologue with 16 or 32 bytes of local variable
    // storage.  Z points to the state structure on input and output.
    Reg rounds = code.prologue_permutation_with_count(name, key_size - 16);

    // Copy the tweakey from the input to local variables and registers
    // because we need the Z register to point at the LFSR tables.
    Reg temp1 = code.allocateHighReg(4);
    Reg temp2 = code.allocateHighReg(4);
    Reg tk1_0 = code.allocateReg(4);
    Reg tk1_1 = code.allocateReg(4);
    Reg tk1_2 = code.allocateReg(4);
    Reg tk1_3 = code.allocateReg(4);
    code.ldz(tk1_0, 0);
    code.ldz(tk1_1, 4);
    code.ldz(tk1_2, 8);
    code.ldz(tk1_3, 12);
    for (offset = 16; offset < key_size; offset += 4) {
        code.ldz(temp1, offset);
        code.stlocal(temp1, offset - 16);
    }
    code.push(Reg::z_ptr());

    // Perform all reversing rounds.
    unsigned char top_label = 0;
    code.sbox_setup(SBOX128_LFSR3, get_forkskinny_sbox(SBOX128_LFSR3));
    code.label(top_label);
    code.move(temp1, tk1_0);
    code.move(temp2, tk1_1);
    code.move(tk1_0, tk1_2);
    code.move(tk1_1, tk1_3);
    // Permute TK1
    code.move(Reg(tk1_2, 0, 1), Reg(temp1, 2, 1));      // 2
    code.move(Reg(tk1_2, 1, 1), Reg(temp1, 0, 1));      // 0
    code.move(Reg(tk1_2, 2, 1), Reg(temp2, 0, 1));      // 4
    code.move(Reg(tk1_2, 3, 1), Reg(temp2, 3, 1));      // 7
    code.move(Reg(tk1_3, 0, 1), Reg(temp2, 2, 1));      // 6
    code.move(Reg(tk1_3, 1, 1), Reg(temp1, 3, 1));      // 3
    code.move(Reg(tk1_3, 2, 1), Reg(temp2, 1, 1));      // 5
    code.move(Reg(tk1_3, 3, 1), Reg(temp1, 1, 1));      // 1
    // Permute TK2 and apply the LFSR.
    code.ldlocal(temp1, 0);
    code.ldlocal(temp2, 4);
    Reg temp3 = code.allocateReg(1);
    for (offset = 0; offset < 8; ++offset) {
        code.ldlocal(temp3, offset + 8);
        code.stlocal(temp3, offset);
    }
    code.sbox_lookup(temp1, temp1);
    code.sbox_lookup(temp2, temp2);
    code.stlocal(Reg(temp1, 2, 1), 8);      // 2
    code.stlocal(Reg(temp1, 0, 1), 9);      // 0
    code.stlocal(Reg(temp2, 0, 1), 10);     // 4
    code.stlocal(Reg(temp2, 3, 1), 11);     // 7
    code.stlocal(Reg(temp2, 2, 1), 12);     // 6
    code.stlocal(Reg(temp1, 3, 1), 13);     // 3
    code.stlocal(Reg(temp2, 1, 1), 14);     // 5
    code.stlocal(Reg(temp1, 1, 1), 15);     // 1
    // Permute TK3 and apply the LFSR.
    if (key_size == 48) {
        code.sbox_switch(SBOX128_LFSR2, get_forkskinny_sbox(SBOX128_LFSR2), temp1);
        code.ldlocal(temp1, 16);
        code.ldlocal(temp2, 20);
        for (offset = 16; offset < 24; ++offset) {
            code.ldlocal(temp3, offset + 8);
            code.stlocal(temp3, offset);
        }
        code.sbox_lookup(temp1, temp1);
        code.sbox_lookup(temp2, temp2);
        code.stlocal(Reg(temp1, 2, 1), 24);     // 2
        code.stlocal(Reg(temp1, 0, 1), 25);     // 0
        code.stlocal(Reg(temp2, 0, 1), 26);     // 4
        code.stlocal(Reg(temp2, 3, 1), 27);     // 7
        code.stlocal(Reg(temp2, 2, 1), 28);     // 6
        code.stlocal(Reg(temp1, 3, 1), 29);     // 3
        code.stlocal(Reg(temp2, 1, 1), 30);     // 5
        code.stlocal(Reg(temp1, 1, 1), 31);     // 1
        code.sbox_switch(SBOX128_LFSR3, get_forkskinny_sbox(SBOX128_LFSR3), temp1);
    }
    code.dec(rounds);
    code.brne(top_label);

    // Restore Z and copy the tweakey back to the state structure.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(tk1_0, 0);
    code.stz(tk1_1, 4);
    code.stz(tk1_2, 8);
    code.stz(tk1_3, 12);
    for (offset = 16; offset < key_size; offset += 4) {
        code.ldlocal(temp1, offset - 16);
        code.stz(temp1, offset);
    }
}

/**
 * \brief Performs the tweakey permutation for ForkSkinny-128.
 *
 * \param code Code block to generate into.
 * \param offset Offset of the TK value in local variables.
 * \param t0 First 32-bit temporary register.
 * \param t1 Second 32-bit temporary register.
 * \param lfsr Set to true if the LFSR should be applied as well.
 */
static void forkskinny128_permute_tk
    (Code &code, int offset, const Reg &t0, const Reg &t1, bool lfsr = false)
{
    // PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]
    code.ldlocal(t0, offset + 8);
    code.ldlocal(t1, offset + 12);
    if (lfsr) {
        code.sbox_lookup(t0, t0);
        code.sbox_lookup(t1, t1);
    }
    for (int posn = 0; posn < 8; ++posn) {
        code.memory(Insn::LD_Y, TEMP_REG, 1 + offset + posn);
        code.memory(Insn::ST_Y, TEMP_REG, 1 + offset + posn + 8);
    }
    code.memory(Insn::ST_Y, t0.reg(1), 1 + offset);     // 9
    code.memory(Insn::ST_Y, t1.reg(3), 1 + offset + 1); // 15
    code.memory(Insn::ST_Y, t0.reg(0), 1 + offset + 2); // 8
    code.memory(Insn::ST_Y, t1.reg(1), 1 + offset + 3); // 13
    code.memory(Insn::ST_Y, t0.reg(2), 1 + offset + 4); // 10
    code.memory(Insn::ST_Y, t1.reg(2), 1 + offset + 5); // 14
    code.memory(Insn::ST_Y, t1.reg(0), 1 + offset + 6); // 12
    code.memory(Insn::ST_Y, t0.reg(3), 1 + offset + 7); // 11
}

/**
 * \brief Performs the inverse of the tweakey permutation for ForkSkinny-128.
 *
 * \param code Code block to generate into.
 * \param offset Offset of the TK value in local variables.
 * \param t0 First 32-bit temporary register.
 * \param t1 Second 32-bit temporary register.
 * \param lfsr Set to true if the LFSR should be applied as well.
 */
static void forkskinny128_inv_permute_tk
    (Code &code, int offset, const Reg &t0, const Reg &t1, bool lfsr = false)
{
    // PT' = [8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1]
    code.ldlocal(t0, offset);
    code.ldlocal(t1, offset + 4);
    if (lfsr) {
        code.sbox_lookup(t0, t0);
        code.sbox_lookup(t1, t1);
    }
    for (int posn = 0; posn < 8; ++posn) {
        code.memory(Insn::LD_Y, TEMP_REG, 1 + offset + posn + 8);
        code.memory(Insn::ST_Y, TEMP_REG, 1 + offset + posn);
    }
    code.memory(Insn::ST_Y, t0.reg(2), 9 + offset);       // 2
    code.memory(Insn::ST_Y, t0.reg(0), 9 + offset + 1);   // 0
    code.memory(Insn::ST_Y, t1.reg(0), 9 + offset + 2);   // 4
    code.memory(Insn::ST_Y, t1.reg(3), 9 + offset + 3);   // 7
    code.memory(Insn::ST_Y, t1.reg(2), 9 + offset + 4);   // 6
    code.memory(Insn::ST_Y, t0.reg(3), 9 + offset + 5);   // 3
    code.memory(Insn::ST_Y, t1.reg(1), 9 + offset + 6);   // 5
    code.memory(Insn::ST_Y, t0.reg(1), 9 + offset + 7);   // 1
}

/**
 * \brief Generate the ForkSkinny-128 round function.
 *
 * \param code Code block to generate into.
 * \param name Name of the function to generate.
 * \param key_size Size of the tweakey; either 32 or 48.
 */
static void gen_forkskinny128_rounds(Code &code, const char *name, int key_size)
{
    int offset;

    // Set up the function prologue with enough local variable storage
    // to copy the tweakey.  We will need Z later for S-box pointers.
    code.prologue_permutation(name, key_size + 1);
    code.setFlag(Code::TempR1);
    Reg args = code.arg(4);
    Reg first = Reg(args, 2, 1);
    Reg last = Reg(args, 0, 1);
    code.releaseReg(Reg(args, 1, 1));
    code.releaseReg(Reg(args, 3, 1));

    // Read the state into registers and copy the tweakey to local variables.
    Reg t0 = code.allocateHighReg(4);
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);
    code.ldz(s0, key_size);
    code.ldz(s1, key_size + 4);
    code.ldz(s2, key_size + 8);
    code.ldz(s3, key_size + 12);
    for (offset = 0; offset < key_size; offset += 4) {
        code.ldz(t0, offset);
        code.stlocal(t0, offset);
    }

    // We are running low on registers so store "last" in a local variable.
    code.lsl(last, 1);
    code.stlocal(last, key_size);
    code.releaseReg(last);
    Reg t1 = code.allocateReg(4);

    // Save Z on the stack and then point it at the S-box table.
    code.push(Reg::z_ptr());
    code.sbox_setup(SBOX128_MAIN, get_forkskinny_sbox(SBOX128_MAIN), t0);

    // Top of the round loop.
    unsigned char top_label = 0;
    code.lsl(first, 1);
    code.label(top_label);

    // Apply the S-box to all cells in the state.
    code.sbox_lookup(s0, s0);
    code.sbox_lookup(s1, s1);
    code.sbox_lookup(s2, s2);
    code.sbox_lookup(s3, s3);

    // XOR the round constant and the subkey for this round.
    code.ldlocal(t0, 0);            // TK1[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 4);            // TK1[1]
    code.logxor(s1, t0);
    code.ldlocal(t0, 16);           // TK2[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 20);           // TK2[1]
    code.logxor(s1, t0);
    if (key_size == 48) {
        code.ldlocal(t0, 32);       // TK3[0]
        code.logxor(s0, t0);
        code.ldlocal(t0, 36);       // TK3[1]
        code.logxor(s1, t0);
    }
    code.sbox_switch(SBOX_RC, get_forkskinny_sbox(SBOX_RC), t0);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.logxor(s0, Reg(t0, 0, 1));
    code.inc(first);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.logxor(s1, Reg(t0, 0, 1));
    code.move(Reg(t0, 0, 1), 2);
    code.logxor(s2, Reg(t0, 0, 1));
    code.logxor(Reg(s0, 2, 1), Reg(t0, 0, 1));

    // Shift the cells in each row.
    code.rol(s1, 8);
    code.rol(s2, 16);
    code.rol(s3, 24);

    // Mix the columns.
    code.logxor(s1, s2);            // s1 ^= s2;
    code.logxor(s2, s0);            // s2 ^= s0;
    code.move(t0, s3);              // temp = s3 ^ s2;
    code.logxor(t0, s2);
    code.move(s3, s2);              // s3 = s2;
    code.move(s2, s1);              // s2 = s1;
    code.move(s1, s0);              // s1 = s0;
    code.move(s0, t0);              // s0 = temp;

    // Permute the tweakey for the next round.
    forkskinny128_permute_tk(code, 0, t0, t1);
    code.sbox_switch(SBOX128_LFSR2, get_forkskinny_sbox(SBOX128_LFSR2), t0);
    forkskinny128_permute_tk(code, 16, t0, t1, true);
    if (key_size == 48) {
        code.sbox_switch(SBOX128_LFSR3, get_forkskinny_sbox(SBOX128_LFSR3), t0);
        forkskinny128_permute_tk(code, 32, t0, t1, true);
    }

    // Bottom of the round loop.
    code.sbox_switch(SBOX128_MAIN, get_forkskinny_sbox(SBOX128_MAIN), t0);
    code.inc(first);
    code.ldlocal(Reg(t0, 0, 1), key_size);
    code.compare(first, Reg(t0, 0, 1));
    code.brne(top_label);

    // Copy the state and the tweakey back to the parameter.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(s0, key_size);
    code.stz(s1, key_size + 4);
    code.stz(s2, key_size + 8);
    code.stz(s3, key_size + 12);
    for (offset = 0; offset < key_size; offset += 4) {
        code.ldlocal(t0, offset);
        code.stz(t0, offset);
    }
}

/**
 * \brief Generate the ForkSkinny-128 inverse round function.
 *
 * \param code Code block to generate into.
 * \param name Name of the function to generate.
 * \param key_size Size of the tweakey; either 32 or 48.
 */
static void gen_forkskinny128_inv_rounds
    (Code &code, const char *name, int key_size)
{
    int offset;

    // Set up the function prologue with enough local variable storage
    // to copy the tweakey.  We will need Z later for S-box pointers.
    code.prologue_permutation(name, key_size + 1);
    code.setFlag(Code::TempR1);
    Reg args = code.arg(4);
    Reg first = Reg(args, 2, 1);
    Reg last = Reg(args, 0, 1);
    code.releaseReg(Reg(args, 1, 1));
    code.releaseReg(Reg(args, 3, 1));

    // Read the state into registers and copy the tweakey to local variables.
    Reg t0 = code.allocateHighReg(4);
    Reg s0 = code.allocateReg(4);
    Reg s1 = code.allocateReg(4);
    Reg s2 = code.allocateReg(4);
    Reg s3 = code.allocateReg(4);
    code.ldz(s0, key_size);
    code.ldz(s1, key_size + 4);
    code.ldz(s2, key_size + 8);
    code.ldz(s3, key_size + 12);
    for (offset = 0; offset < key_size; offset += 4) {
        code.ldz(t0, offset);
        code.stlocal(t0, offset);
    }

    // We are running low on registers so store "last" in a local variable.
    code.lsl(last, 1);
    code.stlocal(last, key_size);
    code.releaseReg(last);
    Reg t1 = code.allocateReg(4);

    // Save Z on the stack and then point it at the LFSR3 table.
    code.push(Reg::z_ptr());
    code.sbox_setup(SBOX128_LFSR3, get_forkskinny_sbox(SBOX128_LFSR3), t0);

    // Top of the round loop.
    unsigned char top_label = 0;
    code.lsl(first, 1);
    code.label(top_label);

    // Permute the tweakey for the next round.
    forkskinny128_inv_permute_tk(code, 0, t0, t1);
    forkskinny128_inv_permute_tk(code, 16, t0, t1, true);
    if (key_size == 48) {
        code.sbox_switch(SBOX128_LFSR2, get_forkskinny_sbox(SBOX128_LFSR2), t0);
        forkskinny128_inv_permute_tk(code, 32, t0, t1, true);
    }

    // Inverse mix of the columns.
    code.move(t0, s0);          // temp = s0;
    code.move(s0, s1);          // s0 = s1;
    code.move(s1, s2);          // s1 = s2;
    code.move(s2, s3);          // s2 = s3;
    code.move(s3, t0);          // s3 = temp ^ s2;
    code.logxor(s3, s2);
    code.logxor(s2, s0);        // s2 ^= s0;
    code.logxor(s1, s2);        // s1 ^= s2;

    // Shift the cells in each row.
    code.ror(s1, 8);
    code.ror(s2, 16);
    code.ror(s3, 24);

    // XOR the round constant and the subkey for this round.
    code.ldlocal(t0, 0);            // TK1[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 4);            // TK1[1]
    code.logxor(s1, t0);
    code.ldlocal(t0, 16);           // TK2[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 20);           // TK2[1]
    code.logxor(s1, t0);
    if (key_size == 48) {
        code.ldlocal(t0, 32);       // TK3[0]
        code.logxor(s0, t0);
        code.ldlocal(t0, 36);       // TK3[1]
        code.logxor(s1, t0);
    }
    code.sbox_switch(SBOX_RC, get_forkskinny_sbox(SBOX_RC), t0);
    code.dec(first);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.logxor(s1, Reg(t0, 0, 1));
    code.dec(first);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.logxor(s0, Reg(t0, 0, 1));
    code.move(Reg(t0, 0, 1), 2);
    code.logxor(s2, Reg(t0, 0, 1));
    code.logxor(Reg(s0, 2, 1), Reg(t0, 0, 1));

    // Apply the inverse of the S-box to all cells in the state.
    code.sbox_switch(SBOX128_MAIN_INV, get_forkskinny_sbox(SBOX128_MAIN_INV), t0);
    code.sbox_lookup(s0, s0);
    code.sbox_lookup(s1, s1);
    code.sbox_lookup(s2, s2);
    code.sbox_lookup(s3, s3);

    // Bottom of the round loop.
    code.sbox_switch(SBOX128_LFSR3, get_forkskinny_sbox(SBOX128_LFSR3), t0);
    code.ldlocal(Reg(t0, 0, 1), key_size);
    code.compare(first, Reg(t0, 0, 1));
    code.brne(top_label);

    // Copy the state and the tweakey back to the parameter.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(s0, key_size);
    code.stz(s1, key_size + 4);
    code.stz(s2, key_size + 8);
    code.stz(s3, key_size + 12);
    for (offset = 0; offset < key_size; offset += 4) {
        code.ldlocal(t0, offset);
        code.stz(t0, offset);
    }
}

void gen_forkskinny128_256_rounds(Code &code)
{
    gen_forkskinny128_rounds(code, "forkskinny_128_256_rounds", 32);
}

void gen_forkskinny128_256_inv_rounds(Code &code)
{
    gen_forkskinny128_inv_rounds(code, "forkskinny_128_256_inv_rounds", 32);
}

void gen_forkskinny128_256_forward_tk(Code &code)
{
    gen_forkskinny128_forward_tk
        (code, "forkskinny_128_256_forward_tk", 32);
}

void gen_forkskinny128_256_reverse_tk(Code &code)
{
    gen_forkskinny128_reverse_tk
        (code, "forkskinny_128_256_reverse_tk", 32);
}

void gen_forkskinny128_384_rounds(Code &code)
{
    gen_forkskinny128_rounds(code, "forkskinny_128_384_rounds", 48);
}

void gen_forkskinny128_384_inv_rounds(Code &code)
{
    gen_forkskinny128_inv_rounds(code, "forkskinny_128_384_inv_rounds", 48);
}

void gen_forkskinny128_384_forward_tk(Code &code)
{
    gen_forkskinny128_forward_tk
        (code, "forkskinny_128_384_forward_tk", 48);
}

void gen_forkskinny128_384_reverse_tk(Code &code)
{
    gen_forkskinny128_reverse_tk
        (code, "forkskinny_128_384_reverse_tk", 48);
}

/**
 * \brief Performs the 64-bit tweakey permutation.
 *
 * \param code Code block to generate into.
 * \param tk_0 First word of the tweakey.
 * \param tk_1 Second word of the tweakey.
 * \param tk_2 Third word of the tweakey.
 * \param tk_3 Fourth word of the tweakey.
 */
static void forkskinny64_permute_tk
    (Code &code, const Reg &tk_0, const Reg &tk_1, const Reg &tk_2,
     const Reg &tk_3)
{
    // PT = 9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7
    Reg t0 = code.allocateHighReg(1);
    code.push(tk_0);
    code.push(tk_1);
    code.move(Reg(tk_0, 1, 1), Reg(tk_2, 1, 1));    // 9
    code.rol(Reg(tk_0, 1, 1), 4);
    code.logand(Reg(tk_0, 1, 1), 0xF0);
    code.move(t0, Reg(tk_3, 0, 1));                 // 15
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_0, 1, 1), t0);
    code.move(Reg(tk_0, 0, 1), Reg(tk_2, 1, 1));    // 8
    code.logand(Reg(tk_0, 0, 1), 0xF0);
    code.move(t0, Reg(tk_3, 1, 1));                 // 13
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_0, 0, 1), t0);
    code.move(Reg(tk_1, 1, 1), Reg(tk_2, 0, 1));    // 10
    code.logand(Reg(tk_1, 1, 1), 0xF0);
    code.rol(Reg(tk_3, 0, 1), 4);                   // 14
    code.logand(Reg(tk_3, 0, 1), 0x0F);
    code.logor(Reg(tk_1, 1, 1), Reg(tk_3, 0, 1));
    code.move(Reg(tk_1, 0, 1), Reg(tk_3, 1, 1));    // 12
    code.logand(Reg(tk_1, 0, 1), 0xF0);
    code.logand(Reg(tk_2, 0, 1), 0x0F);             // 11
    code.logor(Reg(tk_1, 0, 1), Reg(tk_2, 0, 1));
    code.pop(tk_3);
    code.pop(tk_2);
    code.releaseReg(t0);
}

/**
 * \brief Performs the inverse of the 64-bit tweakey permutation.
 *
 * \param code Code block to generate into.
 * \param tk_0 First word of the tweakey.
 * \param tk_1 Second word of the tweakey.
 * \param tk_2 Third word of the tweakey.
 * \param tk_3 Fourth word of the tweakey.
 */
static void forkskinny64_inv_permute_tk
    (Code &code, const Reg &tk_0, const Reg &tk_1, const Reg &tk_2,
     const Reg &tk_3)
{
    // PT' = 8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1
    Reg t0 = code.allocateHighReg(1);
    code.push(tk_2);
    code.push(tk_3);
    code.move(Reg(tk_2, 1, 1), Reg(tk_0, 0, 1));    // 2
    code.logand(Reg(tk_2, 1, 1), 0xF0);
    code.move(t0, Reg(tk_0, 1, 1));                 // 0
    code.rol(Reg(t0, 0, 1), 4);
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_2, 1, 1), t0);
    code.move(Reg(tk_2, 0, 1), Reg(tk_1, 1, 1));    // 2
    code.logand(Reg(tk_2, 0, 1), 0xF0);
    code.move(t0, Reg(tk_1, 0, 1));                 // 7
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_2, 0, 1), t0);
    code.move(Reg(tk_3, 1, 1), Reg(tk_1, 0, 1));    // 6
    code.logand(Reg(tk_3, 1, 1), 0xF0);
    code.logand(Reg(tk_0, 0, 1), 0x0F);             // 3
    code.logor(Reg(tk_3, 1, 1), Reg(tk_0, 0, 1));
    code.move(Reg(tk_3, 0, 1), Reg(tk_1, 1, 1));    // 5
    code.rol(Reg(tk_3, 0, 1), 4);
    code.logand(Reg(tk_3, 0, 1), 0xF0);
    code.logand(Reg(tk_0, 1, 1), 0x0F);             // 1
    code.logor(Reg(tk_3, 0, 1), Reg(tk_0, 1, 1));
    code.pop(tk_1);
    code.pop(tk_0);
    code.releaseReg(t0);
}

void gen_forkskinny64_192_forward_tk(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable
    // storage.  Z points to the state structure on input and output.
    Reg rounds = code.prologue_permutation_with_count
        ("forkskinny_64_192_forward_tk", 0);
    code.setFlag(Code::TempY);

    // Copy the tweakey from the input to registers because we need the
    // Z register to point at the LFSR tables.
    Reg tk1_0 = code.allocateReg(2);
    Reg tk1_1 = code.allocateReg(2);
    Reg tk1_2 = code.allocateReg(2);
    Reg tk1_3 = code.allocateReg(2);
    Reg tk2_0 = code.allocateReg(2);
    Reg tk2_1 = code.allocateReg(2);
    Reg tk2_2 = code.allocateReg(2);
    Reg tk2_3 = code.allocateReg(2);
    Reg tk3_0 = code.allocateReg(2);
    Reg tk3_1 = code.allocateReg(2);
    Reg tk3_2 = code.allocateReg(2);
    Reg tk3_3 = code.allocateReg(2);
    code.ldz(tk1_0, 0);
    code.ldz(tk1_1, 2);
    code.ldz(tk1_2, 4);
    code.ldz(tk1_3, 6);
    code.ldz(tk2_0, 8);
    code.ldz(tk2_1, 10);
    code.ldz(tk2_2, 12);
    code.ldz(tk2_3, 14);
    code.ldz(tk3_0, 16);
    code.ldz(tk3_1, 18);
    code.ldz(tk3_2, 20);
    code.ldz(tk3_3, 22);
    code.push(Reg::z_ptr());

    // Perform all forwarding rounds.
    unsigned char top_label = 0;
    code.sbox_setup(SBOX64_LFSR2, get_forkskinny_sbox(SBOX64_LFSR2));
    code.label(top_label);
    // Permute TK1, TK2, and TK3.
    forkskinny64_permute_tk(code, tk1_0, tk1_1, tk1_2, tk1_3);
    forkskinny64_permute_tk(code, tk2_0, tk2_1, tk2_2, tk2_3);
    forkskinny64_permute_tk(code, tk3_0, tk3_1, tk3_2, tk3_3);
    // Apply LFSR2 to TK2 and LFSR3 to TK3.
    code.sbox_lookup(tk2_0, tk2_0);
    code.sbox_lookup(tk2_1, tk2_1);
    code.sbox_switch(SBOX64_LFSR3, get_forkskinny_sbox(SBOX64_LFSR3));
    code.sbox_lookup(tk3_0, tk3_0);
    code.sbox_lookup(tk3_1, tk3_1);
    code.sbox_switch(SBOX64_LFSR2, get_forkskinny_sbox(SBOX64_LFSR2));
    code.dec(rounds);
    code.brne(top_label);

    // Restore Z and copy the tweakey back to the state structure.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(tk1_0, 0);
    code.stz(tk1_1, 2);
    code.stz(tk1_2, 4);
    code.stz(tk1_3, 6);
    code.stz(tk2_0, 8);
    code.stz(tk2_1, 10);
    code.stz(tk2_2, 12);
    code.stz(tk2_3, 14);
    code.stz(tk3_0, 16);
    code.stz(tk3_1, 18);
    code.stz(tk3_2, 20);
    code.stz(tk3_3, 22);
}

void gen_forkskinny64_192_reverse_tk(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable
    // storage.  Z points to the state structure on input and output.
    Reg rounds = code.prologue_permutation_with_count
        ("forkskinny_64_192_reverse_tk", 0);
    code.setFlag(Code::TempY);

    // Copy the tweakey from the input to registers because we need the
    // Z register to point at the LFSR tables.
    Reg tk1_0 = code.allocateReg(2);
    Reg tk1_1 = code.allocateReg(2);
    Reg tk1_2 = code.allocateReg(2);
    Reg tk1_3 = code.allocateReg(2);
    Reg tk2_0 = code.allocateReg(2);
    Reg tk2_1 = code.allocateReg(2);
    Reg tk2_2 = code.allocateReg(2);
    Reg tk2_3 = code.allocateReg(2);
    Reg tk3_0 = code.allocateReg(2);
    Reg tk3_1 = code.allocateReg(2);
    Reg tk3_2 = code.allocateReg(2);
    Reg tk3_3 = code.allocateReg(2);
    code.ldz(tk1_0, 0);
    code.ldz(tk1_1, 2);
    code.ldz(tk1_2, 4);
    code.ldz(tk1_3, 6);
    code.ldz(tk2_0, 8);
    code.ldz(tk2_1, 10);
    code.ldz(tk2_2, 12);
    code.ldz(tk2_3, 14);
    code.ldz(tk3_0, 16);
    code.ldz(tk3_1, 18);
    code.ldz(tk3_2, 20);
    code.ldz(tk3_3, 22);
    code.push(Reg::z_ptr());

    // Perform all reversing rounds.
    unsigned char top_label = 0;
    code.sbox_setup(SBOX64_LFSR3, get_forkskinny_sbox(SBOX64_LFSR3));
    code.label(top_label);
    // Apply LFSR3 to TK2 and LFSR2 to TK3.
    code.sbox_lookup(tk2_0, tk2_0);
    code.sbox_lookup(tk2_1, tk2_1);
    code.sbox_switch(SBOX64_LFSR2, get_forkskinny_sbox(SBOX64_LFSR2));
    code.sbox_lookup(tk3_0, tk3_0);
    code.sbox_lookup(tk3_1, tk3_1);
    code.sbox_switch(SBOX64_LFSR3, get_forkskinny_sbox(SBOX64_LFSR3));
    // Inverse permutation on TK1, TK2, and TK3.
    forkskinny64_inv_permute_tk(code, tk1_0, tk1_1, tk1_2, tk1_3);
    forkskinny64_inv_permute_tk(code, tk2_0, tk2_1, tk2_2, tk2_3);
    forkskinny64_inv_permute_tk(code, tk3_0, tk3_1, tk3_2, tk3_3);
    code.dec(rounds);
    code.brne(top_label);

    // Restore Z and copy the tweakey back to the state structure.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(tk1_0, 0);
    code.stz(tk1_1, 2);
    code.stz(tk1_2, 4);
    code.stz(tk1_3, 6);
    code.stz(tk2_0, 8);
    code.stz(tk2_1, 10);
    code.stz(tk2_2, 12);
    code.stz(tk2_3, 14);
    code.stz(tk3_0, 16);
    code.stz(tk3_1, 18);
    code.stz(tk3_2, 20);
    code.stz(tk3_3, 22);
}

/**
 * \brief Performs the 64-bit tweakey permutation on local variables.
 *
 * \param code Code block to generate into.
 * \param offset Offset of the tweakey in local variables.
 * \param tk_0 First temporary variable.
 * \param tk_1 Second temporary variable.
 * \param tk_2 Third temporary variable.
 * \param tk_3 Fourth temporary variable.
 * \param lfsr Applies the LFSR as well.
 */
static void forkskinny64_permute_tk_local
    (Code &code, int offset, const Reg &tk_0, const Reg &tk_1,
     const Reg &tk_2, const Reg &tk_3, bool lfsr = false)
{
    // PT = 9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7
    Reg t0 = code.allocateHighReg(1);
    code.ldlocal(tk_0, offset);
    code.ldlocal(tk_1, offset + 2);
    code.ldlocal(tk_2, offset + 4);
    code.ldlocal(tk_3, offset + 6);
    code.stlocal(tk_0, offset + 4);
    code.stlocal(tk_1, offset + 6);
    if (lfsr) {
        code.sbox_lookup(tk_2, tk_2);
        code.sbox_lookup(tk_3, tk_3);
    }
    code.move(Reg(tk_0, 1, 1), Reg(tk_2, 1, 1));    // 9
    code.rol(Reg(tk_0, 1, 1), 4);
    code.logand(Reg(tk_0, 1, 1), 0xF0);
    code.move(t0, Reg(tk_3, 0, 1));                 // 15
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_0, 1, 1), t0);
    code.move(Reg(tk_0, 0, 1), Reg(tk_2, 1, 1));    // 8
    code.logand(Reg(tk_0, 0, 1), 0xF0);
    code.move(t0, Reg(tk_3, 1, 1));                 // 13
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_0, 0, 1), t0);
    code.move(Reg(tk_1, 1, 1), Reg(tk_2, 0, 1));    // 10
    code.logand(Reg(tk_1, 1, 1), 0xF0);
    code.rol(Reg(tk_3, 0, 1), 4);                   // 14
    code.logand(Reg(tk_3, 0, 1), 0x0F);
    code.logor(Reg(tk_1, 1, 1), Reg(tk_3, 0, 1));
    code.move(Reg(tk_1, 0, 1), Reg(tk_3, 1, 1));    // 12
    code.logand(Reg(tk_1, 0, 1), 0xF0);
    code.logand(Reg(tk_2, 0, 1), 0x0F);             // 11
    code.logor(Reg(tk_1, 0, 1), Reg(tk_2, 0, 1));
    code.stlocal(tk_0, offset);
    code.stlocal(tk_1, offset + 2);
    code.releaseReg(t0);
}

void gen_forkskinny64_192_rounds(Code &code)
{
    int offset;

    // Set up the function prologue with enough local variable storage
    // to copy the tweakey.  We will need Z later for S-box pointers.
    code.prologue_permutation("forkskinny_64_192_rounds", 24);
    Reg args = code.arg(4);
    Reg first = Reg(args, 2, 1);
    Reg last = Reg(args, 0, 1);
    code.releaseReg(Reg(args, 1, 1));
    code.releaseReg(Reg(args, 3, 1));

    // Read the state into registers and copy the tweakey to local variables.
    Reg t0 = code.allocateHighReg(2);
    Reg s0 = code.allocateReg(2);
    Reg s1 = code.allocateReg(2);
    Reg s2 = code.allocateReg(2);
    Reg s3 = code.allocateReg(2);
    Reg t1 = code.allocateReg(2);
    code.ldz(s0, 24);
    code.ldz(s1, 26);
    code.ldz(s2, 28);
    code.ldz(s3, 30);
    for (offset = 0; offset < 24; offset += 2) {
        code.ldz(t0, offset);
        code.stlocal(t0, offset);
    }

    // Save Z on the stack and then point it at the S-box table.
    code.push(Reg::z_ptr());
    code.sbox_setup(SBOX64_MAIN, get_forkskinny_sbox(SBOX64_MAIN), t0);

    // Top of the round loop.
    unsigned char top_label = 0;
    code.lsl(first, 1);
    code.lsl(last, 1);
    code.label(top_label);

    // Apply the S-box to all cells in the state.
    code.sbox_lookup(s0, s0);
    code.sbox_lookup(s1, s1);
    code.sbox_lookup(s2, s2);
    code.sbox_lookup(s3, s3);

    // XOR the round constant and the subkey for this round.
    code.ldlocal(t0, 0);            // TK1[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 2);            // TK1[1]
    code.logxor(s1, t0);
    code.ldlocal(t0, 8);            // TK2[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 10);           // TK2[1]
    code.logxor(s1, t0);
    code.ldlocal(t0, 16);           // TK3[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 18);           // TK3[1]
    code.logxor(s1, t0);
    code.sbox_switch(SBOX_RC, get_forkskinny_sbox(SBOX_RC), t0);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.rol(Reg(t0, 0, 1), 4);
    code.logxor(Reg(s0, 1, 1), Reg(t0, 0, 1));
    code.inc(first);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.rol(Reg(t0, 0, 1), 4);
    code.logxor(Reg(s1, 1, 1), Reg(t0, 0, 1));
    code.move(Reg(t0, 0, 1), 0x20);
    code.logxor(Reg(s2, 1, 1), Reg(t0, 0, 1));
    code.logxor(Reg(s0, 0, 1), Reg(t0, 0, 1));

    // Shift the cells in each row.
    code.ror(s1, 4);
    code.ror(s2, 8);
    code.ror(s3, 12);

    // Mix the columns.
    code.logxor(s1, s2);            // s1 ^= s2;
    code.logxor(s2, s0);            // s2 ^= s0;
    code.move(t0, s3);              // temp = s3 ^ s2;
    code.logxor(t0, s2);
    code.move(s3, s2);              // s3 = s2;
    code.move(s2, s1);              // s2 = s1;
    code.move(s1, s0);              // s1 = s0;
    code.move(s0, t0);              // s0 = temp;

    // Permute the tweakey for the next round.
    Reg tk_0 = t0;
    Reg tk_1 = t1;
    Reg tk_2 = code.allocateReg(2);
    Reg tk_3 = code.allocateReg(2);
    forkskinny64_permute_tk_local(code, 0, tk_0, tk_1, tk_2, tk_3);
    code.sbox_switch(SBOX64_LFSR2, get_forkskinny_sbox(SBOX64_LFSR2), t0);
    forkskinny64_permute_tk_local(code, 8, tk_0, tk_1, tk_2, tk_3, true);
    code.sbox_switch(SBOX64_LFSR3, get_forkskinny_sbox(SBOX64_LFSR3), t0);
    forkskinny64_permute_tk_local(code, 16, tk_0, tk_1, tk_2, tk_3, true);

    // Bottom of the round loop.
    code.sbox_switch(SBOX64_MAIN, get_forkskinny_sbox(SBOX64_MAIN), t0);
    code.inc(first);
    code.compare(first, last);
    code.brne(top_label);

    // Copy the state and the tweakey back to the parameter.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(s0, 24);
    code.stz(s1, 26);
    code.stz(s2, 28);
    code.stz(s3, 30);
    for (offset = 0; offset < 24; offset += 2) {
        code.ldlocal(t0, offset);
        code.stz(t0, offset);
    }
}

/**
 * \brief Performs the inverse of the 64-bit tweakey permutation on
 * local variables.
 *
 * \param code Code block to generate into.
 * \param offset Offset of the tweakey in local variables.
 * \param tk_0 First temporary variable.
 * \param tk_1 Second temporary variable.
 * \param tk_2 Third temporary variable.
 * \param tk_3 Fourth temporary variable.
 * \param lfsr Applies the LFSR as well.
 */
static void forkskinny64_inv_permute_tk_local
    (Code &code, int offset, const Reg &tk_0, const Reg &tk_1,
     const Reg &tk_2, const Reg &tk_3, bool lfsr = false)
{
    // PT' = 8, 9, 10, 11, 12, 13, 14, 15, 2, 0, 4, 7, 6, 3, 5, 1
    Reg t0 = code.allocateHighReg(1);
    code.ldlocal(tk_0, offset);
    code.ldlocal(tk_1, offset + 2);
    code.ldlocal(tk_2, offset + 4);
    code.ldlocal(tk_3, offset + 6);
    code.stlocal(tk_2, offset);
    code.stlocal(tk_3, offset + 2);
    if (lfsr) {
        code.sbox_lookup(tk_0, tk_0);
        code.sbox_lookup(tk_1, tk_1);
    }
    code.move(Reg(tk_2, 1, 1), Reg(tk_0, 0, 1));    // 2
    code.logand(Reg(tk_2, 1, 1), 0xF0);
    code.move(t0, Reg(tk_0, 1, 1));                 // 0
    code.rol(Reg(t0, 0, 1), 4);
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_2, 1, 1), t0);
    code.move(Reg(tk_2, 0, 1), Reg(tk_1, 1, 1));    // 2
    code.logand(Reg(tk_2, 0, 1), 0xF0);
    code.move(t0, Reg(tk_1, 0, 1));                 // 7
    code.logand(t0, 0x0F);
    code.logor(Reg(tk_2, 0, 1), t0);
    code.move(Reg(tk_3, 1, 1), Reg(tk_1, 0, 1));    // 6
    code.logand(Reg(tk_3, 1, 1), 0xF0);
    code.logand(Reg(tk_0, 0, 1), 0x0F);             // 3
    code.logor(Reg(tk_3, 1, 1), Reg(tk_0, 0, 1));
    code.move(Reg(tk_3, 0, 1), Reg(tk_1, 1, 1));    // 5
    code.rol(Reg(tk_3, 0, 1), 4);
    code.logand(Reg(tk_3, 0, 1), 0xF0);
    code.logand(Reg(tk_0, 1, 1), 0x0F);             // 1
    code.logor(Reg(tk_3, 0, 1), Reg(tk_0, 1, 1));
    code.stlocal(tk_2, offset + 4);
    code.stlocal(tk_3, offset + 6);
    code.releaseReg(t0);
}

void gen_forkskinny64_192_inv_rounds(Code &code)
{
    int offset;

    // Set up the function prologue with enough local variable storage
    // to copy the tweakey.  We will need Z later for S-box pointers.
    code.prologue_permutation("forkskinny_64_192_inv_rounds", 24);
    Reg args = code.arg(4);
    Reg first = Reg(args, 2, 1);
    Reg last = Reg(args, 0, 1);
    code.releaseReg(Reg(args, 1, 1));
    code.releaseReg(Reg(args, 3, 1));

    // Read the state into registers and copy the tweakey to local variables.
    Reg t0 = code.allocateHighReg(2);
    Reg s0 = code.allocateReg(2);
    Reg s1 = code.allocateReg(2);
    Reg s2 = code.allocateReg(2);
    Reg s3 = code.allocateReg(2);
    Reg t1 = code.allocateReg(2);
    code.ldz(s0, 24);
    code.ldz(s1, 26);
    code.ldz(s2, 28);
    code.ldz(s3, 30);
    for (offset = 0; offset < 24; offset += 2) {
        code.ldz(t0, offset);
        code.stlocal(t0, offset);
    }

    // Save Z on the stack and then point it at the LFSR3 table.
    code.push(Reg::z_ptr());
    code.sbox_setup(SBOX64_LFSR3, get_forkskinny_sbox(SBOX64_LFSR3), t0);

    // Top of the round loop.
    unsigned char top_label = 0;
    code.lsl(first, 1);
    code.lsl(last, 1);
    code.label(top_label);

    // Permute the tweakey for the next round.
    Reg tk_0 = t0;
    Reg tk_1 = t1;
    Reg tk_2 = code.allocateReg(2);
    Reg tk_3 = code.allocateReg(2);
    forkskinny64_inv_permute_tk_local(code, 0, tk_0, tk_1, tk_2, tk_3);
    forkskinny64_inv_permute_tk_local(code, 8, tk_0, tk_1, tk_2, tk_3, true);
    code.sbox_switch(SBOX64_LFSR2, get_forkskinny_sbox(SBOX64_LFSR2), t0);
    forkskinny64_inv_permute_tk_local(code, 16, tk_0, tk_1, tk_2, tk_3, true);

    // Inverse mix of the columns.
    code.move(t0, s0);          // temp = s0;
    code.move(s0, s1);          // s0 = s1;
    code.move(s1, s2);          // s1 = s2;
    code.move(s2, s3);          // s2 = s3;
    code.move(s3, t0);          // s3 = temp ^ s2;
    code.logxor(s3, s2);
    code.logxor(s2, s0);        // s2 ^= s0;
    code.logxor(s1, s2);        // s1 ^= s2;

    // Shift the cells in each row.
    code.rol(s1, 4);
    code.rol(s2, 8);
    code.rol(s3, 12);

    // XOR the round constant and the subkey for this round.
    code.ldlocal(t0, 0);            // TK1[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 2);            // TK1[1]
    code.logxor(s1, t0);
    code.ldlocal(t0, 8);            // TK2[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 10);           // TK2[1]
    code.logxor(s1, t0);
    code.ldlocal(t0, 16);           // TK3[0]
    code.logxor(s0, t0);
    code.ldlocal(t0, 18);           // TK3[1]
    code.logxor(s1, t0);
    code.sbox_switch(SBOX_RC, get_forkskinny_sbox(SBOX_RC), t0);
    code.dec(first);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.rol(Reg(t0, 0, 1), 4);
    code.logxor(Reg(s1, 1, 1), Reg(t0, 0, 1));
    code.dec(first);
    code.sbox_lookup(Reg(t0, 0, 1), first);
    code.rol(Reg(t0, 0, 1), 4);
    code.logxor(Reg(s0, 1, 1), Reg(t0, 0, 1));
    code.move(Reg(t0, 0, 1), 0x20);
    code.logxor(Reg(s2, 1, 1), Reg(t0, 0, 1));
    code.logxor(Reg(s0, 0, 1), Reg(t0, 0, 1));

    // Apply the S-box to all cells in the state.
    code.sbox_switch(SBOX64_MAIN_INV, get_forkskinny_sbox(SBOX64_MAIN_INV), t0);
    code.sbox_lookup(s0, s0);
    code.sbox_lookup(s1, s1);
    code.sbox_lookup(s2, s2);
    code.sbox_lookup(s3, s3);

    // Bottom of the round loop.
    code.sbox_switch(SBOX64_LFSR3, get_forkskinny_sbox(SBOX64_LFSR3), t0);
    code.compare(first, last);
    code.brne(top_label);

    // Copy the state and the tweakey back to the parameter.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.stz(s0, 24);
    code.stz(s1, 26);
    code.stz(s2, 28);
    code.stz(s3, 30);
    for (offset = 0; offset < 24; offset += 2) {
        code.ldlocal(t0, offset);
        code.stz(t0, offset);
    }
}

/* Test vectors for ForkSkinny-128-256 */
static unsigned char forkskinny128_256_key_in[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};
static unsigned char forkskinny128_256_key_out[32] = {
    0x0b, 0x0d, 0x0f, 0x0c, 0x09, 0x0a, 0x08, 0x0e,
    0x07, 0x03, 0x01, 0x06, 0x00, 0x04, 0x02, 0x05,
    0xb5, 0x46, 0x17, 0x6e, 0xe4, 0x9d, 0xcc, 0x3f,
    0x29, 0x78, 0x50, 0x3d, 0x44, 0x15, 0x6c, 0x01
};
static unsigned char forkskinny128_256_state_in[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static unsigned char forkskinny128_256_state_out[48] = {
    0x0d, 0x0e, 0x0b, 0x0a, 0x0f, 0x08, 0x09, 0x0c,
    0x03, 0x05, 0x07, 0x04, 0x01, 0x02, 0x00, 0x06,
    0x32, 0xfe, 0xab, 0xef, 0xba, 0x67, 0x23, 0x76,
    0xc4, 0x08, 0x4c, 0xaa, 0x80, 0x66, 0x22, 0xee,
    0xd1, 0x27, 0xf3, 0x2b, 0x82, 0x2a, 0x00, 0x05,
    0x41, 0x99, 0xd5, 0x74, 0x4b, 0xd1, 0x19, 0x2e
};

/* Test vectors for ForkSkinny-128-384 */
static unsigned char forkskinny128_384_key_in[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};
static unsigned char forkskinny128_384_key_out[48] = {
    0x0b, 0x0d, 0x0f, 0x0c, 0x09, 0x0a, 0x08, 0x0e,
    0x07, 0x03, 0x01, 0x06, 0x00, 0x04, 0x02, 0x05,
    0xb5, 0x46, 0x17, 0x6e, 0xe4, 0x9d, 0xcc, 0x3f,
    0x29, 0x78, 0x50, 0x3d, 0x44, 0x15, 0x6c, 0x01,
    0x9e, 0xa1, 0xb4, 0x2b, 0x8b, 0x14, 0x01, 0x3e,
    0xc2, 0x97, 0xbd, 0xd7, 0xa8, 0xfd, 0x82, 0xe8
};
static unsigned char forkskinny128_384_state_in[64] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};
static unsigned char forkskinny128_384_state_out[64] = {
    0x0d, 0x0e, 0x0b, 0x0a, 0x0f, 0x08, 0x09, 0x0c,
    0x03, 0x05, 0x07, 0x04, 0x01, 0x02, 0x00, 0x06,
    0x32, 0xfe, 0xab, 0xef, 0xba, 0x67, 0x23, 0x76,
    0xc4, 0x08, 0x4c, 0xaa, 0x80, 0x66, 0x22, 0xee,
    0xf4, 0xc7, 0x93, 0x82, 0xd6, 0xa0, 0xb1, 0xe5,
    0x32, 0xfd, 0xb8, 0xdf, 0x77, 0x10, 0x55, 0x9a,
    0x53, 0x36, 0x61, 0x98, 0x22, 0xea, 0xbe, 0x32,
    0x60, 0xf4, 0x13, 0xdc, 0x6f, 0xaa, 0xef, 0x23
};

/* Test vectors for ForkSkinny-64-192 */
static unsigned char forkskinny64_192_key_in[24] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};
static unsigned char forkskinny64_192_key_out[24] = {
    0x60, 0x47, 0x00, 0x50, 0x10, 0x20, 0x03, 0x00,
    0x50, 0xba, 0x00, 0x40, 0xc0, 0x4b, 0x03, 0x00,
    0xb3, 0xd8, 0x33, 0xe3, 0x66, 0xd0, 0x6b, 0x66
};
static unsigned char forkskinny64_192_state_in[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
};
static unsigned char forkskinny64_192_state_out[32] = {
    0x40, 0x70, 0x50, 0x60, 0x20, 0x03, 0x00, 0x10,
    0xe0, 0x70, 0x60, 0xf0, 0x60, 0xea, 0x00, 0x20,
    0x92, 0xf2, 0xb2, 0xd2, 0x94, 0x0d, 0x44, 0x44,
    0xea, 0xd4, 0x1c, 0x84, 0xee, 0xf6, 0xa7, 0x5b
};

bool test_forkskinny128_256_rounds(Code &code)
{
    unsigned char state[48];
    memcpy(state, forkskinny128_256_state_in, 48);
    code.exec_permutation(state, sizeof(state), 0, 87);
    return !memcmp(forkskinny128_256_state_out, state, 48);
}

bool test_forkskinny128_256_inv_rounds(Code &code)
{
    unsigned char state[48];
    memcpy(state, forkskinny128_256_state_out, 48);
    code.exec_permutation(state, sizeof(state), 87, 0);
    return !memcmp(forkskinny128_256_state_in, state, 48);
}

bool test_forkskinny128_256_forward_tk(Code &code)
{
    unsigned char state[32];
    memcpy(state, forkskinny128_256_key_in, 32);
    code.exec_permutation(state, sizeof(state), 21);
    return !memcmp(forkskinny128_256_key_out, state, 32);
}

bool test_forkskinny128_256_reverse_tk(Code &code)
{
    unsigned char state[32];
    memcpy(state, forkskinny128_256_key_out, 32);
    code.exec_permutation(state, sizeof(state), 21);
    return !memcmp(forkskinny128_256_key_in, state, 32);
}

bool test_forkskinny128_384_rounds(Code &code)
{
    unsigned char state[64];
    memcpy(state, forkskinny128_384_state_in, 64);
    code.exec_permutation(state, sizeof(state), 0, 87);
    return !memcmp(forkskinny128_384_state_out, state, 64);
}

bool test_forkskinny128_384_inv_rounds(Code &code)
{
    unsigned char state[64];
    memcpy(state, forkskinny128_384_state_out, 64);
    code.exec_permutation(state, sizeof(state), 87, 0);
    return !memcmp(forkskinny128_384_state_in, state, 64);
}

bool test_forkskinny128_384_forward_tk(Code &code)
{
    unsigned char state[48];
    memcpy(state, forkskinny128_384_key_in, 48);
    code.exec_permutation(state, sizeof(state), 21);
    return !memcmp(forkskinny128_384_key_out, state, 48);
}

bool test_forkskinny128_384_reverse_tk(Code &code)
{
    unsigned char state[48];
    memcpy(state, forkskinny128_384_key_out, 48);
    code.exec_permutation(state, sizeof(state), 21);
    return !memcmp(forkskinny128_384_key_in, state, 48);
}

bool test_forkskinny64_192_rounds(Code &code)
{
    unsigned char state[32];
    memcpy(state, forkskinny64_192_state_in, 32);
    code.exec_permutation(state, sizeof(state), 0, 87);
    return !memcmp(forkskinny64_192_state_out, state, 32);
}

bool test_forkskinny64_192_inv_rounds(Code &code)
{
    unsigned char state[32];
    memcpy(state, forkskinny64_192_state_out, 32);
    code.exec_permutation(state, sizeof(state), 87, 0);
    return !memcmp(forkskinny64_192_state_in, state, 32);
}

bool test_forkskinny64_192_forward_tk(Code &code)
{
    unsigned char state[24];
    memcpy(state, forkskinny64_192_key_in, 24);
    code.exec_permutation(state, sizeof(state), 21);
    return !memcmp(forkskinny64_192_key_out, state, 24);
}

bool test_forkskinny64_192_reverse_tk(Code &code)
{
    unsigned char state[24];
    memcpy(state, forkskinny64_192_key_out, 24);
    code.exec_permutation(state, sizeof(state), 21);
    return !memcmp(forkskinny64_192_key_in, state, 24);
}
