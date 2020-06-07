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

// Size of the WAGE state in bytes.
#define WAGE_STATE_SIZE 37

// Number of rounds for the WAGE permutation.
#define WAGE_NUM_ROUNDS 111

// Table numbers.
#define WAGE_TABLE_WGP_SBOX  0
#define WAGE_TABLE_RC        1

// RC0 and RC1 round constants for WAGE, interleaved with each other.
static unsigned char const wage_rc[WAGE_NUM_ROUNDS * 2] = {
    0x7f, 0x3f, 0x1f, 0x0f, 0x07, 0x03, 0x01, 0x40, 0x20, 0x10, 0x08, 0x04,
    0x02, 0x41, 0x60, 0x30, 0x18, 0x0c, 0x06, 0x43, 0x21, 0x50, 0x28, 0x14,
    0x0a, 0x45, 0x62, 0x71, 0x78, 0x3c, 0x1e, 0x4f, 0x27, 0x13, 0x09, 0x44,
    0x22, 0x51, 0x68, 0x34, 0x1a, 0x4d, 0x66, 0x73, 0x39, 0x5c, 0x2e, 0x57,
    0x2b, 0x15, 0x4a, 0x65, 0x72, 0x79, 0x7c, 0x3e, 0x5f, 0x2f, 0x17, 0x0b,
    0x05, 0x42, 0x61, 0x70, 0x38, 0x1c, 0x0e, 0x47, 0x23, 0x11, 0x48, 0x24,
    0x12, 0x49, 0x64, 0x32, 0x59, 0x6c, 0x36, 0x5b, 0x2d, 0x56, 0x6b, 0x35,
    0x5a, 0x6d, 0x76, 0x7b, 0x3d, 0x5e, 0x6f, 0x37, 0x1b, 0x0d, 0x46, 0x63,
    0x31, 0x58, 0x2c, 0x16, 0x4b, 0x25, 0x52, 0x69, 0x74, 0x3a, 0x5d, 0x6e,
    0x77, 0x3b, 0x1d, 0x4e, 0x67, 0x33, 0x19, 0x4c, 0x26, 0x53, 0x29, 0x54,
    0x2a, 0x55, 0x6a, 0x75, 0x7a, 0x7d, 0x7e, 0x7f, 0x3f, 0x1f, 0x0f, 0x07,
    0x03, 0x01, 0x40, 0x20, 0x10, 0x08, 0x04, 0x02, 0x41, 0x60, 0x30, 0x18,
    0x0c, 0x06, 0x43, 0x21, 0x50, 0x28, 0x14, 0x0a, 0x45, 0x62, 0x71, 0x78,
    0x3c, 0x1e, 0x4f, 0x27, 0x13, 0x09, 0x44, 0x22, 0x51, 0x68, 0x34, 0x1a,
    0x4d, 0x66, 0x73, 0x39, 0x5c, 0x2e, 0x57, 0x2b, 0x15, 0x4a, 0x65, 0x72,
    0x79, 0x7c, 0x3e, 0x5f, 0x2f, 0x17, 0x0b, 0x05, 0x42, 0x61, 0x70, 0x38,
    0x1c, 0x0e, 0x47, 0x23, 0x11, 0x48, 0x24, 0x12, 0x49, 0x64, 0x32, 0x59,
    0x6c, 0x36, 0x5b, 0x2d, 0x56, 0x6b, 0x35, 0x5a, 0x6d, 0x76, 0x7b, 0x3d,
    0x5e, 0x6f, 0x37, 0x1b, 0x0d, 0x46
};

// WGP and S-box combined into a single 256 byte table.
static unsigned char const wage_wgp_sbox[256] = {
    // S-box
    0x2e, 0x1c, 0x6d, 0x2b, 0x35, 0x07, 0x7f, 0x3b, 0x28, 0x08, 0x0b, 0x5f,
    0x31, 0x11, 0x1b, 0x4d, 0x6e, 0x54, 0x0d, 0x09, 0x1f, 0x45, 0x75, 0x53,
    0x6a, 0x5d, 0x61, 0x00, 0x04, 0x78, 0x06, 0x1e, 0x37, 0x6f, 0x2f, 0x49,
    0x64, 0x34, 0x7d, 0x19, 0x39, 0x33, 0x43, 0x57, 0x60, 0x62, 0x13, 0x05,
    0x77, 0x47, 0x4f, 0x4b, 0x1d, 0x2d, 0x24, 0x48, 0x74, 0x58, 0x25, 0x5e,
    0x5a, 0x76, 0x41, 0x42, 0x27, 0x3e, 0x6c, 0x01, 0x2c, 0x3c, 0x4e, 0x1a,
    0x21, 0x2a, 0x0a, 0x55, 0x3a, 0x38, 0x18, 0x7e, 0x0c, 0x63, 0x67, 0x56,
    0x50, 0x7c, 0x32, 0x7a, 0x68, 0x02, 0x6b, 0x17, 0x7b, 0x59, 0x71, 0x0f,
    0x30, 0x10, 0x22, 0x3d, 0x40, 0x69, 0x52, 0x14, 0x36, 0x44, 0x46, 0x03,
    0x16, 0x65, 0x66, 0x72, 0x12, 0x0e, 0x29, 0x4a, 0x4c, 0x70, 0x15, 0x26,
    0x79, 0x51, 0x23, 0x3f, 0x73, 0x5b, 0x20, 0x5c,

    // WGP
    0x00, 0x12, 0x0a, 0x4b, 0x66, 0x0c, 0x48, 0x73, 0x79, 0x3e, 0x61, 0x51,
    0x01, 0x15, 0x17, 0x0e, 0x7e, 0x33, 0x68, 0x36, 0x42, 0x35, 0x37, 0x5e,
    0x53, 0x4c, 0x3f, 0x54, 0x58, 0x6e, 0x56, 0x2a, 0x1d, 0x25, 0x6d, 0x65,
    0x5b, 0x71, 0x2f, 0x20, 0x06, 0x18, 0x29, 0x3a, 0x0d, 0x7a, 0x6c, 0x1b,
    0x19, 0x43, 0x70, 0x41, 0x49, 0x22, 0x77, 0x60, 0x4f, 0x45, 0x55, 0x02,
    0x63, 0x47, 0x75, 0x2d, 0x40, 0x46, 0x7d, 0x5c, 0x7c, 0x59, 0x26, 0x0b,
    0x09, 0x03, 0x57, 0x5d, 0x27, 0x78, 0x30, 0x2e, 0x44, 0x52, 0x3b, 0x08,
    0x67, 0x2c, 0x05, 0x6b, 0x2b, 0x1a, 0x21, 0x38, 0x07, 0x0f, 0x4a, 0x11,
    0x50, 0x6a, 0x28, 0x31, 0x10, 0x4d, 0x5f, 0x72, 0x39, 0x16, 0x5a, 0x13,
    0x04, 0x3c, 0x34, 0x1f, 0x76, 0x1e, 0x14, 0x23, 0x1c, 0x32, 0x4e, 0x7b,
    0x24, 0x74, 0x7f, 0x3d, 0x69, 0x64, 0x62, 0x6f
};

Sbox get_wage_round_constants(int num)
{
    if (num == WAGE_TABLE_RC)
        return Sbox(wage_rc, sizeof(wage_rc));
    else
        return Sbox(wage_wgp_sbox, sizeof(wage_wgp_sbox));
}

struct WageState
{
    Code *code;
    Reg s[WAGE_STATE_SIZE];
    Reg fb[3];
    Reg temp;
    unsigned char modified[WAGE_STATE_SIZE];
    int last_used[WAGE_STATE_SIZE];
    int time;

    WageState(Code &c)
        : code(&c), time(1)
    {
        memset(modified, 0, sizeof(modified));
        memset(last_used, 0, sizeof(last_used));
        temp = code->allocateHighReg(1);
    }

    // Load a byte from the state into a register if not already in one.
    // Return the existing register if the value is still in a register.
    // If we have run out of registers, spill the oldest one.
    Reg reg(int num);

    // Mark a byte as having been used to keep the register fresh.
    // This will avoid a spill on a value we know we'll need again
    // soon in the upcoming code.
    void used(int num);

    // Mark a byte as dirty.  Register contents have been modified.
    void dirty(int num);

    // Spill a register back to the stack if the value has been modified.
    // Then release the register back to the allocation pool.
    void spill(int num);

    // Spill the oldest unmodified value that is in a high register.
    void spillHigh();

    // Spill the oldest unmodified value that is in any register.
    void spillAny();

    // Determine if a state byte is active in a register or if it is
    // still on the stack.
    bool isActive(int num);

    // Copy a value into the stack and release the original register.
    void copy(int to, int from);
};

Reg WageState::reg(int num)
{
    if (s[num].size() != 0) {
        last_used[num] = time++;
        return s[num];
    }
    s[num] = code->allocateOptionalReg(1);
    if (s[num].size() == 0) {
        // We have run out of registers so find the oldest value
        // that is not modified and reuse that register.  We should
        // be able to find something.
        int age = 0x7FFFFFFF;
        int oldest = -1;
        for (int index = 0; index < WAGE_STATE_SIZE; ++index) {
            if (s[index].size() != 0 && !modified[index]) {
                if (last_used[index] < age) {
                    age = last_used[index];
                    oldest = index;
                }
            }
        }
        if (oldest == -1) {
            // Try again but this time find the oldest modified register.
            int age = 0x7FFFFFFF;
            int oldest = -1;
            for (int index = 0; index < WAGE_STATE_SIZE; ++index) {
                 if (s[index].size() != 0 && modified[index]) {
                    if (last_used[index] < age) {
                        age = last_used[index];
                        oldest = index;
                    }
                }
            }
            if (oldest == -1)
                throw std::invalid_argument("not enough registers for wage");
        }
        spill(oldest);
        s[num] = code->allocateReg(1);
    }
    code->ldlocal(s[num], num);
    last_used[num] = time++;
    modified[num] = 0;
    return s[num];
}

void WageState::used(int num)
{
    last_used[num] = time++;
}

void WageState::dirty(int num)
{
    modified[num] = 1;
    last_used[num] = time++;
}

void WageState::spill(int num)
{
    if (s[num].size() == 0) {
        // Register not currently in use.
        return;
    }
    if (modified[num])
        code->stlocal(s[num], num);
    code->releaseReg(s[num]);
    s[num] = Reg();
}

void WageState::spillHigh()
{
    int age = 0x7FFFFFFF;
    int oldest = -1;
    for (int index = 0; index < WAGE_STATE_SIZE; ++index) {
        if (s[index].size() != 0 && !modified[index]) {
            if (s[index].reg(0) >= 16 && last_used[index] < age) {
                age = last_used[index];
                oldest = index;
            }
        }
    }
    if (oldest == -1)
        throw std::invalid_argument("cannot find a high register to spill");
    spill(oldest);
}

void WageState::spillAny()
{
    int age = 0x7FFFFFFF;
    int oldest = -1;
    for (int index = 0; index < WAGE_STATE_SIZE; ++index) {
        if (s[index].size() != 0 && !modified[index]) {
            if (last_used[index] < age) {
                age = last_used[index];
                oldest = index;
            }
        }
    }
    if (oldest == -1)
        throw std::invalid_argument("cannot find a register to spill");
    spill(oldest);
}

bool WageState::isActive(int num)
{
    return s[num].size() != 0;
}

void WageState::copy(int to, int from)
{
    if (s[from].size() != 0) {
        // The source value is already in a register.
        code->stlocal(s[from], to);
        code->releaseReg(s[from]);
        s[from] = Reg();
    } else {
        // The source value is still on the stack, so copy via a temporary.
        code->ldlocal(temp, from);
        code->stlocal(temp, to);
    }
}

void gen_wage_permutation(Code &code)
{
    int index;

    // Set up the function prologue with 37 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("wage_permute", 37);

    // Allocate temporary registers and the state object.
    WageState s(code);
    Reg round = code.allocateHighReg(1);
    Reg fb = code.allocateReg(3);
    Reg fb0 = Reg(fb, 0, 1);
    Reg fb1 = Reg(fb, 1, 1);
    Reg fb2 = Reg(fb, 2, 1);
    #define S(num) (s.reg((num)))

    // Copy the input to local variables because we need Z to point
    // at the S-box, WGP, and RC tables.
    for (index = 0; index < 36; index += 3) {
        code.ldz(fb, index);
        code.stlocal(fb, index);
    }
    code.ldz(fb0, 36);
    code.stlocal(fb0, 36);

    // Save Z on the stack and set it up to point at the WGP/S-box table.
    code.push(Reg::z_ptr());
    code.sbox_setup
        (WAGE_TABLE_WGP_SBOX, get_wage_round_constants(WAGE_TABLE_WGP_SBOX));

    // Perform all rounds 3 at a time.
    unsigned char top_label = 0;
    code.move(round, 0);
    code.label(top_label);

    // Calculate the feedback value for the LFSR.
    //
    // fb = omega(s[0]) ^ s[6] ^ s[8] ^ s[12] ^ s[13] ^ s[19] ^
    //      s[24] ^ s[26] ^ s[30] ^ s[31] ^ WGP(s[36]) ^ RC1[round]
    //
    // where omega(x) is (x >> 1) if the low bit of x is zero and
    // (x >> 1) ^ 0x78 if the low bit of x is one.
    //
    // fb0 = (s[0] >> 1) ^ (0x78 & -(s[0] & 0x01));
    code.ldlocal(fb0, 0);
    code.tworeg(Insn::MOV, s.temp.reg(0), ZERO_REG);
    code.lsr(fb0, 1);
    code.tworeg(Insn::SBC, s.temp.reg(0), ZERO_REG);
    code.logand(s.temp, 0x78);
    code.logxor(fb0, s.temp);

    // fb0 ^= s[6]  ^ s[8]  ^ s[12] ^ s[13] ^ s[19] ^
    //        s[24] ^ s[26] ^ s[30] ^ s[31] ^ rc[1];
    code.logxor(fb0, S(6));
    code.logxor(fb0, S(8));
    code.logxor(fb0, S(12));
    code.logxor(fb0, S(13));
    code.logxor(fb0, S(19));
    code.logxor(fb0, S(24));
    code.logxor(fb0, S(26));
    code.logxor(fb0, S(30));
    code.logxor(fb0, S(31));

    // fb1 = (s[1] >> 1) ^ (0x78 & -(s[1] & 0x01));
    code.ldlocal(fb1, 1);
    code.tworeg(Insn::MOV, s.temp.reg(0), ZERO_REG);
    code.lsr(fb1, 1);
    code.tworeg(Insn::SBC, s.temp.reg(0), ZERO_REG);
    code.logand(s.temp, 0x78);
    code.logxor(fb1, s.temp);

    // fb1 ^= s[7]  ^ s[9]  ^ s[13] ^ s[14] ^ s[20] ^
    //        s[25] ^ s[27] ^ s[31] ^ s[32] ^ rc[3];
    code.logxor(fb1, S(7));
    code.logxor(fb1, S(9));
    code.logxor(fb1, S(13));
    code.logxor(fb1, S(14));
    code.logxor(fb1, S(20));
    code.logxor(fb1, S(25));
    code.logxor(fb1, S(27));
    code.logxor(fb1, S(31));
    code.logxor(fb1, S(32));

    // fb2 = (s[2] >> 1) ^ (0x78 & -(s[2] & 0x01));
    code.ldlocal(fb2, 2);
    code.tworeg(Insn::MOV, s.temp.reg(0), ZERO_REG);
    code.lsr(fb2, 1);
    code.tworeg(Insn::SBC, s.temp.reg(0), ZERO_REG);
    code.logand(s.temp, 0x78);
    code.logxor(fb2, s.temp);

    // fb2 ^= s[8]  ^ s[10] ^ s[14] ^ s[15] ^ s[21] ^
    //        s[26] ^ s[28] ^ s[32] ^ s[33] ^ rc[5];
    code.logxor(fb2, S(8));
    code.logxor(fb2, S(10));
    code.logxor(fb2, S(14));
    code.logxor(fb2, S(15));
    code.logxor(fb2, S(21));
    code.logxor(fb2, S(26));
    code.logxor(fb2, S(28));
    code.logxor(fb2, S(32));
    code.logxor(fb2, S(33));

    // Apply the S-box and WGP permutation to certain components.
    // s[5] ^= wage_sbox[s[8]];
    code.sbox_lookup(s.temp, S(8));
    code.logxor(S(5), s.temp);
    s.dirty(5);

    // s[6] ^= wage_sbox[s[9]];
    code.sbox_lookup(s.temp, S(9));
    code.logxor(S(6), s.temp);
    s.dirty(6);

    // s[7] ^= wage_sbox[s[10]];
    code.sbox_lookup(s.temp, S(10));
    code.logxor(S(7), s.temp);
    s.dirty(7);

    // s[11] ^= wage_sbox[s[15]];
    code.sbox_lookup(s.temp, S(15));
    code.logxor(S(11), s.temp);
    s.dirty(11);

    // s[12] ^= wage_sbox[s[16]];
    code.sbox_lookup(s.temp, S(16));
    code.logxor(S(12), s.temp);
    s.dirty(12);

    // s[13] ^= wage_sbox[s[17]];
    code.sbox_lookup(s.temp, S(17));
    code.logxor(S(13), s.temp);
    s.dirty(13);

    // s[24] ^= wage_sbox[s[27]];
    code.sbox_lookup(s.temp, S(27));
    code.logxor(S(24), s.temp);
    s.dirty(24);

    // s[25] ^= wage_sbox[s[28]];
    code.sbox_lookup(s.temp, S(28));
    code.logxor(S(25), s.temp);
    s.dirty(25);

    // s[26] ^= wage_sbox[s[29]];
    code.sbox_lookup(s.temp, S(29));
    code.logxor(S(26), s.temp);
    s.dirty(26);

    // s[30] ^= wage_sbox[s[34]];
    code.sbox_lookup(s.temp, S(34));
    code.logxor(S(30), s.temp);
    s.dirty(30);

    // s[31] ^= wage_sbox[s[35]];
    code.sbox_lookup(s.temp, S(35));
    code.logxor(S(31), s.temp);
    s.dirty(31);

    // s[32] ^= wage_sbox[s[36]];
    code.sbox_lookup(s.temp, S(36));
    code.logxor(S(32), s.temp);
    s.dirty(32);

    // Prepare to load round constants rc[0], rc[2], rc[4] for later.
    s.spillHigh(); // Need a spare high register for sbox_switch().
    s.spillAny();  // Need some other spare registers for the round constants.
    s.spillAny();
    code.sbox_switch(WAGE_TABLE_RC, get_wage_round_constants(WAGE_TABLE_RC));
    Reg rc0 = code.allocateReg(1);
    Reg rc2 = code.allocateReg(1);
    Reg rc4 = code.allocateReg(1);

    // Load rc[0];
    code.sbox_lookup(rc0, round);
    code.inc(round);

    // fb0 ^= rc[1];
    code.sbox_lookup(s.temp, round);
    code.logxor(fb0, s.temp);
    code.inc(round);

    // Load rc[2];
    code.sbox_lookup(rc2, round);
    code.inc(round);

    // fb1 ^= rc[3];
    code.sbox_lookup(s.temp, round);
    code.logxor(fb1, s.temp);
    code.inc(round);

    // Load rc[4];
    code.sbox_lookup(rc4, round);
    code.inc(round);

    // fb2 ^= rc[5];
    code.sbox_lookup(s.temp, round);
    code.logxor(fb2, s.temp);
    code.inc(round);

    // s[19] ^= wage_wgp[s[18]] ^ rc[0];
    Reg zlow = Reg(Reg::z_ptr(), 0, 1);
    s.spillHigh(); // Need a spare high register for sbox_switch().
    code.sbox_switch
        (WAGE_TABLE_WGP_SBOX, get_wage_round_constants(WAGE_TABLE_WGP_SBOX));
    code.move(zlow, S(18));
    code.logor(zlow, 0x80);
    code.sbox_lookup(s.temp, zlow);
    code.logxor(S(19), s.temp);
    code.logxor(S(19), rc0);
    code.releaseReg(rc0);
    s.dirty(19);

    // s[20] ^= wage_wgp[s[19]] ^ rc[2];
    code.move(zlow, S(19));
    code.logor(zlow, 0x80);
    code.sbox_lookup(s.temp, zlow);
    code.logxor(S(20), s.temp);
    code.logxor(S(20), rc2);
    code.releaseReg(rc2);
    s.dirty(20);

    // s[21] ^= wage_wgp[s[20]] ^ rc[4];
    code.move(zlow, S(20));
    code.logor(zlow, 0x80);
    code.sbox_lookup(s.temp, zlow);
    code.logxor(S(21), s.temp);
    code.logxor(S(21), rc4);
    code.releaseReg(rc4);
    s.dirty(21);

    // fb0 ^= wage_wgp[s[36]];
    code.move(zlow, S(36));
    code.logor(zlow, 0x80);
    code.sbox_lookup(s.temp, zlow);
    code.logxor(fb0, s.temp);

    // fb1 ^= wage_wgp[fb0];
    code.move(zlow, fb0);
    code.logor(zlow, 0x80);
    code.sbox_lookup(s.temp, zlow);
    code.logxor(fb1, s.temp);

    // fb2 ^= wage_wgp[fb1];
    code.move(zlow, fb1);
    code.logor(zlow, 0x80);
    code.sbox_lookup(s.temp, zlow);
    code.logxor(fb2, s.temp);

    // Rotate the components of the state by 3 positions.
    for (index = 0; index < 34; ++index)
        s.copy(index, index + 3);
    code.stlocal(fb0, 34);
    code.stlocal(fb1, 35);
    code.stlocal(fb2, 36);

    // Bottom of the round loop.
    code.compare_and_loop(round, WAGE_NUM_ROUNDS * 2, top_label);

    // Restore Z and copy the local variables back to the state.
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    for (index = 0; index < 36; index += 3) {
        code.ldlocal(fb, index);
        code.stz(fb, index);
    }
    code.ldlocal(fb0, 36);
    code.stz(fb0, 36);
}

// 7-bit components for the rate.
static unsigned char wage_rate_bytes[10] = {
    8, 9, 15, 16, 18, 27, 28, 34, 35, 36
};

void gen_wage_absorb(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    code.prologue_setup_key("wage_absorb", 0);
    code.setFlag(Code::NoLocals);

    // Load the first 32 bits of the block to be absorbed.
    Reg temp = code.allocateReg(5);
    code.ldx(Reg(temp, 1, 4).reversed(), POST_INC);
    code.move(Reg(temp, 0, 1), 0);

    // Absorb the first 32-bits into the state pointed to by Z,
    // after breaking it up into 7-bit components.
    code.lsr(temp, 1);
    code.ldz_xor_in(Reg(temp, 4, 1), wage_rate_bytes[0]);
    Reg tnext = Reg(temp, 0, 4);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 3, 1), wage_rate_bytes[1]);
    tnext = Reg(temp, 0, 3);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 2, 1), wage_rate_bytes[2]);
    tnext = Reg(temp, 0, 2);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 1, 1), wage_rate_bytes[3]);
    tnext = Reg(temp, 0, 1);
    code.lsr(tnext, 1);
    code.ldz_xor_in(tnext, wage_rate_bytes[4]);

    // Load the next 32 bits of the block to be absorbed.
    code.releaseReg(temp);
    temp = code.allocateReg(6);
    code.ldx(Reg(temp, 1, 4).reversed(), POST_INC);
    code.move(Reg(temp, 5, 1), 0);
    code.move(Reg(temp, 0, 1), 0);

    // Absorb the next 32-bits into the state pointed to by Z,
    // after breaking it up into 7-bit components.
    code.lsl(Reg(temp, 1, 5), 3);
    code.ldz_xor_in(Reg(temp, 5, 1), wage_rate_bytes[4]);
    tnext = Reg(temp, 1, 4);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 3, 1), wage_rate_bytes[5]);
    tnext = Reg(temp, 1, 3);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 2, 1), wage_rate_bytes[6]);
    tnext = Reg(temp, 1, 2);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 1, 1), wage_rate_bytes[7]);
    tnext = Reg(temp, 0, 2);
    code.lsr(tnext, 1);
    code.ldz_xor_in(Reg(tnext, 1, 1), wage_rate_bytes[8]);
    tnext = Reg(temp, 0, 1);
    code.lsr(tnext, 1);
    code.ldz_xor_in(tnext, wage_rate_bytes[9]);
}

void gen_wage_get_rate(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    code.prologue_setup_key("wage_get_rate", 0);
    code.setFlag(Code::NoLocals);

    // Combine the components for the first 32-bit word.
    Reg temp = code.allocateReg(4);
    code.ldz(Reg(temp, 3, 1), wage_rate_bytes[0]);
    code.ldz(Reg(temp, 2, 1), wage_rate_bytes[1]);
    code.ldz(Reg(temp, 1, 1), wage_rate_bytes[2]);
    code.ldz(Reg(temp, 0, 1), wage_rate_bytes[3]);
    code.lsl(Reg(temp, 0, 1), 1);
    code.lsl(Reg(temp, 0, 2), 1);
    code.lsl(Reg(temp, 0, 3), 1);
    code.lsl(Reg(temp, 0, 4), 1);
    Reg temp2 = code.allocateReg(1);
    code.ldz(temp2, wage_rate_bytes[4]);
    code.lsr(temp2, 3);
    code.logor(Reg(temp, 0, 1), temp2);
    code.stx(temp.reversed(), POST_INC);

    // Combine the components for the second 32-bit word.
    code.ldz(Reg(temp, 3, 1), wage_rate_bytes[4]);
    code.ldz(Reg(temp, 2, 1), wage_rate_bytes[5]);
    code.ldz(Reg(temp, 1, 1), wage_rate_bytes[6]);
    code.ldz(Reg(temp, 0, 1), wage_rate_bytes[7]);
    code.lsl(Reg(temp, 0, 1), 1);
    code.lsl(Reg(temp, 0, 2), 1);
    code.lsl(Reg(temp, 0, 3), 1);
    code.lsr(Reg(temp, 0, 4), 3);
    code.stx(Reg(temp, 0, 3).reversed(), POST_INC);
    code.ldz(Reg(temp, 1, 1), wage_rate_bytes[8]);
    code.ldz(Reg(temp, 0, 1), wage_rate_bytes[9]);
    code.lsl(Reg(temp, 0, 1), 1);
    code.lsl(Reg(temp, 0, 2), 1);
    code.stx(Reg(temp, 1, 1), POST_INC);
}

void gen_wage_set_rate(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    code.prologue_setup_key("wage_set_rate", 0);
    code.setFlag(Code::NoLocals);

    // Load the first 32 bits of the block to be set.
    Reg temp = code.allocateReg(5);
    code.ldx(Reg(temp, 1, 4).reversed(), POST_INC);
    code.move(Reg(temp, 0, 1), 0);

    // Set the first 32-bits into the state pointed to by Z,
    // after breaking it up into 7-bit components.
    code.lsr(temp, 1);
    code.stz(Reg(temp, 4, 1), wage_rate_bytes[0]);
    Reg tnext = Reg(temp, 0, 4);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 3, 1), wage_rate_bytes[1]);
    tnext = Reg(temp, 0, 3);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 2, 1), wage_rate_bytes[2]);
    tnext = Reg(temp, 0, 2);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 1, 1), wage_rate_bytes[3]);
    tnext = Reg(temp, 0, 1);
    code.lsr(tnext, 1);
    code.stz(tnext, wage_rate_bytes[4]);

    // Load the next 32 bits of the block to be set.
    code.releaseReg(temp);
    temp = code.allocateReg(6);
    code.ldx(Reg(temp, 1, 4).reversed(), POST_INC);
    code.move(Reg(temp, 5, 1), 0);
    code.move(Reg(temp, 0, 1), 0);

    // Set the next 32-bits into the state pointed to by Z,
    // after breaking it up into 7-bit components.
    code.lsl(Reg(temp, 1, 5), 3);
    code.ldz_xor_in(Reg(temp, 5, 1), wage_rate_bytes[4]);
    tnext = Reg(temp, 1, 4);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 3, 1), wage_rate_bytes[5]);
    tnext = Reg(temp, 1, 3);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 2, 1), wage_rate_bytes[6]);
    tnext = Reg(temp, 1, 2);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 1, 1), wage_rate_bytes[7]);
    tnext = Reg(temp, 0, 2);
    code.lsr(tnext, 1);
    code.stz(Reg(tnext, 1, 1), wage_rate_bytes[8]);
    tnext = Reg(temp, 0, 1);
    code.lsr(tnext, 1);
    Reg tprev = code.allocateHighReg(1);
    code.ldz(tprev, wage_rate_bytes[9]);
    code.logand(tprev, 0x3F);
    code.logxor(tprev, tnext);
    code.stz(tprev, wage_rate_bytes[9]);
}

bool test_wage_permutation(Code &code)
{
    static unsigned char const wage_input[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24
    };
    static unsigned char const wage_output[] = {
        0x44, 0x78, 0x43, 0x21, 0x25, 0x6f, 0x30, 0x64,
        0x00, 0x27, 0x00, 0x76, 0x27, 0x4b, 0x73, 0x25,
        0x33, 0x43, 0x6c, 0x0e, 0x76, 0x17, 0x35, 0x49,
        0x0a, 0x16, 0x69, 0x23, 0x1d, 0x39, 0x64, 0x36,
        0x5f, 0x72, 0x18, 0x61, 0x01
    };
    unsigned char state[37];
    memcpy(state, wage_input, 37);
    code.exec_permutation(state, 37);
    return !memcmp(wage_output, state, 37);
}
