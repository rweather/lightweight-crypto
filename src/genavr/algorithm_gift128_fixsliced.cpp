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
#include <cstdio>

/* Round constants for GIFT-128 in the fixsliced representation */
static uint32_t const GIFT128_RC_fixsliced[40] = {
    0x10000008, 0x80018000, 0x54000002, 0x01010181, 0x8000001f, 0x10888880,
    0x6001e000, 0x51500002, 0x03030180, 0x8000002f, 0x10088880, 0x60016000,
    0x41500002, 0x03030080, 0x80000027, 0x10008880, 0x4001e000, 0x11500002,
    0x03020180, 0x8000002b, 0x10080880, 0x60014000, 0x01400002, 0x02020080,
    0x80000021, 0x10000080, 0x0001c000, 0x51000002, 0x03010180, 0x8000002e,
    0x10088800, 0x60012000, 0x40500002, 0x01030080, 0x80000006, 0x10008808,
    0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};

enum {
    StateBE,    /**< Load and store in bit-sliced big-endian byte order */
    StateLE,    /**< Load and store in bit-sliced little-endian byte order */
    StateNibble,/**< Load and store in nibble order */
    StateNibbleBE,/**< Load and store in big-endian nibble order */
    StateTweak  /**< Nibble-based with in-place tweaked key schedule */
};

class Gift128StateFS
{
public:
    Gift128StateFS(Code &code);

    // 32-bit registers that hold the state.
    Reg s0, s1, s2, s3;

    // Temporaries.
    Reg t1;

    // 32-bit register that holds the last word of the key schedule.
    // Bit-sliced decryption only.
    Reg w3;

    // True if the key schedule is in-place without a w3 register.
    // Bit-sliced decryption only.
    bool inplace;

    void sbox(Code &code, const Reg &s0, const Reg &s1,
              const Reg &s2, const Reg &s3);
    void inv_sbox(Code &code, const Reg &s0, const Reg &s1,
                  const Reg &s2, const Reg &s3);
    void load_state(Code &code, int ordering);
    void store_state(Code &code, int ordering);
    void print_state(Code &code);

    void rol_nibble(Code &code, const Reg &reg, unsigned shift);

    void permute_state_1(Code &code);
    void permute_state_2(Code &code);
    void permute_state_3(Code &code);
    void permute_state_4(Code &code);
    void permute_state_5(Code &code);

    void inv_permute_state_1(Code &code);
    void inv_permute_state_2(Code &code);
    void inv_permute_state_3(Code &code);
    void inv_permute_state_4(Code &code);
    void inv_permute_state_5(Code &code);

    void xor_rc_inc(Code &code, const Reg &sreg);
    void xor_rc_dec(Code &code, const Reg &sreg);
    void xor_tweak(Code &code, const Reg &tweak);

    void inv_sub_cells(Code &code);
    void perm_bits(Code &code, bool inverse = false);
    void inv_rotate_key(Code &code, int round);
};

Gift128StateFS::Gift128StateFS(Code &code)
    : inplace(false)
{
    // Allocate a temporary; must be in a high register.
    t1 = code.allocateHighReg(4);

    // Allocate registers for the state.
    s0 = code.allocateReg(4);
    s1 = code.allocateReg(4);
    s2 = code.allocateReg(4);
    s3 = code.allocateReg(4);
}

void Gift128StateFS::sbox
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    // s1 ^= s0 & s2;
    code.logxor_and(s1, s0, s2);

    // s0 ^= s1 & s3;
    code.logxor_and(s0, s1, s3);

    // s2 ^= s0 | s1;
    code.logxor_or(s2, s0, s1);

    // s3 ^= s2;
    code.logxor(s3, s2);

    // s1 ^= s3;
    code.logxor(s1, s3);

    // s3 ^= 0xFFFFFFFFU;
    code.lognot(s3);

    // s2 ^= s0 & s1;
    code.logxor_and(s2, s0, s1);
}

void Gift128StateFS::inv_sbox
    (Code &code, const Reg &s0, const Reg &s1, const Reg &s2, const Reg &s3)
{
    // s2 ^= s3 & s1;
    code.logxor_and(s2, s3, s1);

    // s0 ^= 0xFFFFFFFFU;
    code.lognot(s0);

    // s1 ^= s0;
    code.logxor(s1, s0);

    // s0 ^= s2;
    code.logxor(s0, s2);

    // s2 ^= s3 | s1;
    code.logxor_or(s2, s3, s1);

    // s3 ^= s1 & s0;
    code.logxor_and(s3, s1, s0);

    // s1 ^= s3 & s2;
    code.logxor_and(s1, s3, s2);
}

void Gift128StateFS::load_state(Code &code, int ordering)
{
    if (ordering == StateBE) {
        code.ldx(s0.reversed(), POST_INC);
        code.ldx(s1.reversed(), POST_INC);
        code.ldx(s2.reversed(), POST_INC);
        code.ldx(s3.reversed(), POST_INC);
    } else if (ordering == StateLE) {
        code.ldx(s0, POST_INC);
        code.ldx(s1, POST_INC);
        code.ldx(s2, POST_INC);
        code.ldx(s3, POST_INC);
    } else if (ordering == StateNibbleBE) {
        int word, bit;
        for (word = 0; word < 4; ++word) {
            code.ldx(t1.reversed(), POST_INC);
            for (bit = 0; bit < 32; ++bit) {
                Reg dst;
                switch (bit % 4) {
                case 0: default:    dst = s3; break;
                case 1:             dst = s2; break;
                case 2:             dst = s1; break;
                case 3:             dst = s0; break;
                }
                code.bit_get(t1, 31 - bit);
                code.bit_put(dst, ((31 - bit) / 4) + ((3 - word) * 8));
            }
        }
    } else {
        int word, bit;
        for (word = 0; word < 4; ++word) {
            code.ldx(t1, POST_INC);
            for (bit = 0; bit < 32; ++bit) {
                Reg dst;
                switch (bit % 4) {
                case 0: default:    dst = s0; break;
                case 1:             dst = s1; break;
                case 2:             dst = s2; break;
                case 3:             dst = s3; break;
                }
                code.bit_get(t1, bit);
                code.bit_put(dst, (bit / 4) + (word * 8));
            }
        }
    }
}

void Gift128StateFS::store_state(Code &code, int ordering)
{
    if (ordering == StateBE) {
        code.stx(s0.reversed(), POST_INC);
        code.stx(s1.reversed(), POST_INC);
        code.stx(s2.reversed(), POST_INC);
        code.stx(s3.reversed(), POST_INC);
    } else if (ordering == StateLE) {
        code.stx(s0, POST_INC);
        code.stx(s1, POST_INC);
        code.stx(s2, POST_INC);
        code.stx(s3, POST_INC);
    } else if (ordering == StateNibbleBE) {
        int word, bit;
        for (word = 0; word < 4; ++word) {
            for (bit = 0; bit < 32; ++bit) {
                Reg src;
                switch (bit % 4) {
                case 0: default:    src = s3; break;
                case 1:             src = s2; break;
                case 2:             src = s1; break;
                case 3:             src = s0; break;
                }
                code.bit_get(src, ((31 - bit) / 4) + ((3 - word) * 8));
                code.bit_put(t1, 31 - bit);
            }
            code.stx(t1.reversed(), POST_INC);
        }
    } else {
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
                code.bit_put(t1, bit);
            }
            code.stx(t1, POST_INC);
        }
    }
}

void Gift128StateFS::print_state(Code &code)
{
    if (!code.hasFlag(Code::Print))
        code.setFlag(Code::Print);
    code.print(s0);
    code.print(s1);
    code.print(s2);
    code.print(s3);
    code.println();
}

// Rotate the nibbles of a word left by a number of bits.
void Gift128StateFS::rol_nibble(Code &code, const Reg &reg, unsigned shift)
{
    uint32_t mask;
    if (shift == 1) {
        mask = 0xEEEEEEEEU;
    } else if (shift == 2) {
        mask = 0xCCCCCCCCU;
    } else {
        mask = 0x88888888U;
    }
    code.move(t1, reg);
    code.lsl(t1, shift);
    code.logand(t1, mask);
    code.lsr(reg, 4 - shift);
    code.logand(reg, ~mask);
    code.logor(reg, t1);
}

void Gift128StateFS::permute_state_1(Code &code)
{
    // s1 = ((s1 >> 2) & 0x33333333U) | ((s1 & 0x33333333U) << 2);
    rol_nibble(code, s1, 2);

    // s2 = ((s2 >> 3) & 0x11111111U) | ((s2 & 0x77777777U) << 1);
    rol_nibble(code, s2, 1);

    // s3 = ((s3 >> 1) & 0x77777777U) | ((s3 & 0x11111111U) << 3);
    rol_nibble(code, s3, 3);
}

void Gift128StateFS::permute_state_2(Code &code)
{
    // s0 = ((s0 >>  4) & 0x0FFF0FFFU) | ((s0 & 0x000F000FU) << 12);
    code.ror(Reg(s0, 0, 2), 4);
    code.ror(Reg(s0, 2, 2), 4);

    // s1 = ((s1 >>  8) & 0x00FF00FFU) | ((s1 & 0x00FF00FFU) << 8);
    code.rol(Reg(s1, 0, 2), 8);
    code.rol(Reg(s1, 2, 2), 8);

    // s2 = ((s2 >> 12) & 0x000F000FU) | ((s2 & 0x0FFF0FFFU) << 4);
    code.rol(Reg(s2, 0, 2), 4);
    code.rol(Reg(s2, 2, 2), 4);
}

void Gift128StateFS::permute_state_3(Code &code)
{
    // gift128b_swap_move(s1, s1, 0x55555555U, 1);
    code.swapmove(s1, 0x55555555U, 1, t1);

    // s2 = leftRotate16(s2);
    // gift128b_swap_move(s2, s2, 0x00005555U, 1);
    code.rol(s2, 16);
    code.swapmove(s2, 0x00005555U, 1, t1);

    // s3 = leftRotate16(s3);
    // gift128b_swap_move(s3, s3, 0x55550000U, 1);
    code.rol(s3, 16);
    code.swapmove(s3, 0x55550000U, 1, t1);
}

void Gift128StateFS::permute_state_4(Code &code)
{
    // s0 = ((s0 >> 6) & 0x03030303U) | ((s0 & 0x3F3F3F3FU) << 2);
    code.rol(Reg(s0, 0, 1), 2);
    code.rol(Reg(s0, 1, 1), 2);
    code.rol(Reg(s0, 2, 1), 2);
    code.rol(Reg(s0, 3, 1), 2);

    // s1 = ((s1 >> 4) & 0x0F0F0F0FU) | ((s1 & 0x0F0F0F0FU) << 4);
    code.rol(Reg(s1, 0, 1), 4);
    code.rol(Reg(s1, 1, 1), 4);
    code.rol(Reg(s1, 2, 1), 4);
    code.rol(Reg(s1, 3, 1), 4);

    // s2 = ((s2 >> 2) & 0x3F3F3F3FU) | ((s2 & 0x03030303U) << 6);
    code.ror(Reg(s2, 0, 1), 2);
    code.ror(Reg(s2, 1, 1), 2);
    code.ror(Reg(s2, 2, 1), 2);
    code.ror(Reg(s2, 3, 1), 2);
}

void Gift128StateFS::permute_state_5(Code &code)
{
    // s1 = leftRotate16(s1);
    code.rol(s1, 16);

    // s2 = rightRotate8(s2);
    code.ror(s2, 8);

    // s3 = leftRotate8(s3);
    code.rol(s3, 8);
}

void Gift128StateFS::inv_permute_state_1(Code &code)
{
    // s1 = ((s1 >> 2) & 0x33333333U) | ((s1 & 0x33333333U) << 2);
    rol_nibble(code, s1, 2);

    // s2 = ((s2 >> 1) & 0x77777777U) | ((s2 & 0x11111111U) << 3);
    rol_nibble(code, s2, 3);

    // s3 = ((s3 >> 3) & 0x11111111U) | ((s3 & 0x77777777U) << 1);
    rol_nibble(code, s3, 1);
}

void Gift128StateFS::inv_permute_state_2(Code &code)
{
    // s0 = ((s0 >> 12) & 0x000F000FU) | ((s0 & 0x0FFF0FFFU) << 4);
    code.rol(Reg(s0, 0, 2), 4);
    code.rol(Reg(s0, 2, 2), 4);

    // s1 = ((s1 >>  8) & 0x00FF00FFU) | ((s1 & 0x00FF00FFU) << 8);
    code.rol(Reg(s1, 0, 2), 8);
    code.rol(Reg(s1, 2, 2), 8);

    // s2 = ((s2 >>  4) & 0x0FFF0FFFU) | ((s2 & 0x000F000FU) << 12);
    code.ror(Reg(s2, 0, 2), 4);
    code.ror(Reg(s2, 2, 2), 4);
}

void Gift128StateFS::inv_permute_state_3(Code &code)
{
    // gift128b_swap_move(s1, s1, 0x55555555U, 1);
    code.swapmove(s1, 0x55555555U, 1, t1);

    // gift128b_swap_move(s2, s2, 0x00005555U, 1);
    // s2 = leftRotate16(s2);
    code.swapmove(s2, 0x00005555U, 1, t1);
    code.rol(s2, 16);

    // gift128b_swap_move(s3, s3, 0x55550000U, 1);
    // s3 = leftRotate16(s3);
    code.swapmove(s3, 0x55550000U, 1, t1);
    code.rol(s3, 16);
}

void Gift128StateFS::inv_permute_state_4(Code &code)
{
    // s0 = ((s0 >> 2) & 0x3F3F3F3FU) | ((s0 & 0x03030303U) << 6);
    code.ror(Reg(s0, 0, 1), 2);
    code.ror(Reg(s0, 1, 1), 2);
    code.ror(Reg(s0, 2, 1), 2);
    code.ror(Reg(s0, 3, 1), 2);

    // s1 = ((s1 >> 4) & 0x0F0F0F0FU) | ((s1 & 0x0F0F0F0FU) << 4);
    code.rol(Reg(s1, 0, 1), 4);
    code.rol(Reg(s1, 1, 1), 4);
    code.rol(Reg(s1, 2, 1), 4);
    code.rol(Reg(s1, 3, 1), 4);

    // s2 = ((s2 >> 6) & 0x03030303U) | ((s2 & 0x3F3F3F3FU) << 2);
    code.rol(Reg(s2, 0, 1), 2);
    code.rol(Reg(s2, 1, 1), 2);
    code.rol(Reg(s2, 2, 1), 2);
    code.rol(Reg(s2, 3, 1), 2);
}

void Gift128StateFS::inv_permute_state_5(Code &code)
{
    // s1 = leftRotate16(s1);
    code.rol(s1, 16);

    // s2 = leftRotate8(s2);
    code.rol(s2, 8);

    // s3 = rightRotate8(s3);
    code.ror(s3, 8);
}

void Gift128StateFS::xor_rc_inc(Code &code, const Reg &sreg)
{
    Reg zlow = Reg(Reg::z_ptr(), 0, 1);
    code.sbox_lookup(Reg(t1, 0, 1), zlow);
    code.inc(zlow);
    code.sbox_lookup(Reg(t1, 1, 1), zlow);
    code.inc(zlow);
    code.sbox_lookup(Reg(t1, 2, 1), zlow);
    code.inc(zlow);
    code.sbox_lookup(Reg(t1, 3, 1), zlow);
    code.inc(zlow);
    code.logxor(sreg, t1);
}

void Gift128StateFS::xor_rc_dec(Code &code, const Reg &sreg)
{
    Reg zlow = Reg(Reg::z_ptr(), 0, 1);
    code.dec(zlow);
    code.sbox_lookup(Reg(t1, 3, 1), zlow);
    code.dec(zlow);
    code.sbox_lookup(Reg(t1, 2, 1), zlow);
    code.dec(zlow);
    code.sbox_lookup(Reg(t1, 1, 1), zlow);
    code.dec(zlow);
    code.sbox_lookup(Reg(t1, 0, 1), zlow);
    code.logxor(sreg, t1);
}

void Gift128StateFS::xor_tweak(Code &code, const Reg &tweak)
{
    code.logxor(Reg(s0, 0, 1), tweak);
    code.logxor(Reg(s0, 1, 1), tweak);
    code.logxor(Reg(s0, 2, 1), tweak);
    code.logxor(Reg(s0, 3, 1), tweak);
}

void Gift128StateFS::inv_sub_cells(Code &code)
{
    // swap(s0, s3);
    code.move(t1, s3);
    code.move(s3, s0);
    code.move(s0, t1);

    // s2 ^= s0 & s1;
    code.logand(t1, s1);
    code.logxor(s2, t1);

    // s3 ^= 0xFFFFFFFFU;
    code.lognot(s3);

    // s1 ^= s3;
    code.logxor(s1, s3);

    // s3 ^= s2;
    code.logxor(s3, s2);

    // s2 ^= s0 | s1;
    code.logxor_or(s2, s0, s1);

    // s0 ^= s1 & s3;
    code.logxor_and(s0, s1, s3);

    // s1 ^= s0 & s2;
    code.logxor_and(s1, s0, s2);
}

void Gift128StateFS::perm_bits(Code &code, bool inverse)
{
    // Permutations to apply to the state words.
    static unsigned char const P0[32] =
        {0, 24, 16, 8, 1, 25, 17, 9, 2, 26, 18, 10, 3, 27, 19, 11,
         4, 28, 20, 12, 5, 29, 21, 13, 6, 30, 22, 14, 7, 31, 23, 15};
    static unsigned char const P1[32] =
        {8, 0, 24, 16, 9, 1, 25, 17, 10, 2, 26, 18, 11, 3, 27, 19,
         12, 4, 28, 20, 13, 5, 29, 21, 14, 6, 30, 22, 15, 7, 31, 23};
    static unsigned char const P2[32] =
        {16, 8, 0, 24, 17, 9, 1, 25, 18, 10, 2, 26, 19, 11, 3, 27,
         20, 12, 4, 28, 21, 13, 5, 29, 22, 14, 6, 30, 23, 15, 7, 31};
    static unsigned char const P3[32] =
        {24, 16, 8, 0, 25, 17, 9, 1, 26, 18, 10, 2, 27, 19, 11, 3,
         28, 20, 12, 4, 29, 21, 13, 5, 30, 22, 14, 6, 31, 23, 15, 7};

    // Apply the permutations bit by bit.  The mask and shift approach
    // from the 32-bit implementation uses more instructions than simply
    // moving the bits around one at a time.
    code.bit_permute(s0, P0, 32, inverse);
    code.bit_permute(s1, P1, 32, inverse);
    code.bit_permute(s2, P2, 32, inverse);
    code.bit_permute(s3, P3, 32, inverse);
}

void Gift128StateFS::inv_rotate_key(Code &code, int round)
{
    int curr_offset;
    int next_offset;
    switch (round % 4) {
    case 0: default:
        curr_offset = 12;
        next_offset = 8;
        break;
    case 1:
        curr_offset = 8;
        next_offset = 4;
        break;
    case 2:
        curr_offset = 4;
        next_offset = 0;
        break;
    case 3:
        curr_offset = 0;
        next_offset = 12;
        break;
    }
    code.stlocal(w3, next_offset);
    code.ldlocal(w3, curr_offset);
    code.ror(Reg(w3, 0, 2), 4);
    code.rol(Reg(w3, 2, 2), 2);
}

/**
 * \brief Gets the round contant table to use with GIFT-128 (fix-sliced).
 *
 * \return The round constant table.
 */
Sbox get_gift128_fs_round_constants()
{
    unsigned char table[40 * 4];
    for (int r = 0; r < 40; ++r) {
        table[r * 4]     = (unsigned char)(GIFT128_RC_fixsliced[r]);
        table[r * 4 + 1] = (unsigned char)(GIFT128_RC_fixsliced[r] >> 8);
        table[r * 4 + 2] = (unsigned char)(GIFT128_RC_fixsliced[r] >> 16);
        table[r * 4 + 3] = (unsigned char)(GIFT128_RC_fixsliced[r] >> 24);
    }
    return Sbox(table, sizeof(table));
}

/**
 * \brief Expands the keys for the first 10 rounds of the key schedule.
 *
 * \param code Code block to generate into.
 * \param state GIFT-128 generator state.
 *
 * It is assumed that the first 4 key words are in s0 .. s3 and that
 * Z points to the start of the key schedule on entry and exit.
 */
static void gen_gift128_fs_setup_key_first_10_rounds
    (Code &code, Gift128StateFS &state)
{
    // Need a loop index variable.
    Reg index = code.allocateHighReg(1);

    // Store the first 4 words and advance Z to just past them.
    code.stz(state.s0, POST_INC);
    code.stz(state.s1, POST_INC);
    code.stz(state.s2, POST_INC);
    code.stz(state.s3, POST_INC);

    // for (index = 4; index < 20; index += 2) {
    //     ks->k[index] = ks->k[index - 3];
    //     temp = ks->k[index - 4];
    //     temp = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
    //            ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
    //     ks->k[index + 1] = temp;
    // }
    unsigned char label = 0;
    code.move(index, 4);
    code.label(label);
    code.stz(state.s1, POST_INC);
    code.rol(Reg(state.s0, 0, 2), 4);
    code.ror(Reg(state.s0, 2, 2), 2);
    code.stz(state.s0, POST_INC);
    code.swap(state.s0, state.s1);
    code.stz(state.s3, POST_INC);
    code.rol(Reg(state.s2, 0, 2), 4);
    code.ror(Reg(state.s2, 2, 2), 2);
    code.stz(state.s2, POST_INC);
    code.swap(state.s2, state.s3);
    code.dec(index);
    code.brne(label);

    // Rewind Z to point at the start of the schedule again.
    code.add_ptr_z(-80);

    // Permute the round keys into fix-sliced form.
    unsigned char end_label = 0;
    label = 0;
    code.move(index, 2);
    code.label(label);

    // Keys 0 and 10:
    //      temp = ks->k[index];
    //      gift128b_swap_move(temp, temp, 0x00550055U, 9);
    //      gift128b_swap_move(temp, temp, 0x000F000FU, 12);
    //      gift128b_swap_move(temp, temp, 0x00003333U, 18);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index] = temp;
    // The final swapmove is a simple swap of the high and low bytes
    // of the value, so we can do that virtually with a shuffle.
    Reg temp = state.s0;
    Reg temp2 = state.t1; // swapmove needs a temporary word in high registers.
    code.ldz(temp, 0);
    code.swapmove(temp, 0x00550055U,  9, temp2);
    code.swapmove(temp, 0x000F000FU, 12, temp2);
    code.swapmove(temp, 0x00003333U, 18, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 0);

    // Keys 1 and 11:
    //      temp = ks->k[index + 1];
    //      gift128b_swap_move(temp, temp, 0x00550055U, 9);
    //      gift128b_swap_move(temp, temp, 0x000F000FU, 12);
    //      gift128b_swap_move(temp, temp, 0x00003333U, 18);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 1] = temp;
    code.ldz(temp, 4);
    code.swapmove(temp, 0x00550055U,  9, temp2);
    code.swapmove(temp, 0x000F000FU, 12, temp2);
    code.swapmove(temp, 0x00003333U, 18, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 4);

    // Keys 2 and 12:
    //      temp = ks->k[index + 2];
    //      gift128b_swap_move(temp, temp, 0x11111111U, 3);
    //      gift128b_swap_move(temp, temp, 0x03030303U, 6);
    //      gift128b_swap_move(temp, temp, 0x000F000FU, 12);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 2] = temp;
    code.ldz(temp, 8);
    code.swapmove(temp, 0x11111111U,  3, temp2);
    code.swapmove(temp, 0x03030303U,  6, temp2);
    code.swapmove(temp, 0x000F000FU, 12, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 8);

    // Keys 3 and 13:
    //      temp = ks->k[index + 3];
    //      gift128b_swap_move(temp, temp, 0x11111111U, 3);
    //      gift128b_swap_move(temp, temp, 0x03030303U, 6);
    //      gift128b_swap_move(temp, temp, 0x000F000FU, 12);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 3] = temp;
    code.ldz(temp, 12);
    code.swapmove(temp, 0x11111111U,  3, temp2);
    code.swapmove(temp, 0x03030303U,  6, temp2);
    code.swapmove(temp, 0x000F000FU, 12, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 12);

    // Keys 4 and 14:
    //      temp = ks->k[index + 4];
    //      gift128b_swap_move(temp, temp, 0x0000AAAAU, 15);
    //      gift128b_swap_move(temp, temp, 0x00003333U, 18);
    //      gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 4] = temp;
    code.ldz(temp, 16);
    code.swapmove(temp, 0x0000AAAAU, 15, temp2);
    code.swapmove(temp, 0x00003333U, 18, temp2);
    code.swapmove(temp, 0x0000F0F0U, 12, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 16);

    // Keys 5 and 15:
    //      temp = ks->k[index + 5];
    //      gift128b_swap_move(temp, temp, 0x0000AAAAU, 15);
    //      gift128b_swap_move(temp, temp, 0x00003333U, 18);
    //      gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 5] = temp;
    code.ldz(temp, 20);
    code.swapmove(temp, 0x0000AAAAU, 15, temp2);
    code.swapmove(temp, 0x00003333U, 18, temp2);
    code.swapmove(temp, 0x0000F0F0U, 12, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 20);

    // Keys 6 and 16:
    //      temp = ks->k[index + 6];
    //      gift128b_swap_move(temp, temp, 0x0A0A0A0AU, 3);
    //      gift128b_swap_move(temp, temp, 0x00CC00CCU, 6);
    //      gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 6] = temp;
    code.ldz(temp, 24);
    code.swapmove(temp, 0x0A0A0A0AU,  3, temp2);
    code.swapmove(temp, 0x00CC00CCU,  6, temp2);
    code.swapmove(temp, 0x0000F0F0U, 12, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 24);

    // Keys 7 and 17:
    //      temp = ks->k[index + 7];
    //      gift128b_swap_move(temp, temp, 0x0A0A0A0AU, 3);
    //      gift128b_swap_move(temp, temp, 0x00CC00CCU, 6);
    //      gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
    //      gift128b_swap_move(temp, temp, 0x000000FFU, 24);
    //      ks->k[index + 7] = temp;
    code.ldz(temp, 28);
    code.swapmove(temp, 0x0A0A0A0AU,  3, temp2);
    code.swapmove(temp, 0x00CC00CCU,  6, temp2);
    code.swapmove(temp, 0x0000F0F0U, 12, temp2);
    code.stz(temp.shuffle(3, 1, 2, 0), 28);

    // Bottom of the permutation loop.
    code.dec(index);
    code.breq(end_label);
    code.add_ptr_z(40);
    code.jmp(label);
    code.label(end_label);

    // Release temporaries.
    code.releaseReg(index);
}

/**
 * \brief Derives keys for the next 5 rounds from keys 10 rounds previous.
 *
 * \param code Code block to generate into.
 * \param state GIFT-128 generator state.
 * \param inplace Set to true if the keys should be derived in-place
 * at the Z pointer; set to false if the keys should be derived from
 * the keys at the X pointer.
 *
 * This function will destroy s0 and s1 in \a state to create temporary words.
 * The caller must save them on the stack if this will be a problem.
 */
static void gen_gift128_fs_derive_keys_5_rounds
    (Code &code, Gift128StateFS &state, bool inplace = false)
{
    // Allocate temporaries.
    Reg s, t;
    s = state.s0;
    if (inplace)
        t = code.allocateReg(4);
    else
        t = state.s1;

    // Key 0:
    //      uint32_t s = (prev)[0];
    //      uint32_t t = (prev)[1];
    //      gift128b_swap_move(t, t, 0x00003333U, 16);
    //      gift128b_swap_move(t, t, 0x55554444U, 1);
    //      (next)[0] = t;
    if (inplace) {
        code.ldz(s, 0);
        code.ldz(t, 4);
    } else {
        code.ldx(s, POST_INC);
        code.ldx(t, POST_INC);
    }
    code.swapmove(t, 0x00003333U, 16, state.t1);
    code.swapmove(t, 0x55554444U,  1, state.t1);
    code.stz(t, 0);

    // Key 1:
    //      s = leftRotate8(s & 0x33333333U) | leftRotate16(s & 0xCCCCCCCCU);
    //      gift128b_swap_move(s, s, 0x55551100U, 1);
    //      (next)[1] = s;
    code.move(state.t1, s);
    code.logand(state.t1, 0x33333333U);
    code.logand(s, 0xCCCCCCCCU);
    Reg srot = s.shuffle(2, 3, 0, 1);
    code.logor(srot, state.t1.shuffle(3, 0, 1, 2));
    code.swapmove(srot, 0x55551100U, 1, state.t1);
    code.stz(srot, 4);

    // Key 2:
    //      s = (prev)[2];
    //      t = (prev)[3];
    //      (next)[2] = ((t >> 4) & 0x0F000F00U) | ((t & 0x0F000F00U) << 4) |
    //                  ((t >> 6) & 0x00030003U) | ((t & 0x003F003FU) << 2);
    if (inplace) {
        code.ldz(s, 8);
        code.ldz(t, 12);
    } else {
        code.ldx(s, POST_INC);
        code.ldx(t, POST_INC);
    }
    code.rol(Reg(t, 0, 1), 2);
    code.rol(Reg(t, 1, 1), 4);
    code.rol(Reg(t, 2, 1), 2);
    code.rol(Reg(t, 3, 1), 4);
    code.stz(t, 8);

    // Key 3:
    //      (next)[3] = ((s >> 6) & 0x03000300U) | ((s & 0x3F003F00U) << 2) |
    //                  ((s >> 5) & 0x00070007U) | ((s & 0x001F001FU) << 3);
    code.rol(Reg(s, 0, 1), 3);
    code.rol(Reg(s, 1, 1), 2);
    code.rol(Reg(s, 2, 1), 3);
    code.rol(Reg(s, 3, 1), 2);
    code.stz(s, 12);

    // Key 4:
    //      s = (prev)[4];
    //      t = (prev)[5];
    //      (next)[4] = leftRotate8(t & 0xAAAAAAAAU) |
    //                 leftRotate16(t & 0x55555555U);
    if (inplace) {
        code.ldz(s, 16);
        code.ldz(t, 20);
    } else {
        code.ldx(s, POST_INC);
        code.ldx(t, POST_INC);
    }
    code.move(state.t1, t);
    code.logand(state.t1, 0xAAAAAAAAU);
    code.logand(t, 0x55555555U);
    code.logor(t, state.t1.shuffle(1, 2, 3, 0));
    code.stz(t.shuffle(2, 3, 0, 1), 16);

    // Key 5:
    //      (next)[5] = leftRotate8(s & 0x55555555U) |
    //                 leftRotate12(s & 0xAAAAAAAAU);
    code.move(state.t1, s);
    code.logand(state.t1, 0x55555555U);
    code.logand(s, 0xAAAAAAAAU);
    code.rol(s, 4);
    code.logor(s, state.t1);
    code.stz(s.shuffle(3, 0, 1, 2), 20);

    // Key 6:
    //      s = (prev)[6];
    //      t = (prev)[7];
    //      (next)[6] = ((t >> 2) & 0x03030303U) | ((t & 0x03030303U) << 2) |
    //                  ((t >> 1) & 0x70707070U) | ((t & 0x10101010U) << 3);
    if (inplace) {
        code.ldz(s, 24);
        code.ldz(t, 28);
    } else {
        code.ldx(s, POST_INC);
        code.ldx(t, POST_INC);
    }
    code.swapmove(t, 0x03030303U, 2, state.t1);
    code.move(state.t1, t);
    code.lsr(state.t1, 1);
    code.logand(state.t1, 0x78787878U);
    if (inplace)
        code.swapmove(state.t1, 0x08080808U, 4, state.s1);
    else
        code.swapmove(state.t1, 0x08080808U, 4);
    code.logand(t, 0x0F0F0F0FU);
    code.logor(t, state.t1);
    code.stz(t, 24);

    // Key 7:
    //      (next)[7] = ((s >> 18) & 0x00003030U) | ((s & 0x01010101U) << 3)  |
    //                  ((s >> 14) & 0x0000C0C0U) | ((s & 0x0000E0E0U) << 15) |
    //                  ((s >>  1) & 0x07070707U) | ((s & 0x00001010U) << 19);
    // t = (s >> 18) & 0x00003030U;
    code.move(Reg(state.t1, 0, 2), Reg(s, 2, 2));
    code.lsr(Reg(state.t1, 0, 2), 2);
    code.logand(Reg(state.t1, 0, 2), 0x00003030U);
    // t |= (s & 0x01010101U) << 3;
    code.move(t, s);
    code.logand(t, 0x01010101U);
    code.lsl(t, 3);
    code.logor(Reg(t, 0, 2), Reg(state.t1, 0, 2));
    // t |= (s >> 14) & 0x0000C0C0U;
    code.move(Reg(state.t1, 0, 2), Reg(s, 2, 2));
    code.lsl(Reg(state.t1, 0, 2), 2);
    code.logand(Reg(state.t1, 0, 2), 0x0000C0C0U);
    code.logor(Reg(t, 0, 2), Reg(state.t1, 0, 2));
    // t |= (s & 0x0000E0E0U) << 15;
    code.move(Reg(state.t1, 0, 2), Reg(s, 0, 2));
    code.logand(Reg(state.t1, 0, 2), 0x0000E0E0U);
    code.lsr(Reg(state.t1, 0, 2), 1);
    code.logor(Reg(t, 2, 2), Reg(state.t1, 0, 2));
    // t |= (s >> 1) & 0x07070707U;
    code.move(state.t1, s);
    code.lsr(state.t1, 1);
    code.logand(state.t1, 0x07070707U);
    code.logor(t, state.t1);
    // t |= (s & 0x00001010U) << 19;
    code.logand(Reg(s, 0, 2), 0x00001010U);
    code.lsl(Reg(s, 0, 2), 3);
    code.logor(Reg(t, 2, 2), Reg(s, 0, 2));
    code.stz(t, 28);

    // Key 8:
    //      s = (prev)[8];
    //      t = (prev)[9];
    //      (next)[8] = ((t >> 4) & 0x0FFF0000U) | ((t & 0x000F0000U) << 12) |
    //                  ((t >> 8) & 0x000000FFU) | ((t & 0x000000FFU) << 8);
    if (inplace) {
        code.ldz(s, 32);
        code.ldz(t, 36);
    } else {
        code.ldx(s, POST_INC);
        code.ldx(t, POST_INC);
    }
    code.ror(Reg(t, 2, 2), 4);
    code.stz(t.shuffle(1, 0, 2, 3), 32);

    // Key 9:
    //      (next)[9] = ((s >> 6) & 0x03FF0000U) | ((s & 0x003F0000U) << 10) |
    //                  ((s >> 4) & 0x00000FFFU) | ((s & 0x0000000FU) << 12);
    code.ror(Reg(s, 0, 2), 4);
    code.ror(Reg(s, 2, 2), 6);
    code.stz(s, 36);

    // Release temporaries.
    if (inplace)
        code.releaseReg(t);
}

/**
 * \brief Generates the AVR code for a GIFT-128 key setup function.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 * \param ordering Byte ordering of the input key.
 * \param alt Alternative parameter order if true.
 */
static void gen_gift128_fs_setup_key
    (Code &code, const char *name, int num_keys, int ordering, bool alt)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    if (alt)
        code.prologue_setup_key_reversed(name, 0);
    else
        code.prologue_setup_key(name, 0);
    if (num_keys < 80)
        code.setFlag(Code::NoLocals); // We don't need the Y register.
    else
        code.setFlag(Code::TempY);    // Need some extra temporary registers.

    // Allocate the temporary registers to be used.
    Gift128StateFS state(code);

    // Copy the key into the key schedule structure and rearrange:
    //      k0 = be_load_word32(key);
    //      k1 = be_load_word32(key + 4);
    //      k2 = be_load_word32(key + 8);
    //      k3 = be_load_word32(key + 12);
    //      ks->k[0] = k3;
    //      ks->k[1] = k1;
    //      ks->k[2] = k2;
    //      ks->k[3] = k0;
    // Renumber the words so that s0 = k3, s1 = k1, s2 = k2, s3 = k0.
    if (ordering == StateBE) {
        code.ldx(state.s3.reversed(), POST_INC);
        code.ldx(state.s1.reversed(), POST_INC);
        code.ldx(state.s2.reversed(), POST_INC);
        code.ldx(state.s0.reversed(), POST_INC);
    } else {
        code.ldx(state.s0, POST_INC);
        code.ldx(state.s2, POST_INC);
        code.ldx(state.s1, POST_INC);
        code.ldx(state.s3, POST_INC);
    }

    // If we only need 4 round keys, then we are finished after a store.
    if (num_keys == 4) {
        code.stz(state.s0, 0);
        code.stz(state.s1, 4);
        code.stz(state.s2, 8);
        code.stz(state.s3, 12);
        return;
    }

    // Pre-compute the keys for rounds 3..10 and permute into fixsliced form.
    gen_gift128_fs_setup_key_first_10_rounds(code, state);

    // If we only need 20 round keys, then we are finished.
    if (num_keys == 20)
        return;

    // Z is currently pointing 40 bytes into the key schedule but we need
    // it to be 80 bytes into the key schedule for the next phase.
    code.add_ptr_z(40);

    // Derive the fixsliced keys for the remaining rounds 11..40.
    code.move(Reg::x_ptr(), Reg::z_ptr());
    code.add_ptr_x(-80);
    Reg count = code.allocateHighReg(1);
    code.move(count, 6);
    unsigned char label = 0;
    unsigned char end_label = 0;
    code.label(label);
    gen_gift128_fs_derive_keys_5_rounds(code, state);
    code.dec(count);
    code.breq(end_label);
    code.add_ptr_z(40);
    code.jmp(label);
    code.label(end_label);
    code.releaseReg(count);
}

/**
 * \brief Generates the AVR code for the gift128b key setup function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_setup_key(Code &code, int num_keys)
{
    gen_gift128_fs_setup_key
        (code, "gift128b_init", num_keys, StateBE, false);
}

/**
 * \brief Generates the AVR code for the gift128b key setup function
 * with alternative function naming.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_setup_key_alt(Code &code, int num_keys)
{
    gen_gift128_fs_setup_key
        (code, "gift128_keyschedule", num_keys, StateBE, true);
}

/**
 * \brief Generates the AVR code for the gift128n key setup function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128n_fs_setup_key(Code &code, int num_keys)
{
    gen_gift128_fs_setup_key
        (code, "gift128n_init", num_keys, StateLE, false);
}

/**
 * \brief Generates the AVR code for the gift128 encryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 * \param name Name of the function to generate.
 * \param ordering Byte ordering for the input and output.
 * \param alt Alternative parameter order if true.
 */
static void gen_gift128_fs_encrypt
    (Code &code, const char *name, int num_keys, int ordering, bool alt)
{
    // Determine how much local variable storage we need to expand the key.
    int locals = (num_keys == 80) ? 0 : 80;

    // Set up the function prologue with the needed local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (alt)
        code.prologue_encrypt_block_key2(name, locals);
    else if (ordering != StateTweak)
        code.prologue_encrypt_block(name, locals);
    else
        tweak = code.prologue_encrypt_block_with_tweak(name, locals);

    // Allocate the temporary registers to be used.
    Gift128StateFS state(code);

    // If the number of keys is 4, then derive the first 20 round keys.
    // If the number of keys is 20, then copy the first 20 round keys.
    // Otherwise leave Z pointing to the key schedule for now.
    if (num_keys == 4) {
        code.ldz(state.s0, 0);
        code.ldz(state.s1, 4);
        code.ldz(state.s2, 8);
        code.ldz(state.s3, 12);
        code.move(Reg::z_ptr(), Reg::y_ptr());
        code.add_ptr_z(1); // Y points one byte below the first local variable.
        gen_gift128_fs_setup_key_first_10_rounds(code, state);
    } else if (num_keys == 20) {
        Reg count = code.allocateHighReg(1);
        code.move(count, 20);
        unsigned char copy_label = 0;
        code.label(copy_label);
        code.ldz(state.s0, POST_INC);
        code.stlocal(state.s0, 0);
        code.add_ptr_y(4);
        code.dec(count);
        code.brne(copy_label);
        code.add_ptr_y(-80);
        code.releaseReg(count);
    }

    // Load the state from X into the s0, s1, s2, and s3 registers.
    state.load_state(code, ordering);

    // Point X at the key schedule because we need to use Z for the RC table.
    if (num_keys == 80) {
        code.move(Reg::x_ptr(), Reg::z_ptr());
    } else {
        code.move(Reg::x_ptr(), Reg::y_ptr());
        code.add_ptr_x(1); // Y points one byte below the first local variable.
    }

    // Load up the sbox table into Z.
    code.sbox_setup(0, get_gift128_fs_round_constants());

    // Unroll the outer loop, performing 5 rounds at a time.  The rounds
    // and key derivation are in local subroutines.
    #define DERIVE_KEYS(round) \
        do { \
            if (num_keys != 80) { \
                code.sbox_cleanup(); \
                code.call(derive_keys_subroutine); \
                code.sbox_setup(0, get_gift128_fs_round_constants()); \
                code.move(Reg(Reg::z_ptr(), 0, 1), round * 4); \
                if ((round % 10) == 0) \
                    code.add_ptr_x(-40); \
                else \
                    code.add_ptr_x(40); \
            } \
        } while (0)
    unsigned char end_label = 0;
    unsigned char rounds_subroutine = 0;
    unsigned char derive_keys_subroutine = 0;
    code.call(rounds_subroutine);           // Rounds 1..5
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    DERIVE_KEYS(5);
    code.call(rounds_subroutine);           // Rounds 6..10
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    DERIVE_KEYS(10);
    code.call(rounds_subroutine);           // Rounds 11..15
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    DERIVE_KEYS(15);
    code.call(rounds_subroutine);           // Rounds 16..20
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    DERIVE_KEYS(20);
    code.call(rounds_subroutine);           // Rounds 21..25
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    DERIVE_KEYS(25);
    code.call(rounds_subroutine);           // Rounds 26..30
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    DERIVE_KEYS(30);
    code.call(rounds_subroutine);           // Rounds 31..35
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 36..40
    code.jmp(end_label);

    // Output the start of the rounds subroutine.
    code.label(rounds_subroutine);

    // 1st round - S-box, rotate left, add round key:
    //      gift128b_sbox(s0, s1, s2, s3);
    //      gift128b_permute_state_1(s0, s1, s2, s3);
    //      s1 ^= (rk)[0];
    //      s2 ^= (rk)[1];
    //      s0 ^= (rc)[0];
    state.sbox(code, state.s0, state.s1, state.s2, state.s3);
    state.permute_state_1(code);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s1, state.t1);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s2, state.t1);
    state.xor_rc_inc(code, state.s0);

    // 2nd round - S-box, rotate up, add round key:
    //      gift128b_sbox(s3, s1, s2, s0);
    //      gift128b_permute_state_2(s0, s1, s2, s3);
    //      s1 ^= (rk)[2];
    //      s2 ^= (rk)[3];
    //      s3 ^= (rc)[1];
    state.sbox(code, state.s3, state.s1, state.s2, state.s0);
    state.permute_state_2(code);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s1, state.t1);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s2, state.t1);
    state.xor_rc_inc(code, state.s3);

    // 3rd round - S-box, swap columns, add round key:
    //      gift128b_sbox(s0, s1, s2, s3);
    //      gift128b_permute_state_3(s0, s1, s2, s3);
    //      s1 ^= (rk)[4];
    //      s2 ^= (rk)[5];
    //      s0 ^= (rc)[2];
    state.sbox(code, state.s0, state.s1, state.s2, state.s3);
    state.permute_state_3(code);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s1, state.t1);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s2, state.t1);
    state.xor_rc_inc(code, state.s0);

    // 4th round - S-box, rotate left and swap rows, add round key:
    //      gift128b_sbox(s3, s1, s2, s0);
    //      gift128b_permute_state_4(s0, s1, s2, s3);
    //      s1 ^= (rk)[6];
    //      s2 ^= (rk)[7];
    //      s3 ^= (rc)[3];
    state.sbox(code, state.s3, state.s1, state.s2, state.s0);
    state.permute_state_4(code);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s1, state.t1);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s2, state.t1);
    state.xor_rc_inc(code, state.s3);

    // 5th round - S-box, rotate up, add round key:
    //      gift128b_sbox(s0, s1, s2, s3);
    //      gift128b_permute_state_5(s0, s1, s2, s3);
    //      s1 ^= (rk)[8];
    //      s2 ^= (rk)[9];
    //      s0 ^= (rc)[4];
    state.sbox(code, state.s0, state.s1, state.s2, state.s3);
    state.permute_state_5(code);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s1, state.t1);
    code.ldx(state.t1, POST_INC);
    code.logxor(state.s2, state.t1);
    state.xor_rc_inc(code, state.s0);

    // Swap s0 and s3 in preparation for the next 1st round:
    //      s0 ^= s3;
    //      s3 ^= s0;
    //      s0 ^= s3;
    code.logxor(state.s0, state.s3);
    code.logxor(state.s3, state.s0);
    code.logxor(state.s0, state.s3);

    // End of the rounds subroutine.
    code.ret();

    // Output the key derivation subroutine.
    if (num_keys != 80) {
        code.label(derive_keys_subroutine);
        code.move(Reg::z_ptr(), Reg::x_ptr());
        code.add_ptr_z(-40);
        code.setFlag(Code::TempX);
        code.push(state.s0);
        code.push(state.s1);
        gen_gift128_fs_derive_keys_5_rounds(code, state, true);
        code.pop(state.s1);
        code.pop(state.s0);
        code.clearFlag(Code::TempX);
        code.move(Reg::x_ptr(), Reg::z_ptr());
        code.ret();
    }

    // Store the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    state.store_state(code, ordering);
}

/**
 * \brief Generates the AVR code for the gift128b encryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_encrypt(Code &code, int num_keys)
{
    gen_gift128_fs_encrypt
        (code, "gift128b_encrypt", num_keys, StateBE, false);
}

/**
 * \brief Generates the AVR code for the gift128b encryption function
 * with alternative function argument ordering.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_encrypt_alt(Code &code, int num_keys)
{
    gen_gift128_fs_encrypt
        (code, "giftb128_encrypt_block", num_keys, StateBE, true);
}

/**
 * \brief Generates the AVR code for the gift128b encryption function,
 * little-endian version.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_encrypt_preloaded(Code &code, int num_keys)
{
    gen_gift128_fs_encrypt
        (code, "gift128b_encrypt_preloaded", num_keys, StateLE, false);
}

/**
 * \brief Generates the AVR code for the gift128n encryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128n_fs_encrypt(Code &code, int num_keys)
{
    gen_gift128_fs_encrypt
        (code, "gift128n_encrypt", num_keys, StateNibble, false);
}

/**
 * \brief Generates the AVR code for the gift128n encryption function
 * with alternative function argument ordering.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128n_fs_encrypt_alt(Code &code, int num_keys)
{
    gen_gift128_fs_encrypt
        (code, "gift128_encrypt_block", num_keys, StateNibbleBE, true);
}

/**
 * \brief Generates the AVR code for the gift128t encryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128t_fs_encrypt(Code &code, int num_keys)
{
    gen_gift128_fs_encrypt
        (code, "gift128t_encrypt", num_keys, StateTweak, false);
}

/**
 * \brief Generates the AVR code for the gift128 decryption function
 * with a full fix-sliced key schedule.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param ordering Byte ordering for the input and output.
 * \param alt Alternative parameter order if true.
 */
static void gen_gift128_fs_decrypt
    (Code &code, const char *name, int ordering, bool alt)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (alt)
        code.prologue_decrypt_block_key2(name, 0);
    else if (ordering != StateTweak)
        code.prologue_decrypt_block(name, 0);
    else
        tweak = code.prologue_decrypt_block_with_tweak(name, 0);

    // Allocate the temporary registers to be used.
    Gift128StateFS state(code);

    // Load the state from X into the s0, s1, s2, and s3 registers.
    state.load_state(code, ordering);

    // Point X at the key schedule because we need to use Z for the RC table.
    code.move(Reg::x_ptr(), Reg::z_ptr());
    code.add_ptr_x(80 * 4); // Fast-forward to the end of the schedule.

    // Load up the sbox table into Z and fast-forward to the end.
    code.sbox_setup(0, get_gift128_fs_round_constants());
    code.move(Reg(Reg::z_ptr(), 0, 1), sizeof(GIFT128_RC_fixsliced));

    // Unroll the outer loop, performing 5 rounds at a time.
    // The rounds themselves are in a local subroutine.
    unsigned char end_label = 0;
    unsigned char rounds_subroutine = 0;
    code.call(rounds_subroutine);           // Rounds 36..40
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 31..35
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 26..30
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 21..25
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 16..20
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 11..15
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 6..10
    if (ordering == StateTweak)
        state.xor_tweak(code, tweak);
    code.call(rounds_subroutine);           // Rounds 1..5
    code.jmp(end_label);

    // Output the start of the rounds subroutine.
    code.label(rounds_subroutine);

    // Swap s0 and s3 in preparation for the next 5th round:
    //      s0 ^= s3;
    //      s3 ^= s0;
    //      s0 ^= s3;
    code.logxor(state.s0, state.s3);
    code.logxor(state.s3, state.s0);
    code.logxor(state.s0, state.s3);

    // 5th round - S-box, rotate up, add round key:
    //      s1 ^= (rk)[8];
    //      s2 ^= (rk)[9];
    //      s0 ^= (rc)[4];
    //      gift128b_inv_permute_state_5(s0, s1, s2, s3);
    //      gift128b_inv_sbox(s3, s1, s2, s0);
    state.xor_rc_dec(code, state.s0);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s2, state.t1);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s1, state.t1);
    state.inv_permute_state_5(code);
    state.inv_sbox(code, state.s3, state.s1, state.s2, state.s0);

    // 4th round - S-box, rotate left and swap rows, add round key:
    //      s1 ^= (rk)[6];
    //      s2 ^= (rk)[7];
    //      s3 ^= (rc)[3];
    //      gift128b_inv_permute_state_4(s0, s1, s2, s3);
    //      gift128b_inv_sbox(s0, s1, s2, s3);
    state.xor_rc_dec(code, state.s3);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s2, state.t1);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s1, state.t1);
    state.inv_permute_state_4(code);
    state.inv_sbox(code, state.s0, state.s1, state.s2, state.s3);

    // 3rd round - S-box, swap columns, add round key:
    //      s1 ^= (rk)[4];
    //      s2 ^= (rk)[5];
    //      s0 ^= (rc)[2];
    //      gift128b_inv_sbox(s0, s1, s2, s3);
    //      gift128b_inv_permute_state_3(s3, s1, s2, s0);
    state.xor_rc_dec(code, state.s0);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s2, state.t1);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s1, state.t1);
    state.inv_permute_state_3(code);
    state.inv_sbox(code, state.s3, state.s1, state.s2, state.s0);

    // 2nd round - S-box, rotate up, add round key:
    //      s1 ^= (rk)[2];
    //      s2 ^= (rk)[3];
    //      s3 ^= (rc)[1];
    //      gift128b_inv_permute_state_2(s0, s1, s2, s3);
    //      gift128b_inv_sbox(s0, s1, s2, s3);
    state.xor_rc_dec(code, state.s3);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s2, state.t1);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s1, state.t1);
    state.inv_permute_state_2(code);
    state.inv_sbox(code, state.s0, state.s1, state.s2, state.s3);

    // 1st round - S-box, rotate left, add round key:
    //      s1 ^= (rk)[0];
    //      s2 ^= (rk)[1];
    //      s0 ^= (rc)[0];
    //      gift128b_inv_permute_state_1(s0, s1, s2, s3);
    //      gift128b_inv_sbox(s3, s1, s2, s0);
    state.xor_rc_dec(code, state.s0);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s2, state.t1);
    code.ldx(state.t1, PRE_DEC);
    code.logxor(state.s1, state.t1);
    state.inv_permute_state_1(code);
    state.inv_sbox(code, state.s3, state.s1, state.s2, state.s0);

    // End of the rounds subroutine.
    code.ret();

    // Store the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    state.store_state(code, ordering);
}

/**
 * \brief Generates the AVR code for the gift128 decryption function
 * with a shortened key schedule.
 *
 * \param code The code block to generate into.
 * \param name Name of the function to generate.
 * \param ordering Byte ordering for the input and output.
 * \param alt Alternative parameter order if true.
 *
 * This version uses bit-slicing based on fast-forwarding the first
 * four words of the input key schedule.  This is for key schedules
 * with either 4 or 20 round keys.  Fast-forwarding the key schedule
 * for fix-sliced decryption is too hard.
 */
static void gen_gift128_fs_decrypt_short
    (Code &code, const char *name, int num_keys, int ordering, bool alt)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (alt)
        code.prologue_decrypt_block_key2(name, 16);
    else if (ordering != StateTweak)
        code.prologue_decrypt_block(name, 16);
    else
        tweak = code.prologue_decrypt_block_with_tweak(name, 16);

    // Allocate the temporary registers to be used.
    Gift128StateFS state(code);

    // Load the state from X and then release X for use as temporaries.
    state.load_state(code, ordering);
    code.setFlag(Code::TempX);

    // Allocate a register for the key schedule.
    state.w3 = code.allocateReg(4);

    // Copy the key schedule into local variable storage and fast-forward
    // the key schedule to the end of the schedule.  For 4 keys we only
    // need to load and permute the words.  For 20 keys we also need to
    // undo the permutations that converted the words into fixsliced form.
    code.ldz(state.w3, 12);
    if (num_keys == 20) {
        // gift128b_swap_move(w0, w0, 0x000000FFU, 24);
        // gift128b_swap_move(w0, w0, 0x000F000FU, 12);
        // gift128b_swap_move(w0, w0, 0x03030303U, 6);
        // gift128b_swap_move(w0, w0, 0x11111111U, 3);
        code.swapmove(state.w3, 0x000000FFU, 24, state.t1);
        code.swapmove(state.w3, 0x000F000FU, 12, state.t1);
        code.swapmove(state.w3, 0x03030303U, 6,  state.t1);
        code.swapmove(state.w3, 0x11111111U, 3,  state.t1);
    }
    code.rol(Reg(state.w3, 0, 2), 8);
    code.ror(Reg(state.w3, 2, 2), 4);
    code.stlocal(state.w3, 0);
    code.ldz(state.w3, 4);
    if (num_keys == 20) {
        // gift128b_swap_move(w1, w1, 0x000000FFU, 24);
        // gift128b_swap_move(w1, w1, 0x00003333U, 18);
        // gift128b_swap_move(w1, w1, 0x000F000FU, 12);
        // gift128b_swap_move(w1, w1, 0x00550055U, 9);
        code.swapmove(state.w3, 0x000000FFU, 24, state.t1);
        code.swapmove(state.w3, 0x00003333U, 18, state.t1);
        code.swapmove(state.w3, 0x000F000FU, 12, state.t1);
        code.swapmove(state.w3, 0x00550055U, 9,  state.t1);
    }
    code.rol(Reg(state.w3, 0, 2), 8);
    code.ror(Reg(state.w3, 2, 2), 4);
    code.stlocal(state.w3, 4);
    code.ldz(state.w3, 8);
    if (num_keys == 20) {
        // gift128b_swap_move(w2, w2, 0x000000FFU, 24);
        // gift128b_swap_move(w2, w2, 0x000F000FU, 12);
        // gift128b_swap_move(w2, w2, 0x03030303U, 6);
        // gift128b_swap_move(w2, w2, 0x11111111U, 3);
        code.swapmove(state.w3, 0x000000FFU, 24, state.t1);
        code.swapmove(state.w3, 0x000F000FU, 12, state.t1);
        code.swapmove(state.w3, 0x03030303U, 6,  state.t1);
        code.swapmove(state.w3, 0x11111111U, 3,  state.t1);
    }
    code.rol(Reg(state.w3, 0, 2), 8);
    code.ror(Reg(state.w3, 2, 2), 4);
    code.stlocal(state.w3, 8);
    code.ldz(state.w3, 0); // Leave the last word in a register.
    if (num_keys == 20) {
        // gift128b_swap_move(w3, w3, 0x000000FFU, 24);
        // gift128b_swap_move(w3, w3, 0x00003333U, 18);
        // gift128b_swap_move(w3, w3, 0x000F000FU, 12);
        // gift128b_swap_move(w3, w3, 0x00550055U, 9);
        code.swapmove(state.w3, 0x000000FFU, 24, state.t1);
        code.swapmove(state.w3, 0x00003333U, 18, state.t1);
        code.swapmove(state.w3, 0x000F000FU, 12, state.t1);
        code.swapmove(state.w3, 0x00550055U, 9,  state.t1);
    }
    code.rol(Reg(state.w3, 0, 2), 8);
    code.ror(Reg(state.w3, 2, 2), 4);

    // If we are generating the tweaked version, then don't use w3.
    // Always load the key schedule in-place from local stack space.
    state.inplace = false;
    if (ordering == StateTweak) {
        code.stlocal(state.w3, 12);
        code.releaseReg(state.w3);
        state.w3 = Reg();
        state.inplace = true;
    }

    // We will need a high register for the round counter.
    Reg counter = code.allocateHighReg(1);

    // We can discard Z now.  Replace it with a program memory
    // pointer to the table of round constants.
    code.sbox_setup(1, get_gift128_round_constants());

    // Perform all decryption rounds 4 at a time.  The bulk of the round
    // is in a subroutine with the outer loop unrolled to deal with rotating
    // the key schedule.
    unsigned char subroutine = 0;
    unsigned char top_label = 0;
    unsigned char end_label = 0;
    code.move(counter, 40);
    if (ordering != StateTweak) {
        code.label(top_label);

        // Round 4 out of 4.
        code.ldlocal_xor(state.s2, 8);
        state.inv_rotate_key(code, 3);
        code.call(subroutine);

        // Round 3 out of 4.
        code.ldlocal_xor(state.s2, 12);
        state.inv_rotate_key(code, 2);
        code.call(subroutine);

        // Round 2 out of 4.
        code.ldlocal_xor(state.s2, 0);
        state.inv_rotate_key(code, 1);
        code.call(subroutine);

        // Round 1 out of 4.
        code.ldlocal_xor(state.s2, 4);
        state.inv_rotate_key(code, 0);
        code.call(subroutine);

        // Bottom of the round loop and the inner subroutine.
        code.compare_and_loop(counter, 0, top_label);
        code.jmp(end_label);
        code.label(subroutine);
        code.logxor(state.s1, state.w3);
        code.move(Reg(state.t1, 0, 1), 0x80);
        code.logxor(Reg(state.s3, 3, 1), Reg(state.t1, 0, 1));
        code.dec(counter);
        code.sbox_lookup(Reg(state.t1, 0, 1), counter);
        code.logxor(Reg(state.s3, 0, 1), Reg(state.t1, 0, 1));
        state.perm_bits(code, true);
        state.inv_sub_cells(code);
        code.ret();
    } else {
        // Tweaked version performs 1 round at a time with an XOR
        // of the tweak every 5 rounds except the last.
        Reg counter2 = code.allocateHighReg(1);
        code.move(counter2, 0);
        code.label(top_label);
        for (int index = 0; index < 4; ++index) {
            // Rotate the key schedule backwards one byte at a time.
            // Set things up so that the final version of w3 is in t1.
            code.memory(Insn::LD_Y, TEMP_REG, 12 + index + 1);
            code.memory(Insn::LD_Y, state.t1.reg(index), 8 + index + 1);
            code.memory(Insn::ST_Y, TEMP_REG, 8 + index + 1);
            code.memory(Insn::LD_Y, TEMP_REG, 4 + index + 1);
            code.memory(Insn::ST_Y, state.t1.reg(index), 4 + index + 1);
            code.memory(Insn::LD_Y, state.t1.reg(index), index + 1);
            code.memory(Insn::ST_Y, TEMP_REG, index + 1);
        }
        code.ror(Reg(state.t1, 0, 2), 4);
        code.rol(Reg(state.t1, 2, 2), 2);
        code.stlocal(state.t1, 12);
        code.logxor(state.s1, state.t1);
        code.ldlocal_xor(state.s2, 4);
        code.move(Reg(state.t1, 0, 1), 0x80);
        code.logxor(Reg(state.s3, 3, 1), Reg(state.t1, 0, 1));
        code.dec(counter);
        code.sbox_lookup(Reg(state.t1, 0, 1), counter);
        code.logxor(Reg(state.s3, 0, 1), Reg(state.t1, 0, 1));
        state.perm_bits(code, true);
        state.inv_sub_cells(code);
        code.compare(counter, 0);
        code.breq(end_label);
        code.inc(counter2);
        code.compare_and_loop(counter2, 5, top_label);
        code.move(counter2, 0);
        code.logxor(Reg(state.s0, 0, 1), tweak);
        code.logxor(Reg(state.s0, 1, 1), tweak);
        code.logxor(Reg(state.s0, 2, 1), tweak);
        code.logxor(Reg(state.s0, 3, 1), tweak);
        code.jmp(top_label);
    }

    // Store the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    state.store_state(code, ordering);
}

/**
 * \brief Generates the AVR code for the gift128b decryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_decrypt(Code &code, int num_keys)
{
    if (num_keys == 80) {
        gen_gift128_fs_decrypt
            (code, "gift128b_decrypt", StateBE, false);
    } else {
        gen_gift128_fs_decrypt_short
            (code, "gift128b_decrypt", num_keys, StateBE, false);
    }
}

/**
 * \brief Generates the AVR code for the gift128b decryption function
 * with alternative function argument ordering.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128b_fs_decrypt_alt(Code &code, int num_keys)
{
    if (num_keys == 80) {
        gen_gift128_fs_decrypt
            (code, "giftb128_decrypt_block", StateBE, true);
    } else {
        gen_gift128_fs_decrypt_short
            (code, "giftb128_decrypt_block", num_keys, StateBE, true);
    }
}

/**
 * \brief Generates the AVR code for the gift128n decryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128n_fs_decrypt(Code &code, int num_keys)
{
    if (num_keys == 80) {
        gen_gift128_fs_decrypt
            (code, "gift128n_decrypt", StateNibble, false);
    } else {
        gen_gift128_fs_decrypt_short
            (code, "gift128n_decrypt", num_keys, StateNibble, false);
    }
}

/**
 * \brief Generates the AVR code for the gift128n decryption function
 * with alternative function argument ordering.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128n_fs_decrypt_alt(Code &code, int num_keys)
{
    if (num_keys == 80) {
        gen_gift128_fs_decrypt
            (code, "gift128_decrypt_block", StateNibbleBE, true);
    } else {
        gen_gift128_fs_decrypt_short
            (code, "gift128_decrypt_block", num_keys, StateNibbleBE, true);
    }
}

/**
 * \brief Generates the AVR code for the gift128t decryption function.
 *
 * \param code The code block to generate into.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
void gen_gift128t_fs_decrypt(Code &code, int num_keys)
{
    if (num_keys == 80) {
        gen_gift128_fs_decrypt
            (code, "gift128t_decrypt", StateTweak, false);
    } else {
        gen_gift128_fs_decrypt_short
            (code, "gift128t_decrypt", num_keys, StateTweak, false);
    }
}

/**
 * \brief Swaps bits within two words.
 *
 * \param a The first word.
 * \param b The second word.
 * \param mask Mask for the bits to shift.
 * \param shift Shift amount in bits.
 */
#define gift128b_swap_move(a, b, mask, shift) \
    do { \
        uint32_t tmp = ((b) ^ ((a) >> (shift))) & (mask); \
        (b) ^= tmp; \
        (a) ^= tmp << (shift); \
    } while (0)

static uint32_t leftRotate8(uint32_t x)
{
    return (x << 8) | (x >> 24);
}

static uint32_t leftRotate16(uint32_t x)
{
    return (x << 16) | (x >> 16);
}

static uint32_t leftRotate12(uint32_t x)
{
    return (x << 12) | (x >> 20);
}

#define be_load_word32(ptr) \
    ((((uint32_t)((ptr)[0])) << 24) | \
     (((uint32_t)((ptr)[1])) << 16) | \
     (((uint32_t)((ptr)[2])) << 8) | \
      ((uint32_t)((ptr)[3])))

#define le_load_word32(ptr) \
    ((((uint32_t)((ptr)[3])) << 24) | \
     (((uint32_t)((ptr)[2])) << 16) | \
     (((uint32_t)((ptr)[1])) << 8) | \
      ((uint32_t)((ptr)[0])))

/**
 * \brief Derives the next 10 fixsliced keys in the key schedule.
 *
 * \param next Points to the buffer to receive the next 10 keys.
 * \param prev Points to the buffer holding the previous 10 keys.
 *
 * The \a next and \a prev buffers are allowed to be the same.
 */
#define gift128b_derive_keys(next, prev) \
    do { \
        /* Key 0 */ \
        uint32_t s = (prev)[0]; \
        uint32_t t = (prev)[1]; \
        gift128b_swap_move(t, t, 0x00003333U, 16); \
        gift128b_swap_move(t, t, 0x55554444U, 1); \
        (next)[0] = t; \
        /* Key 1 */ \
        s = leftRotate8(s & 0x33333333U) | leftRotate16(s & 0xCCCCCCCCU); \
        gift128b_swap_move(s, s, 0x55551100U, 1); \
        (next)[1] = s; \
        /* Key 2 */ \
        s = (prev)[2]; \
        t = (prev)[3]; \
        (next)[2] = ((t >> 4) & 0x0F000F00U) | ((t & 0x0F000F00U) << 4) | \
                    ((t >> 6) & 0x00030003U) | ((t & 0x003F003FU) << 2); \
        /* Key 3 */ \
        (next)[3] = ((s >> 6) & 0x03000300U) | ((s & 0x3F003F00U) << 2) | \
                    ((s >> 5) & 0x00070007U) | ((s & 0x001F001FU) << 3); \
        /* Key 4 */ \
        s = (prev)[4]; \
        t = (prev)[5]; \
        (next)[4] = leftRotate8(t & 0xAAAAAAAAU) | \
                   leftRotate16(t & 0x55555555U); \
        /* Key 5 */ \
        (next)[5] = leftRotate8(s & 0x55555555U) | \
                   leftRotate12(s & 0xAAAAAAAAU); \
        /* Key 6 */ \
        s = (prev)[6]; \
        t = (prev)[7]; \
        (next)[6] = ((t >> 2) & 0x03030303U) | ((t & 0x03030303U) << 2) | \
                    ((t >> 1) & 0x70707070U) | ((t & 0x10101010U) << 3); \
        /* Key 7 */ \
	(next)[7] = ((s >> 18) & 0x00003030U) | ((s & 0x01010101U) << 3)  | \
                    ((s >> 14) & 0x0000C0C0U) | ((s & 0x0000E0E0U) << 15) | \
                    ((s >>  1) & 0x07070707U) | ((s & 0x00001010U) << 19); \
        /* Key 8 */ \
        s = (prev)[8]; \
        t = (prev)[9]; \
        (next)[8] = ((t >> 4) & 0x0FFF0000U) | ((t & 0x000F0000U) << 12) | \
                    ((t >> 8) & 0x000000FFU) | ((t & 0x000000FFU) << 8); \
        /* Key 9 */ \
        (next)[9] = ((s >> 6) & 0x03FF0000U) | ((s & 0x003F0000U) << 10) | \
                    ((s >> 4) & 0x00000FFFU) | ((s & 0x0000000FU) << 12); \
    } while (0)

/**
 * \brief Compute the round keys for GIFT-128 in the fixsliced representation.
 *
 * \param ks Points to the key schedule to initialize.
 * \param k0 First key word.
 * \param k1 Second key word.
 * \param k2 Third key word.
 * \param k3 Fourth key word.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 *
 * This function is used to simulate the expected key schedule for a
 * specific 128-bit input key.
 */
static void gift128b_compute_round_keys
    (uint32_t *k, uint32_t k0, uint32_t k1, uint32_t k2,
     uint32_t k3, int num_keys)
{
    unsigned index;
    uint32_t temp;

    /* Set the regular key with k0 and k3 pre-swapped for the round function */
    k[0] = k3;
    k[1] = k1;
    k[2] = k2;
    k[3] = k0;
    if (num_keys == 4)
        return;

    /* Pre-compute the keys for rounds 3..10 and permute into fixsliced form */
    for (index = 4; index < 20; index += 2) {
        k[index] = k[index - 3];
        temp = k[index - 4];
        temp = ((temp & 0xFFFC0000U) >> 2) | ((temp & 0x00030000U) << 14) |
               ((temp & 0x00000FFFU) << 4) | ((temp & 0x0000F000U) >> 12);
        k[index + 1] = temp;
    }
    for (index = 0; index < 20; index += 10) {
        /* Keys 0 and 10 */
        temp = k[index];
        gift128b_swap_move(temp, temp, 0x00550055U, 9);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index] = temp;

        /* Keys 1 and 11 */
        temp = k[index + 1];
        gift128b_swap_move(temp, temp, 0x00550055U, 9);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 1] = temp;

        /* Keys 2 and 12 */
        temp = k[index + 2];
        gift128b_swap_move(temp, temp, 0x11111111U, 3);
        gift128b_swap_move(temp, temp, 0x03030303U, 6);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 2] = temp;

        /* Keys 3 and 13 */
        temp = k[index + 3];
        gift128b_swap_move(temp, temp, 0x11111111U, 3);
        gift128b_swap_move(temp, temp, 0x03030303U, 6);
        gift128b_swap_move(temp, temp, 0x000F000FU, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 3] = temp;

        /* Keys 4 and 14 */
        temp = k[index + 4];
        gift128b_swap_move(temp, temp, 0x0000AAAAU, 15);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 4] = temp;

        /* Keys 5 and 15 */
        temp = k[index + 5];
        gift128b_swap_move(temp, temp, 0x0000AAAAU, 15);
        gift128b_swap_move(temp, temp, 0x00003333U, 18);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 5] = temp;

        /* Keys 6 and 16 */
        temp = k[index + 6];
        gift128b_swap_move(temp, temp, 0x0A0A0A0AU, 3);
        gift128b_swap_move(temp, temp, 0x00CC00CCU, 6);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 6] = temp;

        /* Keys 7 and 17 */
        temp = k[index + 7];
        gift128b_swap_move(temp, temp, 0x0A0A0A0AU, 3);
        gift128b_swap_move(temp, temp, 0x00CC00CCU, 6);
        gift128b_swap_move(temp, temp, 0x0000F0F0U, 12);
        gift128b_swap_move(temp, temp, 0x000000FFU, 24);
        k[index + 7] = temp;

        /* Keys 8, 9, 18, and 19 do not need any adjustment */
    }
    if (num_keys == 20)
        return;

    /* Derive the fixsliced keys for the remaining rounds 11..40 */
    for (index = 20; index < 80; index += 10) {
        gift128b_derive_keys(k + index, k + index - 20);
    }
}

/**
 * \brief Set up a key schedule for testing the fixsliced version of GIFT-128.
 *
 * \param schedule Points to the output key schedule.
 * \param key Points to the input key.
 * \param order Byte ordering for the key, StateLE or StateBE.
 * \param num_keys Number of round keys to be generated: 4, 20, or 80.
 */
static void gift128_setup_key
    (unsigned char *schedule, const unsigned char key[16],
     int ordering, int num_keys)
{
    uint32_t k[80];
    if (ordering == StateBE) {
        gift128b_compute_round_keys
            (k, be_load_word32(key), be_load_word32(key + 4),
             be_load_word32(key + 8), be_load_word32(key + 12), num_keys);
    } else {
        gift128b_compute_round_keys
            (k, le_load_word32(key + 12), le_load_word32(key + 8),
             le_load_word32(key + 4), le_load_word32(key), num_keys);
    }
    for (int index = 0; index < num_keys; ++index) {
        schedule[index * 4]     = (unsigned char)(k[index]);
        schedule[index * 4 + 1] = (unsigned char)(k[index] >> 8);
        schedule[index * 4 + 2] = (unsigned char)(k[index] >> 16);
        schedule[index * 4 + 3] = (unsigned char)(k[index] >> 24);
    }
}

/* Test vectors for GIFT-128 (bit-sliced version) */
static block_cipher_test_vector_t const gift128b_1 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* plaintext */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0xA9, 0x4A, 0xF7, 0xF9, 0xBA, 0x18, 0x1D, 0xF9,    /* ciphertext */
     0xB2, 0xB0, 0x0E, 0xB7, 0xDB, 0xFA, 0x93, 0xDF}
};
static block_cipher_test_vector_t const gift128b_2 = {
    "Test Vector 2",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x33, 0x31, 0xEF, 0xC3, 0xA6, 0x60, 0x4F, 0x95,    /* ciphertext */
     0x99, 0xED, 0x42, 0xB7, 0xDB, 0xC0, 0x2A, 0x38}
};
static block_cipher_test_vector_t const gift128b_3 = {
    "Test Vector 3",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x5e, 0x8e, 0x3a, 0x2e, 0x16, 0x97, 0xa7, 0x7d,    /* ciphertext */
     0xcc, 0x0b, 0x89, 0xdc, 0xd9, 0x7a, 0x64, 0xee}
};
static block_cipher_test_vector_t const gift128b_4 = {
    "Test Vector 4",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0x22, 0x58, 0x14, 0x37, 0xe5, 0xe9, 0x61, 0xef,    /* ciphertext */
     0x6d, 0x12, 0x50, 0x46, 0xc5, 0xf2, 0x07, 0x88}
};
static block_cipher_test_vector_t const gift128b_5 = {
    "Test Vector 5",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0xda, 0x1d, 0xc8, 0x87, 0x38, 0x23, 0xe3, 0x25,    /* ciphertext */
     0xc4, 0xb4, 0xa7, 0x7c, 0x1a, 0x73, 0x33, 0x0e}
};

/* Test vectors for GIFT-128 (nibble-based version) */
static block_cipher_test_vector_t const gift128n_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x92, 0xff, 0xb6, 0xce, 0x36, 0x5a, 0xb1, 0x68,    /* ciphertext */
     0xf6, 0xd3, 0x8a, 0x38, 0x38, 0xd7, 0x0b, 0xcd}
};
static block_cipher_test_vector_t const gift128n_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0xeb, 0xda, 0xda, 0xa8, 0xbc, 0x83, 0xd5, 0x16,    /* ciphertext */
     0xd5, 0x0a, 0x45, 0x6e, 0xf8, 0x0e, 0x7f, 0x72}
};
static block_cipher_test_vector_t const gift128n_3 = {
    "Test Vector 3",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0xb2, 0x3e, 0x1f, 0xb4, 0xfd, 0xd8, 0xc0, 0x88,    /* ciphertext */
     0xd3, 0x72, 0xe8, 0xbe, 0xf3, 0x43, 0x06, 0x02}
};

/* Test vectors for GIFT-128 (big endian nibble-based version) */
static block_cipher_test_vector_t const gift128n_alt_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xcd, 0x0b, 0xd7, 0x38, 0x38, 0x8a, 0xd3, 0xf6,    /* ciphertext */
     0x68, 0xb1, 0x5a, 0x36, 0xce, 0xb6, 0xff, 0x92}
};
static block_cipher_test_vector_t const gift128n_alt_2 = {
    "Test Vector 2",
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* key */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    16,                                                 /* key_len */
    {0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,    /* plaintext */
     0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10},
    {0x84, 0x22, 0x24, 0x1a, 0x6d, 0xbf, 0x5a, 0x93,    /* ciphertext */
     0x46, 0xaf, 0x46, 0x84, 0x09, 0xee, 0x01, 0x52}
};
static block_cipher_test_vector_t const gift128n_alt_3 = {
    "Test Vector 3",
    {0xd0, 0xf5, 0xc5, 0x9a, 0x77, 0x00, 0xd3, 0xe7,    /* key */
     0x99, 0x02, 0x8f, 0xa9, 0xf9, 0x0a, 0xd8, 0x37},
    16,                                                 /* key_len */
    {0xe3, 0x9c, 0x14, 0x1f, 0xa5, 0x7d, 0xba, 0x43,    /* plaintext */
     0xf0, 0x8a, 0x85, 0xb6, 0xa9, 0x1f, 0x86, 0xc1},
    {0x13, 0xed, 0xe6, 0x7c, 0xbd, 0xcc, 0x3d, 0xbf,    /* ciphertext */
     0x40, 0x0a, 0x62, 0xd6, 0x97, 0x72, 0x65, 0xea}
};

/* Test vectors for GIFT-128 (tweakable version) */
static block_cipher_test_vector_t const gift128t_1 = {
    "Test Vector 1",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* key */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    16,                                                 /* key_len */
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,    /* plaintext */
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x92, 0xFF, 0xB6, 0xCE, 0x36, 0x5A, 0xB1, 0x68,    /* ciphertext */
     0xF6, 0xD3, 0x8A, 0x38, 0x38, 0xD7, 0x0B, 0xCD}
    /* tweak = 0 */
};
static block_cipher_test_vector_t const gift128t_2 = {
    "Test Vector 1",
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* key */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    16,                                                 /* key_len */
    {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,    /* plaintext */
     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    {0xC8, 0xAE, 0x66, 0x59, 0xE8, 0xF1, 0x63, 0x62,    /* ciphertext */
     0xD1, 0xC6, 0xAB, 0xC4, 0x63, 0x09, 0x06, 0x1F}
    /* tweak = 11 */
};
static block_cipher_test_vector_t const gift128t_3 = {
    "Test Vector 2",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x23, 0x02, 0x80, 0xCD, 0x95, 0x78, 0xBB, 0xB6,    /* ciphertext */
     0xC5, 0x9B, 0xD0, 0x2E, 0x96, 0x32, 0x96, 0x2F}
    /* tweak = 4 */
};
static block_cipher_test_vector_t const gift128t_4 = {
    "Test Vector 4",
    {0xE0, 0x84, 0x1F, 0x8F, 0xB9, 0x07, 0x83, 0x13,    /* key */
     0x6A, 0xA8, 0xB7, 0xF1, 0x92, 0xF5, 0xC4, 0x74},
    16,                                                 /* key_len */
    {0xE4, 0x91, 0xC6, 0x65, 0x52, 0x20, 0x31, 0xCF,    /* plaintext */
     0x03, 0x3B, 0xF7, 0x1B, 0x99, 0x89, 0xEC, 0xB3},
    {0x4E, 0x1F, 0xCB, 0xC8, 0x7A, 0x54, 0x72, 0x79,    /* ciphertext */
     0x9C, 0x61, 0x77, 0x4F, 0xA4, 0x03, 0x16, 0xED}
    /* tweak = 0 */
};

static bool test_gift128b_fs_setup_key
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char expected[80 * 4] = {0};
    gift128_setup_key(expected, test->key, StateBE, num_keys);
    code.exec_setup_key(schedule, sizeof(schedule), test->key, test->key_len);
    if (memcmp(schedule, expected, num_keys * 4) != 0)
        return false;
    return true;
}

bool test_gift128b_fs_setup_key(Code &code, int num_keys)
{
    if (!test_gift128b_fs_setup_key(code, num_keys, &gift128b_1))
        return false;
    if (!test_gift128b_fs_setup_key(code, num_keys, &gift128b_2))
        return false;
    if (!test_gift128b_fs_setup_key(code, num_keys, &gift128b_3))
        return false;
    if (!test_gift128b_fs_setup_key(code, num_keys, &gift128b_4))
        return false;
    if (!test_gift128b_fs_setup_key(code, num_keys, &gift128b_5))
        return false;
    return true;
}

static bool test_gift128n_fs_setup_key
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char expected[80 * 4] = {0};
    gift128_setup_key(expected, test->key, StateLE, num_keys);
    code.exec_setup_key(schedule, sizeof(schedule), test->key, test->key_len);
    if (memcmp(schedule, expected, num_keys * 4) != 0)
        return false;
    return true;
}

bool test_gift128n_fs_setup_key(Code &code, int num_keys)
{
    if (!test_gift128n_fs_setup_key(code, num_keys, &gift128n_1))
        return false;
    if (!test_gift128n_fs_setup_key(code, num_keys, &gift128n_2))
        return false;
    if (!test_gift128n_fs_setup_key(code, num_keys, &gift128n_3))
        return false;
    return true;
}

static bool test_gift128b_fs_encrypt
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateBE, num_keys);
    code.exec_encrypt_block
        (schedule, num_keys * 4, output, 16, test->plaintext, 16);
    if (memcmp(output, test->ciphertext, 16) != 0)
        return false;
    return true;
}

bool test_gift128b_fs_encrypt(Code &code, int num_keys)
{
    if (!test_gift128b_fs_encrypt(code, num_keys, &gift128b_1))
        return false;
    if (!test_gift128b_fs_encrypt(code, num_keys, &gift128b_2))
        return false;
    if (!test_gift128b_fs_encrypt(code, num_keys, &gift128b_3))
        return false;
    if (!test_gift128b_fs_encrypt(code, num_keys, &gift128b_4))
        return false;
    if (!test_gift128b_fs_encrypt(code, num_keys, &gift128b_5))
        return false;
    return true;
}

static void gift128_swap_words
    (unsigned char out[16], const unsigned char in[16])
{
    for (int index = 0; index < 16; index += 4) {
        unsigned char x0 = in[index];
        unsigned char x1 = in[index + 1];
        unsigned char x2 = in[index + 2];
        unsigned char x3 = in[index + 3];
        out[index] = x3;
        out[index + 1] = x2;
        out[index + 2] = x1;
        out[index + 3] = x0;
    }
}

static bool test_gift128b_fs_encrypt_preloaded
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char input[16] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateBE, num_keys);
    gift128_swap_words(input, test->plaintext);
    code.exec_encrypt_block(schedule, num_keys * 4, output, 16, input, 16);
    gift128_swap_words(input, output);
    if (memcmp(input, test->ciphertext, 16) != 0)
        return false;
    return true;
}

bool test_gift128b_fs_encrypt_preloaded(Code &code, int num_keys)
{
    if (!test_gift128b_fs_encrypt_preloaded(code, num_keys, &gift128b_1))
        return false;
    if (!test_gift128b_fs_encrypt_preloaded(code, num_keys, &gift128b_2))
        return false;
    if (!test_gift128b_fs_encrypt_preloaded(code, num_keys, &gift128b_3))
        return false;
    if (!test_gift128b_fs_encrypt_preloaded(code, num_keys, &gift128b_4))
        return false;
    if (!test_gift128b_fs_encrypt_preloaded(code, num_keys, &gift128b_5))
        return false;
    return true;
}

static bool test_gift128n_fs_encrypt
    (Code &code, int num_keys, const block_cipher_test_vector_t *test,
     uint16_t tweak = 0)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateLE, num_keys);
    code.exec_encrypt_block
        (schedule, num_keys * 4, output, 16, test->plaintext, 16, tweak);
    if (memcmp(output, test->ciphertext, 16) != 0)
        return false;
    return true;
}

bool test_gift128n_fs_encrypt(Code &code, int num_keys)
{
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128n_1))
        return false;
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128n_2))
        return false;
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128n_3))
        return false;
    return true;
}

static bool test_gift128n_fs_encrypt_alt
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateBE, num_keys);
    code.exec_encrypt_block
        (schedule, num_keys * 4, output, 16, test->plaintext, 16);
    if (memcmp(output, test->ciphertext, 16) != 0)
        return false;
    return true;
}

bool test_gift128n_fs_encrypt_alt(Code &code, int num_keys)
{
    if (!test_gift128n_fs_encrypt_alt(code, num_keys, &gift128n_alt_1))
        return false;
    if (!test_gift128n_fs_encrypt_alt(code, num_keys, &gift128n_alt_2))
        return false;
    if (!test_gift128n_fs_encrypt_alt(code, num_keys, &gift128n_alt_3))
        return false;
    return true;
}

bool test_gift128t_fs_encrypt(Code &code, int num_keys)
{
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128t_1, 0))
        return false;
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128t_2, 0x4b4b))
        return false;
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128t_3, 0xb4b4))
        return false;
    if (!test_gift128n_fs_encrypt(code, num_keys, &gift128t_4, 0))
        return false;
    return true;
}

static bool test_gift128b_fs_decrypt
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateBE, num_keys);
    code.exec_decrypt_block
        (schedule, num_keys * 4, output, 16, test->ciphertext, 16);
    if (memcmp(output, test->plaintext, 16) != 0)
        return false;
    return true;
}

bool test_gift128b_fs_decrypt(Code &code, int num_keys)
{
    if (!test_gift128b_fs_decrypt(code, num_keys, &gift128b_1))
        return false;
    if (!test_gift128b_fs_decrypt(code, num_keys, &gift128b_2))
        return false;
    if (!test_gift128b_fs_decrypt(code, num_keys, &gift128b_3))
        return false;
    if (!test_gift128b_fs_decrypt(code, num_keys, &gift128b_4))
        return false;
    if (!test_gift128b_fs_decrypt(code, num_keys, &gift128b_5))
        return false;
    return true;
}

static bool test_gift128n_fs_decrypt
    (Code &code, int num_keys, const block_cipher_test_vector_t *test,
     uint16_t tweak = 0)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateLE, num_keys);
    code.exec_decrypt_block
        (schedule, num_keys * 4, output, 16, test->ciphertext, 16, tweak);
    if (memcmp(output, test->plaintext, 16) != 0)
        return false;
    return true;
}

bool test_gift128n_fs_decrypt(Code &code, int num_keys)
{
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128n_1))
        return false;
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128n_2))
        return false;
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128n_3))
        return false;
    return true;
}

static bool test_gift128n_fs_decrypt_alt
    (Code &code, int num_keys, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[80 * 4] = {0};
    unsigned char output[16] = {0};
    gift128_setup_key(schedule, test->key, StateBE, num_keys);
    code.exec_encrypt_block
        (schedule, num_keys * 4, output, 16, test->ciphertext, 16);
    if (memcmp(output, test->plaintext, 16) != 0)
        return false;
    return true;
}

bool test_gift128n_fs_decrypt_alt(Code &code, int num_keys)
{
    if (!test_gift128n_fs_decrypt_alt(code, num_keys, &gift128n_alt_1))
        return false;
    if (!test_gift128n_fs_decrypt_alt(code, num_keys, &gift128n_alt_2))
        return false;
    if (!test_gift128n_fs_decrypt_alt(code, num_keys, &gift128n_alt_3))
        return false;
    return true;
}

bool test_gift128t_fs_decrypt(Code &code, int num_keys)
{
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128t_1, 0))
        return false;
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128t_2, 0x4b4b))
        return false;
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128t_3, 0xb4b4))
        return false;
    if (!test_gift128n_fs_decrypt(code, num_keys, &gift128t_4, 0))
        return false;
    return true;
}
