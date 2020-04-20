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

/* Round constants for GIFT-128 */
static uint8_t const GIFT128_RC[40] = {
    0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3E, 0x3D, 0x3B,
    0x37, 0x2F, 0x1E, 0x3C, 0x39, 0x33, 0x27, 0x0E,
    0x1D, 0x3A, 0x35, 0x2B, 0x16, 0x2C, 0x18, 0x30,
    0x21, 0x02, 0x05, 0x0B, 0x17, 0x2E, 0x1C, 0x38,
    0x31, 0x23, 0x06, 0x0D, 0x1B, 0x36, 0x2D, 0x1A
};

enum {
    StateBE,    /**< Load and store in bit-sliced big-endian byte order */
    StateLE,    /**< Load and store in bit-sliced little-endian byte order */
    StateNibble,/**< Load and store in nibble order */
    StateTweak  /**< Nibble-based with in-place tweaked key schedule */
};

class Gift128State
{
public:
    Gift128State(Code &code, int ordering, bool decrypt = false);

    // 32-bit registers that hold the state.
    Reg s0, s1, s2, s3;

    // 32-bit register that holds the last word of the key schedule.
    Reg w3;

    // Temporaries.
    Reg t1;

    // True if the key schedule is in-place without a w3 register.
    bool inplace;

    void sub_cells(Code &code);
    void inv_sub_cells(Code &code);
    void perm_bits(Code &code, bool inverse = false);
    void rotate_key(Code &code, int round);
    void inv_rotate_key(Code &code, int round);
    void load_state(Code &code, int ordering);
    void store_state(Code &code, int ordering);
    void print_state(Code &code);
};

Gift128State::Gift128State(Code &code, int ordering, bool decrypt)
{
    // Allocate a temporary; must be in a high register for constant loading.
    t1 = code.allocateHighReg(4);

    // Allocate registers for the state.
    s0 = code.allocateReg(4);
    s1 = code.allocateReg(4);
    s2 = code.allocateReg(4);
    s3 = code.allocateReg(4);

    // Load the state from X and then release X for use as temporaries.
    load_state(code, ordering);
    code.setFlag(Code::TempX);

    // Allocate a register for the key schedule.
    w3 = code.allocateReg(4);

    // Copy the key schedule into local variable storage.  For decryption
    // we also fast-forward the key schedule to the end of the schedule.
    if (!decrypt) {
        code.ldz(w3, 0);
        code.sty(w3, 0);
        code.ldz(w3, 4);
        code.sty(w3, 4);
        code.ldz(w3, 8);
        code.sty(w3, 8);
        code.ldz(w3, 12); // Leave the last word in a register.
    } else {
        code.ldz(w3, 0);
        code.rol(Reg(w3, 0, 2), 8);
        code.ror(Reg(w3, 2, 2), 4);
        code.sty(w3, 0);
        code.ldz(w3, 4);
        code.rol(Reg(w3, 0, 2), 8);
        code.ror(Reg(w3, 2, 2), 4);
        code.sty(w3, 4);
        code.ldz(w3, 8);
        code.rol(Reg(w3, 0, 2), 8);
        code.ror(Reg(w3, 2, 2), 4);
        code.sty(w3, 8);
        code.ldz(w3, 12); // Leave the last word in a register.
        code.rol(Reg(w3, 0, 2), 8);
        code.ror(Reg(w3, 2, 2), 4);
    }

    // If we are generating the tweaked version, then don't use w3.
    // Always load the key schedule in-place from local stack space.
    inplace = false;
    if (ordering == StateTweak) {
        code.sty(w3, 12);
        code.releaseReg(w3);
        w3 = Reg();
        inplace = true;
    }
}

void Gift128State::sub_cells(Code &code)
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
    code.move(t1, s0);
    code.logxor_and(s2, s1, t1);

    // swap(s0, s3);
    code.move(s0, s3);
    code.move(s3, t1);
}

void Gift128State::inv_sub_cells(Code &code)
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

void Gift128State::perm_bits(Code &code, bool inverse)
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

void Gift128State::rotate_key(Code &code, int round)
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
    code.rol(Reg(w3, 0, 2), 4);
    code.ror(Reg(w3, 2, 2), 2);
    code.sty(w3, curr_offset);
    code.ldy(w3, next_offset);
}

void Gift128State::inv_rotate_key(Code &code, int round)
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
    code.sty(w3, next_offset);
    code.ldy(w3, curr_offset);
    code.ror(Reg(w3, 0, 2), 4);
    code.rol(Reg(w3, 2, 2), 2);
}

void Gift128State::load_state(Code &code, int ordering)
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

void Gift128State::store_state(Code &code, int ordering)
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

void Gift128State::print_state(Code &code)
{
    if (!code.hasFlag(Code::Print))
        code.setFlag(Code::Print);
    code.print(s0);
    code.print(s1);
    code.print(s2);
    code.print(s3);
    code.println();
}

/**
 * \brief Gets the round contant table to use with GIFT-128.
 *
 * \return The round constant table.
 */
Sbox get_gift128_round_constants()
{
    return Sbox(GIFT128_RC, sizeof(GIFT128_RC));
}

/**
 * \brief Generates the AVR code for the gift128b key setup function.
 *
 * \param code The code block to generate into.
 */
void gen_gift128b_setup_key(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("gift128b_init", 0);
    code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Copy the key into the key schedule structure and rearrange:
    //      ks->k[0] = be_load_word32(key);
    //      ks->k[1] = be_load_word32(key + 4);
    //      ks->k[2] = be_load_word32(key + 8);
    //      ks->k[3] = be_load_word32(key + 12);
    Reg temp = code.allocateReg(4);
    code.ldx(temp.reversed(), POST_INC);
    code.stz(temp, 0);
    code.ldx(temp.reversed(), POST_INC);
    code.stz(temp, 4);
    code.ldx(temp.reversed(), POST_INC);
    code.stz(temp, 8);
    code.ldx(temp.reversed(), POST_INC);
    code.stz(temp, 12);
}

/**
 * \brief Generates the AVR code for the gift128n key setup function.
 *
 * \param code The code block to generate into.
 */
void gen_gift128n_setup_key(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("gift128n_init", 0);
    code.setFlag(Code::NoLocals); // Don't need to save the Y register.

    // Copy the key into the key schedule structure and rearrange:
    //      ks->k[0] = le_load_word32(key + 12);
    //      ks->k[1] = le_load_word32(key + 8);
    //      ks->k[2] = le_load_word32(key + 4);
    //      ks->k[3] = le_load_word32(key);
    Reg temp = code.allocateReg(4);
    code.ldx(temp, POST_INC);
    code.stz(temp, 12);
    code.ldx(temp, POST_INC);
    code.stz(temp, 8);
    code.ldx(temp, POST_INC);
    code.stz(temp, 4);
    code.ldx(temp, POST_INC);
    code.stz(temp, 0);
}

/**
 * \brief Generates the AVR code for the GIFT-128 encryption function.
 *
 * \param code The code block to generate into.
 * \param name Name of the encryption function to generate.
 * \param ordering Ordering of the state on input and output.
 */
static void gen_gift128_encrypt(Code &code, const char *name, int ordering)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (ordering != StateTweak)
        code.prologue_encrypt_block(name, 16);
    else
        tweak = code.prologue_encrypt_block_with_tweak(name, 16);

    // Allocate the registers that we need and load the state and key schedule.
    Gift128State s(code, ordering);

    // We will need a high register for the round counter.
    Reg counter = code.allocateHighReg(1);

    // We can discard Z now.  Replace it with a program memory
    // pointer to the table of round constants.
    code.sbox_setup(0, get_gift128_round_constants());

    // Perform all encryption rounds 4 at a time.  The bulk of the round
    // is in a subroutine with the outer loop unrolled to deal with rotating
    // the key schedule.
    unsigned char subroutine = 0;
    unsigned char top_label = 0;
    unsigned char end_label = 0;
    code.move(counter, 0);
    if (ordering != StateTweak) {
        code.label(top_label);

        // Round 1 out of 4.
        code.call(subroutine);
        code.ldy_xor(s.s2, 4);
        s.rotate_key(code, 0);

        // Round 2 out of 4.
        code.call(subroutine);
        code.ldy_xor(s.s2, 0);
        s.rotate_key(code, 1);

        // Round 3 out of 4.
        code.call(subroutine);
        code.ldy_xor(s.s2, 12);
        s.rotate_key(code, 2);

        // Round 4 out of 4.
        code.call(subroutine);
        code.ldy_xor(s.s2, 8);
        s.rotate_key(code, 3);

        // Bottom of the round loop and the inner subroutine.
        code.compare_and_loop(counter, 40, top_label);
        code.jmp(end_label);
        code.label(subroutine);
        s.sub_cells(code);
        s.perm_bits(code);
        code.logxor(s.s1, s.w3);
        code.move(Reg(s.t1, 0, 1), 0x80);
        code.logxor(Reg(s.s3, 3, 1), Reg(s.t1, 0, 1));
        code.sbox_lookup(Reg(s.t1, 0, 1), counter);
        code.logxor(Reg(s.s3, 0, 1), Reg(s.t1, 0, 1));
        code.inc(counter);
        code.ret();
    } else {
        // Tweaked version performs 1 round at a time with an XOR
        // of the tweak every 5 rounds except the last.
        Reg counter2 = code.allocateHighReg(1);
        code.move(counter2, 0);
        code.label(top_label);
        s.sub_cells(code);
        s.perm_bits(code);
        code.ldy_xor(s.s2, 4);
        code.ldy(s.t1, 12);
        code.logxor(s.s1, s.t1);
        code.rol(Reg(s.t1, 0, 2), 4);
        code.ror(Reg(s.t1, 2, 2), 2);
        for (int index = 0; index < 4; ++index) {
            // Rotate the key schedule one byte at a time.
            code.memory(Insn::LD_Y, TEMP_REG, index);
            code.memory(Insn::ST_Y, s.t1.reg(index), index);
            code.memory(Insn::LD_Y, s.t1.reg(index), 4 + index);
            code.memory(Insn::ST_Y, TEMP_REG, 4 + index);
            code.memory(Insn::LD_Y, TEMP_REG, 8 + index);
            code.memory(Insn::ST_Y, s.t1.reg(index), 8 + index);
            code.memory(Insn::ST_Y, TEMP_REG, 12 + index);
        }
        code.move(Reg(s.t1, 0, 1), 0x80);
        code.logxor(Reg(s.s3, 3, 1), Reg(s.t1, 0, 1));
        code.sbox_lookup(Reg(s.t1, 0, 1), counter);
        code.logxor(Reg(s.s3, 0, 1), Reg(s.t1, 0, 1));
        code.inc(counter);
        code.compare(counter, 40);
        code.breq(end_label);
        code.inc(counter2);
        code.compare_and_loop(counter2, 5, top_label);
        code.move(counter2, 0);
        code.logxor(Reg(s.s0, 0, 1), tweak);
        code.logxor(Reg(s.s0, 1, 1), tweak);
        code.logxor(Reg(s.s0, 2, 1), tweak);
        code.logxor(Reg(s.s0, 3, 1), tweak);
        code.jmp(top_label);
    }

    // Store the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    s.store_state(code, ordering);
}

/**
 * \brief Generates the AVR code for the GIFT-128 decryption function.
 *
 * \param code The code block to generate into.
 * \param name Name of the decryption function to generate.
 * \param ordering Ordering of the state on input and output.
 */
static void gen_gift128_decrypt(Code &code, const char *name, int ordering)
{
    // Set up the function prologue with 16 bytes of local variable storage.
    // X will point to the input, Z points to the key, Y is local variables.
    Reg tweak;
    if (ordering != StateTweak)
        code.prologue_decrypt_block(name, 16);
    else
        tweak = code.prologue_decrypt_block_with_tweak(name, 16);

    // Allocate the registers that we need and load the state and key schedule.
    Gift128State s(code, ordering, true);

    // We will need a high register for the round counter.
    Reg counter = code.allocateHighReg(1);

    // We can discard Z now.  Replace it with a program memory
    // pointer to the table of round constants.
    code.sbox_setup(0, get_gift128_round_constants());

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
        code.ldy_xor(s.s2, 8);
        s.inv_rotate_key(code, 3);
        code.call(subroutine);

        // Round 3 out of 4.
        code.ldy_xor(s.s2, 12);
        s.inv_rotate_key(code, 2);
        code.call(subroutine);

        // Round 2 out of 4.
        code.ldy_xor(s.s2, 0);
        s.inv_rotate_key(code, 1);
        code.call(subroutine);

        // Round 1 out of 4.
        code.ldy_xor(s.s2, 4);
        s.inv_rotate_key(code, 0);
        code.call(subroutine);

        // Bottom of the round loop and the inner subroutine.
        code.compare_and_loop(counter, 0, top_label);
        code.jmp(end_label);
        code.label(subroutine);
        code.logxor(s.s1, s.w3);
        code.move(Reg(s.t1, 0, 1), 0x80);
        code.logxor(Reg(s.s3, 3, 1), Reg(s.t1, 0, 1));
        code.dec(counter);
        code.sbox_lookup(Reg(s.t1, 0, 1), counter);
        code.logxor(Reg(s.s3, 0, 1), Reg(s.t1, 0, 1));
        s.perm_bits(code, true);
        s.inv_sub_cells(code);
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
            code.memory(Insn::LD_Y, TEMP_REG, 12 + index);
            code.memory(Insn::LD_Y, s.t1.reg(index), 8 + index);
            code.memory(Insn::ST_Y, TEMP_REG, 8 + index);
            code.memory(Insn::LD_Y, TEMP_REG, 4 + index);
            code.memory(Insn::ST_Y, s.t1.reg(index), 4 + index);
            code.memory(Insn::LD_Y, s.t1.reg(index), index);
            code.memory(Insn::ST_Y, TEMP_REG, index);
        }
        code.ror(Reg(s.t1, 0, 2), 4);
        code.rol(Reg(s.t1, 2, 2), 2);
        code.sty(s.t1, 12);
        code.logxor(s.s1, s.t1);
        code.ldy_xor(s.s2, 4);
        code.move(Reg(s.t1, 0, 1), 0x80);
        code.logxor(Reg(s.s3, 3, 1), Reg(s.t1, 0, 1));
        code.dec(counter);
        code.sbox_lookup(Reg(s.t1, 0, 1), counter);
        code.logxor(Reg(s.s3, 0, 1), Reg(s.t1, 0, 1));
        s.perm_bits(code, true);
        s.inv_sub_cells(code);
        code.compare(counter, 0);
        code.breq(end_label);
        code.inc(counter2);
        code.compare_and_loop(counter2, 5, top_label);
        code.move(counter2, 0);
        code.logxor(Reg(s.s0, 0, 1), tweak);
        code.logxor(Reg(s.s0, 1, 1), tweak);
        code.logxor(Reg(s.s0, 2, 1), tweak);
        code.logxor(Reg(s.s0, 3, 1), tweak);
        code.jmp(top_label);
    }

    // Store the state to the output buffer.
    code.label(end_label);
    code.sbox_cleanup();
    code.load_output_ptr();
    s.store_state(code, ordering);
}

void gen_gift128b_encrypt(Code &code)
{
    gen_gift128_encrypt(code, "gift128b_encrypt", StateBE);
}

void gen_gift128b_encrypt_preloaded(Code &code)
{
    gen_gift128_encrypt(code, "gift128b_encrypt_preloaded", StateLE);
}

void gen_gift128b_decrypt(Code &code)
{
    gen_gift128_decrypt(code, "gift128b_decrypt", StateBE);
}

void gen_gift128n_encrypt(Code &code)
{
    gen_gift128_encrypt(code, "gift128n_encrypt", StateNibble);
}

void gen_gift128n_decrypt(Code &code)
{
    gen_gift128_decrypt(code, "gift128n_decrypt", StateNibble);
}

void gen_gift128t_encrypt(Code &code)
{
    gen_gift128_encrypt(code, "gift128t_encrypt", StateTweak);
}

void gen_gift128t_decrypt(Code &code)
{
    gen_gift128_decrypt(code, "gift128t_decrypt", StateTweak);
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

// Set up the key schedule for GIFT-128 (bit-sliced version).
static void gift128b_setup
    (unsigned char schedule[16], const block_cipher_test_vector_t *test)
{
    schedule[0]  = test->key[3];
    schedule[1]  = test->key[2];
    schedule[2]  = test->key[1];
    schedule[3]  = test->key[0];
    schedule[4]  = test->key[7];
    schedule[5]  = test->key[6];
    schedule[6]  = test->key[5];
    schedule[7]  = test->key[4];
    schedule[8]  = test->key[11];
    schedule[9]  = test->key[10];
    schedule[10] = test->key[9];
    schedule[11] = test->key[8];
    schedule[12] = test->key[15];
    schedule[13] = test->key[14];
    schedule[14] = test->key[13];
    schedule[15] = test->key[12];
}

static bool test_gift128b_setup_key
    (Code &code, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[16];
    unsigned char expected[16];
    code.exec_setup_key(schedule, sizeof(schedule),
                        test->key, test->key_len);
    gift128b_setup(expected, test);
    if (memcmp(schedule, expected, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_gift128b_setup_key(Code &code)
{
    if (!test_gift128b_setup_key(code, &gift128b_1))
        return false;
    if (!test_gift128b_setup_key(code, &gift128b_2))
        return false;
    if (!test_gift128b_setup_key(code, &gift128b_3))
        return false;
    if (!test_gift128b_setup_key(code, &gift128b_4))
        return false;
    if (!test_gift128b_setup_key(code, &gift128b_5))
        return false;
    return true;
}

static bool test_gift128b_encrypt
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char output[16];
    gift128b_setup(schedule, test);
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            test->plaintext, 16, tweak);
    if (memcmp(output, test->ciphertext, 16) != 0)
        return false;
    return true;
}

bool test_gift128b_encrypt(Code &code)
{
    if (!test_gift128b_encrypt(code, &gift128b_1))
        return false;
    if (!test_gift128b_encrypt(code, &gift128b_2))
        return false;
    if (!test_gift128b_encrypt(code, &gift128b_3))
        return false;
    if (!test_gift128b_encrypt(code, &gift128b_4))
        return false;
    if (!test_gift128b_encrypt(code, &gift128b_5))
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

static bool test_gift128b_encrypt_preloaded
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char input[16];
    unsigned char output[16];
    gift128b_setup(schedule, test);
    gift128_swap_words(input, test->plaintext);
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            input, sizeof(input), tweak);
    gift128_swap_words(input, test->ciphertext);
    if (memcmp(output, input, 16) != 0)
        return false;
    return true;
}

bool test_gift128b_encrypt_preloaded(Code &code)
{
    if (!test_gift128b_encrypt_preloaded(code, &gift128b_1))
        return false;
    if (!test_gift128b_encrypt_preloaded(code, &gift128b_2))
        return false;
    if (!test_gift128b_encrypt_preloaded(code, &gift128b_3))
        return false;
    if (!test_gift128b_encrypt_preloaded(code, &gift128b_4))
        return false;
    if (!test_gift128b_encrypt_preloaded(code, &gift128b_5))
        return false;
    return true;
}

static bool test_gift128b_decrypt
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char output[16];
    gift128b_setup(schedule, test);
    code.exec_decrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            test->ciphertext, 16, tweak);
    if (memcmp(output, test->plaintext, 16) != 0)
        return false;
    return true;
}

bool test_gift128b_decrypt(Code &code)
{
    if (!test_gift128b_decrypt(code, &gift128b_1))
        return false;
    if (!test_gift128b_decrypt(code, &gift128b_2))
        return false;
    if (!test_gift128b_decrypt(code, &gift128b_3))
        return false;
    if (!test_gift128b_decrypt(code, &gift128b_4))
        return false;
    if (!test_gift128b_decrypt(code, &gift128b_5))
        return false;
    return true;
}

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

// Set up the key schedule for GIFT-128 (nibble version).
static void gift128n_setup
    (unsigned char schedule[16], const block_cipher_test_vector_t *test)
{
    schedule[0]  = test->key[12];
    schedule[1]  = test->key[13];
    schedule[2]  = test->key[14];
    schedule[3]  = test->key[15];
    schedule[4]  = test->key[8];
    schedule[5]  = test->key[9];
    schedule[6]  = test->key[10];
    schedule[7]  = test->key[11];
    schedule[8]  = test->key[4];
    schedule[9]  = test->key[5];
    schedule[10] = test->key[6];
    schedule[11] = test->key[7];
    schedule[12] = test->key[0];
    schedule[13] = test->key[1];
    schedule[14] = test->key[2];
    schedule[15] = test->key[3];
}

static bool test_gift128n_setup_key
    (Code &code, const block_cipher_test_vector_t *test)
{
    unsigned char schedule[16];
    unsigned char expected[16];
    code.exec_setup_key(schedule, sizeof(schedule),
                        test->key, test->key_len);
    gift128n_setup(expected, test);
    if (memcmp(schedule, expected, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_gift128n_setup_key(Code &code)
{
    if (!test_gift128n_setup_key(code, &gift128n_1))
        return false;
    if (!test_gift128n_setup_key(code, &gift128n_2))
        return false;
    if (!test_gift128n_setup_key(code, &gift128n_3))
        return false;
    return true;
}

static bool test_gift128n_encrypt
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char output[16];
    gift128n_setup(schedule, test);
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            test->plaintext, 16, tweak);
    if (memcmp(output, test->ciphertext, 16) != 0)
        return false;
    return true;
}

bool test_gift128n_encrypt(Code &code)
{
    if (!test_gift128n_encrypt(code, &gift128n_1))
        return false;
    if (!test_gift128n_encrypt(code, &gift128n_2))
        return false;
    if (!test_gift128n_encrypt(code, &gift128n_3))
        return false;
    return true;
}

static bool test_gift128n_decrypt
    (Code &code, const block_cipher_test_vector_t *test, unsigned tweak = 0)
{
    unsigned char schedule[16];
    unsigned char output[16];
    gift128n_setup(schedule, test);
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            test->ciphertext, 16, tweak);
    if (memcmp(output, test->plaintext, 16) != 0)
        return false;
    return true;
}

bool test_gift128n_decrypt(Code &code)
{
    if (!test_gift128n_decrypt(code, &gift128n_1))
        return false;
    if (!test_gift128n_decrypt(code, &gift128n_2))
        return false;
    if (!test_gift128n_decrypt(code, &gift128n_3))
        return false;
    return true;
}

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

bool test_gift128t_encrypt(Code &code)
{
    if (!test_gift128n_encrypt(code, &gift128t_1, 0))
        return false;
    if (!test_gift128n_encrypt(code, &gift128t_2, 0x4b4b))
        return false;
    if (!test_gift128n_encrypt(code, &gift128t_3, 0xb4b4))
        return false;
    if (!test_gift128n_encrypt(code, &gift128t_4, 0))
        return false;
    return true;
}

bool test_gift128t_decrypt(Code &code)
{
    if (!test_gift128n_decrypt(code, &gift128t_1, 0))
        return false;
    if (!test_gift128n_decrypt(code, &gift128t_2, 0x4b4b))
        return false;
    if (!test_gift128n_decrypt(code, &gift128t_3, 0xb4b4))
        return false;
    if (!test_gift128n_decrypt(code, &gift128t_4, 0))
        return false;
    return true;
}
