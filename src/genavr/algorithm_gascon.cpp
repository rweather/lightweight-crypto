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

// Offset of a byte in the GASCON-128 state in little-endian byte order.
#define GASCON128_BYTE(word, byte) ((word) * 8 + (byte))

// Offset of a 64-bit word in the GASCON-128 state.  Points to the low byte.
#define GASCON128_WORD(word) ((word) * 8)

// Offset of a 32-bit word in the GASCON-128 state.  Points to the low byte.
#define GASCON128_WORD32(word) ((word) * 4)

// Offset of a rate word in the DrySPONGE-128 state.  Points to the low byte.
#define GASCON128_RATE_WORD(word) ((word) * 4 + 40)

static void gascon128_substitute
    (Code &code, int offset, const Reg &x0, const Reg &x2)
{
    // Allocate and load the registers for x1, x3, and x4.
    // The x0 and x2 values have already been loaded by the calling function.
    Reg x1 = code.allocateReg(1);
    Reg x3 = code.allocateReg(1);
    Reg x4 = code.allocateReg(1);
    code.ldz(x1, GASCON128_BYTE(1, offset));
    code.ldz(x3, GASCON128_BYTE(3, offset));
    code.ldz(x4, GASCON128_BYTE(4, offset));

    // We need some temporary registers as well.
    Reg t0 = code.allocateReg(1);
    Reg t1 = code.allocateReg(1);
    Reg t2 = code.allocateReg(1);
    Reg t3 = code.allocateReg(1);
    Reg t4 = code.allocateReg(1);

    // x0 ^= x4; x2 ^= x1; x4 ^= x3;
    code.logxor(x0, x4);
    code.logxor(x2, x1);
    code.logxor(x4, x3);

    // t0 = (~x0) & x1; t1 = (~x1) & x2; t2 = (~x2) & x3;
    code.move(t0, x1);
    code.logand_not(t0, x0);
    code.move(t1, x2);
    code.logand_not(t1, x1);
    code.move(t2, x3);
    code.logand_not(t2, x2);

    // t3 = (~x3) & x4; t4 = (~x4) & x0;
    code.move(t3, x4);
    code.logand_not(t3, x3);
    code.move(t4, x0);
    code.logand_not(t4, x4);

    // x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0;
    code.logxor(x0, t1);
    code.logxor(x1, t2);
    code.logxor(x2, t3);
    code.logxor(x3, t4);
    code.logxor(x4, t0);

    // x1 ^= x0; x3 ^= x2; x0 ^= x4; x2 = ~x2;
    code.logxor(x1, x0);
    code.logxor(x3, x2);
    code.logxor(x0, x4);
    code.lognot(x2);

    // Write x0, x1, x3, and x4 back to the state.  We keep x2 in a
    // register in preparation for the diffusion step that follows.
    code.stz(x0, GASCON128_BYTE(0, offset));
    code.stz(x1, GASCON128_BYTE(1, offset));
    code.stz(x3, GASCON128_BYTE(3, offset));
    code.stz(x4, GASCON128_BYTE(4, offset));

    // Release all registers except x0 and x2.
    code.releaseReg(x1);
    code.releaseReg(x3);
    code.releaseReg(x4);
    code.releaseReg(t0);
    code.releaseReg(t1);
    code.releaseReg(t2);
    code.releaseReg(t3);
    code.releaseReg(t4);
}

// 32-bit rotation using a shuffle for byte-sized shifts.
static Reg rotate32(Code &code, const Reg &x, int shift)
{
    // Rotate by the left-over bits.
    if ((shift % 8) <= 4) {
        code.ror(x, shift % 8);
        shift -= shift % 8;
    } else {
        code.rol(x, 8 - (shift % 8));
        shift -= shift % 8;
        shift = (shift + 8) % 32;
    }

    // Rotate the bytes using a shuffle.
    if (shift == 8)
        return x.shuffle(1, 2, 3, 0);
    else if (shift == 16)
        return x.shuffle(2, 3, 0, 1);
    else if (shift == 24)
        return x.shuffle(3, 0, 1, 2);
    else
        return x;
}

// Interleaved rotation of a 64-bit value in two 32-bit halves.
static Reg intRightRotate
    (Code &code, const Reg &x, int shift, bool reorder = false)
{
    if (shift & 1) {
        // Odd shift amount: rotate the subwords and swap.
        // We can virtualise rotations by 8 or more by rearranging
        // the bytes in the result.  Then we only need to rotate
        // by the left-over bits.
        Reg t = rotate32(code, Reg(x, 0, 4), ((shift / 2) + 1) % 32);
        Reg u = rotate32(code, Reg(x, 4, 4), shift / 2);
        return u.append(t);
    } else if (reorder) {
        // Even shift amount with re-ordering allowed.
        Reg t = rotate32(code, Reg(x, 0, 4), shift / 2);
        Reg u = rotate32(code, Reg(x, 4, 4), shift / 2);
        return t.append(u);
    } else {
        // Even shift amount: rotate the subwords with no swap.
        code.ror(Reg(x, 0, 4), shift / 2);
        code.ror(Reg(x, 4, 4), shift / 2);
        return x;
    }
}

static void gascon128_diffuse
    (Code &code, const Reg &x, int word, int shift1, int shift2)
{
    // One of the shifts will be even and the other odd.  Make sure
    // that "shift2" is always the even one so that the final byte
    // ordering on "x" is the same as the input byte ordering.
    if (shift2 & 1) {
        int temp = shift1;
        shift1 = shift2;
        shift2 = temp;
    }

    // Compute "x ^= (x >>> shift1) ^ (x >>> shift2)".
    Reg t = code.allocateReg(8);
    if (word != 2)
        code.ldz(x, GASCON128_WORD(word));
    code.move(t, x);
    t = intRightRotate(code, t, shift1);
    code.logxor(t, x);
    if (word != 0 && word != 2) {
        Reg xrot = intRightRotate(code, x, shift2, true);
        code.logxor(xrot, t);
        code.stz(xrot, GASCON128_WORD(word));
    } else {
        intRightRotate(code, x, shift2);
        code.logxor(x, t);
    }
    code.releaseReg(t);
}

void gen_gascon128_core_round(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg round = code.prologue_permutation_with_count("gascon128_core_round", 0);
    code.setFlag(Code::NoLocals); // Don't need Y, so no point creating locals.

    // Compute "round = ((0x0F - round) << 4) | round" to convert the
    // round number into a round constant.
    Reg temp = code.allocateHighReg(1);
    code.move(temp, 0x0F);
    code.sub(temp, round);
    code.onereg(Insn::SWAP, temp.reg(0));
    code.logor(round, temp);
    code.releaseReg(temp);

    // Preload "x0" and "x2" into registers.
    Reg x0 = code.allocateReg(8);
    Reg x2 = code.allocateReg(8);
    code.ldz(x0, GASCON128_WORD(0));
    code.ldz(x2, GASCON128_WORD(2));

    // XOR the round constant with the low byte of "x2".
    code.logxor(x2, round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index)
        gascon128_substitute(code, index, Reg(x0, index, 1), Reg(x2, index, 1));

    // Perform the linear diffusion layer on each of the state words.
    // We spilled "x0" out to the state during the substitution layer,
    // so we can use that as a temporary register.  We diffuse the "x0"
    // row last so that it is ready in registers for the next round.
    gascon128_diffuse(code, x0, 1, 61, 38);
    gascon128_diffuse(code, x2, 2,  1,  6);
    gascon128_diffuse(code, x0, 3, 10, 17);
    gascon128_diffuse(code, x0, 4,  7, 40);
    gascon128_diffuse(code, x0, 0, 19, 28);

    // Store "x0" and "x2" back to the state memory.
    code.stz(x0, GASCON128_WORD(0));
    code.stz(x2, GASCON128_WORD(2));
}

void gen_gascon128_permutation(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    Reg round = code.prologue_permutation_with_count("gascon_permute", 0);
    code.setFlag(Code::NoLocals); // Don't need Y, so no point creating locals.

    // Compute "round = ((0x0F - round) << 4) | round" to convert the
    // round number into a round constant.
    Reg temp = code.allocateHighReg(1);
    code.move(temp, 0x0F);
    code.sub(temp, round);
    code.onereg(Insn::SWAP, temp.reg(0));
    code.logor(round, temp);
    code.releaseReg(temp);

    // Preload "x0" and "x2" into registers.
    Reg x0 = code.allocateReg(8);
    Reg x2 = code.allocateReg(8);
    code.ldz(x0, GASCON128_WORD(0));
    code.ldz(x2, GASCON128_WORD(2));

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // XOR the round constant with the low byte of "x2".
    code.logxor(x2, round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index)
        gascon128_substitute(code, index, Reg(x0, index, 1), Reg(x2, index, 1));

    // Perform the linear diffusion layer on each of the state words.
    // We spilled "x0" out to the state during the substitution layer,
    // so we can use that as a temporary register.  We diffuse the "x0"
    // row last so that it is ready in registers for the next round.
    gascon128_diffuse(code, x0, 1, 61, 38);
    gascon128_diffuse(code, x2, 2,  1,  6);
    gascon128_diffuse(code, x0, 3, 10, 17);
    gascon128_diffuse(code, x0, 4,  7, 40);
    gascon128_diffuse(code, x0, 0, 19, 28);

    // Bottom of the round loop.  Adjust the round constant and
    // check to see if we have reached the final round.
    code.sub(round, 0x0F);
    code.compare_and_loop(round, 0x3C, top_label);

    // Store "x0" and "x2" back to the state memory.
    code.stz(x0, GASCON128_WORD(0));
    code.stz(x2, GASCON128_WORD(2));
}

void gen_drysponge128_g(Code &code)
{
    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.
    code.prologue_permutation("drysponge128_g", 0);
    code.setFlag(Code::NoLocals); // Don't need Y, so no point creating locals.

    // Load the round count and initialize the round constant variable.
    Reg round = code.allocateHighReg(1);
    Reg count = code.allocateReg(1);
    code.ldz(count, 76); // Offset of "rounds" in "drysponge128_state_t".
    code.move(round, 0xF0);

    // Zero the rate bytes before we start.
    code.stz_zero(GASCON128_RATE_WORD(0), 16);

    // Preload "x0" and "x2" into registers.
    Reg x0 = code.allocateReg(8);
    Reg x2 = code.allocateReg(8);
    code.ldz(x0, GASCON128_WORD(0));
    code.ldz(x2, GASCON128_WORD(2));

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // XOR the round constant with the low byte of "x2".
    code.logxor(x2, round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index)
        gascon128_substitute(code, index, Reg(x0, index, 1), Reg(x2, index, 1));

    // Perform the linear diffusion layer on each of the state words.
    // We spilled "x0" out to the state during the substitution layer,
    // so we can use that as a temporary register.  We diffuse the "x0"
    // row last so that it is ready in registers for the next round.
    gascon128_diffuse(code, x0, 1, 61, 38);
    gascon128_diffuse(code, x2, 2,  1,  6);
    gascon128_diffuse(code, x0, 3, 10, 17);
    gascon128_diffuse(code, x0, 4,  7, 40);
    gascon128_diffuse(code, x0, 0, 19, 28);

    // Collect up the rate bytes for this round.
    Reg temp = code.allocateReg(4);
    code.ldz(temp, GASCON128_RATE_WORD(0));
    code.logxor(temp, Reg(x0, 0, 4));
    code.logxor(temp, Reg(x2, 4, 4));
    code.stz(temp, GASCON128_RATE_WORD(0));
    code.ldz(temp, GASCON128_RATE_WORD(1));
    code.logxor(temp, Reg(x0, 4, 4));
    code.ldz_xor(temp, GASCON128_WORD32(6));
    code.stz(temp, GASCON128_RATE_WORD(1));
    code.ldz(temp, GASCON128_RATE_WORD(2));
    code.ldz_xor(temp, GASCON128_WORD32(2));
    code.ldz_xor(temp, GASCON128_WORD32(7));
    code.stz(temp, GASCON128_RATE_WORD(2));
    code.ldz(temp, GASCON128_RATE_WORD(3));
    code.ldz_xor(temp, GASCON128_WORD32(3));
    code.logxor(temp, Reg(x2, 0, 4));
    code.stz(temp, GASCON128_RATE_WORD(3));
    code.releaseReg(temp);

    // Bottom of the round loop.  Adjust the round constant and
    // check to see if we have reached the final round.
    code.sub(round, 0x0F);
    code.dec(count);
    code.brne(top_label);

    // Store "x0" and "x2" back to the state memory.
    code.stz(x0, GASCON128_WORD(0));
    code.stz(x2, GASCON128_WORD(2));
}

// Offset of a byte in the GASCON-256 state in little-endian byte order.
// Note: We assume that the words are offset by 1 (see below).
#define GASCON256_BYTE(word, byte) (((word) - 1) * 8 + (byte))

// Offset of a 64-bit word in the GASCON-256 state.  Points to the low byte.
#define GASCON256_WORD(word) (((word) - 1) * 8)

// Offset of a 32-bit word in the GASCON-256 state.  Points to the low byte.
#define GASCON256_WORD32(word) (((word) - 2) * 4)

// Offset of a rate word on the stack.  Points to the low byte.
#define GASCON256_RATE_WORD(word) ((word) * 4 + 8)

static void gascon256_substitute
    (Code &code, int offset, const Reg &x0, const Reg &x4)
{
    // Allocate and load the registers for x1, x2, x3, x5, x6, x7, and x8.
    // The x0 and x4 values have already been loaded by the calling function.
    Reg x1 = code.allocateReg(1);
    Reg x2 = code.allocateReg(1);
    Reg x3 = code.allocateReg(1);
    Reg x5 = code.allocateReg(1);
    Reg x6 = code.allocateReg(1);
    Reg x7 = code.allocateReg(1);
    Reg x8 = code.allocateReg(1);
    code.ldz(x1, GASCON256_BYTE(1, offset));
    code.ldz(x2, GASCON256_BYTE(2, offset));
    code.ldz(x3, GASCON256_BYTE(3, offset));
    code.ldz(x5, GASCON256_BYTE(5, offset));
    code.ldz(x6, GASCON256_BYTE(6, offset));
    code.ldz(x7, GASCON256_BYTE(7, offset));
    code.ldz(x8, GASCON256_BYTE(8, offset));

    // We need some temporary registers as well.  Best would be if we
    // could get 9 temporary registers but we are very low on registers
    // at the moment.  It is possible to rearrange the substitution layer
    // code to only use 3 temporary registers, so that is what we do.
    Reg t0 = code.allocateReg(1);
    Reg t1 = code.allocateReg(1);
    Reg t2 = code.allocateReg(1);

    // x0 ^= x8; x2 ^= x1; x4 ^= x3; x6 ^= x5; x8 ^= x7;
    code.logxor(x0, x8);
    code.logxor(x2, x1);
    code.logxor(x4, x3);
    code.logxor(x6, x5);
    code.logxor(x8, x7);

    // t0 = (~x0) & x1; t1 = (~x1) & x2; x0 ^= t1;
    code.move(t2, x0); // Save the original version of "x0" for later.
    code.move(t0, x1);
    code.logand_not(t0, x0);
    code.move(t1, x2);
    code.logand_not(t1, x1);
    code.logxor(x0, t1);

    // t2 = (~x2) & x3; x1 ^= t2; (t2..t8 are actually stored in t1)
    code.move(t1, x3);
    code.logand_not(t1, x2);
    code.logxor(x1, t1);

    // t3 = (~x3) & x4; x2 ^= t3;
    code.move(t1, x4);
    code.logand_not(t1, x3);
    code.logxor(x2, t1);

    // t4 = (~x4) & x5; x3 ^= t4;
    code.move(t1, x5);
    code.logand_not(t1, x4);
    code.logxor(x3, t1);

    // t5 = (~x5) & x6; x4 ^= r5;
    code.move(t1, x6);
    code.logand_not(t1, x5);
    code.logxor(x4, t1);

    // t6 = (~x6) & x7; x5 ^= t6;
    code.move(t1, x7);
    code.logand_not(t1, x6);
    code.logxor(x5, t1);

    // t7 = (~x7) & x8; x6 ^= t7;
    code.move(t1, x8);
    code.logand_not(t1, x7);
    code.logxor(x6, t1);

    // t8 = (~x8) & x0; x7 ^= t8;
    code.logand_not(t2, x8);
    code.logxor(x7, t2);

    // x8 ^= t0;
    code.logxor(x8, t0);

    // x1 ^= x0; x3 ^= x2; x5 ^= x4; x7 ^= x6; x0 ^= x8; x4 = ~x4;
    code.logxor(x1, x0);
    code.logxor(x3, x2);
    code.logxor(x5, x4);
    code.logxor(x7, x6);
    code.logxor(x0, x8);
    code.lognot(x4);

    // Write x0 to x3 and x5 to x8 back to the state.  We keep x4 in a
    // register in preparation for the diffusion step that follows.
    code.stlocal(x0, offset); // "x0" is spilled out to Y, not Z.
    code.stz(x1, GASCON256_BYTE(1, offset));
    code.stz(x2, GASCON256_BYTE(2, offset));
    code.stz(x3, GASCON256_BYTE(3, offset));
    code.stz(x5, GASCON256_BYTE(5, offset));
    code.stz(x6, GASCON256_BYTE(6, offset));
    code.stz(x7, GASCON256_BYTE(7, offset));
    code.stz(x8, GASCON256_BYTE(8, offset));

    // Release all registers except x0 and x4.
    code.releaseReg(x1);
    code.releaseReg(x2);
    code.releaseReg(x3);
    code.releaseReg(x5);
    code.releaseReg(x6);
    code.releaseReg(x7);
    code.releaseReg(x8);
    code.releaseReg(t0);
    code.releaseReg(t1);
    code.releaseReg(t2);
}

static void gascon256_diffuse
    (Code &code, const Reg &x, int word, int shift1, int shift2)
{
    // One of the shifts will be even and the other odd.  Make sure
    // that "shift2" is always the even one so that the final byte
    // ordering on "x" is the same as the input byte ordering.
    if (shift2 & 1) {
        int temp = shift1;
        shift1 = shift2;
        shift2 = temp;
    }

    // Compute "x ^= (x >>> shift1) ^ (x >>> shift2)".
    Reg t = code.allocateReg(8);
    if (word == 0)
        code.ldlocal(x, 0); // "x0" is spilled out to Y, not Z.
    else if (word != 4)
        code.ldz(x, GASCON256_WORD(word));
    code.move(t, x);
    t = intRightRotate(code, t, shift1);
    code.logxor(t, x);
    if (word != 0 && word != 4) {
        Reg xrot = intRightRotate(code, x, shift2, true);
        code.logxor(xrot, t);
        code.stz(xrot, GASCON256_WORD(word));
    } else {
        intRightRotate(code, x, shift2);
        code.logxor(x, t);
    }
    code.releaseReg(t);
}

void gen_gascon256_core_round(Code &code)
{
    // Set up the function prologue with 8 bytes of local variable storage.
    // Z points to the permutation state on input and output.  The state is
    // 72 bytes in size, which is further than the 0-63 offsets relative
    // to Z can reach.  To work around this, we preload "x0" and then spill
    // it out to Y[0..7] during each round.  We then adjust Z to point at
    // "x1" during the rest of the function.
    Reg round = code.prologue_permutation_with_count("gascon256_core_round", 8);

    // Compute "round = ((0x0F - round) << 4) | round" to convert the
    // round number into a round constant.
    Reg temp = code.allocateHighReg(1);
    code.move(temp, 0x0F);
    code.sub(temp, round);
    code.onereg(Insn::SWAP, temp.reg(0));
    code.logor(round, temp);
    code.releaseReg(temp);

    // Preload "x0" and "x4" into registers and advance Z to point at "x1".
    Reg x0 = code.allocateReg(8);
    Reg x4 = code.allocateReg(8);
    code.ldz(x0, POST_INC);
    code.ldz(x4, GASCON256_WORD(4));

    // XOR the round constant with the low byte of "x4".
    code.logxor(x4, round);
    code.releaseReg(round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index)
        gascon256_substitute(code, index, Reg(x0, index, 1), Reg(x4, index, 1));

    // Perform the linear diffusion layer on each of the state words.
    // We spilled "x0" out to the state during the substitution layer,
    // so we can use that as a temporary register.  We diffuse the "x0"
    // row last so that it is ready in registers for the next round.
    gascon256_diffuse(code, x0, 1, 61, 38);
    gascon256_diffuse(code, x0, 2,  1,  6);
    gascon256_diffuse(code, x0, 3, 10, 17);
    gascon256_diffuse(code, x4, 4,  7, 40);
    gascon256_diffuse(code, x0, 5, 31, 26);
    gascon256_diffuse(code, x0, 6, 53, 58);
    gascon256_diffuse(code, x0, 7,  9, 46);
    gascon256_diffuse(code, x0, 8, 43, 50);
    gascon256_diffuse(code, x0, 0, 19, 28);

    // Store "x0" and "x4" back to the state memory.
    code.stz(x4, GASCON256_WORD(4));
    code.stz(x0, PRE_DEC);
}

void gen_drysponge256_g(Code &code)
{
    // Set up the function prologue with 26 bytes of local variable storage.
    // Z points to the permutation state on input and output.  The state is
    // 72 bytes in size, which is further than the 0-63 offsets relative
    // to Z can reach.  To work around this, we preload "x0" and then spill
    // it out to Y[0..7] during each round.  We then adjust Z to point at
    // "x1" during the rest of the function.  We also store the rate data
    // on the stack in Y[8..23] before copying to the state structure later.
    code.prologue_permutation("drysponge256_g", 26);

    // Load the round count and initialize the round constant variable.
    // We store the values on the stack because we need the registers
    // during the main part of the loop.
    Reg round = code.allocateHighReg(1);
    Reg count = code.allocateReg(1);
    code.ldz(count, 108); // Offset of "rounds" in "drysponge256_state_t".
    code.move(round, 0xF0);
    code.stlocal(count, 24);
    code.stlocal(round, 25);
    code.releaseReg(count);
    code.releaseReg(round);

    // Zero the rate bytes before we start.
    code.stlocal_zero(GASCON256_RATE_WORD(0), 16);

    // Preload "x0" and "x4" into registers and advance Z to point at "x1".
    Reg x0 = code.allocateReg(8);
    Reg x4 = code.allocateReg(8);
    code.ldz(x0, POST_INC);
    code.ldz(x4, GASCON256_WORD(4));

    // Top of the round loop.
    unsigned char top_label = 0;
    code.label(top_label);

    // XOR the round constant with the low byte of "x4" and update it.
    round = code.allocateHighReg(1);
    code.ldlocal(round, 25);
    code.logxor(x4, round);
    code.sub(round, 0x0F);
    code.stlocal(round, 25);
    code.releaseReg(round);

    // Perform the substitution layer byte by byte.
    for (int index = 0; index < 8; ++index)
        gascon256_substitute(code, index, Reg(x0, index, 1), Reg(x4, index, 1));

    // Perform the linear diffusion layer on each of the state words.
    // We spilled "x0" out to the state during the substitution layer,
    // so we can use that as a temporary register.  We diffuse the "x0"
    // row last so that it is ready in registers for the next round.
    gascon256_diffuse(code, x0, 1, 61, 38);
    gascon256_diffuse(code, x0, 2,  1,  6);
    gascon256_diffuse(code, x0, 3, 10, 17);
    gascon256_diffuse(code, x4, 4,  7, 40);
    gascon256_diffuse(code, x0, 5, 31, 26);
    gascon256_diffuse(code, x0, 6, 53, 58);
    gascon256_diffuse(code, x0, 7,  9, 46);
    gascon256_diffuse(code, x0, 8, 43, 50);
    gascon256_diffuse(code, x0, 0, 19, 28);

    // Collect up the rate bytes for this round.
    Reg temp = code.allocateReg(4);
    code.ldlocal(temp, GASCON256_RATE_WORD(0));
    code.logxor(temp, Reg(x0, 0, 4));
    code.ldz_xor(temp, GASCON256_WORD32(5));
    code.ldz_xor(temp, GASCON256_WORD32(10));
    code.ldz_xor(temp, GASCON256_WORD32(15));
    code.stlocal(temp, GASCON256_RATE_WORD(0));
    code.ldlocal(temp, GASCON256_RATE_WORD(1));
    code.logxor(temp, Reg(x0, 4, 4));
    code.ldz_xor(temp, GASCON256_WORD32(6));
    code.ldz_xor(temp, GASCON256_WORD32(11));
    code.ldz_xor(temp, GASCON256_WORD32(12));
    code.stlocal(temp, GASCON256_RATE_WORD(1));
    code.ldlocal(temp, GASCON256_RATE_WORD(2));
    code.logxor(temp, Reg(x4, 0, 4));
    code.ldz_xor(temp, GASCON256_WORD32(2));
    code.ldz_xor(temp, GASCON256_WORD32(7));
    code.ldz_xor(temp, GASCON256_WORD32(13));
    code.stlocal(temp, GASCON256_RATE_WORD(2));
    code.ldlocal(temp, GASCON256_RATE_WORD(3));
    code.logxor(temp, Reg(x4, 4, 4));
    code.ldz_xor(temp, GASCON256_WORD32(3));
    code.ldz_xor(temp, GASCON256_WORD32(4));
    code.ldz_xor(temp, GASCON256_WORD32(14));
    code.stlocal(temp, GASCON256_RATE_WORD(3));
    code.releaseReg(temp);

    // Bottom of the round loop.
    count = code.allocateReg(1);
    code.ldlocal(count, 24);
    code.dec(count);
    code.stlocal(count, 24);
    code.brne(top_label);
    code.releaseReg(count);

    // Store "x0" and "x4" back to the state memory.
    code.stz(x4, GASCON256_WORD(4));
    code.stz(x0, PRE_DEC);

    // Copy the rate data from the stack to the state.
    code.add(Reg::z_ptr(), 72);
    code.ldlocal(x0, 8);
    code.ldlocal(x4, 16);
    code.stz(x0, 0);
    code.stz(x4, 8);
}

// Test vectors for GASCON-128 and DrySPONGE-128.
static unsigned char const gascon128_input[40] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27
};
static unsigned char const gascon128_output[40] = {
    0x97, 0x49, 0xac, 0x0d, 0xe8, 0x26, 0x7f, 0xc6,
    0x50, 0xf7, 0x28, 0x5f, 0xe8, 0xf7, 0xb8, 0xb1,
    0x38, 0x85, 0x6a, 0x2f, 0xc6, 0x5b, 0xf3, 0xd5,
    0x91, 0x12, 0x21, 0x91, 0x0d, 0x18, 0x6c, 0x19,
    0x21, 0x7a, 0xba, 0xdd, 0x24, 0xa9, 0x82, 0xee
};
static unsigned char const gascon128_squeezed[16] = {
    0x87, 0xe9, 0xea, 0xdd, 0x8c, 0xc7, 0x17, 0x68,
    0x79, 0xbe, 0x72, 0x24, 0x42, 0xea, 0xcf, 0xa3
};

bool test_gascon128_core_round(Code &code)
{
    unsigned char state[40];
    memcpy(state, gascon128_input, 40);
    for (unsigned round = 0; round < 12; ++round)
        code.exec_permutation(state, 40, round);
    return !memcmp(gascon128_output, state, 40);
}

bool test_gascon128_permutation(Code &code)
{
    unsigned char state[40];
    memcpy(state, gascon128_input, 40);
    code.exec_permutation(state, 40, 0);
    return !memcmp(gascon128_output, state, 40);
}

typedef struct
{
    unsigned char c[40];
    unsigned char r[16];
    unsigned char x[16];
    uint32_t domain;
    uint32_t rounds;

} drysponge128_state_t;

bool test_drysponge128_g(Code &code)
{
    drysponge128_state_t state;
    memset(&state, 0, sizeof(state));
    memcpy(state.c, gascon128_input, 40);
    state.rounds = 12;
    code.exec_permutation(&state, sizeof(state));
    if (memcmp(gascon128_output, state.c, 40))
        return false;
    return !memcmp(gascon128_squeezed, state.r, 16);
}

// Test vectors for GASCON-256 and DrySPONGE-256.
static unsigned char const gascon256_input[72] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47
};
static unsigned char const gascon256_output[72] = {
    0x44, 0x51, 0x6c, 0x30, 0x52, 0x18, 0x16, 0x38,
    0xff, 0xcf, 0x0a, 0x8e, 0x0e, 0xbc, 0xb4, 0xbc,
    0x8b, 0x11, 0x3a, 0xcd, 0xd6, 0x47, 0x61, 0xd6,
    0x48, 0xa2, 0xc8, 0xfa, 0x4d, 0x42, 0x7e, 0x8a,
    0xf6, 0x65, 0x70, 0x39, 0xf2, 0x03, 0x8a, 0x41,
    0x10, 0xcc, 0xcb, 0xbf, 0xd1, 0x6c, 0x49, 0x43,
    0xeb, 0x5a, 0xb2, 0x8b, 0x13, 0x84, 0x93, 0x13,
    0x49, 0xa7, 0x6a, 0x42, 0xd1, 0x3a, 0xfc, 0x8c,
    0x67, 0xb2, 0xe2, 0xab, 0x18, 0xeb, 0x4f, 0x8f
};
static unsigned char const gascon256_squeezed[16] = {
    0xaa, 0x10, 0xc7, 0x86, 0x39, 0x65, 0xf0, 0x6f,
    0x5b, 0xde, 0xbc, 0xb3, 0x8d, 0x86, 0x61, 0xd1
};

typedef struct
{
    unsigned char c[72];
    unsigned char r[16];
    unsigned char x[16];
    uint32_t domain;
    uint32_t rounds;

} drysponge256_state_t;

bool test_gascon256_core_round(Code &code)
{
    unsigned char state[72];
    memcpy(state, gascon256_input, 72);
    for (unsigned round = 0; round < 12; ++round)
        code.exec_permutation(state, 72, round);
    return !memcmp(gascon256_output, state, 72);
}

bool test_drysponge256_g(Code &code)
{
    drysponge256_state_t state;
    memset(&state, 0, sizeof(state));
    memcpy(state.c, gascon256_input, 72);
    state.rounds = 12;
    code.exec_permutation(&state, sizeof(state));
    if (memcmp(gascon256_output, state.c, 72))
        return false;
    return !memcmp(gascon256_squeezed, state.r, 16);
}
