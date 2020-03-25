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

// The 8 basic round constants from the specification.
#define RC_0 0xB7E15162
#define RC_1 0xBF715880
#define RC_2 0x38B4DA56
#define RC_3 0x324E7738
#define RC_4 0xBB1185EB
#define RC_5 0x4F7C7B57
#define RC_6 0xCFBFA1C8
#define RC_7 0xC2B3293D

// Round constants for all SPARKLE steps; maximum of 12 for SPARKLE-512.
static unsigned long const sparkle_rc[12] = {
    RC_0, RC_1, RC_2, RC_3, RC_4, RC_5, RC_6, RC_7,
    RC_0, RC_1, RC_2, RC_3
};

// Offsets of words within the state.
#define X0_OFFSET 0
#define Y0_OFFSET 4
#define X1_OFFSET 8
#define Y1_OFFSET 12
#define X2_OFFSET 16
#define Y2_OFFSET 20
#define X3_OFFSET 24
#define Y3_OFFSET 28
#define X4_OFFSET 32
#define Y4_OFFSET 36
#define X5_OFFSET 40
#define Y5_OFFSET 44
#define X6_OFFSET 48
#define Y6_OFFSET 52
#define X7_OFFSET 56
#define Y7_OFFSET 60

static void alzette
    (Code &code, const Reg& x, const Reg &y, unsigned long k, const Reg &t)
{
    // x += leftRotate1(y);
    code.move(t, y);
    code.rol(t, 1);
    code.add(x, t);

    // y ^= leftRotate8(x);
    Reg rotx = Reg(x, 3, 4);
    code.logxor(y, rotx);

    // x ^= k;
    code.move(t, k);
    code.logxor(x, t);

    // x += leftRotate15(y);
    code.move(t, y);
    code.ror(t, 1);
    Reg rott = Reg(t, 2, 4);
    code.add(x, rott);

    // y ^= leftRotate15(x);
    code.move(t, x);
    code.ror(t, 1);
    code.logxor(y, rott);

    // x ^= k;
    code.move(t, k);
    code.logxor(x, t);

    // x += y;
    code.add(x, y);

    // y ^= leftRotate1(x);
    code.move(t, x);
    code.rol(t, 1);
    code.logxor(y, t);

    // x ^= k;
    code.move(t, k);
    code.logxor(x, t);

    // x += leftRotate8(y);
    Reg roty = Reg(y, 3, 4);
    code.add(x, roty);

    // y ^= leftRotate16(x);
    rotx = Reg(x, 2, 4);
    code.logxor(y, rotx);

    // x ^= k;
    code.logxor(x, t);
}

/**
 * \brief Generates the AVR code for the SPARKLE-256 permutation.
 *
 * \param code The code block to generate into.
 */
void gen_sparkle256_permutation(Code &code)
{
    unsigned step;

    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.  The step
    // parameter will be either 7 or 10 so we special case those values.
    Reg steps = code.prologue_permutation_with_count("sparkle_256", 0);

    // We don't need the Y register any more, so use it for extra temporaries.
    code.setFlag(Code::TempY);

    // Push the step counter on the stack.  We need the extra register.
    code.push(steps);
    code.releaseReg(steps);

    // Allocate some temporary registers for use later.
    Reg t = code.allocateHighReg(4);
    Reg x0 = code.allocateReg(4);
    Reg x1 = code.allocateReg(4);
    Reg y0 = code.allocateReg(4);
    Reg y1 = code.allocateReg(4);
    Reg tx = code.allocateReg(4);
    Reg ty = code.allocateReg(4);
    Reg x2 = x0; // Aliases for convenience.
    Reg x3 = x1;
    Reg y2 = y0;
    Reg y3 = y1;

    // Preload x0, y0, x1, y1 before the first round.  These values will
    // be left in registers between each round to reduce load/store overhead.
    code.ldz(x0, X0_OFFSET);
    code.ldz(y0, Y0_OFFSET);
    code.ldz(x1, X1_OFFSET);
    code.ldz(y1, Y1_OFFSET);

    // Perform all permutation steps.  We unroll the outer part of the
    // loop to deal with the round constants, with the ARXbox and linear
    // layers in a local subroutine to save program space.
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (step = 0; step < 10; ++step) {
        code.move(t, sparkle_rc[step]);
        code.logxor(y0, t);
        Reg smallt = Reg(t, 0, 1);
        if (step != 0) {
            code.move(smallt, step);
            code.logxor(y1, smallt);
        }
        code.call(subroutine);
        if (step == 6) {
            // May need an early bail-out after 7 rounds.
            // The "steps" value is on the top of the stack.
            code.pop(smallt);
            code.compare(smallt, 7);
            code.breq(end_label);
        }
    }
    code.jmp(end_label);

    // Output the subroutine for the ARXbox and linear layers.
    // On entry, x0, y0, x1, y1 are already in registers.
    code.label(subroutine);

    // ARXbox layer:
    //      alzette(x0, y0, RC_0);
    //      alzette(x1, y1, RC_1);
    //      alzette(x2, y2, RC_2);
    //      alzette(x3, y3, RC_3);
    alzette(code, x0, y0, RC_0, t);
    alzette(code, x1, y1, RC_1, t);
    code.stz(x0, X0_OFFSET);
    code.stz(y0, Y0_OFFSET);
    code.stz(x1, X1_OFFSET);
    code.stz(y1, Y1_OFFSET);
    code.move(tx, x0);      // precompute tx = x0 ^ x1 for later
    code.logxor(tx, x1);
    code.move(ty, y0);      // precompute ty = y0 ^ y1 for later
    code.logxor(ty, y1);
    code.ldz(x2, X2_OFFSET);
    code.ldz(y2, Y2_OFFSET);
    code.ldz(x3, X3_OFFSET);
    code.ldz(y3, Y3_OFFSET);
    alzette(code, x2, y2, RC_2, t);
    alzette(code, x3, y3, RC_3, t);

    // Linear layer: x2, y2, x3, y3, tx, ty are already in registers.
    // tx = x0 ^ x1;  (already done)
    // ty = y0 ^ y1;  (already done)
    // tx = leftRotate16(tx ^ (tx << 16));
    // ty = leftRotate16(ty ^ (ty << 16));
    Reg tx_top = Reg(tx, 2, 2);
    Reg tx_bot = Reg(tx, 0, 2);
    code.logxor(tx_top, tx_bot);
    tx = Reg(tx, 2, 4); // leftRotate16 tx by rearranging the registers
    Reg ty_top = Reg(ty, 2, 2);
    Reg ty_bot = Reg(ty, 0, 2);
    code.logxor(ty_top, ty_bot);
    ty = Reg(ty, 2, 4); // leftRotate16 ty by rearranging the registers
    // y2 ^= tx;
    code.logxor(y2, tx);
    // tx ^= y3;
    code.logxor(tx, y3);
    // y3 = y1;
    code.ldz(y3, Y1_OFFSET);
    code.stz(y3, Y3_OFFSET);
    // y2 = y2 ^ y0;
    code.ldz(t, Y0_OFFSET);     // t = y0
    code.logxor(y2, t);
    // y2 = y0;
    code.stz(t, Y2_OFFSET);
    // t = y2
    code.move(t, y2);
    // y0 = tx ^ y3;
    code.move(y0, tx);
    code.logxor(y0, y3);
    // y1 = t
    code.move(y1, t);
    // x2 ^= ty;
    code.logxor(x2, ty);
    // ty ^= x3;
    code.logxor(ty, x3);
    // x3 = x1;
    code.ldz(x3, X1_OFFSET);
    code.stz(x3, X3_OFFSET);
    // tx = x2 ^ x0;
    code.ldz(t, X0_OFFSET);     // t = x0
    code.move(tx, x2);
    code.logxor(tx, t);
    // x2 = x0;
    code.stz(t, X2_OFFSET);
    // x0 = ty ^ x3;
    code.move(x0, ty);
    code.logxor(x0, x3);
    // x1 = tx
    code.move(x1, tx);

    // Return from the subroutine.
    code.ret();

    // Jump here once all 7 or 10 rounds have been completed.
    code.label(end_label);

    // x0, y0, x1, y1 are still in registers - store back to the state.
    code.stz(x0, X0_OFFSET);
    code.stz(y0, Y0_OFFSET);
    code.stz(x1, X1_OFFSET);
    code.stz(y1, Y1_OFFSET);
}

/**
 * \brief Generates the AVR code for the SPARKLE-384 permutation.
 *
 * \param code The code block to generate into.
 */
void gen_sparkle384_permutation(Code &code)
{
    unsigned step;

    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.  The step
    // parameter will be either 7 or 11 so we special case those values.
    Reg steps = code.prologue_permutation_with_count("sparkle_384", 0);

    // We don't need the Y register any more, so use it for extra temporaries.
    code.setFlag(Code::TempY);

    // Push the step counter on the stack.  We need the extra register.
    code.push(steps);
    code.releaseReg(steps);

    // Allocate some temporary registers for use later.
    Reg t = code.allocateHighReg(4);
    Reg x0 = code.allocateReg(4);
    Reg x1 = code.allocateReg(4);
    Reg y0 = code.allocateReg(4);
    Reg y1 = code.allocateReg(4);
    Reg tx = code.allocateReg(4);
    Reg ty = code.allocateReg(4);
    Reg x2 = x0; // Aliases for convenience.
    Reg x3 = x1;
    Reg y2 = y0;
    Reg y3 = y1;
    Reg x4 = x0;
    Reg x5 = x1;
    Reg y4 = y0;
    Reg y5 = y1;

    // Preload x0, y0, x1, y1 before the first round.  These values will
    // be left in registers between each round to reduce load/store overhead.
    code.ldz(x0, X0_OFFSET);
    code.ldz(y0, Y0_OFFSET);
    code.ldz(x1, X1_OFFSET);
    code.ldz(y1, Y1_OFFSET);

    // Perform all permutation steps.  We unroll the outer part of the
    // loop to deal with the round constants, with the ARXbox and linear
    // layers in a local subroutine to save program space.
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (step = 0; step < 11; ++step) {
        code.move(t, sparkle_rc[step]);
        code.logxor(y0, t);
        Reg smallt = Reg(t, 0, 1);
        if (step != 0) {
            code.move(smallt, step);
            code.logxor(y1, smallt);
        }
        code.call(subroutine);
        if (step == 6) {
            // May need an early bail-out after 7 rounds.
            // The "steps" value is on the top of the stack.
            code.pop(smallt);
            code.compare(smallt, 7);
            code.breq(end_label);
        }
    }
    code.jmp(end_label);

    // Output the subroutine for the ARXbox and linear layers.
    // On entry, x0, y0, x1, y1 are already in registers.
    code.label(subroutine);

    // ARXbox layer:
    //      alzette(x0, y0, RC_0);
    //      alzette(x1, y1, RC_1);
    //      alzette(x2, y2, RC_2);
    //      alzette(x3, y3, RC_3);
    //      alzette(x4, y4, RC_4);
    //      alzette(x5, y5, RC_5);
    alzette(code, x0, y0, RC_0, t);
    alzette(code, x1, y1, RC_1, t);
    code.stz(x0, X0_OFFSET);
    code.stz(y0, Y0_OFFSET);
    code.stz(x1, X1_OFFSET);
    code.stz(y1, Y1_OFFSET);
    code.move(tx, x0);      // precompute tx = x0 ^ x1 for later
    code.logxor(tx, x1);
    code.move(ty, y0);      // precompute ty = y0 ^ y1 for later
    code.logxor(ty, y1);
    code.ldz(x2, X2_OFFSET);
    code.ldz(y2, Y2_OFFSET);
    code.ldz(x3, X3_OFFSET);
    code.ldz(y3, Y3_OFFSET);
    alzette(code, x2, y2, RC_2, t);
    alzette(code, x3, y3, RC_3, t);
    code.stz(x2, X2_OFFSET);
    code.stz(y2, Y2_OFFSET);
    code.stz(x3, X3_OFFSET);
    code.stz(y3, Y3_OFFSET);
    code.logxor(tx, x2);    // tx ^= x2
    code.logxor(ty, y2);    // ty ^= y2
    code.ldz(x4, X4_OFFSET);
    code.ldz(y4, Y4_OFFSET);
    code.ldz(x5, X5_OFFSET);
    code.ldz(y5, Y5_OFFSET);
    alzette(code, x4, y4, RC_4, t);
    alzette(code, x5, y5, RC_5, t);

    // Linear layer: x4, y4, x5, y5, tx, ty are already in registers.
    // tx = x0 ^ x1 ^ x2;  (already done)
    // ty = y0 ^ y1 ^ y2;  (already done)
    // tx = leftRotate16(tx ^ (tx << 16));
    // ty = leftRotate16(ty ^ (ty << 16));
    Reg tx_top = Reg(tx, 2, 2);
    Reg tx_bot = Reg(tx, 0, 2);
    code.logxor(tx_top, tx_bot);
    tx = Reg(tx, 2, 4); // leftRotate16 tx by rearranging the registers
    Reg ty_top = Reg(ty, 2, 2);
    Reg ty_bot = Reg(ty, 0, 2);
    code.logxor(ty_top, ty_bot);
    ty = Reg(ty, 2, 4); // leftRotate16 ty by rearranging the registers
    // y3 ^= tx;
    code.ldz(t, Y3_OFFSET);
    code.logxor(t, tx);
    // y4 ^= tx;
    code.logxor(y4, tx);
    // tx ^= y5;
    code.logxor(tx, y5);
    // y5 = y2;
    code.ldz(y5, Y2_OFFSET);
    code.stz(y5, Y5_OFFSET);
    // y2 = y3 ^ y0;
    code.ldz_xor(t, Y0_OFFSET);
    code.stz(t, Y2_OFFSET);
    // y3 = y0;
    code.ldz(t, Y0_OFFSET);
    code.stz(t, Y3_OFFSET);
    // y0 = y4 ^ y1;
    code.ldz(t, Y1_OFFSET);
    code.logxor(y4, t);             // y0 and y4 are aliased
    // y4 = y1;
    code.stz(t, Y4_OFFSET);
    // y1 = tx ^ y5;
    code.logxor(y5, tx);            // y1 and y5 are aliased
    // x3 ^= ty;
    code.ldz(t, X3_OFFSET);
    code.logxor(t, ty);
    // x4 ^= ty;
    code.logxor(x4, ty);
    // ty ^= x5;
    code.logxor(ty, x5);
    // x5 = x2;
    code.ldz(x5, X2_OFFSET);
    code.stz(x5, X5_OFFSET);
    // x2 = x3 ^ x0;
    code.ldz(tx, X0_OFFSET);
    code.logxor(t, tx);
    code.stz(t, X2_OFFSET);
    // x3 = x0;
    code.stz(tx, X3_OFFSET);
    // x0 = x4 ^ x1;
    code.ldz(t, X1_OFFSET);
    code.logxor(x4, t);             // x0 and x4 are aliased
    // x4 = x1;
    code.stz(t, X4_OFFSET);
    // x1 = ty ^ x5;
    code.logxor(x5, ty);            // x1 and x5 are aliased

    // Return from the subroutine.
    code.ret();

    // Jump here once all 7 or 11 rounds have been completed.
    code.label(end_label);

    // x0, y0, x1, y1 are still in registers - store back to the state.
    code.stz(x0, X0_OFFSET);
    code.stz(y0, Y0_OFFSET);
    code.stz(x1, X1_OFFSET);
    code.stz(y1, Y1_OFFSET);
}

/**
 * \brief Generates the AVR code for the SPARKLE-512 permutation.
 *
 * \param code The code block to generate into.
 */
void gen_sparkle512_permutation(Code &code)
{
    unsigned step;

    // Set up the function prologue with 0 bytes of local variable storage.
    // Z points to the permutation state on input and output.  The step
    // parameter will be either 8 or 12 so we special case those values.
    Reg steps = code.prologue_permutation_with_count("sparkle_512", 0);

    // We don't need the Y register any more, so use it for extra temporaries.
    code.setFlag(Code::TempY);

    // Push the step counter on the stack.  We need the extra register.
    code.push(steps);
    code.releaseReg(steps);

    // Allocate some temporary registers for use later.
    Reg t = code.allocateHighReg(4);
    Reg x0 = code.allocateReg(4);
    Reg x1 = code.allocateReg(4);
    Reg y0 = code.allocateReg(4);
    Reg y1 = code.allocateReg(4);
    Reg tx = code.allocateReg(4);
    Reg ty = code.allocateReg(4);
    Reg x2 = x0; // Aliases for convenience.
    Reg x3 = x1;
    Reg y2 = y0;
    Reg y3 = y1;
    Reg x4 = x0;
    Reg x5 = x1;
    Reg y4 = y0;
    Reg y5 = y1;
    Reg x6 = x0;
    Reg x7 = x1;
    Reg y6 = y0;
    Reg y7 = y1;

    // Preload x0, y0, x1, y1 before the first round.  These values will
    // be left in registers between each round to reduce load/store overhead.
    code.ldz(x0, X0_OFFSET);
    code.ldz(y0, Y0_OFFSET);
    code.ldz(x1, X1_OFFSET);
    code.ldz(y1, Y1_OFFSET);

    // Perform all permutation steps.  We unroll the outer part of the
    // loop to deal with the round constants, with the ARXbox and linear
    // layers in a local subroutine to save program space.
    unsigned char subroutine = 0;
    unsigned char end_label = 0;
    for (step = 0; step < 12; ++step) {
        code.move(t, sparkle_rc[step]);
        code.logxor(y0, t);
        Reg smallt = Reg(t, 0, 1);
        if (step != 0) {
            code.move(smallt, step);
            code.logxor(y1, smallt);
        }
        code.call(subroutine);
        if (step == 7) {
            // May need an early bail-out after 8 rounds.
            // The "steps" value is on the top of the stack.
            code.pop(smallt);
            code.compare(smallt, 8);
            code.breq(end_label);
        }
    }
    code.jmp(end_label);

    // Output the subroutine for the ARXbox and linear layers.
    // On entry, x0, y0, x1, y1 are already in registers.
    code.label(subroutine);

    // ARXbox layer:
    //      alzette(x0, y0, RC_0);
    //      alzette(x1, y1, RC_1);
    //      alzette(x2, y2, RC_2);
    //      alzette(x3, y3, RC_3);
    //      alzette(x4, y4, RC_4);
    //      alzette(x5, y5, RC_5);
    //      alzette(x6, y6, RC_6);
    //      alzette(x7, y7, RC_7);
    alzette(code, x0, y0, RC_0, t);
    alzette(code, x1, y1, RC_1, t);
    code.stz(x0, X0_OFFSET);
    code.stz(y0, Y0_OFFSET);
    code.stz(x1, X1_OFFSET);
    code.stz(y1, Y1_OFFSET);
    code.move(tx, x0);      // precompute tx = x0 ^ x1 for later
    code.logxor(tx, x1);
    code.move(ty, y0);      // precompute ty = y0 ^ y1 for later
    code.logxor(ty, y1);
    code.ldz(x2, X2_OFFSET);
    code.ldz(y2, Y2_OFFSET);
    code.ldz(x3, X3_OFFSET);
    code.ldz(y3, Y3_OFFSET);
    alzette(code, x2, y2, RC_2, t);
    alzette(code, x3, y3, RC_3, t);
    code.stz(x2, X2_OFFSET);
    code.stz(y2, Y2_OFFSET);
    code.stz(x3, X3_OFFSET);
    code.stz(y3, Y3_OFFSET);
    code.logxor(tx, x2);    // tx ^= x2 ^ x3
    code.logxor(tx, x3);
    code.logxor(ty, y2);    // ty ^= y2 ^ y3
    code.logxor(ty, y3);
    code.ldz(x4, X4_OFFSET);
    code.ldz(y4, Y4_OFFSET);
    code.ldz(x5, X5_OFFSET);
    code.ldz(y5, Y5_OFFSET);
    alzette(code, x4, y4, RC_4, t);
    alzette(code, x5, y5, RC_5, t);
    code.stz(x4, X4_OFFSET);
    code.stz(y4, Y4_OFFSET);
    code.stz(x5, X5_OFFSET);
    code.stz(y5, Y5_OFFSET);
    code.ldz(x6, X6_OFFSET);
    code.ldz(y6, Y6_OFFSET);
    code.ldz(x7, X7_OFFSET);
    code.ldz(y7, Y7_OFFSET);
    alzette(code, x6, y6, RC_6, t);
    alzette(code, x7, y7, RC_7, t);

    // Linear layer: x6, y6, x7, y7, tx, ty are already in registers.
    // tx = x0 ^ x1 ^ x2 ^ x3;  (already done)
    // ty = y0 ^ y1 ^ y2 ^ y3;  (already done)
    // tx = leftRotate16(tx ^ (tx << 16));
    // ty = leftRotate16(ty ^ (ty << 16));
    Reg tx_top = Reg(tx, 2, 2);
    Reg tx_bot = Reg(tx, 0, 2);
    code.logxor(tx_top, tx_bot);
    tx = Reg(tx, 2, 4); // leftRotate16 tx by rearranging the registers
    Reg ty_top = Reg(ty, 2, 2);
    Reg ty_bot = Reg(ty, 0, 2);
    code.logxor(ty_top, ty_bot);
    ty = Reg(ty, 2, 4); // leftRotate16 ty by rearranging the registers
    // y6 ^= tx;
    code.logxor(y6, tx);
    code.stz(y6, Y6_OFFSET);
    // y4 ^= tx;
    code.ldz(y4, Y4_OFFSET);
    code.logxor(y4, tx);
    // y5 ^= tx;
    code.ldz(t, Y5_OFFSET);
    code.logxor(t, tx);
    // tx ^= y7;
    code.logxor(tx, y7);
    // y7 = y3;
    code.ldz(y3, Y3_OFFSET);
    code.stz(y3, Y7_OFFSET);
    // y3 = y4 ^ y0;
    code.ldz(y3, Y0_OFFSET);
    code.logxor(y4, y3);
    code.stz(y4, Y3_OFFSET);
    // y4 = y0;
    code.stz(y3, Y4_OFFSET);
    // y0 = y5 ^ y1;
    code.ldz(y1, Y1_OFFSET);
    code.logxor(t, y1);
    // y5 = y1;
    code.stz(y1, Y5_OFFSET);
    // y1 = y6 ^ y2;
    code.ldz(y1, Y6_OFFSET);
    code.ldz(y2, Y2_OFFSET);
    code.logxor(y1, y2);
    // y6 = y2;
    code.stz(y2, Y6_OFFSET);
    // y2 = tx ^ y7;
    code.ldz_xor(tx, Y7_OFFSET);
    code.stz(tx, Y2_OFFSET);
    code.move(y0, t);
    // x6 ^= ty;
    code.logxor(x6, ty);
    code.stz(x6, X6_OFFSET);
    // x4 ^= ty;
    code.ldz(x4, X4_OFFSET);
    code.logxor(x4, ty);
    // x5 ^= ty;
    code.ldz(t, X5_OFFSET);
    code.logxor(t, ty);
    // ty ^= x7;
    code.logxor(ty, x7);
    // x7 = x3;
    code.ldz(tx, X3_OFFSET);
    code.stz(tx, X7_OFFSET);
    // x3 = x4 ^ x0;
    code.ldz(tx, X0_OFFSET);
    code.logxor(x4, tx);
    code.stz(x4, X3_OFFSET);
    // x4 = x0;
    code.stz(tx, X4_OFFSET);
    // x0 = x5 ^ x1;
    code.ldz(tx, X1_OFFSET);
    code.logxor(t, tx);
    code.move(x0, t);
    // x5 = x1;
    code.stz(tx, X5_OFFSET);
    // x1 = x6 ^ x2;
    code.ldz(x1, X6_OFFSET);
    code.ldz(tx, X2_OFFSET);
    code.logxor(x1, tx);
    // x6 = x2;
    code.stz(tx, X6_OFFSET);
    // x2 = ty ^ x7;
    code.ldz_xor(ty, X7_OFFSET);
    code.stz(ty, X2_OFFSET);

    // Return from the subroutine.
    code.ret();

    // Jump here once all 8 or 12 rounds have been completed.
    code.label(end_label);

    // x0, y0, x1, y1 are still in registers - store back to the state.
    code.stz(x0, X0_OFFSET);
    code.stz(y0, Y0_OFFSET);
    code.stz(x1, X1_OFFSET);
    code.stz(y1, Y1_OFFSET);
}

bool test_sparkle256_permutation(Code &code)
{
    static unsigned char const input[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static unsigned char const output[32] = {
        0x4a, 0x1c, 0x59, 0xa2, 0x96, 0xfe, 0xae, 0xf7,
        0x52, 0x9f, 0x19, 0xec, 0x1e, 0x66, 0x34, 0x1b,
        0x4c, 0xa2, 0x0e, 0xc8, 0x70, 0xee, 0x03, 0x43,
        0x31, 0xef, 0x69, 0x57, 0x76, 0x72, 0x1e, 0x34
    };
    static unsigned char const output_7[32] = {
        0xa2, 0xdd, 0x2d, 0xb3, 0xc9, 0xfc, 0x34, 0xc2,
        0x0a, 0xfe, 0x0a, 0x77, 0xfc, 0xd4, 0x2c, 0x0b,
        0xf1, 0xf4, 0x47, 0xaa, 0xaf, 0x45, 0xb1, 0x74,
        0xa4, 0x96, 0x6f, 0x5f, 0xca, 0xcf, 0x1e, 0x8e
    };
    unsigned char state[32];
    int ok;
    memcpy(state, input, 32);
    code.exec_permutation(state, 32, 10);
    ok = !memcmp(output, state, 32);
    memcpy(state, input, 32);
    code.exec_permutation(state, 32, 7);
    return ok && !memcmp(output_7, state, 32);
}

bool test_sparkle384_permutation(Code &code)
{
    static unsigned char const input[48] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
    };
    static unsigned char const output[48] = {
        0xc3, 0xb3, 0x56, 0xd6, 0x38, 0x37, 0x68, 0x21,
        0xdb, 0xc1, 0x03, 0x67, 0x82, 0xea, 0x95, 0xa3,
        0xf0, 0xfd, 0xd1, 0x0d, 0x08, 0x4f, 0xa0, 0x93,
        0xa9, 0x7d, 0xc5, 0xd9, 0x4e, 0x97, 0xa6, 0xe7,
        0xf3, 0x4d, 0xb2, 0x24, 0x9f, 0x96, 0x28, 0x59,
        0xd2, 0x42, 0xeb, 0x07, 0x51, 0xc0, 0xd2, 0xbd
    };
    static unsigned char const output_7[48] = {
        0xbb, 0xbe, 0x68, 0xfd, 0x44, 0x98, 0xe7, 0xf1,
        0xce, 0x2d, 0x59, 0x52, 0x46, 0xb3, 0x92, 0x12,
        0x3c, 0xd7, 0xfb, 0x4f, 0x29, 0x6b, 0xe4, 0x15,
        0x3a, 0x73, 0xfe, 0x69, 0xc6, 0x53, 0x7f, 0x26,
        0x03, 0x09, 0x5a, 0x32, 0xed, 0x63, 0x5c, 0x2d,
        0x58, 0xbd, 0xa4, 0xf6, 0xa1, 0x23, 0x82, 0x04
    };
    unsigned char state[48];
    int ok;
    memcpy(state, input, 48);
    code.exec_permutation(state, 48, 11);
    ok = !memcmp(output, state, 48);
    memcpy(state, input, 48);
    code.exec_permutation(state, 48, 7);
    return ok && !memcmp(output_7, state, 48);
}

bool test_sparkle512_permutation(Code &code)
{
    static unsigned char const input[64] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f
    };
    static unsigned char const output[64] = {
        0x97, 0xa3, 0xeb, 0xa4, 0x69, 0xbc, 0x01, 0x8f,
        0x68, 0xe5, 0xc0, 0x4b, 0x3a, 0x55, 0xe0, 0x3a,
        0x8f, 0x23, 0xfb, 0x39, 0x0f, 0xdb, 0x11, 0x50,
        0xb3, 0x95, 0xd7, 0x95, 0xfa, 0x8c, 0xea, 0x17,
        0x8d, 0x12, 0xc7, 0x22, 0x91, 0x18, 0x14, 0xbe,
        0xf7, 0x8d, 0xe3, 0xf0, 0xcc, 0x65, 0xed, 0xd4,
        0x54, 0xad, 0x58, 0xf0, 0xa8, 0x73, 0x8f, 0x00,
        0x46, 0xf1, 0xcc, 0xbd, 0xfb, 0x8d, 0x09, 0xf1
    };
    static unsigned char const output_8[64] = {
        0xb5, 0x57, 0x27, 0x6b, 0x66, 0x07, 0xc8, 0x59,
        0xf2, 0x68, 0x55, 0x1f, 0xb1, 0x54, 0xfd, 0x9c,
        0x08, 0x0d, 0x71, 0x72, 0x17, 0xda, 0x83, 0x69,
        0x0d, 0x82, 0xe5, 0x8f, 0xad, 0x1c, 0xc0, 0x22,
        0xc8, 0x2a, 0x85, 0x7c, 0x3b, 0x18, 0x4f, 0xd1,
        0xec, 0x38, 0xe3, 0x0b, 0x6d, 0xb1, 0x7b, 0x4f,
        0x04, 0xe7, 0xb2, 0xab, 0x37, 0x12, 0x9b, 0x27,
        0xa2, 0x85, 0xb9, 0x69, 0xbd, 0x80, 0xe9, 0x1e
    };
    unsigned char state[64];
    int ok;
    memcpy(state, input, 64);
    code.exec_permutation(state, 64, 12);
    ok = !memcmp(output, state, 64);
    memcpy(state, input, 64);
    code.exec_permutation(state, 64, 8);
    return ok && !memcmp(output_8, state, 64);
}
