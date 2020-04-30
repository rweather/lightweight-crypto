/*
 * Copyright (C) 2020 Southern Storm Software, Pty Ltd.
 *
 * Contributed by Sebatian Renner.
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

// The 6 round constants computed with 0x9e377900 ^ r
#define RC_24 0x9e377900 ^ 24 // Iteration 1
#define RC_20 0x9e377900 ^ 20 // Iteration 5
#define RC_16 0x9e377900 ^ 16 // Iteration 9
#define RC_12 0x9e377900 ^ 12 // Iteration 13
#define RC_8  0x9e377900 ^ 8  // Iteration 17
#define RC_4  0x9e377900 ^ 4  // Iteration 21

// Offsets for each word of the four columns
#define X0_OFFSET 0
#define Y0_OFFSET 16
#define Z0_OFFSET 32

#define X1_OFFSET 4
#define Y1_OFFSET 20
#define Z1_OFFSET 36

#define X2_OFFSET 8
#define Y2_OFFSET 24
#define Z2_OFFSET 40

#define X3_OFFSET 12
#define Y3_OFFSET 28
#define Z3_OFFSET 44


void SPbox(Code &code, const Reg &x, const Reg &y, const Reg &z)
{

  Reg t1 = code.allocateReg(4);
  Reg t0 = code.allocateReg(4);
  
  // Rotate x and y left by shuffling the bytes
  Reg xrot = x.shuffle(1, 2, 3, 0); // xrot = x rotated left by 24
  Reg yrot = y.shuffle(3, 0, 1, 2); // yrot = y rotated left by 9
  code.rol(yrot, 1);

  // Compute x 
  code.move(t1, xrot);
  code.move(t0, z);
  code.lsl(t0, 1);
  code.move(x, yrot),
  code.logand(x, z);
  code.lsl(x, 2);
  code.logxor(x, t0);
  code.logxor(x, t1);

  // Compute y
  code.move(t0, yrot);
  code.move(y, t1);
  code.logor(y, z);
  code.lsl(y, 1);
  code.logxor(y, t1);
  code.logxor(y, t0);

  // Compute z
  code.logand(t1, t0);
  code.lsl(t1, 3);
  code.logxor(t1, t0);
  code.logxor(t1, z);

  // Swap x and z (the final value of z is in t1 from the previous step)
  code.move(z, x);
  code.move(x, t1); 

  code.releaseReg(t0);
  code.releaseReg(t1);

}

// Save Z on the stack to free up some extra temporary registers.
static void gimli24_save_z(Code &code)
{
  code.push(Reg::z_ptr());
  code.setFlag(Code::TempZ);
}

// Restore Z from the stack.
static void gimli24_restore_z(Code &code)
{
  code.clearFlag(Code::TempZ);
  code.pop(Reg::z_ptr());
}

void load_left_half(Code &code, 
                    Reg &x0, Reg &y0, Reg &z0, 
                    Reg &x1, Reg &y1, Reg &z1) {
  

  code.ldz(x0, X0_OFFSET);
  code.ldz(y0, Y0_OFFSET);
  code.ldz(z0, Z0_OFFSET);
  code.ldz(x1, X1_OFFSET);
  code.ldz(y1, Y1_OFFSET);
  code.ldz(z1, Z1_OFFSET);
  
}

void store_left_half(Code &code, 
                    Reg &x0, Reg &y0, Reg &z0, 
                    Reg &x1, Reg &y1, Reg &z1) {
  
  code.stz(x0, X0_OFFSET);
  code.stz(y0, Y0_OFFSET);
  code.stz(z0, Z0_OFFSET);
  code.stz(x1, X1_OFFSET);
  code.stz(y1, Y1_OFFSET);
  code.stz(z1, Z1_OFFSET);

}

void load_right_half(Code &code, 
                    Reg &x0, Reg &y0, Reg &z0, 
                    Reg &x1, Reg &y1, Reg &z1) {
  
  
  code.ldz(x0, X2_OFFSET);
  code.ldz(y0, Y2_OFFSET);
  code.ldz(z0, Z2_OFFSET);
  code.ldz(x1, X3_OFFSET);
  code.ldz(y1, Y3_OFFSET);
  code.ldz(z1, Z3_OFFSET);

}

void store_right_half(Code &code, 
                    Reg &x0, Reg &y0, Reg &z0, 
                    Reg &x1, Reg &y1, Reg &z1) {

  code.stz(x0, X2_OFFSET);
  code.stz(y0, Y2_OFFSET);
  code.stz(z0, Z2_OFFSET);
  code.stz(x1, X3_OFFSET);
  code.stz(y1, Y3_OFFSET);
  code.stz(z1, Z3_OFFSET);

}

void small_swap(Code &code, Reg &x0, Reg &x1) {
  // We can swap the registers without any instructions being generated.
  (void)code;
  Reg t0 = x0;
  x0 = x1;
  x1 = t0;
}

void gen_gimli24_permutation(Code &code) {
    
  code.setFlag(Code::Print);
  
  // Init permuation with no local variables
  code.prologue_permutation("gimli24_permute", 0);
  
  code.setFlag(Code::TempY);
  code.setFlag(Code::TempR0);
  code.setFlag(Code::TempR1);
  
  // Allocate registers for half state
  Reg x0 = code.allocateReg(4);
  Reg y0 = code.allocateReg(4);
  Reg z0 = code.allocateReg(4);
  Reg x1 = code.allocateReg(4);
  Reg y1 = code.allocateReg(4);
  Reg z1 = code.allocateReg(4);

  // Load left half state
  load_left_half(code, x0, y0, z0, x1, y1, z1);

  /* Implement AVR effient permuation according to 
   p. 38 of GIMLI documentation */
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x1, y1, z1);

  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);

  // XOR round constant for first iteration 
  code.logxor(x0, RC_24);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Store left half state
  store_left_half(code, x0, y0, z0, x1, y1, z1);

  // Load right half state
  load_right_half(code, x0, y0, z0, x1, y1, z1);

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x1, y1, z1);

  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Push x0 and x1 to stack
  code.push(x0);
  code.push(x1);
  
  // Load x0 and x1 from first two columns
  code.ldz(x0, X0_OFFSET);
  code.ldz(x1, X1_OFFSET);
  
  // End of round 3, right half is active

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);

  // Store right half state
  store_right_half(code,x0, y0, z0, x1, y1, z1);

  // Load left half state
  load_left_half(code,x0, y0, z0, x1, y1, z1);

  // Pop x0 and x1 into left half (Big Swap)
  code.pop(x1);
  code.pop(x0);
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  // XOR round constant for 5th iteration 
  code.logxor(x0, RC_20);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Push x0 and x1 to stack
  code.push(x0);
  code.push(x1);
  
  // Load x0 and x1 from last two columns
  code.ldz(x0, X2_OFFSET);
  code.ldz(x1, X3_OFFSET);

  // End of round 7, left half is active 
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  // XOR round constant for 9th iteration 
  code.logxor(x0, RC_16);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Store left half state
  store_left_half(code,x0, y0, z0, x1, y1, z1);

  // Load right half state
  load_right_half(code,x0, y0, z0, x1, y1, z1);

  // Pop x0 and x1 into right half (Big Swap)
  code.pop(x1);
  code.pop(x0);

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);

  // Push x0 and x1 to stack
  code.push(x0);
  code.push(x1);

  // Load x0 and x1 from first two columns
  code.ldz(x0, X0_OFFSET);
  code.ldz(x1, X1_OFFSET);
  
  // End of round 11, right half is active
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);

  // Store right half state
  store_right_half(code,x0, y0, z0, x1, y1, z1);

  // Load left half state
  load_left_half(code,x0, y0, z0, x1, y1, z1);

  // Pop x0 and x1 into left half (Big Swap)
  code.pop(x1);
  code.pop(x0);
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  // XOR round constant for 13th iteration 
  code.logxor(x0, RC_12);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Push x0 and x1 to stack
  code.push(x0);
  code.push(x1);
  
  // Load x0 and x1 from last two columns
  code.ldz(x0, X2_OFFSET);
  code.ldz(x1, X3_OFFSET);
  
  // End of round 15, left half is active 
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  // XOR round constant for 17th iteration 
  code.logxor(x0, RC_8);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Store left half state
  store_left_half(code,x0, y0, z0, x1, y1, z1);

  // Load right half state
  load_right_half(code,x0, y0, z0, x1, y1, z1);

  // Pop x0 and x1 into right half (Big Swap)
  code.pop(x1);
  code.pop(x0);

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);

  // Push x0 and x1 to stack
  code.push(x0);
  code.push(x1);

  // Load x0 and x1 from first two columns
  code.ldz(x0, X0_OFFSET);
  code.ldz(x1, X1_OFFSET);
  
  // End of round 19, right half is active

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);

  // Store right half state
  store_right_half(code,x0, y0, z0, x1, y1, z1);

  // Load left half state
  load_left_half(code,x0, y0, z0, x1, y1, z1);

  // Pop x0 and x1 into left half (Big Swap)
  code.pop(x1);
  code.pop(x0);

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);

  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);
  
  // Swap x0 and x1 "Small Swap"
  small_swap(code, x0, x1);
  
  // XOR round constant for 21st iteration 
  code.logxor(x0, RC_4);
  
  SPbox(code, x1, y1, z1);
  SPbox(code, x1, y1, z1);

  SPbox(code, x0, y0, z0);
  SPbox(code, x0, y0, z0);
  gimli24_restore_z(code);
  
  // Push x0 and x1 to stack
  code.push(x0);
  code.push(x1);
  
  // Load x0 and x1 from last two columns
  code.ldz(x0, X2_OFFSET);
  code.ldz(x1, X3_OFFSET);
  
  // End of round 23, left half is active 
  
  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x1, y1, z1);
  gimli24_restore_z(code);

  // Store left half state
  store_left_half(code,x0, y0, z0, x1, y1, z1);

  // Load right half state
  load_right_half(code,x0, y0, z0, x1, y1, z1);
  
  // Pop x0 and x1 into right half (Big Swap)
  code.pop(x1);
  code.pop(x0);

  gimli24_save_z(code);
  SPbox(code, x0, y0, z0);
  SPbox(code, x1, y1, z1);
  gimli24_restore_z(code);
  
  // Store right half state
  store_right_half(code,x0, y0, z0, x1, y1, z1);
}

bool test_gimli24_permutation(Code &code)
{
    static unsigned char const input[48] = {
        0x00, 0x00, 0x00, 0x00, 0xba, 0x79, 0x37, 0x9e,
        0x7a, 0xf3, 0x6e, 0x3c, 0x46, 0x6d, 0xa6, 0xda,
        0x24, 0xe7, 0xdd, 0x78, 0x1a, 0x61, 0x15, 0x17,
        0x2e, 0xdb, 0x4c, 0xb5, 0x66, 0x55, 0x84, 0x53,
        0xc8, 0xcf, 0xbb, 0xf1, 0x5a, 0x4a, 0xf3, 0x8f,
        0x22, 0xc5, 0x2a, 0x2e, 0x26, 0x40, 0x62, 0xcc
    };
    static unsigned char const output[48] = {
        0x5a, 0xc8, 0x11, 0xba, 0x19, 0xd1, 0xba, 0x91,
        0x80, 0xe8, 0x0c, 0x38, 0x68, 0x2c, 0x4c, 0xd2,
        0xea, 0xff, 0xce, 0x3e, 0x1c, 0x92, 0x7a, 0x27,
        0xbd, 0xa0, 0x73, 0x4f, 0xd8, 0x9c, 0x5a, 0xda,
        0xf0, 0x73, 0xb6, 0x84, 0xf7, 0x2f, 0xe5, 0x34,
        0x49, 0xef, 0x2b, 0x9e, 0xd6, 0xb8, 0x1b, 0xf4
    };

    unsigned char state[48];
    memcpy(state, input, 48);
    code.exec_permutation(state, 48);
    return !memcmp(output, state, 48);
}
