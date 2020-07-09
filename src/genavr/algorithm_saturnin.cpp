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

// Round constants for various combinations of rounds and domain_sep.
static uint32_t const saturnin_rc[] = {
    /* RC_10_1 */
    0x4eb026c2, 0x90595303, 0xaa8fe632, 0xfe928a92, 0x4115a419,
    0x93539532, 0x5db1cc4e, 0x541515ca, 0xbd1f55a8, 0x5a6e1a0d,
    /* RC_10_2 */
    0x4e4526b5, 0xa3565ff0, 0x0f8f20d8, 0x0b54bee1, 0x7d1a6c9d,
    0x17a6280a, 0xaa46c986, 0xc1199062, 0x182c5cde, 0xa00d53fe,
    /* RC_10_3 */
    0x4e162698, 0xb2535ba1, 0x6c8f9d65, 0x5816ad30, 0x691fd4fa,
    0x6bf5bcf9, 0xf8eb3525, 0xb21decfa, 0x7b3da417, 0xf62c94b4,
    /* RC_10_4 */
    0x4faf265b, 0xc5484616, 0x45dcad21, 0xe08bd607, 0x0504fdb8,
    0x1e1f5257, 0x45fbc216, 0xeb529b1f, 0x52194e32, 0x5498c018,
    /* RC_10_5 */
    0x4ffc2676, 0xd44d4247, 0x26dc109c, 0xb3c9c5d6, 0x110145df,
    0x624cc6a4, 0x17563eb5, 0x9856e787, 0x3108b6fb, 0x02b90752,
    /* RC_10_6 */
    0x4f092601, 0xe7424eb4, 0x83dcd676, 0x460ff1a5, 0x2d0e8d5b,
    0xe6b97b9c, 0xe0a13b7d, 0x0d5a622f, 0x943bbf8d, 0xf8da4ea1,
    /* Align on a 64-word / 256-byte boundary */
    0, 0, 0, 0,
    /* RC_16_7 */
    0x3fba180c, 0x563ab9ab, 0x125ea5ef, 0x859da26c, 0xb8cf779b,
    0x7d4de793, 0x07efb49f, 0x8d525306, 0x1e08e6ab, 0x41729f87,
    0x8c4aef0a, 0x4aa0c9a7, 0xd93a95ef, 0xbb00d2af, 0xb62c5bf0,
    0x386d94d8,
    /* RC_16_8 */
    0x3c9b19a7, 0xa9098694, 0x23f878da, 0xa7b647d3, 0x74fc9d78,
    0xeacaae11, 0x2f31a677, 0x4cc8c054, 0x2f51ca05, 0x5268f195,
    0x4f5b8a2b, 0xf614b4ac, 0xf1d95401, 0x764d2568, 0x6a493611,
    0x8eef9c3e
};

/**
 * \brief Gets the round constants for Saturnin.
 */
Sbox get_saturnin_round_constants()
{
    unsigned char table[sizeof(saturnin_rc)];
    for (unsigned index = 0;
            index < (sizeof(saturnin_rc) / sizeof(uint32_t)); ++index) {
        table[index * 4]     = (unsigned char)(saturnin_rc[index]);
        table[index * 4 + 1] = (unsigned char)(saturnin_rc[index] >> 8);
        table[index * 4 + 2] = (unsigned char)(saturnin_rc[index] >> 16);
        table[index * 4 + 3] = (unsigned char)(saturnin_rc[index] >> 24);
    }
    return Sbox(table, sizeof(table));
}

/**
 * \brief Generates the AVR code for the Saturnin key setup function.
 *
 * \param code The code block to generate into.
 */
void gen_saturnin_setup_key(Code &code)
{
    unsigned offset;

    // Set up the function prologue with 0 bytes of local variable storage.
    // X points to the key, and Z points to the key schedule.
    code.prologue_setup_key("saturnin_setup_key", 0);
    code.setFlag(Code::NoLocals);

    // Load the words of the key and rotate into their final form.
    // Each 32-bit word is stored in two 16-bit halves in the left
    // and right sides of the incoming key.  Redistribute the bytes.
    Reg temp = code.allocateReg(2);
    for (offset = 0; offset < 16; offset += 2) {
        code.ldx(temp, POST_INC);
        code.stz(temp, offset * 2);
        code.ror(temp, 5);
        code.stz(temp, offset * 2 + 32);
    }
    for (offset = 0; offset < 16; offset += 2) {
        code.ldx(temp, POST_INC);
        code.stz(temp, offset * 2 + 2);
        code.ror(temp, 5);
        code.stz(temp, offset * 2 + 34);
    }
}

/*
 * \brief Loads the left half of the state from local variables.
 *
 * \param code The code block to generate into.
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 */
static void saturnin_load_left
    (Code &code, const Reg &a, const Reg &b, const Reg &c, const Reg &d)
{
    code.ldlocal(a, 0);
    code.ldlocal(b, 4);
    code.ldlocal(c, 8);
    code.ldlocal(d, 12);
}

/*
 * \brief Stores the left half of the state to local variables.
 *
 * \param code The code block to generate into.
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 */
static void saturnin_store_left
    (Code &code, const Reg &a, const Reg &b, const Reg &c, const Reg &d)
{
    code.stlocal(a, 0);
    code.stlocal(b, 4);
    code.stlocal(c, 8);
    code.stlocal(d, 12);
}

/*
 * \brief Loads the right half of the state from local variables.
 *
 * \param code The code block to generate into.
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 */
static void saturnin_load_right
    (Code &code, const Reg &a, const Reg &b, const Reg &c, const Reg &d)
{
    code.ldlocal(a, 16);
    code.ldlocal(b, 20);
    code.ldlocal(c, 24);
    code.ldlocal(d, 28);
}

/*
 * \brief Stores the right half of the state to local variables.
 *
 * \param code The code block to generate into.
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 */
static void saturnin_store_right
    (Code &code, const Reg &a, const Reg &b, const Reg &c, const Reg &d)
{
    code.stlocal(a, 16);
    code.stlocal(b, 20);
    code.stlocal(c, 24);
    code.stlocal(d, 28);
}

/*
 * \brief Applies the Saturnin S-box to a bit-sliced set of nibbles.
 *
 * \param code The code block to generate into.
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 *
 * The S-box also involves a rotation on the output words.  We perform the
 * rotation implicitly in the higher layers.
 */
static void saturnin_sbox
    (Code &code, const Reg &a, const Reg &b, const Reg &c, const Reg &d)
{
    // a ^= b & c;
    code.logxor_and(a, b, c);

    // b ^= a | d;
    code.logxor_or(b, a, d);

    // d ^= b | c;
    code.logxor_or(d, b, c);

    // c ^= b & d;
    code.logxor_and(c, b, d);

    // b ^= a | c;
    code.logxor_or(b, a, c);

    // a ^= b | d;
    code.logxor_or(a, b, d);
}

/*
 * \brief Applies the inverse of the Saturnin S-box.
 *
 * \param code The code block to generate into.
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 *
 * The S-box also involves a rotation on the input words.  We perform the
 * rotation implicitly in the higher layers.
 */
static void saturnin_inv_sbox
    (Code &code, const Reg &a, const Reg &b, const Reg &c, const Reg &d)
{
    // a ^= b | d;
    code.logxor_or(a, b, d);

    // b ^= a | c;
    code.logxor_or(b, a, c);

    // c ^= b & d;
    code.logxor_and(c, b, d);

    // d ^= b | c;
    code.logxor_or(d, b, c);

    // b ^= a | d;
    code.logxor_or(b, a, d);

    // a ^= b & c;
    code.logxor_and(a, b, c);
}

/**
 * \brief Applies the MDS matrix to the Saturnin state.
 *
 * \param code The code block to generate into.
 * \param x Array of registers to access the bit-sliced state.
 * \param i0 Index of the first word of the bit-sliced state.
 * \param i1 Index of the second word of the bit-sliced state.
 * \param i2 Index of the third word of the bit-sliced state.
 * \param i3 Index of the fourth word of the bit-sliced state.
 * \param i4 Index of the fifth word of the bit-sliced state.
 * \param i5 Index of the sixth word of the bit-sliced state.
 * \param i6 Index of the seventh word of the bit-sliced state.
 * \param i7 Index of the eighth word of the bit-sliced state.
 * \param t0 Temporary 32-bit register.
 *
 * On entry and exit, the right half of the state is loaded
 * into registers.
 */
static void saturnin_mds
    (Code &code, Reg *x, int i0, int i1, int i2, int i3,
     int i4, int i5, int i6, int i7, const Reg &t0)
{
    // x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    code.ldlocal_xor_in(x[i4], i0 * 4);
    code.ldlocal_xor_in(x[i5], i1 * 4);
    code.ldlocal_xor_in(x[i6], i2 * 4);
    code.ldlocal_xor_in(x[i7], i3 * 4);

    // MUL(x4, x5, x6, x7);
    code.move(t0, x[i4]);
    code.move(x[i4], x[i5]);
    code.move(x[i5], x[i6]);
    code.move(x[i6], x[i7]);
    code.move(x[i7], t0);
    code.logxor(x[i7], x[i4]);

    // x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    // x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    code.ldlocal(t0, i0 * 4);
    code.logxor(x[i4], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i1 * 4);
    code.logxor(x[i5], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i2 * 4);
    code.logxor(x[i6], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i3 * 4);
    code.logxor(x[i7], t0.shuffle(2, 3, 0, 1));

    // MUL(x0, x1, x2, x3);
    // MUL(x0, x1, x2, x3);
    // x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    //
    // As we are currently short on registers, do this in multiple
    // passes 16 bits at a time.  The third line above is interleaved
    // with the multiplications to reduce the load/store overhead.
    Reg t = Reg(t0, 0, 2);
    Reg u = Reg(t0, 2, 2);
    for (int round = 0; round < 2; ++round) {
        for (int offset = 0; offset < 4; offset += 2) {
            code.ldlocal(t, i0 * 4 + offset);
            code.ldlocal(u, i1 * 4 + offset);
            code.logxor(t, u);
            if (round != 0)
                code.logxor(u, Reg(x[i4], offset, 2));
            code.stlocal(u, i0 * 4 + offset);
            code.ldlocal(u, i2 * 4 + offset);
            if (round != 0)
                code.logxor(u, Reg(x[i5], offset, 2));
            code.stlocal(u, i1 * 4 + offset);
            code.ldlocal(u, i3 * 4 + offset);
            if (round != 0)
                code.logxor(u, Reg(x[i6], offset, 2));
            code.stlocal(u, i2 * 4 + offset);
            if (round != 0)
                code.logxor(t, Reg(x[i7], offset, 2));
            code.stlocal(t, i3 * 4 + offset);
        }
    }

    // x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    // x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    code.ldlocal(t0, i0 * 4);
    code.logxor(x[i4], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i1 * 4);
    code.logxor(x[i5], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i2 * 4);
    code.logxor(x[i6], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i3 * 4);
    code.logxor(x[i7], t0.shuffle(2, 3, 0, 1));
}

/**
 * \brief Applies the inverse of the MDS matrix to the Saturnin state.
 *
 * \param code The code block to generate into.
 * \param x Array of registers to access the bit-sliced state.
 * \param i0 Index of the first word of the bit-sliced state.
 * \param i1 Index of the second word of the bit-sliced state.
 * \param i2 Index of the third word of the bit-sliced state.
 * \param i3 Index of the fourth word of the bit-sliced state.
 * \param i4 Index of the fifth word of the bit-sliced state.
 * \param i5 Index of the sixth word of the bit-sliced state.
 * \param i6 Index of the seventh word of the bit-sliced state.
 * \param i7 Index of the eighth word of the bit-sliced state.
 * \param t0 Temporary 32-bit register.
 *
 * On entry and exit, the right half of the state is loaded
 * into registers.
 */
static void saturnin_inv_mds
    (Code &code, Reg *x, int i0, int i1, int i2, int i3,
     int i4, int i5, int i6, int i7, const Reg &t0)
{
    // x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    // x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    code.ldlocal(t0, i0 * 4);
    code.logxor(x[i4], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i1 * 4);
    code.logxor(x[i5], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i2 * 4);
    code.logxor(x[i6], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i3 * 4);
    code.logxor(x[i7], t0.shuffle(2, 3, 0, 1));

    // x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    // MULINV(x0, x1, x2, x3);
    // MULINV(x0, x1, x2, x3);
    //
    // As we are currently short on registers, do this in multiple
    // passes 16 bits at a time.  The first line above is interleaved
    // with the multiplications to reduce the load/store overhead.
    Reg t = Reg(t0, 0, 2);
    Reg u = Reg(t0, 2, 2);
    for (int round = 0; round < 2; ++round) {
        for (int offset = 0; offset < 4; offset += 2) {
            code.ldlocal(t, i3 * 4 + offset);
            if (round == 0)
                code.logxor(t, Reg(x[i7], offset, 2));
            code.ldlocal(u, i2 * 4 + offset);
            if (round == 0)
                code.logxor(u, Reg(x[i6], offset, 2));
            code.stlocal(u, i3 * 4 + offset);
            code.ldlocal(u, i1 * 4 + offset);
            if (round == 0)
                code.logxor(u, Reg(x[i5], offset, 2));
            code.stlocal(u, i2 * 4 + offset);
            code.ldlocal(u, i0 * 4 + offset);
            if (round == 0)
                code.logxor(u, Reg(x[i4], offset, 2));
            code.logxor(t, u);
            code.stlocal(u, i1 * 4 + offset);
            code.stlocal(t, i0 * 4 + offset);
        }
    }

    // x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    // x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    code.ldlocal(t0, i0 * 4);
    code.logxor(x[i4], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i1 * 4);
    code.logxor(x[i5], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i2 * 4);
    code.logxor(x[i6], t0.shuffle(2, 3, 0, 1));
    code.ldlocal(t0, i3 * 4);
    code.logxor(x[i7], t0.shuffle(2, 3, 0, 1));

    // MULINV(x4, x5, x6, x7);
    code.move(t0, x[i7]);
    code.move(x[i7], x[i6]);
    code.move(x[i6], x[i5]);
    code.move(x[i5], x[i4]);
    code.move(x[i4], t0);
    code.logxor(x[i4], x[i5]);

    // x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    code.ldlocal_xor_in(x[i4], i0 * 4);
    code.ldlocal_xor_in(x[i5], i1 * 4);
    code.ldlocal_xor_in(x[i6], i2 * 4);
    code.ldlocal_xor_in(x[i7], i3 * 4);
}

/**
 * \brief Applies the left-half slice permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 * \param t Temporary high register.
 */
static void saturnin_slice_left(Code &code, const Reg &x, const Reg &t)
{
    // leftRotate4_N(x, 0xFFFFU, 0, 0x3333, 2);
    code.move(Reg(t, 0, 2), Reg(x, 2, 2));
    code.lsr(Reg(t, 0, 2), 2);
    code.move(Reg(t, 2, 1), 0x33);
    code.logand(Reg(t, 0, 1), Reg(t, 2, 1));
    code.logand(Reg(t, 1, 1), Reg(t, 2, 1));
    code.logand(Reg(x, 2, 1), Reg(t, 2, 1));
    code.logand(Reg(x, 3, 1), Reg(t, 2, 1));
    code.lsl(Reg(x, 2, 2), 2);
    code.logor(Reg(x, 2, 2), Reg(t, 0, 2));
}

/**
 * \brief Applies the right-half slice permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 * \param t Temporary high register.
 */
static void saturnin_slice_right(Code &code, const Reg &x, const Reg &t)
{
    // leftRotate4_N(x, 0x7777U, 1, 0x1111, 3);
    code.move(Reg(t, 0, 2), Reg(x, 0, 2));
    code.lsr(Reg(t, 0, 2), 3);
    code.move(Reg(t, 2, 1), 0x11);
    code.logand(Reg(t, 0, 1), Reg(t, 2, 1));
    code.logand(Reg(t, 1, 1), Reg(t, 2, 1));
    code.move(Reg(t, 2, 1), 0x77);
    code.logand(Reg(x, 0, 1), Reg(t, 2, 1));
    code.logand(Reg(x, 1, 1), Reg(t, 2, 1));
    code.lsl(Reg(x, 0, 2), 1);
    code.logor(Reg(x, 0, 2), Reg(t, 0, 2));

    code.move(Reg(t, 0, 2), Reg(x, 2, 2));
    code.lsr(Reg(t, 0, 2), 1);
    code.logand(Reg(t, 0, 1), Reg(t, 2, 1));
    code.logand(Reg(t, 1, 1), Reg(t, 2, 1));
    code.move(Reg(t, 2, 1), 0x11);
    code.logand(Reg(x, 2, 1), Reg(t, 2, 1));
    code.logand(Reg(x, 3, 1), Reg(t, 2, 1));
    code.lsl(Reg(x, 2, 2), 3);
    code.logor(Reg(x, 2, 2), Reg(t, 0, 2));
}

/**
 * \brief Applies the inverse of the left-half slice permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 * \param t Temporary high register.
 */
static void saturnin_inv_slice_left(Code &code, const Reg &x, const Reg &t)
{
    // leftRotate4_N(x, 0xFFFFU, 0, 0x3333, 2);
    saturnin_slice_left(code, x, t);
}

/**
 * \brief Applies the inverse of the right-half slice permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 * \param t Temporary high register.
 */
static void saturnin_inv_slice_right(Code &code, const Reg &x, const Reg &t)
{
    // leftRotate4_N(x, 0x1111U, 3, 0x7777, 1);
    saturnin_slice_right(code, x.shuffle(2, 3, 0, 1), t);
}

/**
 * \brief Applies the left-half sheet permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 */
static void saturnin_sheet_left(Code &code, const Reg &x)
{
    // leftRotate16_N(x, 0xFFFFU, 0, 0x00FF, 8);
    code.rol(Reg(x, 2, 2), 8);
}

/**
 * \brief Applies the right-half sheet permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 */
static void saturnin_sheet_right(Code &code, const Reg &x)
{
    // leftRotate16_N(x, 0x0FFFU, 4, 0x000F, 12);
    code.rol(Reg(x, 0, 2), 4);
    code.rol(Reg(x, 2, 2), 12);
}

/**
 * \brief Applies the inverse of the left-half sheet permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 */
static void saturnin_inv_sheet_left(Code &code, const Reg &x)
{
    // leftRotate16_N(x, 0xFFFFU, 0, 0x00FF, 8);
    code.rol(Reg(x, 2, 2), 8);
}

/**
 * \brief Applies the inverse of the right-half sheet permutation to a word.
 *
 * \param code The code block to generate into.
 * \param x Word to apply the permutation to.
 */
static void saturnin_inv_sheet_right(Code &code, const Reg &x)
{
    // leftRotate16_N(x, 0x000FU, 12, 0x0FFF, 4);
    code.rol(Reg(x, 0, 2), 12);
    code.rol(Reg(x, 2, 2), 4);
}

/**
 * \brief Loads a round constant.
 *
 * \param code The code block to generate into.
 * \param rc Register to receive the 32-bit round constant.
 * \param domain Index into the round constant table.
 */
static void saturnin_load_rc(Code &code, const Reg &rc, const Reg &domain)
{
    for (int index = 0; index < rc.size(); ++index) {
        code.sbox_lookup(Reg(rc, index, 1), Reg(domain, 0, 1));
        code.inc(Reg(domain, 0, 1));
    }
}

/**
 * \brief Loads a round constant while moving backwards in the table.
 *
 * \param code The code block to generate into.
 * \param rc Register to receive the 32-bit round constant.
 * \param domain Index into the round constant table.
 */
static void saturnin_inv_load_rc(Code &code, const Reg &rc, const Reg &domain)
{
    for (int index = rc.size() - 1; index >= 0; --index) {
        code.dec(Reg(domain, 0, 1));
        code.sbox_lookup(Reg(rc, index, 1), Reg(domain, 0, 1));
    }
}

/**
 * \brief Generates the AVR code for the Saturnin block cipher.
 *
 * \param code The code block to generate into.
 */
void gen_saturnin_encrypt(Code &code)
{
    // Set up the function prologue with 32 bytes of local variable storage.
    // X will point to the input, and Z points to the key.
    code.prologue_encrypt_block("saturnin_encrypt_block", 32);
    Reg domain = code.arg(2);

    // Allocate the temporary variables we will need.
    Reg t0 = code.allocateHighReg(4);
    Reg x0 = code.allocateReg(4);
    Reg x1 = code.allocateReg(4);
    Reg x2 = code.allocateReg(4);
    Reg x3 = code.allocateReg(4);
    Reg x4 = x0; // Aliases
    Reg x5 = x1;
    Reg x6 = x2;
    Reg x7 = x3;
    Reg x[8] = {x0, x1, x2, x3, x4, x5, x6, x7};

    // Load the input block and XOR it with the key.  Leave the
    // left half of the state in x0, x1, x2, x3 at the end of this.
    // The right half x4, x5, x6, x7 is saved in local variables.
    code.ldx(Reg(x0, 0, 2), POST_INC);
    code.ldz_xor(Reg(x0, 0, 2), 0);
    code.ldx(Reg(x1, 0, 2), POST_INC);
    code.ldz_xor(Reg(x1, 0, 2), 4);
    code.ldx(Reg(x2, 0, 2), POST_INC);
    code.ldz_xor(Reg(x2, 0, 2), 8);
    code.ldx(Reg(x3, 0, 2), POST_INC);
    code.ldz_xor(Reg(x3, 0, 2), 12);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 16);
    code.stlocal(Reg(t0, 0, 2), 16);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 20);
    code.stlocal(Reg(t0, 0, 2), 20);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 24);
    code.stlocal(Reg(t0, 0, 2), 24);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 28);
    code.stlocal(Reg(t0, 0, 2), 28);
    code.ldx(Reg(x0, 2, 2), POST_INC);
    code.ldz_xor(Reg(x0, 2, 2), 2);
    code.ldx(Reg(x1, 2, 2), POST_INC);
    code.ldz_xor(Reg(x1, 2, 2), 6);
    code.ldx(Reg(x2, 2, 2), POST_INC);
    code.ldz_xor(Reg(x2, 2, 2), 10);
    code.ldx(Reg(x3, 2, 2), POST_INC);
    code.ldz_xor(Reg(x3, 2, 2), 14);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 18);
    code.stlocal(Reg(t0, 0, 2), 18);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 22);
    code.stlocal(Reg(t0, 0, 2), 22);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 26);
    code.stlocal(Reg(t0, 0, 2), 26);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.ldz_xor(Reg(t0, 0, 2), 30);
    code.stlocal(Reg(t0, 0, 2), 30);

    // Find the starting point in the round constant table
    // and the number of double rounds to be performed.
    unsigned char temp_label = 0;
    Reg rounds = code.allocateHighReg(1);
    code.move(rounds, 5);
    code.compare(domain, 60);
    code.brcs(temp_label);
    code.move(rounds, 8);
    code.add(domain, 4); // Align on a 64-word / 256-byte boundary.
    code.label(temp_label);
    code.lsl(domain, 2);

    // Saturnin is very large which causes problems with "rjmp" which
    // can only jump up to 2K words forwards or backwards in memory.
    // To address this, we put the even and odd round code in subroutines
    // with the main loop in the middle.  This keeps all jumps below 2K.
    unsigned char top_label = 0;
    unsigned char even_label = 0;
    unsigned char odd_label = 0;
    unsigned char end_label = 0;
    code.jmp(top_label);

    // Even rounds.
    code.label(even_label);
    saturnin_sbox(code, x0, x1, x2, x3);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    saturnin_sbox(code, x4, x5, x6, x7);
    saturnin_mds(code, x, 1, 2, 3, 0, 7, 5, 4, 6, t0);
    saturnin_sbox(code, x7, x5, x4, x6);
    saturnin_slice_right(code, x7, t0);
    saturnin_slice_right(code, x5, t0);
    saturnin_slice_right(code, x4, t0);
    saturnin_slice_right(code, x6, t0);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_sbox(code, x1, x2, x3, x0);
    saturnin_slice_left(code, x1, t0);
    saturnin_slice_left(code, x2, t0);
    saturnin_slice_left(code, x3, t0);
    saturnin_slice_left(code, x0, t0);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    saturnin_mds(code, x, 2, 3, 0, 1, 6, 5, 7, 4, t0);
    saturnin_inv_slice_right(code, x6, t0);
    saturnin_inv_slice_right(code, x5, t0);
    saturnin_inv_slice_right(code, x7, t0);
    saturnin_inv_slice_right(code, x4, t0);
    code.ldz_xor(x6, 48); // saturnin_xor_key_rotated right half.
    code.ldz_xor(x5, 52);
    code.ldz_xor(x7, 56);
    code.ldz_xor(x4, 60);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_inv_slice_left(code, x2, t0);
    saturnin_inv_slice_left(code, x3, t0);
    saturnin_inv_slice_left(code, x0, t0);
    saturnin_inv_slice_left(code, x1, t0);
    code.ldz_xor(x2, 32); // saturnin_xor_key_rotated left half.
    code.ldz_xor(x3, 36);
    code.ldz_xor(x0, 40);
    code.ldz_xor(x1, 44);
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_saturnin_round_constants());
    code.sbox_adjust(Reg(domain, 1, 1));
    saturnin_load_rc(code, t0, domain);
    code.logxor(x2, t0); // x2 ^= rc[0];
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.ret();

    // Main round loop in the middle between the even and odd subroutines.
    code.label(top_label);
    code.call(even_label);
    code.call(odd_label);
    code.dec(rounds);
    code.brne(top_label);
    code.jmp(end_label);

    // Odd rounds.
    code.label(odd_label);
    saturnin_sbox(code, x2, x3, x0, x1);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    saturnin_sbox(code, x6, x5, x7, x4);
    saturnin_mds(code, x, 3, 0, 1, 2, 4, 5, 6, 7, t0);
    saturnin_sbox(code, x4, x5, x6, x7);
    saturnin_sheet_right(code, x7);
    saturnin_sheet_right(code, x5);
    saturnin_sheet_right(code, x4);
    saturnin_sheet_right(code, x6);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_sbox(code, x3, x0, x1, x2);
    saturnin_sheet_left(code, x0);
    saturnin_sheet_left(code, x1);
    saturnin_sheet_left(code, x2);
    saturnin_sheet_left(code, x3);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    saturnin_mds(code, x, 0, 1, 2, 3, 7, 5, 4, 6, t0);
    saturnin_inv_sheet_right(code, x7);
    saturnin_inv_sheet_right(code, x5);
    saturnin_inv_sheet_right(code, x4);
    saturnin_inv_sheet_right(code, x6);
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_saturnin_round_constants());
    code.sbox_adjust(Reg(domain, 1, 1));
    saturnin_load_rc(code, t0, domain);
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.ldz_xor(x7, 16); // saturnin_xor_key right half.
    code.ldz_xor(x5, 20);
    code.ldz_xor(x4, 24);
    code.ldz_xor(x6, 28);
    saturnin_store_right(code, x7, x5, x4, x6); // Correct word rotation.
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_inv_sheet_left(code, x0);
    saturnin_inv_sheet_left(code, x1);
    saturnin_inv_sheet_left(code, x2);
    saturnin_inv_sheet_left(code, x3);
    code.ldz_xor(x0, 0); // saturnin_xor_key left half.
    code.ldz_xor(x1, 4);
    code.ldz_xor(x2, 8);
    code.ldz_xor(x3, 12);
    code.logxor(x0, t0); // x0 ^= rc[1];
    code.ret();

    // Store the state to the output buffer.  At this point,
    // the left half of the state is in x0, x1, x2, x3 and the
    // right half of the state is in local variables.
    code.label(end_label);
    code.load_output_ptr();
    code.stx(Reg(x0, 0, 2), POST_INC);
    code.stx(Reg(x1, 0, 2), POST_INC);
    code.stx(Reg(x2, 0, 2), POST_INC);
    code.stx(Reg(x3, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 16);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 20);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 24);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 28);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.stx(Reg(x0, 2, 2), POST_INC);
    code.stx(Reg(x1, 2, 2), POST_INC);
    code.stx(Reg(x2, 2, 2), POST_INC);
    code.stx(Reg(x3, 2, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 18);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 22);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 26);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 30);
    code.stx(Reg(t0, 0, 2), POST_INC);
}

/**
 * \brief Generates the AVR code for the Saturnin block cipher.
 *
 * \param code The code block to generate into.
 */
void gen_saturnin_decrypt(Code &code)
{
    // Set up the function prologue with 32 bytes of local variable storage.
    // X will point to the input, and Z points to the key.
    code.prologue_decrypt_block("saturnin_decrypt_block", 32);
    Reg domain = code.arg(2);

    // Allocate the temporary variables we will need.
    Reg t0 = code.allocateHighReg(4);
    Reg x0 = code.allocateReg(4);
    Reg x1 = code.allocateReg(4);
    Reg x2 = code.allocateReg(4);
    Reg x3 = code.allocateReg(4);
    Reg x4 = x0; // Aliases
    Reg x5 = x1;
    Reg x6 = x2;
    Reg x7 = x3;
    Reg x[8] = {x0, x1, x2, x3, x4, x5, x6, x7};

    // Load the input block.  Leave the left half of the state in
    // x0, x1, x2, x3 at the end of this.  The right half x4, x5,
    // x6, x7 is saved in local variables.
    code.ldx(Reg(x0, 0, 2), POST_INC);
    code.ldx(Reg(x1, 0, 2), POST_INC);
    code.ldx(Reg(x2, 0, 2), POST_INC);
    code.ldx(Reg(x3, 0, 2), POST_INC);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 16);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 20);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 24);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 28);
    code.ldx(Reg(x0, 2, 2), POST_INC);
    code.ldx(Reg(x1, 2, 2), POST_INC);
    code.ldx(Reg(x2, 2, 2), POST_INC);
    code.ldx(Reg(x3, 2, 2), POST_INC);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 18);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 22);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 26);
    code.ldx(Reg(t0, 0, 2), POST_INC);
    code.stlocal(Reg(t0, 0, 2), 30);

    // Find the starting point in the round constant table
    // and the number of rounds to be performed.
    unsigned char temp_label = 0;
    Reg rounds = code.allocateHighReg(1);
    code.move(rounds, 10);
    code.compare(domain, 60);
    code.brcs(temp_label);
    code.move(rounds, 16);
    code.add(domain, 4); // Align on a 64-word / 256-byte boundary.
    code.label(temp_label);
    code.add(domain, rounds);
    code.lsl(domain, 2);

    // Saturnin is very large which causes problems with "rjmp" which
    // can only jump up to 2K words forwards or backwards in memory.
    // To address this, we put the even and odd round code in subroutines
    // with the main loop in the middle.  This keeps all jumps below 2K.
    unsigned char top_label = 0;
    unsigned char even_label = 0;
    unsigned char odd_label = 0;
    unsigned char end_label = 0;
    code.jmp(top_label);

    // Odd rounds.
    code.label(odd_label);
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_saturnin_round_constants());
    code.sbox_adjust(Reg(domain, 1, 1));
    saturnin_inv_load_rc(code, t0, domain);
    code.logxor(x0, t0); // x0 ^= rc[1];
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    code.ldz_xor(x0, 0); // saturnin_xor_key left half.
    code.ldz_xor(x1, 4);
    code.ldz_xor(x2, 8);
    code.ldz_xor(x3, 12);
    saturnin_sheet_left(code, x0);
    saturnin_sheet_left(code, x1);
    saturnin_sheet_left(code, x2);
    saturnin_sheet_left(code, x3);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x7, x5, x4, x6); // Correct word rotation.
    code.ldz_xor(x7, 16); // saturnin_xor_key right half.
    code.ldz_xor(x5, 20);
    code.ldz_xor(x4, 24);
    code.ldz_xor(x6, 28);
    saturnin_sheet_right(code, x7);
    saturnin_sheet_right(code, x5);
    saturnin_sheet_right(code, x4);
    saturnin_sheet_right(code, x6);
    saturnin_inv_mds(code, x, 0, 1, 2, 3, 7, 5, 4, 6, t0);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_inv_sheet_left(code, x0);
    saturnin_inv_sheet_left(code, x1);
    saturnin_inv_sheet_left(code, x2);
    saturnin_inv_sheet_left(code, x3);
    saturnin_inv_sbox(code, x3, x0, x1, x2);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    saturnin_inv_sheet_right(code, x7);
    saturnin_inv_sheet_right(code, x5);
    saturnin_inv_sheet_right(code, x4);
    saturnin_inv_sheet_right(code, x6);
    saturnin_inv_sbox(code, x4, x5, x6, x7);
    saturnin_inv_mds(code, x, 3, 0, 1, 2, 4, 5, 6, 7, t0);
    saturnin_inv_sbox(code, x6, x5, x7, x4);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_inv_sbox(code, x2, x3, x0, x1);
    code.ret();

    // Main round loop in the middle between the even and odd subroutines.
    code.label(top_label);
    code.call(odd_label);
    code.call(even_label);
    code.sub(rounds, 2);
    code.brne(top_label);
    code.jmp(end_label);

    // Even rounds.
    code.label(even_label);
    code.ldz_xor(x2, 32); // saturnin_xor_key_rotated left half.
    code.ldz_xor(x3, 36);
    code.ldz_xor(x0, 40);
    code.ldz_xor(x1, 44);
    code.push(Reg::z_ptr());
    code.sbox_setup(0, get_saturnin_round_constants());
    code.sbox_adjust(Reg(domain, 1, 1));
    saturnin_inv_load_rc(code, t0, domain);
    code.logxor(x2, t0); // x2 ^= rc[0];
    code.sbox_cleanup();
    code.pop(Reg::z_ptr());
    saturnin_slice_left(code, x2, t0);
    saturnin_slice_left(code, x3, t0);
    saturnin_slice_left(code, x0, t0);
    saturnin_slice_left(code, x1, t0);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    code.ldz_xor(x6, 48); // saturnin_xor_key_rotated right half.
    code.ldz_xor(x5, 52);
    code.ldz_xor(x7, 56);
    code.ldz_xor(x4, 60);
    saturnin_slice_right(code, x6, t0);
    saturnin_slice_right(code, x5, t0);
    saturnin_slice_right(code, x7, t0);
    saturnin_slice_right(code, x4, t0);
    saturnin_inv_mds(code, x, 2, 3, 0, 1, 6, 5, 7, 4, t0);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_inv_slice_left(code, x1, t0);
    saturnin_inv_slice_left(code, x2, t0);
    saturnin_inv_slice_left(code, x3, t0);
    saturnin_inv_slice_left(code, x0, t0);
    saturnin_inv_sbox(code, x1, x2, x3, x0);
    saturnin_store_left(code, x0, x1, x2, x3);
    saturnin_load_right(code, x4, x5, x6, x7);
    saturnin_inv_slice_right(code, x7, t0);
    saturnin_inv_slice_right(code, x5, t0);
    saturnin_inv_slice_right(code, x4, t0);
    saturnin_inv_slice_right(code, x6, t0);
    saturnin_inv_sbox(code, x7, x5, x4, x6);
    saturnin_inv_mds(code, x, 1, 2, 3, 0, 7, 5, 4, 6, t0);
    saturnin_inv_sbox(code, x4, x5, x6, x7);
    saturnin_store_right(code, x4, x5, x6, x7);
    saturnin_load_left(code, x0, x1, x2, x3);
    saturnin_inv_sbox(code, x0, x1, x2, x3);
    code.ret();

    // XOR the key with the state and store it to the output buffer.
    // At this point, the left half of the state is in x0, x1, x2, x3
    // and the right half of the state is in local variables.
    code.label(end_label);
    code.load_output_ptr();
    code.ldz_xor(x0, 0);
    code.ldz_xor(x1, 4);
    code.ldz_xor(x2, 8);
    code.ldz_xor(x3, 12);
    code.stx(Reg(x0, 0, 2), POST_INC);
    code.stx(Reg(x1, 0, 2), POST_INC);
    code.stx(Reg(x2, 0, 2), POST_INC);
    code.stx(Reg(x3, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 16);
    code.ldz_xor(Reg(t0, 0, 2), 16);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 20);
    code.ldz_xor(Reg(t0, 0, 2), 20);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 24);
    code.ldz_xor(Reg(t0, 0, 2), 24);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 28);
    code.ldz_xor(Reg(t0, 0, 2), 28);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.stx(Reg(x0, 2, 2), POST_INC);
    code.stx(Reg(x1, 2, 2), POST_INC);
    code.stx(Reg(x2, 2, 2), POST_INC);
    code.stx(Reg(x3, 2, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 18);
    code.ldz_xor(Reg(t0, 0, 2), 18);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 22);
    code.ldz_xor(Reg(t0, 0, 2), 22);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 26);
    code.ldz_xor(Reg(t0, 0, 2), 26);
    code.stx(Reg(t0, 0, 2), POST_INC);
    code.ldlocal(Reg(t0, 0, 2), 30);
    code.ldz_xor(Reg(t0, 0, 2), 30);
    code.stx(Reg(t0, 0, 2), POST_INC);
}

// Test vectors for Saturnin created with the reference code.
static unsigned char const saturnin_test_key[32] = {
    0x44, 0x79, 0x65, 0x0b, 0x43, 0xa0, 0x4b, 0xc0,
    0x9d, 0xae, 0x85, 0x8b, 0xd2, 0xd9, 0x70, 0x1c,
    0x9f, 0xb6, 0xfb, 0x15, 0xb6, 0x0b, 0x47, 0xce,
    0xb3, 0x92, 0xf9, 0xb2, 0x3d, 0x72, 0x8d, 0x1e
};
static unsigned char const saturnin_test_plaintext[32] = {
    0x11, 0x91, 0x38, 0x67, 0x48, 0x4e, 0x4b, 0x8e,
    0xa7, 0x59, 0xf1, 0x9d, 0xbc, 0xf4, 0x24, 0x1b,
    0x0f, 0x65, 0x9d, 0x00, 0xa8, 0x8a, 0x41, 0xba,
    0xb6, 0x78, 0x0f, 0x9a, 0x57, 0xd7, 0x94, 0x92
};
static unsigned char const saturnin_test_ciphertext[32] = {
    0xa8, 0x7c, 0x31, 0x8d, 0xb5, 0x66, 0x8e, 0x84,
    0x0e, 0xbd, 0x66, 0xb9, 0x72, 0x0a, 0x78, 0x1d,
    0xb4, 0x06, 0x07, 0x12, 0xb2, 0xe6, 0x94, 0x5d,
    0xe0, 0x67, 0xac, 0xf4, 0x91, 0xf6, 0xba, 0xfd
};
static unsigned char const saturnin_test_ciphertext_16[32] = {
    0x42, 0x9f, 0x73, 0x3b, 0x5b, 0x99, 0xc4, 0x39,
    0x4f, 0x95, 0xf3, 0x84, 0x21, 0xa2, 0xed, 0x2e,
    0x93, 0x35, 0x09, 0xaf, 0x38, 0x7c, 0x0b, 0x5f,
    0x0b, 0xeb, 0xe7, 0xf1, 0xf0, 0x2c, 0xce, 0xbf
};

// Loads a 32-bit word from the two halves of a 256-bit Saturnin input block.
#define saturnin_load_word32(ptr) \
    ((((uint32_t)((ptr)[17])) << 24) | \
     (((uint32_t)((ptr)[16])) << 16) | \
     (((uint32_t)((ptr)[1]))  << 8) | \
      ((uint32_t)((ptr)[0])))

// Store a little-endian 32-bit word into a byte buffer.
#define le_store_word32(ptr, x) \
    do { \
        uint32_t _x = (x); \
        (ptr)[0] = (uint8_t)_x; \
        (ptr)[1] = (uint8_t)(_x >> 8); \
        (ptr)[2] = (uint8_t)(_x >> 16); \
        (ptr)[3] = (uint8_t)(_x >> 24); \
    } while (0)

// Set up the key schedule for Saturnin.
static void saturnin_setup
    (unsigned char schedule[64], const unsigned char key[32])
{
    int index;
    uint32_t temp;
    for (index = 0; index < 16; index += 2) {
        temp = saturnin_load_word32(key + index);
        le_store_word32(schedule + index * 2, temp);
        temp = ((temp & 0x001F001FU) << 11) | ((temp >> 5) & 0x07FF07FFU);
        le_store_word32(schedule + 32 + index * 2, temp);
    }
}

bool test_saturnin_setup_key(Code &code)
{
    unsigned char schedule[64];
    unsigned char expected[64];
    code.exec_setup_key(schedule, sizeof(schedule),
                        saturnin_test_key, sizeof(saturnin_test_key));
    saturnin_setup(expected, saturnin_test_key);
    if (memcmp(schedule, expected, sizeof(schedule)) != 0)
        return false;
    return true;
}

bool test_saturnin_encrypt(Code &code)
{
    unsigned char schedule[64];
    unsigned char output[32];
    saturnin_setup(schedule, saturnin_test_key);

    // Check the 10-round version of the algorithm.
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            saturnin_test_plaintext,
                            sizeof(saturnin_test_plaintext),
                            20); // SATURNIN_DOMAIN_10_3
    if (memcmp(output, saturnin_test_ciphertext, 32) != 0)
        return false;

    // Check the 16-round version of the algorithm.
    code.exec_encrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            saturnin_test_plaintext,
                            sizeof(saturnin_test_plaintext),
                            60); // SATURNIN_DOMAIN_16_7
    if (memcmp(output, saturnin_test_ciphertext_16, 32) != 0)
        return false;

    return true;
}

bool test_saturnin_decrypt(Code &code)
{
    unsigned char schedule[64];
    unsigned char output[32];
    saturnin_setup(schedule, saturnin_test_key);

    // Check the 10-round version of the algorithm.
    code.exec_decrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            saturnin_test_ciphertext,
                            sizeof(saturnin_test_ciphertext),
                            20); // SATURNIN_DOMAIN_10_3
    if (memcmp(output, saturnin_test_plaintext, 32) != 0)
        return false;

    // Check the 16-round version of the algorithm.
    code.exec_decrypt_block(schedule, sizeof(schedule),
                            output, sizeof(output),
                            saturnin_test_ciphertext_16,
                            sizeof(saturnin_test_ciphertext_16),
                            60); // SATURNIN_DOMAIN_16_7
    if (memcmp(output, saturnin_test_plaintext, 32) != 0)
        return false;

    return true;
}
