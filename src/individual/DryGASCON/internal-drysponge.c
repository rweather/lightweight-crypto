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

#include "internal-drysponge.h"
#include <string.h>

#if !defined(__AVR__)

/* Right rotations in bit-interleaved format */
#define intRightRotateEven(x,bits) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate(_x0, (bits)); \
        _x1 = rightRotate(_x1, (bits)); \
        _x0 | (((uint64_t)_x1) << 32); \
    }))
#define intRightRotateOdd(x,bits) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate(_x0, ((bits) + 1) % 32); \
        _x1 = rightRotate(_x1, (bits)); \
        _x1 | (((uint64_t)_x0) << 32); \
    }))
#define intRightRotate1_64(x) \
    (__extension__ ({ \
        uint32_t _x0 = (uint32_t)(x); \
        uint32_t _x1 = (uint32_t)((x) >> 32); \
        _x0 = rightRotate1(_x0); \
        _x1 | (((uint64_t)_x0) << 32); \
    }))
#define intRightRotate2_64(x)  (intRightRotateEven((x), 1))
#define intRightRotate3_64(x)  (intRightRotateOdd((x), 1))
#define intRightRotate4_64(x)  (intRightRotateEven((x), 2))
#define intRightRotate5_64(x)  (intRightRotateOdd((x), 2))
#define intRightRotate6_64(x)  (intRightRotateEven((x), 3))
#define intRightRotate7_64(x)  (intRightRotateOdd((x), 3))
#define intRightRotate8_64(x)  (intRightRotateEven((x), 4))
#define intRightRotate9_64(x)  (intRightRotateOdd((x), 4))
#define intRightRotate10_64(x) (intRightRotateEven((x), 5))
#define intRightRotate11_64(x) (intRightRotateOdd((x), 5))
#define intRightRotate12_64(x) (intRightRotateEven((x), 6))
#define intRightRotate13_64(x) (intRightRotateOdd((x), 6))
#define intRightRotate14_64(x) (intRightRotateEven((x), 7))
#define intRightRotate15_64(x) (intRightRotateOdd((x), 7))
#define intRightRotate16_64(x) (intRightRotateEven((x), 8))
#define intRightRotate17_64(x) (intRightRotateOdd((x), 8))
#define intRightRotate18_64(x) (intRightRotateEven((x), 9))
#define intRightRotate19_64(x) (intRightRotateOdd((x), 9))
#define intRightRotate20_64(x) (intRightRotateEven((x), 10))
#define intRightRotate21_64(x) (intRightRotateOdd((x), 10))
#define intRightRotate22_64(x) (intRightRotateEven((x), 11))
#define intRightRotate23_64(x) (intRightRotateOdd((x), 11))
#define intRightRotate24_64(x) (intRightRotateEven((x), 12))
#define intRightRotate25_64(x) (intRightRotateOdd((x), 12))
#define intRightRotate26_64(x) (intRightRotateEven((x), 13))
#define intRightRotate27_64(x) (intRightRotateOdd((x), 13))
#define intRightRotate28_64(x) (intRightRotateEven((x), 14))
#define intRightRotate29_64(x) (intRightRotateOdd((x), 14))
#define intRightRotate30_64(x) (intRightRotateEven((x), 15))
#define intRightRotate31_64(x) (intRightRotateOdd((x), 15))
#define intRightRotate32_64(x) (intRightRotateEven((x), 16))
#define intRightRotate33_64(x) (intRightRotateOdd((x), 16))
#define intRightRotate34_64(x) (intRightRotateEven((x), 17))
#define intRightRotate35_64(x) (intRightRotateOdd((x), 17))
#define intRightRotate36_64(x) (intRightRotateEven((x), 18))
#define intRightRotate37_64(x) (intRightRotateOdd((x), 18))
#define intRightRotate38_64(x) (intRightRotateEven((x), 19))
#define intRightRotate39_64(x) (intRightRotateOdd((x), 19))
#define intRightRotate40_64(x) (intRightRotateEven((x), 20))
#define intRightRotate41_64(x) (intRightRotateOdd((x), 20))
#define intRightRotate42_64(x) (intRightRotateEven((x), 21))
#define intRightRotate43_64(x) (intRightRotateOdd((x), 21))
#define intRightRotate44_64(x) (intRightRotateEven((x), 22))
#define intRightRotate45_64(x) (intRightRotateOdd((x), 22))
#define intRightRotate46_64(x) (intRightRotateEven((x), 23))
#define intRightRotate47_64(x) (intRightRotateOdd((x), 23))
#define intRightRotate48_64(x) (intRightRotateEven((x), 24))
#define intRightRotate49_64(x) (intRightRotateOdd((x), 24))
#define intRightRotate50_64(x) (intRightRotateEven((x), 25))
#define intRightRotate51_64(x) (intRightRotateOdd((x), 25))
#define intRightRotate52_64(x) (intRightRotateEven((x), 26))
#define intRightRotate53_64(x) (intRightRotateOdd((x), 26))
#define intRightRotate54_64(x) (intRightRotateEven((x), 27))
#define intRightRotate55_64(x) (intRightRotateOdd((x), 27))
#define intRightRotate56_64(x) (intRightRotateEven((x), 28))
#define intRightRotate57_64(x) (intRightRotateOdd((x), 28))
#define intRightRotate58_64(x) (intRightRotateEven((x), 29))
#define intRightRotate59_64(x) (intRightRotateOdd((x), 29))
#define intRightRotate60_64(x) (intRightRotateEven((x), 30))
#define intRightRotate61_64(x) (intRightRotateOdd((x), 30))
#define intRightRotate62_64(x) (intRightRotateEven((x), 31))
#define intRightRotate63_64(x) (intRightRotateOdd((x), 31))

#ifdef DRYGASCON_G0_OPT
void DRYGASCON_G0_OPT(drysponge128_state_t *state);
static void gascon128_g0(drysponge128_state_t *state){
	 DRYGASCON_G0_OPT(state);
}
#else
void gascon128_core_round(gascon128_state_t *state, uint8_t round)
{
    uint64_t t0, t1, t2, t3, t4;

    /* Load the state into local varaibles */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];
#else
    uint64_t x0 = le_load_word64(state->B);
    uint64_t x1 = le_load_word64(state->B + 8);
    uint64_t x2 = le_load_word64(state->B + 16);
    uint64_t x3 = le_load_word64(state->B + 24);
    uint64_t x4 = le_load_word64(state->B + 32);
#endif

    /* Add the round constant to the middle of the state */
    x2 ^= ((0x0F - round) << 4) | round;

    /* Substitution layer */
    x0 ^= x4; x2 ^= x1; x4 ^= x3; t0 = (~x0) & x1; t1 = (~x1) & x2;
    t2 = (~x2) & x3; t3 = (~x3) & x4; t4 = (~x4) & x0; x0 ^= t1;
    x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t0; x1 ^= x0; x3 ^= x2;
    x0 ^= x4; x2 = ~x2;

    /* Linear diffusion layer */
    x0 ^= intRightRotate19_64(x0) ^ intRightRotate28_64(x0);
    x1 ^= intRightRotate61_64(x1) ^ intRightRotate38_64(x1);
    x2 ^= intRightRotate1_64(x2)  ^ intRightRotate6_64(x2);
    x3 ^= intRightRotate10_64(x3) ^ intRightRotate17_64(x3);
    x4 ^= intRightRotate7_64(x4)  ^ intRightRotate40_64(x4);

    /* Write the local variables back to the state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
#else
    le_store_word64(state->B,      x0);
    le_store_word64(state->B +  8, x1);
    le_store_word64(state->B + 16, x2);
    le_store_word64(state->B + 24, x3);
    le_store_word64(state->B + 32, x4);
#endif
}

static void gascon128_g0(drysponge128_state_t *state){
	gascon128_core_round(&(state->c), 0);
}
#endif

void gascon256_core_round(gascon256_state_t *state, uint8_t round)
{
    uint64_t t0, t1, t2, t3, t4, t5, t6, t7, t8;

    /* Load the state into local varaibles */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    uint64_t x0 = state->S[0];
    uint64_t x1 = state->S[1];
    uint64_t x2 = state->S[2];
    uint64_t x3 = state->S[3];
    uint64_t x4 = state->S[4];
    uint64_t x5 = state->S[5];
    uint64_t x6 = state->S[6];
    uint64_t x7 = state->S[7];
    uint64_t x8 = state->S[8];
#else
    uint64_t x0 = le_load_word64(state->B);
    uint64_t x1 = le_load_word64(state->B + 8);
    uint64_t x2 = le_load_word64(state->B + 16);
    uint64_t x3 = le_load_word64(state->B + 24);
    uint64_t x4 = le_load_word64(state->B + 32);
    uint64_t x5 = le_load_word64(state->B + 40);
    uint64_t x6 = le_load_word64(state->B + 48);
    uint64_t x7 = le_load_word64(state->B + 56);
    uint64_t x8 = le_load_word64(state->B + 64);
#endif

    /* Add the round constant to the middle of the state */
    x4 ^= ((0x0F - round) << 4) | round;

    /* Substitution layer */
    x0 ^= x8; x2 ^= x1; x4 ^= x3; x6 ^= x5; x8 ^= x7; t0 = (~x0) & x1;
    t1 = (~x1) & x2; t2 = (~x2) & x3; t3 = (~x3) & x4; t4 = (~x4) & x5;
    t5 = (~x5) & x6; t6 = (~x6) & x7; t7 = (~x7) & x8; t8 = (~x8) & x0;
    x0 ^= t1; x1 ^= t2; x2 ^= t3; x3 ^= t4; x4 ^= t5; x5 ^= t6; x6 ^= t7;
    x7 ^= t8; x8 ^= t0; x1 ^= x0; x3 ^= x2; x5 ^= x4; x7 ^= x6; x0 ^= x8;
    x4 = ~x4;

    /* Linear diffusion layer */
    x0 ^= intRightRotate19_64(x0) ^ intRightRotate28_64(x0);
    x1 ^= intRightRotate61_64(x1) ^ intRightRotate38_64(x1);
    x2 ^= intRightRotate1_64(x2)  ^ intRightRotate6_64(x2);
    x3 ^= intRightRotate10_64(x3) ^ intRightRotate17_64(x3);
    x4 ^= intRightRotate7_64(x4)  ^ intRightRotate40_64(x4);
    x5 ^= intRightRotate31_64(x5) ^ intRightRotate26_64(x5);
    x6 ^= intRightRotate53_64(x6) ^ intRightRotate58_64(x6);
    x7 ^= intRightRotate9_64(x7)  ^ intRightRotate46_64(x7);
    x8 ^= intRightRotate43_64(x8) ^ intRightRotate50_64(x8);

    /* Write the local variables back to the state */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    state->S[0] = x0;
    state->S[1] = x1;
    state->S[2] = x2;
    state->S[3] = x3;
    state->S[4] = x4;
    state->S[5] = x5;
    state->S[6] = x6;
    state->S[7] = x7;
    state->S[8] = x8;
#else
    le_store_word64(state->B,      x0);
    le_store_word64(state->B +  8, x1);
    le_store_word64(state->B + 16, x2);
    le_store_word64(state->B + 24, x3);
    le_store_word64(state->B + 32, x4);
    le_store_word64(state->B + 40, x5);
    le_store_word64(state->B + 48, x6);
    le_store_word64(state->B + 56, x7);
    le_store_word64(state->B + 64, x8);
#endif
}

#ifdef DRYGASCON_G_OPT
void DRYGASCON_G_OPT(uint64_t* state, uint32_t rounds);
//use state only to access c,r,x
static void drysponge128_g_impl(drysponge128_state_t *state,unsigned int rounds)
{
    DRYGASCON_G_OPT((uint64_t*)state,rounds);
}
#else

//use state only to access c,r,x
static void drysponge128_g_impl(drysponge128_state_t *state,unsigned int rounds)
{
    unsigned round;

    /* Perform the first round.  For each round we XOR the 16 bytes of
     * the output data with the first 16 bytes of the state.  And then
     * XOR with the next 16 bytes of the state, rotated by 4 bytes */
    gascon128_core_round(&(state->c), 0);
    state->r.W[0] = state->c.W[0] ^ state->c.W[5];
    state->r.W[1] = state->c.W[1] ^ state->c.W[6];
    state->r.W[2] = state->c.W[2] ^ state->c.W[7];
    state->r.W[3] = state->c.W[3] ^ state->c.W[4];

    /* Perform the rest of the rounds */
    for (round = 1; round < rounds; ++round) {
        gascon128_core_round(&(state->c), round);
        state->r.W[0] ^= state->c.W[0] ^ state->c.W[5];
        state->r.W[1] ^= state->c.W[1] ^ state->c.W[6];
        state->r.W[2] ^= state->c.W[2] ^ state->c.W[7];
        state->r.W[3] ^= state->c.W[3] ^ state->c.W[4];
    }
}
#endif

void print_state(void*state);
void drysponge128_g(drysponge128_state_t *state)
{
    drysponge128_g_impl(state,state->rounds);
    //print_state(state);
}

void drysponge256_g(drysponge256_state_t *state)
{
    unsigned round;

    /* Perform the first round.  For each round we XOR the 16 bytes of
     * the output data with the first 16 bytes of the state.  And then
     * XOR with the next 16 bytes of the state, rotated by 4 bytes.
     * And so on for a total of 64 bytes XOR'ed into the output data. */
    gascon256_core_round(&(state->c), 0);
    state->r.W[0] = state->c.W[0]  ^ state->c.W[5] ^
                    state->c.W[10] ^ state->c.W[15];
    state->r.W[1] = state->c.W[1]  ^ state->c.W[6] ^
                    state->c.W[11] ^ state->c.W[12];
    state->r.W[2] = state->c.W[2]  ^ state->c.W[7] ^
                    state->c.W[8]  ^ state->c.W[13];
    state->r.W[3] = state->c.W[3]  ^ state->c.W[4] ^
                    state->c.W[9]  ^ state->c.W[14];

    /* Perform the rest of the rounds */
    for (round = 1; round < state->rounds; ++round) {
        gascon256_core_round(&(state->c), round);
        state->r.W[0] ^= state->c.W[0]  ^ state->c.W[5] ^
                         state->c.W[10] ^ state->c.W[15];
        state->r.W[1] ^= state->c.W[1]  ^ state->c.W[6] ^
                         state->c.W[11] ^ state->c.W[12];
        state->r.W[2] ^= state->c.W[2]  ^ state->c.W[7] ^
                         state->c.W[8]  ^ state->c.W[13];
        state->r.W[3] ^= state->c.W[3]  ^ state->c.W[4] ^
                         state->c.W[9]  ^ state->c.W[14];
    }
}

#endif /* !__AVR__ */

#ifndef DRYGASCON_G_OPT
void drysponge128_g_core(drysponge128_state_t *state)
{
    unsigned round;
    for (round = 0; round < state->rounds; ++round)
        gascon128_core_round(&(state->c), round);
}
#endif

void drysponge256_g_core(drysponge256_state_t *state)
{
    unsigned round;
    for (round = 0; round < state->rounds; ++round)
        gascon256_core_round(&(state->c), round);
}

/**
 * \fn uint32_t drysponge_select_x(const uint32_t x[4], uint8_t index)
 * \brief Selects an element of x in constant time.
 *
 * \param x Points to the four elements of x.
 * \param index Index of which element to extract between 0 and 3.
 *
 * \return The selected element of x.
 */
#if defined(__HAS_CACHE__)
STATIC_INLINE uint32_t drysponge_select_x(const uint32_t x[4], uint8_t index)
{
    /* We need to be careful how we select each element of x because
     * we are doing a data-dependent fetch here.  Do the fetch in a way
     * that should avoid cache timing issues by fetching every element
     * of x and masking away the ones we don't want.
     *
     * There is a possible side channel here with respect to power analysis.
     * The "mask" value will be all-ones for the selected index and all-zeroes
     * for the other indexes.  This may show up as different power consumption
     * for the "result ^= x[i] & mask" statement when i is the selected index.
     * Such a side channel could in theory allow reading the plaintext input
     * to the cipher by analysing the CPU's power consumption.
     *
     * The DryGASCON specification acknowledges the possibility of plaintext
     * recovery in section 7.4.  For software mitigation the specification
     * suggests randomization of the indexes into c and x and randomization
     * of the order of processing words.  We aren't doing that here yet.
     * Patches welcome to fix this.
     */
    uint32_t mask = -((uint32_t)((0x04 - index) >> 2));
    uint32_t result = x[0] & mask;
    mask = -((uint32_t)((0x04 - (index ^ 0x01)) >> 2));
    result ^= x[1] & mask;
    mask = -((uint32_t)((0x04 - (index ^ 0x02)) >> 2));
    result ^= x[2] & mask;
    mask = -((uint32_t)((0x04 - (index ^ 0x03)) >> 2));
    return result ^ (x[3] & mask);
}
#else
/* AVR is more or less immune to cache timing issues because it doesn't
 * have anything like an L1 or L2 cache.  Select the word directly */
#define drysponge_select_x(x, index) ((x)[(index)])
#endif

#ifndef DRYGASCON_F_OPT
/**
 * \brief Mixes a 32-bit value into the DrySPONGE128 state.
 *
 * \param state DrySPONGE128 state.
 * \param data The data to be mixed in the bottom 10 bits.
 */
static void drysponge128_mix_phase_round
    (drysponge128_state_t *state, uint32_t data)
{
    /* Mix in elements from x according to the 2-bit indexes in the data */
    state->c.W[0] ^= drysponge_select_x(state->x.W, data & 0x03);
    state->c.W[2] ^= drysponge_select_x(state->x.W, (data >> 2) & 0x03);
    state->c.W[4] ^= drysponge_select_x(state->x.W, (data >> 4) & 0x03);
    state->c.W[6] ^= drysponge_select_x(state->x.W, (data >> 6) & 0x03);
    state->c.W[8] ^= drysponge_select_x(state->x.W, (data >> 8) & 0x03);
}
#endif

/**
 * \brief Mixes a 32-bit value into the DrySPONGE256 state.
 *
 * \param state DrySPONGE256 state.
 * \param data The data to be mixed in the bottom 18 bits.
 */
static void drysponge256_mix_phase_round
    (drysponge256_state_t *state, uint32_t data)
{
    /* Mix in elements from x according to the 2-bit indexes in the data */
    state->c.W[0]  ^= drysponge_select_x(state->x.W, data & 0x03);
    state->c.W[2]  ^= drysponge_select_x(state->x.W, (data >>  2) & 0x03);
    state->c.W[4]  ^= drysponge_select_x(state->x.W, (data >>  4) & 0x03);
    state->c.W[6]  ^= drysponge_select_x(state->x.W, (data >>  6) & 0x03);
    state->c.W[8]  ^= drysponge_select_x(state->x.W, (data >>  8) & 0x03);
    state->c.W[10] ^= drysponge_select_x(state->x.W, (data >> 10) & 0x03);
    state->c.W[12] ^= drysponge_select_x(state->x.W, (data >> 12) & 0x03);
    state->c.W[14] ^= drysponge_select_x(state->x.W, (data >> 14) & 0x03);
    state->c.W[16] ^= drysponge_select_x(state->x.W, (data >> 16) & 0x03);
}

#ifndef DRYGASCON_F_OPT
/**
 * \brief Mixes an input block into a DrySPONGE128 state.
 *
 * \param state The DrySPONGE128 state.
 * \param data Full rate block containing the input data.
 */
static void drysponge128_mix_phase
    (drysponge128_state_t *state, const unsigned char data[DRYSPONGE128_RATE],unsigned int ds)
{
    /* Mix 10-bit groups into the output, with the domain
     * separator added to the last two groups */
    drysponge128_mix_phase_round
        (state, data[0] | (((uint32_t)(data[1])) << 8));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[1] >> 2) | (((uint32_t)(data[2])) << 6));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[2] >> 4) | (((uint32_t)(data[3])) << 4));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[3] >> 6) | (((uint32_t)(data[4])) << 2));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, data[5] | (((uint32_t)(data[6])) << 8));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[6] >> 2) | (((uint32_t)(data[7])) << 6));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[7] >> 4) | (((uint32_t)(data[8])) << 4));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[8] >> 6) | (((uint32_t)(data[9])) << 2));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, data[10] | (((uint32_t)(data[11])) << 8));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[11] >> 2) | (((uint32_t)(data[12])) << 6));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, (data[12] >> 4) | (((uint32_t)(data[13])) << 4));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round
        (state, ((data[13] >> 6) | (((uint32_t)(data[14])) << 2)));
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round(state, data[15] ^ ds);
    gascon128_core_round(&(state->c), 0);
    drysponge128_mix_phase_round(state, ds >> 10);
}
#endif

/**
 * \brief Mixes an input block into a DrySPONGE256 state.
 *
 * \param state The DrySPONGE256 state.
 * \param data Full rate block containing the input data.
 */
static void drysponge256_mix_phase
    (drysponge256_state_t *state, const unsigned char data[DRYSPONGE256_RATE])
{
    /* Mix 18-bit groups into the output, with the domain in the last group */
    drysponge256_mix_phase_round
        (state, data[0] | (((uint32_t)(data[1])) << 8) |
                (((uint32_t)(data[2])) << 16));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, (data[2] >> 2) | (((uint32_t)(data[3])) << 6) |
                (((uint32_t)(data[4])) << 14));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, (data[4] >> 4) | (((uint32_t)(data[5])) << 4) |
                (((uint32_t)(data[6])) << 12));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, (data[6] >> 6) | (((uint32_t)(data[7])) << 2) |
                (((uint32_t)(data[8])) << 10));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, data[9] | (((uint32_t)(data[10])) << 8) |
                (((uint32_t)(data[11])) << 16));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, (data[11] >> 2) | (((uint32_t)(data[12])) << 6) |
                (((uint32_t)(data[13])) << 14));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, (data[13] >> 4) | (((uint32_t)(data[14])) << 4) |
                (((uint32_t)(data[15])) << 12));
    gascon256_core_round(&(state->c), 0);
    drysponge256_mix_phase_round
        (state, (data[15] >> 6) ^ state->domain);

    /* Revert to the default domain separator for the next block */
    state->domain = 0;
}

#ifdef DRYGASCON_F_OPT
void DRYGASCON_F_OPT(drysponge128_state_t *state, const unsigned char *input,unsigned int ds, unsigned int rounds);
static void drygascon128_f_impl(drysponge128_state_t *state, const unsigned char *input,unsigned int ds, unsigned int rounds){
    DRYGASCON_F_OPT(state, input, ds, rounds);
}
#else
void drygascon128_f_impl(drysponge128_state_t *state, const unsigned char *input,unsigned int ds, unsigned int rounds){
    drysponge128_mix_phase(state, input ,ds);
    drysponge128_g_impl(state,rounds);
}
#endif
void drygascon128_f_wrap(drysponge128_state_t *state, const unsigned char *input, unsigned len){
    drysponge128_rate_t padded;//enforce alignement (if needed by f_impl)
    const unsigned char*in;
    if (len < DRYSPONGE128_RATE) {
        memcpy(padded.B, input, len);
        padded.B[len] = 0x01;
        memset(padded.B + len + 1, 0, DRYSPONGE128_RATE - len - 1);
        in=padded.B;
    } else {
		#ifdef DRYGASCON_ALIGN_INPUT_32
        memcpy(padded.B,input,DRYSPONGE128_RATE);
        in=padded.B;
		#else
        in=input;
		#endif
    }
    drygascon128_f_impl(state, in,state->domain,state->rounds);
    //print_state(state);
    /* Revert to the default domain separator for the next block */
    state->domain = 0;
}

void drysponge256_f_absorb
    (drysponge256_state_t *state, const unsigned char *input, unsigned len)
{
    if (len >= DRYSPONGE256_RATE) {
        drysponge256_mix_phase(state, input);
    } else {
        unsigned char padded[DRYSPONGE256_RATE];
        memcpy(padded, input, len);
        padded[len] = 0x01;
        memset(padded + len + 1, 0, DRYSPONGE256_RATE - len - 1);
        drysponge256_mix_phase(state, padded);
    }
}

/**
 * \brief Determine if some of the words of an "x" value are identical.
 *
 * \param x Points to the "x" buffer to check.
 *
 * \return Non-zero if some of the words are the same, zero if they are
 * distinct from each other.
 *
 * We try to perform the check in constant time to avoid giving away
 * any information about the value of the key.
 */
static int drysponge_x_words_are_same(const uint32_t x[4])
{
    unsigned i, j;
    int result = 0;
    for (i = 0; i < 3; ++i) {
        for (j = i + 1; j < 4; ++j) {
            uint32_t check = x[i] ^ x[j];
            result |= (int)((0x100000000ULL - check) >> 32);
        }
    }
    return result;
}


int drysponge128_safe_alignement(const drysponge128_state_t*state){
	return 0==(0xF & (uintptr_t )&(state->x));
}

void drysponge128_setup
    (drysponge128_state_t *state, const unsigned char *key, unsigned int keysize,
     const unsigned char *nonce, int final_block)
{
	if(DRYGASCON128_SAFEKEY_SIZE==keysize){
		/* Fill C and X directly with the key */
		memcpy(state->c.B, key, sizeof(state->c));
		memcpy(state->x.B, key+ sizeof(state->c), sizeof(state->x));
		while (drysponge_x_words_are_same(state->x.W)); //block here if the key is not valid

	} else {
		/* Fill the GASCON-128 state with repeated copies of the key */
		memcpy(state->c.B, key, 16);
		memcpy(state->c.B + 16, key, 16);
		memcpy(state->c.B + 32, key, 8);

		if(DRYGASCON128_FASTKEY_SIZE==keysize){

			/* Fill X with the 16 last bytes of the key */
			memcpy(state->x.B, key+16, sizeof(state->x));
			while (drysponge_x_words_are_same(state->x.W)); //block here if the key is not valid

		} else if(DRYGASCON128_MINKEY_SIZE==keysize){

			/* Generate the "x" value for the state.  All four words of "x"
			 * must be unique because they will be used in drysponge_select_x()
			 * as stand-ins for the bit pairs 00, 01, 10, and 11.
			 *
			 * Run the core block operation over and over until "x" is unique.
			 * Technically the runtime here is key-dependent and not constant.
			 * If the input key is randomized, this should only take 1 round
			 * on average so it is "almost constant time".
			 */
			do {
				//gascon128_core_round(&(state->c), 0);
				//drysponge128_g_impl(state,1);
				gascon128_g0(state);
			} while (drysponge_x_words_are_same(state->c.W));
			memcpy(state->x.W, state->c.W, sizeof(state->x));

			/* Replace the generated "x" value in the state with the key prefix */
			memcpy(state->c.W, key, sizeof(state->x));
		}
	}

    /* Absorb the nonce into the state with an increased number of rounds */
    state->rounds = DRYSPONGE128_INIT_ROUNDS;
    state->domain = DRYDOMAIN128_NONCE;
    if (final_block)
        state->domain |= DRYDOMAIN128_FINAL;
    drygascon128_f_wrap(state, nonce, 16);

    /* Set up the normal number of rounds for future operations */
    state->rounds = DRYSPONGE128_ROUNDS;
}

void drysponge256_setup
    (drysponge256_state_t *state, const unsigned char *key,
     const unsigned char *nonce, int final_block)
{
    /* Fill the GASCON-256 state with repeated copies of the key */
    memcpy(state->c.B, key, 32);
    memcpy(state->c.B + 32, key, 32);
    memcpy(state->c.B + 64, key, 8);

    /* Generate the "x" value for the state */
    do {
        gascon256_core_round(&(state->c), 0);
    } while (drysponge_x_words_are_same(state->c.W));
    memcpy(state->x.W, state->c.W, sizeof(state->x));

    /* Replace the generated "x" value in the state with the key prefix */
    memcpy(state->c.W, key, sizeof(state->x));

    /* Absorb the nonce into the state with an increased number of rounds */
    state->rounds = DRYSPONGE256_INIT_ROUNDS;
    state->domain = DRYDOMAIN256_NONCE;
    if (final_block)
        state->domain |= DRYDOMAIN256_FINAL;
    drysponge256_f_absorb(state, nonce, 16);
    drysponge256_g(state);

    /* Set up the normal number of rounds for future operations */
    state->rounds = DRYSPONGE256_ROUNDS;
}
