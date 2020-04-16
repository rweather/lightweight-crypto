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

#include "internal-keccak.h"

#if !defined(__AVR__)

/* Faster method to compute ((x + y) % 5) that avoids the division */
static unsigned char const addMod5Table[9] = {
    0, 1, 2, 3, 4, 0, 1, 2, 3
};
#define addMod5(x, y) (addMod5Table[(x) + (y)])

void keccakp_200_permute(keccakp_200_state_t *state)
{
    static uint8_t const RC[18] = {
        0x01, 0x82, 0x8A, 0x00, 0x8B, 0x01, 0x81, 0x09,
        0x8A, 0x88, 0x09, 0x0A, 0x8B, 0x8B, 0x89, 0x03,
        0x02, 0x80
    };
    uint8_t C[5];
    uint8_t D;
    unsigned round;
    unsigned index, index2;
    for (round = 0; round < 18; ++round) {
        /* Step mapping theta.  The specification mentions two temporary
         * arrays of size 5 called C and D.  Compute D on the fly */
        for (index = 0; index < 5; ++index) {
            C[index] = state->A[0][index] ^ state->A[1][index] ^
                       state->A[2][index] ^ state->A[3][index] ^
                       state->A[4][index];
        }
        for (index = 0; index < 5; ++index) {
            D = C[addMod5(index, 4)] ^
                leftRotate1_8(C[addMod5(index, 1)]);
            for (index2 = 0; index2 < 5; ++index2)
                state->A[index2][index] ^= D;
        }

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        D = state->A[0][1];
        state->A[0][1] = leftRotate4_8(state->A[1][1]);
        state->A[1][1] = leftRotate4_8(state->A[1][4]);
        state->A[1][4] = leftRotate5_8(state->A[4][2]);
        state->A[4][2] = leftRotate7_8(state->A[2][4]);
        state->A[2][4] = leftRotate2_8(state->A[4][0]);
        state->A[4][0] = leftRotate6_8(state->A[0][2]);
        state->A[0][2] = leftRotate3_8(state->A[2][2]);
        state->A[2][2] = leftRotate1_8(state->A[2][3]);
        state->A[2][3] = state->A[3][4];
        state->A[3][4] = state->A[4][3];
        state->A[4][3] = leftRotate1_8(state->A[3][0]);
        state->A[3][0] = leftRotate3_8(state->A[0][4]);
        state->A[0][4] = leftRotate6_8(state->A[4][4]);
        state->A[4][4] = leftRotate2_8(state->A[4][1]);
        state->A[4][1] = leftRotate7_8(state->A[1][3]);
        state->A[1][3] = leftRotate5_8(state->A[3][1]);
        state->A[3][1] = leftRotate4_8(state->A[1][0]);
        state->A[1][0] = leftRotate4_8(state->A[0][3]);
        state->A[0][3] = leftRotate5_8(state->A[3][3]);
        state->A[3][3] = leftRotate7_8(state->A[3][2]);
        state->A[3][2] = leftRotate2_8(state->A[2][1]);
        state->A[2][1] = leftRotate6_8(state->A[1][2]);
        state->A[1][2] = leftRotate3_8(state->A[2][0]);
        state->A[2][0] = leftRotate1_8(D);

        /* Step mapping chi.  Combine each lane with two others in its row */
        for (index = 0; index < 5; ++index) {
            C[0] = state->A[index][0];
            C[1] = state->A[index][1];
            C[2] = state->A[index][2];
            C[3] = state->A[index][3];
            C[4] = state->A[index][4];
            for (index2 = 0; index2 < 5; ++index2) {
                state->A[index][index2] =
                    C[index2] ^
                    ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
            }
        }

        /* Step mapping iota.  XOR A[0][0] with the round constant */
        state->A[0][0] ^= RC[round];
    }
}

#if defined(LW_UTIL_LITTLE_ENDIAN)
#define keccakp_400_permute_host keccakp_400_permute
#endif

/* Keccak-p[400] that assumes that the input is already in host byte order */
void keccakp_400_permute_host(keccakp_400_state_t *state, unsigned rounds)
{
    static uint16_t const RC[20] = {
        0x0001, 0x8082, 0x808A, 0x8000, 0x808B, 0x0001, 0x8081, 0x8009,
        0x008A, 0x0088, 0x8009, 0x000A, 0x808B, 0x008B, 0x8089, 0x8003,
        0x8002, 0x0080, 0x800A, 0x000A
    };
    uint16_t C[5];
    uint16_t D;
    unsigned round;
    unsigned index, index2;
    for (round = 20 - rounds; round < 20; ++round) {
        /* Step mapping theta.  The specification mentions two temporary
         * arrays of size 5 called C and D.  Compute D on the fly */
        for (index = 0; index < 5; ++index) {
            C[index] = state->A[0][index] ^ state->A[1][index] ^
                       state->A[2][index] ^ state->A[3][index] ^
                       state->A[4][index];
        }
        for (index = 0; index < 5; ++index) {
            D = C[addMod5(index, 4)] ^
                leftRotate1_16(C[addMod5(index, 1)]);
            for (index2 = 0; index2 < 5; ++index2)
                state->A[index2][index] ^= D;
        }

        /* Step mapping rho and pi combined into a single step.
         * Rotate all lanes by a specific offset and rearrange */
        D = state->A[0][1];
        state->A[0][1] = leftRotate12_16(state->A[1][1]);
        state->A[1][1] = leftRotate4_16 (state->A[1][4]);
        state->A[1][4] = leftRotate13_16(state->A[4][2]);
        state->A[4][2] = leftRotate7_16 (state->A[2][4]);
        state->A[2][4] = leftRotate2_16 (state->A[4][0]);
        state->A[4][0] = leftRotate14_16(state->A[0][2]);
        state->A[0][2] = leftRotate11_16(state->A[2][2]);
        state->A[2][2] = leftRotate9_16 (state->A[2][3]);
        state->A[2][3] = leftRotate8_16 (state->A[3][4]);
        state->A[3][4] = leftRotate8_16 (state->A[4][3]);
        state->A[4][3] = leftRotate9_16 (state->A[3][0]);
        state->A[3][0] = leftRotate11_16(state->A[0][4]);
        state->A[0][4] = leftRotate14_16(state->A[4][4]);
        state->A[4][4] = leftRotate2_16 (state->A[4][1]);
        state->A[4][1] = leftRotate7_16 (state->A[1][3]);
        state->A[1][3] = leftRotate13_16(state->A[3][1]);
        state->A[3][1] = leftRotate4_16 (state->A[1][0]);
        state->A[1][0] = leftRotate12_16(state->A[0][3]);
        state->A[0][3] = leftRotate5_16 (state->A[3][3]);
        state->A[3][3] = leftRotate15_16(state->A[3][2]);
        state->A[3][2] = leftRotate10_16(state->A[2][1]);
        state->A[2][1] = leftRotate6_16 (state->A[1][2]);
        state->A[1][2] = leftRotate3_16 (state->A[2][0]);
        state->A[2][0] = leftRotate1_16(D);

        /* Step mapping chi.  Combine each lane with two others in its row */
        for (index = 0; index < 5; ++index) {
            C[0] = state->A[index][0];
            C[1] = state->A[index][1];
            C[2] = state->A[index][2];
            C[3] = state->A[index][3];
            C[4] = state->A[index][4];
            for (index2 = 0; index2 < 5; ++index2) {
                state->A[index][index2] =
                    C[index2] ^
                    ((~C[addMod5(index2, 1)]) & C[addMod5(index2, 2)]);
            }
        }

        /* Step mapping iota.  XOR A[0][0] with the round constant */
        state->A[0][0] ^= RC[round];
    }
}

#if !defined(LW_UTIL_LITTLE_ENDIAN)

/**
 * \brief Reverses the bytes in a Keccak-p[400] state.
 *
 * \param state The Keccak-p[400] state to apply byte-reversal to.
 */
static void keccakp_400_reverse_bytes(keccakp_400_state_t *state)
{
    unsigned index;
    unsigned char temp1;
    unsigned char temp2;
    for (index = 0; index < 50; index += 2) {
        temp1 = state->B[index];
        temp2 = state->B[index + 1];
        state->B[index] = temp2;
        state->B[index + 1] = temp1;
    }
}

/* Keccak-p[400] that requires byte reversal on input and output */
void keccakp_400_permute(keccakp_400_state_t *state, unsigned rounds)
{
    keccakp_400_reverse_bytes(state);
    keccakp_400_permute_host(state, rounds);
    keccakp_400_reverse_bytes(state);
}

#endif

#endif /* !__AVR__ */
