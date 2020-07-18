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

#include "internal-forkskinny.h"
#include "internal-skinnyutil.h"

/**
 * \brief 7-bit round constants for all ForkSkinny block ciphers.
 */
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

#if !defined(__AVR__)

void forkskinny_128_256_rounds
    (forkskinny_128_256_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    for (; first < last; ++first) {
        /* Apply the S-box to all cells in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1 and TK2 for the next round */
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_256_inv_rounds
    (forkskinny_128_256_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    while (first > last) {
        /* Permute TK1 and TK2 for the next round */
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);

        /* Inverse mix of the columns */
        temp = s0;
        s0 = s1;
        s1 = s2;
        s2 = s3;
        s3 = temp ^ s2;
        s2 ^= s0;
        s1 ^= s2;

        /* Shift the cells in the rows left, which moves the cell
         * values down closer to the LSB.  That is, we do a right
         * rotate on the word to rotate the cells in the word left */
        s1 = rightRotate8(s1);
        s2 = rightRotate16(s2);
        s3 = rightRotate24(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[--first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ (rc & 0x0F) ^ 0x00020000;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ (rc >> 4);
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all cells in the state */
        skinny128_inv_sbox(s0);
        skinny128_inv_sbox(s1);
        skinny128_inv_sbox(s2);
        skinny128_inv_sbox(s3);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_256_forward_tk
    (forkskinny_128_256_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_LFSR2(state->TK2[0]);
            skinny128_LFSR2(state->TK2[1]);
            skinny128_LFSR2(state->TK2[2]);
            skinny128_LFSR2(state->TK2[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
        --rounds;
    }
}

void forkskinny_128_256_reverse_tk
    (forkskinny_128_256_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_inv_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_inv_LFSR2(state->TK2[0]);
            skinny128_inv_LFSR2(state->TK2[1]);
            skinny128_inv_LFSR2(state->TK2[2]);
            skinny128_inv_LFSR2(state->TK2[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);
        --rounds;
    }
}

void forkskinny_128_384_rounds
    (forkskinny_128_384_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    for (; first < last; ++first) {
        /* Apply the S-box to all cells in the state */
        skinny128_sbox(s0);
        skinny128_sbox(s1);
        skinny128_sbox(s2);
        skinny128_sbox(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
              (rc & 0x0F) ^ 0x00020000;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
        s2 ^= 0x02;

        /* Shift the cells in the rows right, which moves the cell
         * values up closer to the MSB.  That is, we do a left rotate
         * on the word to rotate the cells in the word right */
        s1 = leftRotate8(s1);
        s2 = leftRotate16(s2);
        s3 = leftRotate24(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1, TK2, and TK3 for the next round */
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_permute_tk(state->TK3);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
        skinny128_LFSR3(state->TK3[0]);
        skinny128_LFSR3(state->TK3[1]);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_384_inv_rounds
    (forkskinny_128_384_state_t *state, unsigned first, unsigned last)
{
    uint32_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    while (first > last) {
        /* Permute TK1 and TK2 for the next round */
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_LFSR3(state->TK3[0]);
        skinny128_inv_LFSR3(state->TK3[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);
        skinny128_inv_permute_tk(state->TK3);

        /* Inverse mix of the columns */
        temp = s0;
        s0 = s1;
        s1 = s2;
        s2 = s3;
        s3 = temp ^ s2;
        s2 ^= s0;
        s1 ^= s2;

        /* Shift the cells in the rows left, which moves the cell
         * values down closer to the LSB.  That is, we do a right
         * rotate on the word to rotate the cells in the word left */
        s1 = rightRotate8(s1);
        s2 = rightRotate16(s2);
        s3 = rightRotate24(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[--first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
              (rc & 0x0F) ^ 0x00020000;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^ (rc >> 4);
        s2 ^= 0x02;

        /* Apply the inverse of the S-box to all cells in the state */
        skinny128_inv_sbox(s0);
        skinny128_inv_sbox(s1);
        skinny128_inv_sbox(s2);
        skinny128_inv_sbox(s3);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_128_384_forward_tk
    (forkskinny_128_384_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_LFSR2(state->TK2[0]);
            skinny128_LFSR2(state->TK2[1]);
            skinny128_LFSR2(state->TK2[2]);
            skinny128_LFSR2(state->TK2[3]);
            skinny128_LFSR3(state->TK3[0]);
            skinny128_LFSR3(state->TK3[1]);
            skinny128_LFSR3(state->TK3[2]);
            skinny128_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_permute_tk(state->TK1);
        skinny128_permute_tk(state->TK2);
        skinny128_permute_tk(state->TK3);
        skinny128_LFSR2(state->TK2[0]);
        skinny128_LFSR2(state->TK2[1]);
        skinny128_LFSR3(state->TK3[0]);
        skinny128_LFSR3(state->TK3[1]);
        --rounds;
    }
}

void forkskinny_128_384_reverse_tk
    (forkskinny_128_384_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny128_inv_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny128_inv_LFSR2(state->TK2[0]);
            skinny128_inv_LFSR2(state->TK2[1]);
            skinny128_inv_LFSR2(state->TK2[2]);
            skinny128_inv_LFSR2(state->TK2[3]);
            skinny128_inv_LFSR3(state->TK3[0]);
            skinny128_inv_LFSR3(state->TK3[1]);
            skinny128_inv_LFSR3(state->TK3[2]);
            skinny128_inv_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny128_inv_LFSR2(state->TK2[0]);
        skinny128_inv_LFSR2(state->TK2[1]);
        skinny128_inv_LFSR3(state->TK3[0]);
        skinny128_inv_LFSR3(state->TK3[1]);
        skinny128_inv_permute_tk(state->TK1);
        skinny128_inv_permute_tk(state->TK2);
        skinny128_inv_permute_tk(state->TK3);
        --rounds;
    }
}

void forkskinny_64_192_rounds
    (forkskinny_64_192_state_t *state, unsigned first, unsigned last)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    for (; first < last; ++first) {
        /* Apply the S-box to all cells in the state */
        skinny64_sbox(s0);
        skinny64_sbox(s1);
        skinny64_sbox(s2);
        skinny64_sbox(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
              ((rc & 0x0F) << 12) ^ 0x0020;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
              ((rc & 0x70) << 8);
        s2 ^= 0x2000;

        /* Shift the cells in the rows right */
        s1 = rightRotate4_16(s1);
        s2 = rightRotate8_16(s2);
        s3 = rightRotate12_16(s3);

        /* Mix the columns */
        s1 ^= s2;
        s2 ^= s0;
        temp = s3 ^ s2;
        s3 = s2;
        s2 = s1;
        s1 = s0;
        s0 = temp;

        /* Permute TK1, TK2, and TK3 for the next round */
        skinny64_permute_tk(state->TK1);
        skinny64_permute_tk(state->TK2);
        skinny64_permute_tk(state->TK3);
        skinny64_LFSR2(state->TK2[0]);
        skinny64_LFSR2(state->TK2[1]);
        skinny64_LFSR3(state->TK3[0]);
        skinny64_LFSR3(state->TK3[1]);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_inv_rounds
    (forkskinny_64_192_state_t *state, unsigned first, unsigned last)
{
    uint16_t s0, s1, s2, s3, temp;
    uint8_t rc;

    /* Load the state into local variables */
    s0 = state->S[0];
    s1 = state->S[1];
    s2 = state->S[2];
    s3 = state->S[3];

    /* Perform all requested rounds */
    while (first > last) {
        /* Permute TK1, TK2, and TK3 for the next round */
        skinny64_inv_LFSR2(state->TK2[0]);
        skinny64_inv_LFSR2(state->TK2[1]);
        skinny64_inv_LFSR3(state->TK3[0]);
        skinny64_inv_LFSR3(state->TK3[1]);
        skinny64_inv_permute_tk(state->TK1);
        skinny64_inv_permute_tk(state->TK2);
        skinny64_inv_permute_tk(state->TK3);

        /* Inverse mix of the columns */
        temp = s0;
        s0 = s1;
        s1 = s2;
        s2 = s3;
        s3 = temp ^ s2;
        s2 ^= s0;
        s1 ^= s2;

        /* Shift the cells in the rows left */
        s1 = leftRotate4_16(s1);
        s2 = leftRotate8_16(s2);
        s3 = leftRotate12_16(s3);

        /* XOR the round constant and the subkey for this round */
        rc = RC[--first];
        s0 ^= state->TK1[0] ^ state->TK2[0] ^ state->TK3[0] ^
              ((rc & 0x0F) << 12) ^ 0x0020;
        s1 ^= state->TK1[1] ^ state->TK2[1] ^ state->TK3[1] ^
              ((rc & 0x70) << 8);
        s2 ^= 0x2000;

        /* Apply the inverse of the S-box to all cells in the state */
        skinny64_inv_sbox(s0);
        skinny64_inv_sbox(s1);
        skinny64_inv_sbox(s2);
        skinny64_inv_sbox(s3);
    }

    /* Save the local variables back to the state */
    state->S[0] = s0;
    state->S[1] = s1;
    state->S[2] = s2;
    state->S[3] = s3;
}

void forkskinny_64_192_forward_tk
    (forkskinny_64_192_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny64_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny64_LFSR2(state->TK2[0]);
            skinny64_LFSR2(state->TK2[1]);
            skinny64_LFSR2(state->TK2[2]);
            skinny64_LFSR2(state->TK2[3]);
            skinny64_LFSR3(state->TK3[0]);
            skinny64_LFSR3(state->TK3[1]);
            skinny64_LFSR3(state->TK3[2]);
            skinny64_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny64_permute_tk(state->TK1);
        skinny64_permute_tk(state->TK2);
        skinny64_permute_tk(state->TK3);
        skinny64_LFSR2(state->TK2[0]);
        skinny64_LFSR2(state->TK2[1]);
        skinny64_LFSR3(state->TK3[0]);
        skinny64_LFSR3(state->TK3[1]);
        --rounds;
    }
}

void forkskinny_64_192_reverse_tk
    (forkskinny_64_192_state_t *state, unsigned rounds)
{
    unsigned temp;

    /* The tweak permutation repeats every 16 rounds so we can avoid
     * some skinny64_inv_permute_tk() calls in the early stages.  During
     * the 16 rounds, the LFSR will be applied 8 times to every word */
    while (rounds >= 16) {
        for (temp = 0; temp < 8; ++temp) {
            skinny64_inv_LFSR2(state->TK2[0]);
            skinny64_inv_LFSR2(state->TK2[1]);
            skinny64_inv_LFSR2(state->TK2[2]);
            skinny64_inv_LFSR2(state->TK2[3]);
            skinny64_inv_LFSR3(state->TK3[0]);
            skinny64_inv_LFSR3(state->TK3[1]);
            skinny64_inv_LFSR3(state->TK3[2]);
            skinny64_inv_LFSR3(state->TK3[3]);
        }
        rounds -= 16;
    }

    /* Handle the left-over rounds */
    while (rounds > 0) {
        skinny64_inv_LFSR2(state->TK2[0]);
        skinny64_inv_LFSR2(state->TK2[1]);
        skinny64_inv_LFSR3(state->TK3[0]);
        skinny64_inv_LFSR3(state->TK3[1]);
        skinny64_inv_permute_tk(state->TK1);
        skinny64_inv_permute_tk(state->TK2);
        skinny64_inv_permute_tk(state->TK3);
        --rounds;
    }
}

#endif /* !__AVR__ */
