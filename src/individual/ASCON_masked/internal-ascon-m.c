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

#include "internal-ascon-m.h"
#include "internal-util.h"

void ascon_permute_masked(ascon_masked_state_t *state, uint8_t first_round)
{
    mask_uint64_t t0, t1;
    uint64_t temp;

    /* Create aliases for the masked state words */
    #define x0 (state->S[0])
    #define x1 (state->S[1])
    #define x2 (state->S[2])
    #define x3 (state->S[3])
    #define x4 (state->S[4])

    /* Perform all requested rounds */
    while (first_round < 12) {
        /* Add the round constant to the state */
        mask_xor_const(x2, ((0x0F - first_round) << 4) | first_round);

        /* Substitution layer */
        mask_xor(x0, x4);               /* x0 ^= x4; */
        mask_xor(x4, x3);               /* x4 ^= x3; */
        mask_xor(x2, x1);               /* x2 ^= x1; */
        t1 = x0;                        /* t1 = x0; */
        mask_zero(t0);                  /* t0 = (~x0) & x1; */
        mask_and_not(t0, x0, x1);
        mask_and_not(x0, x1, x2);       /* x0 ^= (~x1) & x2; */
        mask_and_not(x1, x2, x3);       /* x1 ^= (~x2) & x3; */
        mask_and_not(x2, x3, x4);       /* x2 ^= (~x3) & x4; */
        mask_and_not(x3, x4, t1);       /* x3 ^= (~x4) & t1; */
        mask_xor(x4, t0);               /* x4 ^= t0; */
        mask_xor(x1, x0);               /* x1 ^= x0; */
        mask_xor(x0, x4);               /* x0 ^= x4; */
        mask_xor(x3, x2);               /* x3 ^= x2; */
        mask_not(x2);                   /* x2 = ~x2; */

        /* Linear diffusion layer */
        /* x0 ^= rightRotate19_64(x0) ^ rightRotate28_64(x0); */
        mask_ror(t0, x0, 19);
        mask_ror(t1, x0, 28);
        mask_xor(x0, t0);
        mask_xor(x0, t1);
        /* x1 ^= rightRotate61_64(x1) ^ rightRotate39_64(x1); */
        mask_ror(t0, x1, 61);
        mask_ror(t1, x1, 39);
        mask_xor(x1, t0);
        mask_xor(x1, t1);
        /* x2 ^= rightRotate1_64(x2)  ^ rightRotate6_64(x2); */
        mask_ror(t0, x2, 1);
        mask_ror(t1, x2, 6);
        mask_xor(x2, t0);
        mask_xor(x2, t1);
        /* x3 ^= rightRotate10_64(x3) ^ rightRotate17_64(x3); */
        mask_ror(t0, x3, 10);
        mask_ror(t1, x3, 17);
        mask_xor(x3, t0);
        mask_xor(x3, t1);
        /* x4 ^= rightRotate7_64(x4)  ^ rightRotate41_64(x4); */
        mask_ror(t0, x4, 7);
        mask_ror(t1, x4, 41);
        mask_xor(x4, t0);
        mask_xor(x4, t1);

        /* Move onto the next round */
        ++first_round;
    }
}

void ascon_mask(ascon_masked_state_t *output, const ascon_state_t *input)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    mask_input(output->S[0], be_load_word64((const unsigned char *)(&(input->S[0]))));
    mask_input(output->S[1], be_load_word64((const unsigned char *)(&(input->S[1]))));
    mask_input(output->S[2], be_load_word64((const unsigned char *)(&(input->S[2]))));
    mask_input(output->S[3], be_load_word64((const unsigned char *)(&(input->S[3]))));
    mask_input(output->S[4], be_load_word64((const unsigned char *)(&(input->S[4]))));
#else
    mask_input(output->S[0], input->S[0]);
    mask_input(output->S[1], input->S[1]);
    mask_input(output->S[2], input->S[2]);
    mask_input(output->S[3], input->S[3]);
    mask_input(output->S[4], input->S[4]);
#endif
}

void ascon_unmask(ascon_state_t *output, const ascon_masked_state_t *input)
{
#if defined(LW_UTIL_LITTLE_ENDIAN)
    be_store_word64((unsigned char *)(&(output->S[0])), mask_output(input->S[0]));
    be_store_word64((unsigned char *)(&(output->S[1])), mask_output(input->S[1]));
    be_store_word64((unsigned char *)(&(output->S[2])), mask_output(input->S[2]));
    be_store_word64((unsigned char *)(&(output->S[3])), mask_output(input->S[3]));
    be_store_word64((unsigned char *)(&(output->S[4])), mask_output(input->S[4]));
#else
    output->S[0] = mask_output(input->S[0]);
    output->S[1] = mask_output(input->S[1]);
    output->S[2] = mask_output(input->S[2]);
    output->S[3] = mask_output(input->S[3]);
    output->S[4] = mask_output(input->S[4]);
#endif
}

#if ASCON_SLICED

void ascon_mask_sliced
    (ascon_masked_state_t *output, const ascon_state_t *input)
{
    int index;
    uint32_t high, low;
    for (index = 0; index < 10; index += 2) {
        high = (input->W[index] >> 16) | (input->W[index + 1] & 0xFFFF0000U);
        low  = (input->W[index] & 0x0000FFFFU) | (input->W[index + 1] << 16);
        ascon_combine(high);
        ascon_combine(low);
        mask_input(output->S[index / 2], (((uint64_t)high) << 32) | low);
    }
}

void ascon_unmask_sliced
    (ascon_state_t *output, const ascon_masked_state_t *input)
{
    int index;
    uint64_t value;
    uint32_t high, low;
    for (index = 0; index < 10; index += 2) {
        value = mask_output(input->S[index / 2]);
        high = (uint32_t)(value >> 32);
        low  = (uint32_t)value;
        ascon_separate(high);
        ascon_separate(low);
        output->W[index] = (high << 16) | (low & 0x0000FFFFU);
        output->W[index + 1] = (high & 0xFFFF0000U) | (low >> 16);
    }
}

#endif
