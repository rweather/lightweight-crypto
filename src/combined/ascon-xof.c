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

#include "ascon128.h"
#include "internal-ascon.h"
#include <string.h>

#define ASCON_XOF_RATE 8
#define ascon_xof_permute() \
    ascon_permute((ascon_state_t *)(state->s.state), 0)

aead_hash_algorithm_t const ascon_xof_algorithm = {
    "ASCON-XOF",
    sizeof(ascon_hash_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_xof,
    (aead_hash_init_t)ascon_xof_init,
    0, /* update */
    0, /* finalize */
    (aead_xof_absorb_t)ascon_xof_absorb,
    (aead_xof_squeeze_t)ascon_xof_squeeze
};

int ascon_xof
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    ascon_hash_state_t state;
    ascon_xof_init(&state);
    ascon_xof_absorb(&state, in, inlen);
    ascon_xof_squeeze(&state, out, ASCON_HASH_SIZE);
    return 0;
}

void ascon_xof_init(ascon_hash_state_t *state)
{
    static unsigned char const xof_iv[40] = {
        0xb5, 0x7e, 0x27, 0x3b, 0x81, 0x4c, 0xd4, 0x16,
        0x2b, 0x51, 0x04, 0x25, 0x62, 0xae, 0x24, 0x20,
        0x66, 0xa3, 0xa7, 0x76, 0x8d, 0xdf, 0x22, 0x18,
        0x5a, 0xad, 0x0a, 0x7a, 0x81, 0x53, 0x65, 0x0c,
        0x4f, 0x3e, 0x0e, 0x32, 0x53, 0x94, 0x93, 0xb6
    };
    memcpy(state->s.state, xof_iv, sizeof(xof_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

void ascon_xof_absorb
    (ascon_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    if (state->s.mode) {
        /* We were squeezing output - go back to the absorb phase */
        state->s.mode = 0;
        state->s.count = 0;
        ascon_xof_permute();
    }
    ascon_hash_update(state, in, inlen);
}

void ascon_xof_squeeze
    (ascon_hash_state_t *state, unsigned char *out, unsigned long long outlen)
{
    unsigned temp;

    /* Pad the final input block if we were still in the absorb phase */
    if (!state->s.mode) {
        state->s.state[state->s.count] ^= 0x80;
        state->s.count = 0;
        state->s.mode = 1;
    }

    /* Handle left-over partial blocks from last time */
    if (state->s.count) {
        temp = ASCON_XOF_RATE - state->s.count;
        if (temp > outlen) {
            temp = (unsigned)outlen;
            memcpy(out, state->s.state + state->s.count, temp);
            state->s.count += temp;
            return;
        }
        memcpy(out, state->s.state + state->s.count, temp);
        out += temp;
        outlen -= temp;
        state->s.count = 0;
    }

    /* Handle full blocks */
    while (outlen >= ASCON_XOF_RATE) {
        ascon_xof_permute();
        memcpy(out, state->s.state, ASCON_XOF_RATE);
        out += ASCON_XOF_RATE;
        outlen -= ASCON_XOF_RATE;
    }

    /* Handle the left-over block */
    if (outlen > 0) {
        temp = (unsigned)outlen;
        ascon_xof_permute();
        memcpy(out, state->s.state, temp);
        state->s.count = temp;
    }
}
