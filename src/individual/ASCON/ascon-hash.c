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

#define ASCON_HASH_RATE 8
#define ascon_hash_permute() \
    ascon_permute((ascon_state_t *)(state->s.state), 0)

aead_hash_algorithm_t const ascon_hash_algorithm = {
    "ASCON-HASH",
    sizeof(ascon_hash_state_t),
    ASCON_HASH_SIZE,
    AEAD_FLAG_NONE,
    ascon_hash,
    (aead_hash_init_t)ascon_hash_init,
    (aead_hash_update_t)ascon_hash_update,
    (aead_hash_finalize_t)ascon_hash_finalize,
    0, /* absorb */
    0  /* squeeze */
};

int ascon_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    ascon_hash_state_t state;
    ascon_hash_init(&state);
    ascon_hash_update(&state, in, inlen);
    ascon_hash_finalize(&state, out);
    return 0;
}

void ascon_hash_init(ascon_hash_state_t *state)
{
    static unsigned char const hash_iv[40] = {
        0xee, 0x93, 0x98, 0xaa, 0xdb, 0x67, 0xf0, 0x3d,
        0x8b, 0xb2, 0x18, 0x31, 0xc6, 0x0f, 0x10, 0x02,
        0xb4, 0x8a, 0x92, 0xdb, 0x98, 0xd5, 0xda, 0x62,
        0x43, 0x18, 0x99, 0x21, 0xb8, 0xf8, 0xe3, 0xe8,
        0x34, 0x8f, 0xa5, 0xc9, 0xd5, 0x25, 0xe1, 0x40
    };
    memcpy(state->s.state, hash_iv, sizeof(hash_iv));
    state->s.count = 0;
    state->s.mode = 0;
}

void ascon_hash_update
    (ascon_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    unsigned temp;

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = ASCON_HASH_RATE - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            lw_xor_block(state->s.state + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        lw_xor_block(state->s.state + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
        ascon_hash_permute();
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= ASCON_HASH_RATE) {
        lw_xor_block(state->s.state, in, ASCON_HASH_RATE);
        in += ASCON_HASH_RATE;
        inlen -= ASCON_HASH_RATE;
        ascon_hash_permute();
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    lw_xor_block(state->s.state, in, temp);
    state->s.count = temp;
}

void ascon_hash_finalize
    (ascon_hash_state_t *state, unsigned char *out)
{
    unsigned index;

    /* Pad the final block */
    state->s.state[state->s.count] ^= 0x80;

    /* Squeeze out the finalized hash value */
    for (index = 0; index < ASCON_HASH_SIZE; index += ASCON_HASH_RATE) {
        ascon_hash_permute();
        memcpy(out, state->s.state, ASCON_HASH_RATE);
        out += ASCON_HASH_RATE;
    }
}
