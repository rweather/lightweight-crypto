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

#include "internal-chachapoly.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const internal_chachapoly_cipher = {
    "ChaChaPoly",
    CHACHAPOLY_KEY_SIZE,
    CHACHAPOLY_NONCE_SIZE,
    CHACHAPOLY_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    internal_chachapoly_aead_encrypt,
    internal_chachapoly_aead_decrypt
};

/**
 * \brief Structure of the ChaCha20 state as both an array of words
 * and an array of bytes.
 */
typedef union
{
    uint32_t words[16];     /**< Words in the state */
    uint8_t bytes[64];      /**< Bytes in the state */

} chacha20_state_t;

/* Perform a ChaCha quarter round operation */
#define quarterRound(a, b, c, d)    \
    do { \
        uint32_t _b = (b); \
        uint32_t _a = (a) + _b; \
        uint32_t _d = leftRotate((d) ^ _a, 16); \
        uint32_t _c = (c) + _d; \
        _b = leftRotate12(_b ^ _c); \
        _a += _b; \
        (d) = _d = leftRotate(_d ^ _a, 8); \
        _c += _d; \
        (a) = _a; \
        (b) = leftRotate7(_b ^ _c); \
        (c) = _c; \
    } while (0)

/**
 * \brief Executes the ChaCha20 hash core on an input memory block.
 *
 * \param output Output memory block, must be at least 16 words in length
 * and must not overlap with \a input.
 * \param input Input memory block, must be at least 16 words in length.
 */
static void chachaCore(uint32_t *output, const uint32_t *input)
{
    uint8_t round;
    uint8_t posn;

    /* Copy the input buffer to the output prior to the first round
     * and convert from little-endian to host byte order */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    for (posn = 0; posn < 16; ++posn)
        output[posn] = input[posn];
#else
    for (posn = 0; posn < 16; ++posn)
        output[posn] = le_load_word32((const uint8_t *)&(input[posn]));
#endif

    /* Perform the ChaCha rounds in sets of two */
    for (round = 20; round >= 2; round -= 2) {
        /* Column round */
        quarterRound(output[0], output[4], output[8],  output[12]);
        quarterRound(output[1], output[5], output[9],  output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);

        /* Diagonal round */
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[8],  output[13]);
        quarterRound(output[3], output[4], output[9],  output[14]);
    }

    /* Add the original input to the final output, convert back to
     * little-endian, and return the result */
#if defined(LW_UTIL_LITTLE_ENDIAN)
    for (posn = 0; posn < 16; ++posn)
        output[posn] += input[posn];
#else
    for (posn = 0; posn < 16; ++posn) {
        uint32_t temp = le_load_word32((const uint8_t *)&(input[posn]));
        temp += output[posn];
        le_store_word32((uint8_t *)&(output[posn]), temp);
    }
#endif
}

static const char tag256[] = "expand 32-byte k";

#if defined(LW_UTIL_LITTLE_ENDIAN)
#define set_counter(c) (state->words[12] = (c))
#else
#define set_counter(c) le_store_word32((uint8_t *)&(state->words[12]), (c))
#endif

STATIC_INLINE void chacha_encrypt
    (chacha20_state_t *state, chacha20_state_t *stream,
     unsigned char *out, const unsigned char *in, unsigned long long len)
{
    /* Note: For simplicity we limit the block counter to 32-bit which
     * limits the maximum packet size to 256Gb.  This should be OK. */
    uint32_t counter = 1;
    while (len >= 64) {
        set_counter(counter);
        chachaCore(stream->words, state->words);
        lw_xor_block_2_src(out, stream->bytes, in, 64);
        in += 64;
        out += 64;
        len -= 64;
        ++counter;
    }
    if (len > 0) {
        set_counter(counter);
        chachaCore(stream->words, state->words);
        lw_xor_block_2_src(out, stream->bytes, in, (unsigned)len);
    }
}

typedef uint32_t limb_t;    /**< Size of a multi-precision integer word */
typedef uint64_t dlimb_t;   /**< Size of a multi-precision integer dword */

#define LIMB_BITS (sizeof(limb_t) * 8)
#define BITS2LIMBS(bits) (((bits) + LIMB_BITS - 1) / LIMB_BITS)
#define NUM_LIMBS_128BIT BITS2LIMBS(128)
#define NUM_LIMBS_130BIT BITS2LIMBS(130)
#define NUM_LIMBS_256BIT BITS2LIMBS(256)

/**
 * \brief State information for Poly1305.
 */
typedef struct
{
    limb_t h[NUM_LIMBS_130BIT];     /**< Current hash value */
    limb_t c[NUM_LIMBS_130BIT];     /**< Collects up input data */
    limb_t r[NUM_LIMBS_128BIT];     /**< Key */

} poly1305_state_t;

#if defined(LW_UTIL_LITTLE_ENDIAN)
#define littleToHost(r,size)    do { ; } while (0)
#else
#define littleToHost(r,size)   \
    do { \
        for (uint8_t i = 0; i < (size); ++i) \
            (r)[i] = le_load_word32((const uint8_t *)((r) + i)); \
    } while (0)
#endif

static void poly1305_init
    (poly1305_state_t *state, unsigned char *key)
{
    /* Convert the key into the correct Poly1305 form */
    key[3] &= 0x0F;
    key[4] &= 0xFC;
    key[7] &= 0x0F;
    key[8] &= 0xFC;
    key[11] &= 0x0F;
    key[12] &= 0xFC;
    key[15] &= 0x0F;

    /* Copy the key into "r" and convert to host byte order */
    memcpy(state->r, key, 16);
    littleToHost(state->r, NUM_LIMBS_128BIT);

    /* Set the initial hash value to zero */
    memset(state->h, 0, sizeof(state->h));
}

static void poly1305_process_chunk(poly1305_state_t *state)
{
    limb_t t[NUM_LIMBS_256BIT + 1];
    dlimb_t carry;
    limb_t word;
    uint8_t i, j;

    /* Compute h = ((h + c) * r) mod (2^130 - 5) */

    /* Start with h += c.  We assume that h is less than (2^130 - 5) * 6
     * and that c is less than 2^129, so the result will be less than 2^133 */
    carry = 0;
    for (i = 0; i < NUM_LIMBS_130BIT; ++i) {
        carry += state->h[i];
        carry += state->c[i];
        state->h[i] = (limb_t)carry;
        carry >>= LIMB_BITS;
    }

    /* Multiply h by r.  We know that r is less than 2^124 because the
     * top 4 bits were AND-ed off by reset().  That makes h * r less
     * than 2^257.  Which is less than the (2^130 - 6)^2 we want for
     * the modulo reduction step that follows */
    carry = 0;
    word = state->r[0];
    for (i = 0; i < NUM_LIMBS_130BIT; ++i) {
        carry += ((dlimb_t)(state->h[i])) * word;
        t[i] = (limb_t)carry;
        carry >>= LIMB_BITS;
    }
    t[NUM_LIMBS_130BIT] = (limb_t)carry;
    for (i = 1; i < NUM_LIMBS_128BIT; ++i) {
        word = state->r[i];
        carry = 0;
        for (j = 0; j < NUM_LIMBS_130BIT; ++j) {
            carry += ((dlimb_t)(state->h[j])) * word;
            carry += t[i + j];
            t[i + j] = (limb_t)carry;
            carry >>= LIMB_BITS;
        }
        t[i + NUM_LIMBS_130BIT] = (limb_t)carry;
    }

    /* Reduce h * r modulo (2^130 - 5) by multiplying the high 130 bits by 5
     * and adding them to the low 130 bits */
    carry = ((dlimb_t)(t[NUM_LIMBS_128BIT] >> 2)) +
                      (t[NUM_LIMBS_128BIT] & ~((limb_t)3));
    t[NUM_LIMBS_128BIT] &= 0x0003;
    for (i = 0; i < NUM_LIMBS_128BIT; ++i) {
        /* Shift the next word of t up by (LIMB_BITS - 2) bits and then
         * multiply it by 5.  Breaking it down, we can add the results
         * of shifting up by LIMB_BITS and shifting up by (LIMB_BITS - 2).
         * The main wrinkle here is that this can result in an intermediate
         * carry that is (LIMB_BITS * 2 + 1) bits in size which doesn't
         * fit within a dlimb_t variable.  However, we can defer adding
         * (word << LIMB_BITS) until after the "carry >>= LIMB_BITS" step
         * because it won't affect the low bits of the carry */
        word = t[i + NUM_LIMBS_130BIT];
        carry += ((dlimb_t)word) << (LIMB_BITS - 2);
        carry += t[i];
        state->h[i] = (limb_t)carry;
        carry >>= LIMB_BITS;
        carry += word;
    }
    state->h[i] = (limb_t)(carry + t[NUM_LIMBS_128BIT]);

    /* At this point, h is either the answer of reducing modulo (2^130 - 5)
     * or it is at most 5 subtractions away from the answer we want.
     * Leave it as-is for now with h less than (2^130 - 5) * 6.  It is
     * still within a range where the next h * r step will not overflow */
}

static void poly1305_update
    (poly1305_state_t *state, const unsigned char *in,
     unsigned long long len, unsigned char padding)
{
    while (len >= 16) {
        /* Absorb the next 16 byte block */
        memcpy(state->c, in, 16);
        littleToHost(state->c, NUM_LIMBS_128BIT);
        state->c[NUM_LIMBS_128BIT] = 1;
        poly1305_process_chunk(state);
        in += 16;
        len -= 16;
    }
    if (len > 0) {
        /* Pad and absorb the last block */
        unsigned temp = (unsigned)len;
        unsigned char *cb = (unsigned char *)(state->c);
        memcpy(cb, in, temp);
        cb[temp] = padding;
        memset(cb + temp + 1, 0, 16 - temp - 1);
        littleToHost(state->c, NUM_LIMBS_128BIT);
        state->c[NUM_LIMBS_128BIT] = 1;
        poly1305_process_chunk(state);
    }
}

static void poly1305_finalize
    (poly1305_state_t *state, unsigned char *out, const unsigned char *nonce)
{
    dlimb_t carry;
    uint8_t i;
    limb_t t[NUM_LIMBS_256BIT + 1];
    limb_t mask, nmask;

    /* At this point, process_chunk has left h as a partially reduced
     * result that is less than (2^130 - 5) * 6.  Perform one more
     * reduction and a trial subtraction to produce the final result */

    /* Multiply the high bits of h by 5 and add them to the 130 low bits */
    carry = (dlimb_t)((state->h[NUM_LIMBS_128BIT] >> 2) +
                      (state->h[NUM_LIMBS_128BIT] & ~((limb_t)3)));
    state->h[NUM_LIMBS_128BIT] &= 0x0003;
    for (i = 0; i < NUM_LIMBS_128BIT; ++i) {
        carry += state->h[i];
        state->h[i] = (limb_t)carry;
        carry >>= LIMB_BITS;
    }
    state->h[i] += (limb_t)carry;

    /* Subtract (2^130 - 5) from h by computing t = h + 5 - 2^130.
     * The "minus 2^130" step is implicit */
    carry = 5;
    for (i = 0; i < NUM_LIMBS_130BIT; ++i) {
        carry += state->h[i];
        t[i] = (limb_t)carry;
        carry >>= LIMB_BITS;
    }

    /* Borrow occurs if bit 2^130 of the previous t result is zero.
     * Carefully turn this into a selection mask so we can select either
     * h or t as the final result.  We don't care about the highest word
     * of the result because we are about to drop it in the next step.
     * We have to do it this way to avoid giving away any information
     * about the value of h in the instruction timing */
    mask = (~((t[NUM_LIMBS_128BIT] >> 2) & 1)) + 1;
    nmask = ~mask;
    for (i = 0; i < NUM_LIMBS_128BIT; ++i) {
        state->h[i] = (state->h[i] & nmask) | (t[i] & mask);
    }

    /* Add the encrypted nonce and format the final hash */
    memcpy(state->c, nonce, 16);
    littleToHost(state->c, NUM_LIMBS_128BIT);
    carry = 0;
    for (i = 0; i < NUM_LIMBS_128BIT; ++i) {
        carry += state->h[i];
        carry += state->c[i];
#if defined(LW_UTIL_LITTLE_ENDIAN)
        state->h[i] = (limb_t)carry;
#else
        le_store_word32((uint8_t *)(&(state->h[i])), (limb_t)carry);
#endif
        carry >>= LIMB_BITS;
    }
    memcpy(out, state->h, 16);
}

int internal_chachapoly_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    chacha20_state_t state;
    chacha20_state_t stream;
    poly1305_state_t poly;
    unsigned char poly_nonce[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + CHACHAPOLY_TAG_SIZE;

    /* Set up the key and nonce in the ChaCha20 state */
    memcpy(state.bytes, tag256, 16);
    memcpy(state.bytes + 16, k, 32);
    state.words[12] = 0;
    state.words[13] = 0;
    memcpy(state.bytes + 56, npub, 8);

    /* Generate the key and nonce to use for Poly1305 and initialize it */
    chachaCore(stream.words, state.words);
    poly1305_init(&poly, stream.bytes);
    memcpy(poly_nonce, stream.bytes + 16, 16);

    /* Absorb the associated data into the Poly1305 state */
    poly1305_update(&poly, ad, adlen, 0);

    /* Encrypt the plaintext to produce the ciphertext */
    chacha_encrypt(&state, &stream, c, m, mlen);

    /* Absorb the ciphertext into the Poly1305 state */
    poly1305_update(&poly, c, mlen, 0);

    /* Absorb adlen and mlen into the Poly1305 state */
    le_store_word64(stream.bytes, adlen);
    le_store_word64(stream.bytes + 8, mlen);
    poly1305_update(&poly, stream.bytes, 16, 1);

    /* Compute the final Poly1305 authentication tag */
    poly1305_finalize(&poly, c + mlen, poly_nonce);
    return 0;
}

int internal_chachapoly_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    chacha20_state_t state;
    chacha20_state_t stream;
    poly1305_state_t poly;
    unsigned char poly_nonce[16];
    (void)nsec;

    /* Set the length of the returned plaintext */
    if (clen < CHACHAPOLY_TAG_SIZE)
        return -1;
    *mlen = clen - CHACHAPOLY_TAG_SIZE;

    /* Set up the key and nonce in the ChaCha20 state */
    memcpy(state.bytes, tag256, 16);
    memcpy(state.bytes + 16, k, 32);
    state.words[12] = 0;
    state.words[13] = 0;
    memcpy(state.bytes + 56, npub, 8);

    /* Generate the key and nonce to use for Poly1305 and initialize it */
    chachaCore(stream.words, state.words);
    poly1305_init(&poly, stream.bytes);
    memcpy(poly_nonce, stream.bytes + 16, 16);

    /* Absorb the associated data into the Poly1305 state */
    poly1305_update(&poly, ad, adlen, 0);

    /* Absorb the ciphertext into the Poly1305 state */
    poly1305_update(&poly, c, *mlen, 0);

    /* Decrypt the ciphertext to produce the plaintext */
    chacha_encrypt(&state, &stream, m, c, *mlen);

    /* Absorb adlen and mlen into the Poly1305 state */
    le_store_word64(stream.bytes, adlen);
    le_store_word64(stream.bytes + 8, *mlen);
    poly1305_update(&poly, stream.bytes, 16, 1);

    /* Check the final Poly1305 authentication tag */
    poly1305_finalize(&poly, stream.bytes, poly_nonce);
    return aead_check_tag(m, *mlen, stream.bytes, c + *mlen, 16);
}
