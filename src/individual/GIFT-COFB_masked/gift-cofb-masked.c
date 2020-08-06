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

#include "gift-cofb-masked.h"
#include "internal-gift128-m.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const gift_cofb_masked_cipher = {
    "GIFT-COFB-Masked",
    GIFT_COFB_MASKED_KEY_SIZE,
    GIFT_COFB_MASKED_NONCE_SIZE,
    GIFT_COFB_MASKED_TAG_SIZE,
    AEAD_FLAG_SC_PROTECT_ALL,
    gift_cofb_masked_aead_encrypt,
    gift_cofb_masked_aead_decrypt
};

/**
 * \brief Structure of an L value.
 *
 * The value is assumed to have already been converted from big-endian
 * to host byte order.
 */
typedef struct
{
    uint32_t x;     /**< High word of the value */
    uint32_t y;     /**< Low word of the value */

} gift_cofb_masked_l_t;

/**
 * \brief Structure of a masked 128-bit block in host byte order.
 *
 * The block is assumed to have already been converted from big-endian
 * to host byte order.
 */
typedef struct
{
    mask_uint32_t x[4]; /**< Words of the block in masked form */

} gift_cofb_masked_block_t;

/**
 * \brief Doubles an L value in the F(2^64) field.
 *
 * \param L The value to be doubled.
 *
 * L = L << 1 if the top-most bit is 0, or L = (L << 1) ^ 0x1B otherwise.
 */
#define gift_cofb_masked_double_L(L) \
    do { \
        uint32_t mask = ((int32_t)((L)->x)) >> 31; \
        (L)->x = ((L)->x << 1) | ((L)->y >> 31); \
        (L)->y = ((L)->y << 1) ^ (mask & 0x1B); \
    } while (0)

/**
 * \brief Triples an L value in the F(2^64) field.
 *
 * \param L The value to be tripled.
 *
 * L = double(L) ^ L
 */
#define gift_cofb_masked_triple_L(L) \
    do { \
        uint32_t mask = ((int32_t)((L)->x)) >> 31; \
        uint32_t tx = ((L)->x << 1) | ((L)->y >> 31); \
        uint32_t ty = ((L)->y << 1) ^ (mask & 0x1B); \
        (L)->x ^= tx; \
        (L)->y ^= ty; \
    } while (0)

/** @cond feedback_rotate */

#if AEAD_MASKING_SHARES == 2
#define gift_cofb_feedback_rotate(xout, yout, xin, yin) \
    do { \
        (xout).a = ((xin).a << 1) | ((yin).a >> 31); \
        (xout).b = ((xin).b << 1) | ((yin).b >> 31); \
        (yout).a = ((yin).a << 1) | ((xin).a >> 31); \
        (yout).b = ((yin).b << 1) | ((xin).b >> 31); \
    } while (0)
#elif AEAD_MASKING_SHARES == 3
#define gift_cofb_feedback_rotate(xout, yout, xin, yin) \
    do { \
        (xout).a = ((xin).a << 1) | ((yin).a >> 31); \
        (xout).b = ((xin).b << 1) | ((yin).b >> 31); \
        (xout).c = ((xin).c << 1) | ((yin).c >> 31); \
        (yout).a = ((yin).a << 1) | ((xin).a >> 31); \
        (yout).b = ((yin).b << 1) | ((xin).b >> 31); \
        (yout).c = ((yin).c << 1) | ((xin).c >> 31); \
    } while (0)
#elif AEAD_MASKING_SHARES == 4
#define gift_cofb_feedback_rotate(xout, yout, xin, yin) \
    do { \
        (xout).a = ((xin).a << 1) | ((yin).a >> 31); \
        (xout).b = ((xin).b << 1) | ((yin).b >> 31); \
        (xout).c = ((xin).c << 1) | ((yin).c >> 31); \
        (xout).d = ((xin).d << 1) | ((yin).d >> 31); \
        (yout).a = ((yin).a << 1) | ((xin).a >> 31); \
        (yout).b = ((yin).b << 1) | ((xin).b >> 31); \
        (yout).c = ((yin).c << 1) | ((xin).c >> 31); \
        (yout).d = ((yin).d << 1) | ((xin).d >> 31); \
    } while (0)
#elif AEAD_MASKING_SHARES == 5
#define gift_cofb_feedback_rotate(xout, yout, xin, yin) \
    do { \
        (xout).a = ((xin).a << 1) | ((yin).a >> 31); \
        (xout).b = ((xin).b << 1) | ((yin).b >> 31); \
        (xout).c = ((xin).c << 1) | ((yin).c >> 31); \
        (xout).d = ((xin).d << 1) | ((yin).d >> 31); \
        (xout).e = ((xin).e << 1) | ((yin).e >> 31); \
        (yout).a = ((yin).a << 1) | ((xin).a >> 31); \
        (yout).b = ((yin).b << 1) | ((xin).b >> 31); \
        (yout).c = ((yin).c << 1) | ((xin).c >> 31); \
        (yout).d = ((yin).d << 1) | ((xin).d >> 31); \
        (yout).e = ((yin).e << 1) | ((xin).e >> 31); \
    } while (0)
#elif AEAD_MASKING_SHARES == 6
#define gift_cofb_feedback_rotate(xout, yout, xin, yin) \
    do { \
        (xout).a = ((xin).a << 1) | ((yin).a >> 31); \
        (xout).b = ((xin).b << 1) | ((yin).b >> 31); \
        (xout).c = ((xin).c << 1) | ((yin).c >> 31); \
        (xout).d = ((xin).d << 1) | ((yin).d >> 31); \
        (xout).e = ((xin).e << 1) | ((yin).e >> 31); \
        (xout).f = ((xin).f << 1) | ((yin).f >> 31); \
        (yout).a = ((yin).a << 1) | ((xin).a >> 31); \
        (yout).b = ((yin).b << 1) | ((xin).b >> 31); \
        (yout).c = ((yin).c << 1) | ((xin).c >> 31); \
        (yout).d = ((yin).d << 1) | ((xin).d >> 31); \
        (yout).e = ((yin).e << 1) | ((xin).e >> 31); \
        (yout).f = ((yin).f << 1) | ((xin).f >> 31); \
    } while (0)
#else
#error "Unknown number of shares"
#endif

/** @endcond */

/**
 * \brief Applies the GIFT-COFB feedback function to Y.
 *
 * \param Y The value to be modified with the feedback function.
 *
 * Y is divided into L and R halves and then (R, L <<< 1) is returned.
 */
#define gift_cofb_masked_feedback(Y) \
    do { \
        mask_uint32_t lx = (Y)->x[0]; \
        mask_uint32_t ly = (Y)->x[1]; \
        (Y)->x[0] = (Y)->x[2]; \
        (Y)->x[1] = (Y)->x[3]; \
        gift_cofb_feedback_rotate((Y)->x[2], (Y)->x[3], lx, ly); \
    } while (0)

/**
 * \brief Process the associated data for GIFT-COFB encryption or decryption.
 *
 * \param ks The GIFT-128 key schedule to use.
 * \param Y GIFT-COFB internal state.
 * \param L GIFT-COFB internal state.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 * \param mlen Length of the plaintext in bytes.
 */
static void gift_cofb_masked_assoc_data
    (gift128b_masked_key_schedule_t *ks, gift_cofb_masked_block_t *Y,
     gift_cofb_masked_l_t *L, const unsigned char *ad,
     unsigned long long adlen, unsigned long long mlen)
{
    /* Deal with all associated data blocks except the last */
    while (adlen > 16) {
        gift_cofb_masked_double_L(L);
        gift_cofb_masked_feedback(Y);
        mask_xor_const(Y->x[0], L->x ^ be_load_word32(ad));
        mask_xor_const(Y->x[1], L->y ^ be_load_word32(ad + 4));
        mask_xor_const(Y->x[2], be_load_word32(ad + 8));
        mask_xor_const(Y->x[3], be_load_word32(ad + 12));
        gift128b_encrypt_preloaded_masked(ks, Y->x, Y->x);
        ad += 16;
        adlen -= 16;
    }

    /* Pad and deal with the last block */
    gift_cofb_masked_feedback(Y);
    if (adlen == 16) {
        mask_xor_const(Y->x[0], be_load_word32(ad));
        mask_xor_const(Y->x[1], be_load_word32(ad + 4));
        mask_xor_const(Y->x[2], be_load_word32(ad + 8));
        mask_xor_const(Y->x[3], be_load_word32(ad + 12));
        gift_cofb_masked_triple_L(L);
    } else {
        unsigned temp = (unsigned)adlen;
        unsigned char padded[16];
        memcpy(padded, ad, temp);
        padded[temp] = 0x80;
        memset(padded + temp + 1, 0, 16 - temp - 1);
        mask_xor_const(Y->x[0], be_load_word32(padded));
        mask_xor_const(Y->x[1], be_load_word32(padded + 4));
        mask_xor_const(Y->x[2], be_load_word32(padded + 8));
        mask_xor_const(Y->x[3], be_load_word32(padded + 12));
        gift_cofb_masked_triple_L(L);
        gift_cofb_masked_triple_L(L);
    }
    if (mlen == 0) {
        gift_cofb_masked_triple_L(L);
        gift_cofb_masked_triple_L(L);
    }
    mask_xor_const(Y->x[0], L->x);
    mask_xor_const(Y->x[1], L->y);
    gift128b_encrypt_preloaded_masked(ks, Y->x, Y->x);
}

/** @cond cofb_masked_byte_swap */

/* Byte-swap a block if the platform is little-endian */
#if defined(LW_UTIL_LITTLE_ENDIAN)
#define gift_cofb_masked_byte_swap_word(y) \
    (__extension__ ({ \
        uint32_t _y = (y); \
        (_y >> 24) | (_y << 24) | ((_y << 8) & 0x00FF0000U) | \
        ((_y >> 8) & 0x0000FF00U); \
    }))
#define gift_cofb_masked_byte_swap(x) \
    do { \
        (x)[0] = gift_cofb_masked_byte_swap_word((x)[0]); \
        (x)[1] = gift_cofb_masked_byte_swap_word((x)[1]); \
        (x)[2] = gift_cofb_masked_byte_swap_word((x)[2]); \
        (x)[3] = gift_cofb_masked_byte_swap_word((x)[3]); \
    } while (0)
#else
#define gift_cofb_masked_byte_swap(x) do { ; } while (0)
#endif

/** @endcond */

int gift_cofb_masked_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128b_masked_key_schedule_t ks;
    gift_cofb_masked_block_t Y;
    gift_cofb_masked_l_t L;
    uint32_t P[4];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + GIFT_COFB_MASKED_TAG_SIZE;

    /* Set up the key schedule and use it to encrypt the nonce */
    gift128b_init_masked(&ks, k);
    mask_input(Y.x[0], be_load_word32(npub));
    mask_input(Y.x[1], be_load_word32(npub + 4));
    mask_input(Y.x[2], be_load_word32(npub + 8));
    mask_input(Y.x[3], be_load_word32(npub + 12));
    gift128b_encrypt_preloaded_masked(&ks, Y.x, Y.x);
    L.x = mask_output(Y.x[0]);
    L.y = mask_output(Y.x[1]);

    /* Authenticate the associated data */
    gift_cofb_masked_assoc_data(&ks, &Y, &L, ad, adlen, mlen);

    /* Encrypt the plaintext to produce the ciphertext */
    if (mlen > 0) {
        /* Deal with all plaintext blocks except the last */
        while (mlen > 16) {
            P[0] = be_load_word32(m);
            P[1] = be_load_word32(m + 4);
            P[2] = be_load_word32(m + 8);
            P[3] = be_load_word32(m + 12);
            be_store_word32(c,      mask_output(Y.x[0]) ^ P[0]);
            be_store_word32(c + 4,  mask_output(Y.x[1]) ^ P[1]);
            be_store_word32(c + 8,  mask_output(Y.x[2]) ^ P[2]);
            be_store_word32(c + 12, mask_output(Y.x[3]) ^ P[3]);
            gift_cofb_masked_double_L(&L);
            gift_cofb_masked_feedback(&Y);
            mask_xor_const(Y.x[0], L.x ^ P[0]);
            mask_xor_const(Y.x[1], L.y ^ P[1]);
            mask_xor_const(Y.x[2], P[2]);
            mask_xor_const(Y.x[3], P[3]);
            gift128b_encrypt_preloaded_masked(&ks, Y.x, Y.x);
            c += 16;
            m += 16;
            mlen -= 16;
        }

        /* Pad and deal with the last plaintext block */
        if (mlen == 16) {
            P[0] = be_load_word32(m);
            P[1] = be_load_word32(m + 4);
            P[2] = be_load_word32(m + 8);
            P[3] = be_load_word32(m + 12);
            be_store_word32(c,      mask_output(Y.x[0]) ^ P[0]);
            be_store_word32(c + 4,  mask_output(Y.x[1]) ^ P[1]);
            be_store_word32(c + 8,  mask_output(Y.x[2]) ^ P[2]);
            be_store_word32(c + 12, mask_output(Y.x[3]) ^ P[3]);
            gift_cofb_masked_feedback(&Y);
            mask_xor_const(Y.x[0], P[0]);
            mask_xor_const(Y.x[1], P[1]);
            mask_xor_const(Y.x[2], P[2]);
            mask_xor_const(Y.x[3], P[3]);
            gift_cofb_masked_triple_L(&L);
            c += 16;
        } else {
            unsigned temp = (unsigned)mlen;
            union {
                uint32_t x[4];
                uint8_t y[16];
            } padded;
            memcpy(padded.y, m, temp);
            padded.y[temp] = 0x80;
            memset(padded.y + temp + 1, 0, 16 - temp - 1);
            P[0] = be_load_word32(padded.y);
            P[1] = be_load_word32(padded.y + 4);
            P[2] = be_load_word32(padded.y + 8);
            P[3] = be_load_word32(padded.y + 12);
            gift_cofb_masked_byte_swap(padded.x);
            padded.x[0] ^= mask_output(Y.x[0]);
            padded.x[1] ^= mask_output(Y.x[1]);
            padded.x[2] ^= mask_output(Y.x[2]);
            padded.x[3] ^= mask_output(Y.x[3]);
            gift_cofb_masked_byte_swap(padded.x);
            memcpy(c, padded.y, temp);
            gift_cofb_masked_feedback(&Y);
            mask_xor_const(Y.x[0], P[0]);
            mask_xor_const(Y.x[1], P[1]);
            mask_xor_const(Y.x[2], P[2]);
            mask_xor_const(Y.x[3], P[3]);
            gift_cofb_masked_triple_L(&L);
            gift_cofb_masked_triple_L(&L);
            c += temp;
        }
        mask_xor_const(Y.x[0], L.x);
        mask_xor_const(Y.x[1], L.y);
        gift128b_encrypt_preloaded_masked(&ks, Y.x, Y.x);
    }

    /* Generate the final authentication tag */
    be_store_word32(c,      mask_output(Y.x[0]));
    be_store_word32(c + 4,  mask_output(Y.x[1]));
    be_store_word32(c + 8,  mask_output(Y.x[2]));
    be_store_word32(c + 12, mask_output(Y.x[3]));
    return 0;
}

int gift_cofb_masked_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    gift128b_masked_key_schedule_t ks;
    gift_cofb_masked_block_t Y;
    gift_cofb_masked_l_t L;
    union {
        uint32_t x[4];
        uint8_t y[16];
    } P;
    unsigned char *mtemp;
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < GIFT_COFB_MASKED_TAG_SIZE)
        return -1;
    *mlen = clen - GIFT_COFB_MASKED_TAG_SIZE;

    /* Set up the key schedule and use it to encrypt the nonce */
    gift128b_init_masked(&ks, k);
    mask_input(Y.x[0], be_load_word32(npub));
    mask_input(Y.x[1], be_load_word32(npub + 4));
    mask_input(Y.x[2], be_load_word32(npub + 8));
    mask_input(Y.x[3], be_load_word32(npub + 12));
    gift128b_encrypt_preloaded_masked(&ks, Y.x, Y.x);
    L.x = mask_output(Y.x[0]);
    L.y = mask_output(Y.x[1]);

    /* Authenticate the associated data */
    gift_cofb_masked_assoc_data(&ks, &Y, &L, ad, adlen, *mlen);

    /* Decrypt the ciphertext to produce the plaintext */
    mtemp = m;
    clen -= GIFT_COFB_MASKED_TAG_SIZE;
    if (clen > 0) {
        /* Deal with all ciphertext blocks except the last */
        while (clen > 16) {
            P.x[0] = mask_output(Y.x[0]) ^ be_load_word32(c);
            P.x[1] = mask_output(Y.x[1]) ^ be_load_word32(c + 4);
            P.x[2] = mask_output(Y.x[2]) ^ be_load_word32(c + 8);
            P.x[3] = mask_output(Y.x[3]) ^ be_load_word32(c + 12);
            be_store_word32(m,      P.x[0]);
            be_store_word32(m + 4,  P.x[1]);
            be_store_word32(m + 8,  P.x[2]);
            be_store_word32(m + 12, P.x[3]);
            gift_cofb_masked_double_L(&L);
            gift_cofb_masked_feedback(&Y);
            mask_xor_const(Y.x[0], L.x ^ P.x[0]);
            mask_xor_const(Y.x[1], L.y ^ P.x[1]);
            mask_xor_const(Y.x[2], P.x[2]);
            mask_xor_const(Y.x[3], P.x[3]);
            gift128b_encrypt_preloaded_masked(&ks, Y.x, Y.x);
            c += 16;
            m += 16;
            clen -= 16;
        }

        /* Pad and deal with the last ciphertext block */
        if (clen == 16) {
            P.x[0] = mask_output(Y.x[0]) ^ be_load_word32(c);
            P.x[1] = mask_output(Y.x[1]) ^ be_load_word32(c + 4);
            P.x[2] = mask_output(Y.x[2]) ^ be_load_word32(c + 8);
            P.x[3] = mask_output(Y.x[3]) ^ be_load_word32(c + 12);
            be_store_word32(m,      P.x[0]);
            be_store_word32(m + 4,  P.x[1]);
            be_store_word32(m + 8,  P.x[2]);
            be_store_word32(m + 12, P.x[3]);
            gift_cofb_masked_feedback(&Y);
            mask_xor_const(Y.x[0], P.x[0]);
            mask_xor_const(Y.x[1], P.x[1]);
            mask_xor_const(Y.x[2], P.x[2]);
            mask_xor_const(Y.x[3], P.x[3]);
            gift_cofb_masked_triple_L(&L);
            c += 16;
        } else {
            unsigned temp = (unsigned)clen;
            P.x[0] = mask_output(Y.x[0]);
            P.x[1] = mask_output(Y.x[1]);
            P.x[2] = mask_output(Y.x[2]);
            P.x[3] = mask_output(Y.x[3]);
            gift_cofb_masked_byte_swap(P.x);
            lw_xor_block_2_dest(m, P.y, c, temp);
            P.y[temp] = 0x80;
            memset(P.y + temp + 1, 0, 16 - temp - 1);
            gift_cofb_masked_byte_swap(P.x);
            gift_cofb_masked_feedback(&Y);
            mask_xor_const(Y.x[0], P.x[0]);
            mask_xor_const(Y.x[1], P.x[1]);
            mask_xor_const(Y.x[2], P.x[2]);
            mask_xor_const(Y.x[3], P.x[3]);
            gift_cofb_masked_triple_L(&L);
            gift_cofb_masked_triple_L(&L);
            c += temp;
        }
        mask_xor_const(Y.x[0], L.x);
        mask_xor_const(Y.x[1], L.y);
        gift128b_encrypt_preloaded_masked(&ks, Y.x, Y.x);
    }

    /* Check the authentication tag at the end of the packet */
    P.x[0] = mask_output(Y.x[0]);
    P.x[1] = mask_output(Y.x[1]);
    P.x[2] = mask_output(Y.x[2]);
    P.x[3] = mask_output(Y.x[3]);
    gift_cofb_masked_byte_swap(P.x);
    return aead_check_tag(mtemp, *mlen, P.y, c, GIFT_COFB_MASKED_TAG_SIZE);
}
