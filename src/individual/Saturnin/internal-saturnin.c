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

#include "internal-saturnin.h"

#if !defined(__AVR__)

/* Round constants for various combinations of rounds and domain_sep */
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

/* Loads a 32-bit word from the two halves of a 256-bit Saturnin input block */
#define saturnin_load_word32(ptr) \
    ((((uint32_t)((ptr)[17])) << 24) | \
     (((uint32_t)((ptr)[16])) << 16) | \
     (((uint32_t)((ptr)[1]))  << 8) | \
      ((uint32_t)((ptr)[0])))

/* Stores a 32-bit word to the two halves of a 256-bit Saturnin output block */
#define saturnin_store_word32(ptr, x) \
    do { \
        (ptr)[0]  = (uint8_t)(x); \
        (ptr)[1]  = (uint8_t)((x) >> 8); \
        (ptr)[16] = (uint8_t)((x) >> 16); \
        (ptr)[17] = (uint8_t)((x) >> 24); \
    } while (0)

/* Rotate the 4-bit nibbles within a 16-bit word left */
#define leftRotate4_N(a, mask1, bits1, mask2, bits2) \
    do { \
        (a) = (((a) & (mask1)) << (bits1)) | \
              (((a) & ((mask1) ^ (uint32_t)0xFFFFU)) >> (4 - (bits1))) | \
              (((a) & (((uint32_t)(mask2)) << 16)) << (bits2)) | \
              (((a) & (((uint32_t)((mask2)) << 16) ^ 0xFFFF0000U)) >> (4 - (bits2))); \
    } while (0)

/* Rotate 16-bit subwords left */
#define leftRotate16_N(a, mask1, bits1, mask2, bits2) \
    do { \
        (a) = (((a) & (mask1)) << (bits1)) | \
              (((a) & ((mask1) ^ (uint32_t)0xFFFFU)) >> (16 - (bits1))) | \
              (((a) & (((uint32_t)(mask2)) << 16)) << (bits2)) | \
              (((a) & (((uint32_t)((mask2)) << 16) ^ 0xFFFF0000U)) >> (16 - (bits2))); \
    } while (0)

/**
 * \brief XOR the key into the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 */
#define saturnin_xor_key(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        x0 ^= ks->k[0]; \
        x1 ^= ks->k[1]; \
        x2 ^= ks->k[2]; \
        x3 ^= ks->k[3]; \
        x4 ^= ks->k[4]; \
        x5 ^= ks->k[5]; \
        x6 ^= ks->k[6]; \
        x7 ^= ks->k[7]; \
    } while (0)

/**
 * \brief XOR a rotated version of the key into the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 */
#define saturnin_xor_key_rotated(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        x0 ^= ks->k[8]; \
        x1 ^= ks->k[9]; \
        x2 ^= ks->k[10]; \
        x3 ^= ks->k[11]; \
        x4 ^= ks->k[12]; \
        x5 ^= ks->k[13]; \
        x6 ^= ks->k[14]; \
        x7 ^= ks->k[15]; \
    } while (0)

/**
 * \brief Applies the Saturnin S-box to a bit-sliced set of nibbles.
 *
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 *
 * The S-box also involves a rotation on the output words.  We perform the
 * rotation implicitly in the higher layers.
 */
#define saturnin_sbox(a, b, c, d) \
    do { \
        (a) ^= (b) & (c); \
        (b) ^= (a) | (d); \
        (d) ^= (b) | (c); \
        (c) ^= (b) & (d); \
        (b) ^= (a) | (c); \
        (a) ^= (b) | (d); \
    } while (0)

/**
 * \brief Applies the inverse of the Saturnin S-box to a set of nibbles.
 *
 * \param a First bit-slice.
 * \param b Second bit-slice.
 * \param c Third bit-slice.
 * \param d Fourth bit-slice.
 *
 * The inverse of the S-box also involves a rotation on the input words.
 * We perform the rotation implicitly in the higher layers.
 */
#define saturnin_sbox_inverse(a, b, c, d) \
    do { \
        (a) ^= (b) | (d); \
        (b) ^= (a) | (c); \
        (c) ^= (b) & (d); \
        (d) ^= (b) | (c); \
        (b) ^= (a) | (d); \
        (a) ^= (b) & (c); \
    } while (0)

/* Helpers for MDS matrix operations, with word rotations done implicitly */
#define SWAP(a) (((a) << 16) | ((a) >> 16))
#define MUL(x0, x1, x2, x3) \
    do { \
        /*temp = x0; x0 = x1; x1 = x2; x2 = x3; x3 = temp ^ x0;*/ \
        x0 ^= x1; \
    } while (0)
#define MULINV(x0, x1, x2, x3) \
    do { \
        /*temp = x3; x3 = x2; x2 = x1; x1 = x0; x0 = x1 ^ temp;*/ \
        x3 ^= x0; \
    } while (0)

/**
 * \brief Applies the MDS matrix to the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 *
 * The rotations for the MUL() operations are performed implicitly.
 * The words of the bit-sliced state on exit will appear in the
 * words x2, x3, x0, x1, x5, x6, x7, x4 in that order.  Follow-on
 * steps need to take the new ordering into account.
 */
#define saturnin_mds(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7; \
        MUL(x4, x5, x6, x7); \
        x5 ^= SWAP(x0); x6 ^= SWAP(x1); \
        x7 ^= SWAP(x2); x4 ^= SWAP(x3); \
        MUL(x0, x1, x2, x3); \
        MUL(x1, x2, x3, x0); \
        x2 ^= x5; x3 ^= x6; x0 ^= x7; x1 ^= x4; \
        x5 ^= SWAP(x2); x6 ^= SWAP(x3); \
        x7 ^= SWAP(x0); x4 ^= SWAP(x1); \
    } while (0)

/**
 * \brief Applies the inverse of the MDS matrix to the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 *
 * The rotations for the MULINV() operations are performed implicitly.
 * The words of the bit-sliced state on exit will appear in the
 * words x2, x3, x0, x1, x7, x4, x5, x6 in that order.  Follow-on
 * steps need to take the new ordering into account.
 */
#define saturnin_mds_inverse(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        x6 ^= SWAP(x2); x7 ^= SWAP(x3); \
        x4 ^= SWAP(x0); x5 ^= SWAP(x1); \
        x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7; \
        MULINV(x0, x1, x2, x3); \
        MULINV(x3, x0, x1, x2); \
        x6 ^= SWAP(x0); x7 ^= SWAP(x1); \
        x4 ^= SWAP(x2); x5 ^= SWAP(x3); \
        MULINV(x4, x5, x6, x7); \
        x2 ^= x7; x3 ^= x4; x0 ^= x5; x1 ^= x6; \
    } while (0)

/**
 * \brief Applies the slice permutation to the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 */
#define saturnin_slice(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        leftRotate4_N(x0, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x1, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x2, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x3, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x4, 0x7777U, 1, 0x1111, 3); \
        leftRotate4_N(x5, 0x7777U, 1, 0x1111, 3); \
        leftRotate4_N(x6, 0x7777U, 1, 0x1111, 3); \
        leftRotate4_N(x7, 0x7777U, 1, 0x1111, 3); \
    } while (0)

/**
 * \brief Applies the inverse of the slice permutation to the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 */
#define saturnin_slice_inverse(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        leftRotate4_N(x0, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x1, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x2, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x3, 0xFFFFU, 0, 0x3333, 2); \
        leftRotate4_N(x4, 0x1111U, 3, 0x7777, 1); \
        leftRotate4_N(x5, 0x1111U, 3, 0x7777, 1); \
        leftRotate4_N(x6, 0x1111U, 3, 0x7777, 1); \
        leftRotate4_N(x7, 0x1111U, 3, 0x7777, 1); \
    } while (0)

/**
 * \brief Applies the sheet permutation to the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 */
#define saturnin_sheet(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        leftRotate16_N(x0, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x1, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x2, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x3, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x4, 0x0FFFU, 4, 0x000F, 12); \
        leftRotate16_N(x5, 0x0FFFU, 4, 0x000F, 12); \
        leftRotate16_N(x6, 0x0FFFU, 4, 0x000F, 12); \
        leftRotate16_N(x7, 0x0FFFU, 4, 0x000F, 12); \
    } while (0)

/**
 * \brief Applies the inverse of the sheet permutation to the Saturnin state.
 *
 * \param x0 First word of the bit-sliced state.
 * \param x1 Second word of the bit-sliced state.
 * \param x2 Third word of the bit-sliced state.
 * \param x3 Fourth word of the bit-sliced state.
 * \param x4 Fifth word of the bit-sliced state.
 * \param x5 Sixth word of the bit-sliced state.
 * \param x6 Seventh word of the bit-sliced state.
 * \param x7 Eighth word of the bit-sliced state.
 */
#define saturnin_sheet_inverse(x0, x1, x2, x3, x4, x5, x6, x7) \
    do { \
        leftRotate16_N(x0, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x1, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x2, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x3, 0xFFFFU, 0, 0x00FF, 8); \
        leftRotate16_N(x4, 0x000FU, 12, 0x0FFF, 4); \
        leftRotate16_N(x5, 0x000FU, 12, 0x0FFF, 4); \
        leftRotate16_N(x6, 0x000FU, 12, 0x0FFF, 4); \
        leftRotate16_N(x7, 0x000FU, 12, 0x0FFF, 4); \
    } while (0)

void saturnin_setup_key
    (saturnin_key_schedule_t *ks, const unsigned char *key)
{
    int index;
    uint32_t temp;
    for (index = 0; index < 16; index += 2) {
        temp = saturnin_load_word32(key + index);
        ks->k[index / 2] = temp;
        ks->k[8 + (index / 2)] = ((temp & 0x001F001FU) << 11) |
                                 ((temp >> 5) & 0x07FF07FFU);
    }
}

void saturnin_encrypt_block
    (const saturnin_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned domain)
{
    unsigned rounds = (domain >= SATURNIN_DOMAIN_16_7) ? 8 : 5;
    const uint32_t *rc = saturnin_rc + domain;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;

    /* Load the input into local variables */
    x0 = saturnin_load_word32(input);
    x1 = saturnin_load_word32(input + 2);
    x2 = saturnin_load_word32(input + 4);
    x3 = saturnin_load_word32(input + 6);
    x4 = saturnin_load_word32(input + 8);
    x5 = saturnin_load_word32(input + 10);
    x6 = saturnin_load_word32(input + 12);
    x7 = saturnin_load_word32(input + 14);

    /* XOR the key into the state */
    saturnin_xor_key(x0, x1, x2, x3, x4, x5, x6, x7);

    /* Perform all encryption rounds, two at a time */
    for (; rounds > 0; --rounds, rc += 2) {
        /* Even rounds */
        saturnin_sbox(x0, x1, x2, x3);
        saturnin_sbox(x4, x5, x6, x7);
        saturnin_mds(x1, x2, x3, x0, x7, x5, x4, x6);
        saturnin_sbox(x3, x0, x1, x2);
        saturnin_sbox(x5, x4, x6, x7);
        saturnin_slice(x0, x1, x2, x3, x7, x4, x5, x6);
        saturnin_mds(x0, x1, x2, x3, x7, x4, x5, x6);
        saturnin_slice_inverse(x2, x3, x0, x1, x4, x5, x6, x7);
        x2 ^= rc[0];
        saturnin_xor_key_rotated(x2, x3, x0, x1, x4, x5, x6, x7);

        /* Odd rounds */
        saturnin_sbox(x2, x3, x0, x1);
        saturnin_sbox(x4, x5, x6, x7);
        saturnin_mds(x3, x0, x1, x2, x7, x5, x4, x6);
        saturnin_sbox(x1, x2, x3, x0);
        saturnin_sbox(x5, x4, x6, x7);
        saturnin_sheet(x2, x3, x0, x1, x7, x4, x5, x6);
        saturnin_mds(x2, x3, x0, x1, x7, x4, x5, x6);
        saturnin_sheet_inverse(x0, x1, x2, x3, x4, x5, x6, x7);
        x0 ^= rc[1];
        saturnin_xor_key(x0, x1, x2, x3, x4, x5, x6, x7);
    }

    /* Store the local variables to the output buffer */
    saturnin_store_word32(output,      x0);
    saturnin_store_word32(output +  2, x1);
    saturnin_store_word32(output +  4, x2);
    saturnin_store_word32(output +  6, x3);
    saturnin_store_word32(output +  8, x4);
    saturnin_store_word32(output + 10, x5);
    saturnin_store_word32(output + 12, x6);
    saturnin_store_word32(output + 14, x7);
}

void saturnin_decrypt_block
    (const saturnin_key_schedule_t *ks, unsigned char *output,
     const unsigned char *input, unsigned domain)
{
    unsigned rounds = (domain >= SATURNIN_DOMAIN_16_7) ? 8 : 5;
    const uint32_t *rc = saturnin_rc + domain + (rounds - 1) * 2;
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;

    /* Load the input into local variables */
    x0 = saturnin_load_word32(input);
    x1 = saturnin_load_word32(input + 2);
    x2 = saturnin_load_word32(input + 4);
    x3 = saturnin_load_word32(input + 6);
    x4 = saturnin_load_word32(input + 8);
    x5 = saturnin_load_word32(input + 10);
    x6 = saturnin_load_word32(input + 12);
    x7 = saturnin_load_word32(input + 14);

    /* Perform all decryption rounds, two at a time */
    for (; rounds > 0; --rounds, rc -= 2) {
        /* Odd rounds */
        saturnin_xor_key(x0, x1, x2, x3, x4, x5, x6, x7);
        x0 ^= rc[1];
        saturnin_sheet(x0, x1, x2, x3, x4, x5, x6, x7);
        saturnin_mds_inverse(x0, x1, x2, x3, x4, x5, x6, x7);
        saturnin_sheet_inverse(x2, x3, x0, x1, x7, x4, x5, x6);
        saturnin_sbox_inverse(x1, x2, x3, x0);
        saturnin_sbox_inverse(x5, x4, x6, x7);
        saturnin_mds_inverse(x1, x2, x3, x0, x5, x4, x6, x7);
        saturnin_sbox_inverse(x2, x3, x0, x1);
        saturnin_sbox_inverse(x4, x5, x6, x7);

        /* Even rounds */
        saturnin_xor_key_rotated(x2, x3, x0, x1, x4, x5, x6, x7);
        x2 ^= rc[0];
        saturnin_slice(x2, x3, x0, x1, x4, x5, x6, x7);
        saturnin_mds_inverse(x2, x3, x0, x1, x4, x5, x6, x7);
        saturnin_slice_inverse(x0, x1, x2, x3, x7, x4, x5, x6);
        saturnin_sbox_inverse(x3, x0, x1, x2);
        saturnin_sbox_inverse(x5, x4, x6, x7);
        saturnin_mds_inverse(x3, x0, x1, x2, x5, x4, x6, x7);
        saturnin_sbox_inverse(x0, x1, x2, x3);
        saturnin_sbox_inverse(x4, x5, x6, x7);
    }

    /* XOR the key into the state */
    saturnin_xor_key(x0, x1, x2, x3, x4, x5, x6, x7);

    /* Store the local variables to the output buffer */
    saturnin_store_word32(output,      x0);
    saturnin_store_word32(output +  2, x1);
    saturnin_store_word32(output +  4, x2);
    saturnin_store_word32(output +  6, x3);
    saturnin_store_word32(output +  8, x4);
    saturnin_store_word32(output + 10, x5);
    saturnin_store_word32(output + 12, x6);
    saturnin_store_word32(output + 14, x7);
}

#endif /* !__AVR__ */
