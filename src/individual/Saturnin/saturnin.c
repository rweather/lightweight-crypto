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

#include "saturnin.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const saturnin_cipher = {
    "SATURNIN-CTR-Cascade",
    SATURNIN_KEY_SIZE,
    SATURNIN_NONCE_SIZE,
    SATURNIN_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    saturnin_aead_encrypt,
    saturnin_aead_decrypt
};

aead_cipher_t const saturnin_short_cipher = {
    "SATURNIN-Short",
    SATURNIN_KEY_SIZE,
    SATURNIN_NONCE_SIZE,
    SATURNIN_TAG_SIZE,
    AEAD_FLAG_NONE,
    saturnin_short_aead_encrypt,
    saturnin_short_aead_decrypt
};

aead_hash_algorithm_t const saturnin_hash_algorithm = {
    "SATURNIN-Hash",
    sizeof(saturnin_hash_state_t),
    SATURNIN_HASH_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    saturnin_hash,
    (aead_hash_init_t)saturnin_hash_init,
    (aead_hash_update_t)saturnin_hash_update,
    (aead_hash_finalize_t)saturnin_hash_finalize,
    0, /* absorb */
    0  /* squeeze */
};

/* Round constant tables for various combinations of rounds and domain_sep */
static uint32_t const RC_10_1[] = {
    0x4eb026c2, 0x90595303, 0xaa8fe632, 0xfe928a92, 0x4115a419,
    0x93539532, 0x5db1cc4e, 0x541515ca, 0xbd1f55a8, 0x5a6e1a0d
};
static uint32_t const RC_10_2[] = {
    0x4e4526b5, 0xa3565ff0, 0x0f8f20d8, 0x0b54bee1, 0x7d1a6c9d,
    0x17a6280a, 0xaa46c986, 0xc1199062, 0x182c5cde, 0xa00d53fe
};
static uint32_t const RC_10_3[] = {
    0x4e162698, 0xb2535ba1, 0x6c8f9d65, 0x5816ad30, 0x691fd4fa,
    0x6bf5bcf9, 0xf8eb3525, 0xb21decfa, 0x7b3da417, 0xf62c94b4
};
static uint32_t const RC_10_4[] = {
    0x4faf265b, 0xc5484616, 0x45dcad21, 0xe08bd607, 0x0504fdb8,
    0x1e1f5257, 0x45fbc216, 0xeb529b1f, 0x52194e32, 0x5498c018
};
static uint32_t const RC_10_5[] = {
    0x4ffc2676, 0xd44d4247, 0x26dc109c, 0xb3c9c5d6, 0x110145df,
    0x624cc6a4, 0x17563eb5, 0x9856e787, 0x3108b6fb, 0x02b90752
};
static uint32_t const RC_10_6[] = {
    0x4f092601, 0xe7424eb4, 0x83dcd676, 0x460ff1a5, 0x2d0e8d5b,
    0xe6b97b9c, 0xe0a13b7d, 0x0d5a622f, 0x943bbf8d, 0xf8da4ea1
};
static uint32_t const RC_16_7[] = {
    0x3fba180c, 0x563ab9ab, 0x125ea5ef, 0x859da26c, 0xb8cf779b,
    0x7d4de793, 0x07efb49f, 0x8d525306, 0x1e08e6ab, 0x41729f87,
    0x8c4aef0a, 0x4aa0c9a7, 0xd93a95ef, 0xbb00d2af, 0xb62c5bf0,
    0x386d94d8
};
static uint32_t const RC_16_8[] = {
    0x3c9b19a7, 0xa9098694, 0x23f878da, 0xa7b647d3, 0x74fc9d78,
    0xeacaae11, 0x2f31a677, 0x4cc8c054, 0x2f51ca05, 0x5268f195,
    0x4f5b8a2b, 0xf614b4ac, 0xf1d95401, 0x764d2568, 0x6a493611,
    0x8eef9c3e
};

/* Rotate the 4-bit nibbles within a 16-bit word left */
#define leftRotate4_N(a, mask1, bits1, mask2, bits2) \
    do { \
        uint32_t _temp = (a); \
        (a) = ((_temp & (mask1)) << (bits1)) | \
              ((_temp & ((mask1) ^ 0xFFFFU)) >> (4 - (bits1))) | \
              ((_temp & ((mask2) << 16)) << (bits2)) | \
              ((_temp & (((mask2) << 16) ^ 0xFFFF0000U)) >> (4 - (bits2))); \
    } while (0)

/* Rotate 16-bit subwords left */
#define leftRotate16_N(a, mask1, bits1, mask2, bits2) \
    do { \
        uint32_t _temp = (a); \
        (a) = ((_temp & (mask1)) << (bits1)) | \
              ((_temp & ((mask1) ^ 0xFFFFU)) >> (16 - (bits1))) | \
              ((_temp & ((mask2) << 16)) << (bits2)) | \
              ((_temp & (((mask2) << 16) ^ 0xFFFF0000U)) >> (16 - (bits2))); \
    } while (0)

/* XOR the SATURNIN state with the key */
#define saturnin_xor_key() \
    do { \
        for (index = 0; index < 8; ++index) \
            S[index] ^= K[index]; \
    } while (0)

/* XOR the SATURNIN state with a rotated version of the key */
#define saturnin_xor_key_rotated() \
    do { \
        for (index = 0; index < 8; ++index) \
            S[index] ^= K[index + 8]; \
    } while (0)

/* Apply an SBOX layer for SATURNIN - definition from the specification */
#define S_LAYER(a, b, c, d) \
    do { \
        (a) ^= (b) & (c); \
        (b) ^= (a) | (d); \
        (d) ^= (b) | (c); \
        (c) ^= (b) & (d); \
        (b) ^= (a) | (c); \
        (a) ^= (b) | (d); \
    } while (0)

/* Apply an SBOX layer for SATURNIN in reverse */
#define S_LAYER_INVERSE(a, b, c, d) \
    do { \
        (a) ^= (b) | (d); \
        (b) ^= (a) | (c); \
        (c) ^= (b) & (d); \
        (d) ^= (b) | (c); \
        (b) ^= (a) | (d); \
        (a) ^= (b) & (c); \
    } while (0)

/**
 * \brief Applies the SBOX to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_sbox(uint32_t S[8])
{
    uint32_t a, b, c, d;

    /* PI_0 on the first half of the state */
    a = S[0]; b = S[1]; c = S[2]; d = S[3];
    S_LAYER(a, b, c, d);
    S[0] = b; S[1] = c; S[2] = d; S[3] = a;

    /* PI_1 on the second half of the state */
    a = S[4]; b = S[5]; c = S[6]; d = S[7];
    S_LAYER(a, b, c, d);
    S[4] = d; S[5] = b; S[6] = a; S[7] = c;
}

/**
 * \brief Applies the inverse of the SBOX to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_sbox_inverse(uint32_t S[8])
{
    uint32_t a, b, c, d;

    /* PI_0 on the first half of the state */
    b = S[0]; c = S[1]; d = S[2]; a = S[3];
    S_LAYER_INVERSE(a, b, c, d);
    S[0] = a; S[1] = b; S[2] = c; S[3] = d;

    /* PI_1 on the second half of the state */
    d = S[4]; b = S[5]; a = S[6]; c = S[7];
    S_LAYER_INVERSE(a, b, c, d);
    S[4] = a; S[5] = b; S[6] = c; S[7] = d;
}

/**
 * \brief Applies the MDS matrix to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_mds(uint32_t S[8])
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t tmp;

    /* Load the state into temporary working variables */
    x0 = S[0]; x1 = S[1]; x2 = S[2]; x3 = S[3];
    x4 = S[4]; x5 = S[5]; x6 = S[6]; x7 = S[7];

    /* Apply the MDS matrix to the state */
    #define SWAP(a) (((a) << 16) | ((a) >> 16))
    #define MUL(x0, x1, x2, x3, tmp) \
        do { \
            tmp = x0; x0 = x1; x1 = x2; x2 = x3; x3 = tmp ^ x0; \
        } while (0)
    x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    MUL(x4, x5, x6, x7, tmp);
    x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    MUL(x0, x1, x2, x3, tmp);
    MUL(x0, x1, x2, x3, tmp);
    x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    x6 ^= SWAP(x2); x7 ^= SWAP(x3);

    /* Store the temporary working variables back into the state */
    S[0] = x0; S[1] = x1; S[2] = x2; S[3] = x3;
    S[4] = x4; S[5] = x5; S[6] = x6; S[7] = x7;
}

/**
 * \brief Applies the inverse of the MDS matrix to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_mds_inverse(uint32_t S[8])
{
    uint32_t x0, x1, x2, x3, x4, x5, x6, x7;
    uint32_t tmp;

    /* Load the state into temporary working variables */
    x0 = S[0]; x1 = S[1]; x2 = S[2]; x3 = S[3];
    x4 = S[4]; x5 = S[5]; x6 = S[6]; x7 = S[7];

    /* Apply the inverse of the MDS matrix to the state */
    #define MULINV(x0, x1, x2, x3, tmp) \
        do { \
            tmp = x3; x3 = x2; x2 = x1; x1 = x0; x0 = x1 ^ tmp; \
        } while (0)
    x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;
    MULINV(x0, x1, x2, x3, tmp);
    MULINV(x0, x1, x2, x3, tmp);
    x6 ^= SWAP(x2); x7 ^= SWAP(x3);
    x4 ^= SWAP(x0); x5 ^= SWAP(x1);
    MULINV(x4, x5, x6, x7, tmp);
    x0 ^= x4; x1 ^= x5; x2 ^= x6; x3 ^= x7;

    /* Store the temporary working variables back into the state */
    S[0] = x0; S[1] = x1; S[2] = x2; S[3] = x3;
    S[4] = x4; S[5] = x5; S[6] = x6; S[7] = x7;
}

/**
 * \brief Applies the slice permutation to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_slice(uint32_t S[8])
{
    leftRotate4_N(S[0], 0xFFFFU, 0, 0x3333, 2);
    leftRotate4_N(S[1], 0xFFFFU, 0, 0x3333, 2);
    leftRotate4_N(S[2], 0xFFFFU, 0, 0x3333, 2);
    leftRotate4_N(S[3], 0xFFFFU, 0, 0x3333, 2);

    leftRotate4_N(S[4], 0x7777U, 1, 0x1111, 3);
    leftRotate4_N(S[5], 0x7777U, 1, 0x1111, 3);
    leftRotate4_N(S[6], 0x7777U, 1, 0x1111, 3);
    leftRotate4_N(S[7], 0x7777U, 1, 0x1111, 3);
}

/**
 * \brief Applies the inverse of the slice permutation to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_slice_inverse(uint32_t S[8])
{
    leftRotate4_N(S[0], 0xFFFFU, 0, 0x3333, 2);
    leftRotate4_N(S[1], 0xFFFFU, 0, 0x3333, 2);
    leftRotate4_N(S[2], 0xFFFFU, 0, 0x3333, 2);
    leftRotate4_N(S[3], 0xFFFFU, 0, 0x3333, 2);

    leftRotate4_N(S[4], 0x1111U, 3, 0x7777, 1);
    leftRotate4_N(S[5], 0x1111U, 3, 0x7777, 1);
    leftRotate4_N(S[6], 0x1111U, 3, 0x7777, 1);
    leftRotate4_N(S[7], 0x1111U, 3, 0x7777, 1);
}

/**
 * \brief Applies the sheet permutation to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_sheet(uint32_t S[8])
{
    leftRotate16_N(S[0], 0xFFFFU, 0, 0x00FF, 8);
    leftRotate16_N(S[1], 0xFFFFU, 0, 0x00FF, 8);
    leftRotate16_N(S[2], 0xFFFFU, 0, 0x00FF, 8);
    leftRotate16_N(S[3], 0xFFFFU, 0, 0x00FF, 8);

    leftRotate16_N(S[4], 0x0FFFU, 4, 0x000F, 12);
    leftRotate16_N(S[5], 0x0FFFU, 4, 0x000F, 12);
    leftRotate16_N(S[6], 0x0FFFU, 4, 0x000F, 12);
    leftRotate16_N(S[7], 0x0FFFU, 4, 0x000F, 12);
}

/**
 * \brief Applies the inverse of the sheet permutation to the SATURNIN state.
 *
 * \param S The state.
 */
static void saturnin_sheet_inverse(uint32_t S[8])
{
    leftRotate16_N(S[0], 0xFFFFU, 0, 0x00FF, 8);
    leftRotate16_N(S[1], 0xFFFFU, 0, 0x00FF, 8);
    leftRotate16_N(S[2], 0xFFFFU, 0, 0x00FF, 8);
    leftRotate16_N(S[3], 0xFFFFU, 0, 0x00FF, 8);

    leftRotate16_N(S[4], 0x000FU, 12, 0x0FFF, 4);
    leftRotate16_N(S[5], 0x000FU, 12, 0x0FFF, 4);
    leftRotate16_N(S[6], 0x000FU, 12, 0x0FFF, 4);
    leftRotate16_N(S[7], 0x000FU, 12, 0x0FFF, 4);
}

/**
 * \brief Encrypts a 256-bit block with the SATURNIN block cipher.
 *
 * \param output Ciphertext output block, 32 bytes.
 * \param input Plaintext input block, 32 bytes.
 * \param key Points to the 32 byte key for the block cipher.
 * \param rounds Number of rounds to perform.
 * \param RC Round constants to use for domain separation.
 *
 * The \a input and \a output buffers can be the same.
 *
 * \sa saturnin_block_decrypt()
 */
static void saturnin_block_encrypt
    (unsigned char *output, const unsigned char *input,
     const unsigned char *key, unsigned rounds, const uint32_t *RC)
{
    uint32_t K[16];
    uint32_t S[8];
    uint32_t temp;
    unsigned index;

    /* Unpack the key and the input block */
    for (index = 0; index < 16; index += 2) {
        temp = ((uint32_t)(key[index])) |
              (((uint32_t)(key[index + 1]))  << 8)  |
              (((uint32_t)(key[index + 16])) << 16) |
              (((uint32_t)(key[index + 17])) << 24);
        K[index / 2] = temp;
        K[8 + (index / 2)] = ((temp & 0x001F001FU) << 11) |
                             ((temp >> 5) & 0x07FF07FFU);
        S[index / 2] = ((uint32_t)(input[index])) |
                      (((uint32_t)(input[index + 1]))  << 8)  |
                      (((uint32_t)(input[index + 16])) << 16) |
                      (((uint32_t)(input[index + 17])) << 24);
    }

    /* XOR the key into the state */
    saturnin_xor_key();

    /* Perform all encryption rounds */
    for (; rounds > 0; rounds -= 2, RC += 2) {
        saturnin_sbox(S);
        saturnin_mds(S);
        saturnin_sbox(S);
        saturnin_slice(S);
        saturnin_mds(S);
        saturnin_slice_inverse(S);
        S[0] ^= RC[0];
        saturnin_xor_key_rotated();

        saturnin_sbox(S);
        saturnin_mds(S);
        saturnin_sbox(S);
        saturnin_sheet(S);
        saturnin_mds(S);
        saturnin_sheet_inverse(S);
        S[0] ^= RC[1];
        saturnin_xor_key();
    }

    /* Encode the state into the output block */
    for (index = 0; index < 16; index += 2) {
        temp = S[index / 2];
        output[index]      = (uint8_t)temp;
        output[index + 1]  = (uint8_t)(temp >> 8);
        output[index + 16] = (uint8_t)(temp >> 16);
        output[index + 17] = (uint8_t)(temp >> 24);
    }
}

/**
 * \brief Decrypts a 256-bit block with the SATURNIN block cipher.
 *
 * \param output Plaintext output block, 32 bytes.
 * \param input Ciphertext input block, 32 bytes.
 * \param key Points to the 32 byte key for the block cipher.
 * \param rounds Number of rounds to perform.
 * \param RC Round constants to use for domain separation.
 *
 * The \a input and \a output buffers can be the same.
 *
 * \sa saturnin_block_encrypt()
 */
static void saturnin_block_decrypt
    (unsigned char *output, const unsigned char *input,
     const unsigned char *key, unsigned rounds, const uint32_t *RC)
{
    uint32_t K[16];
    uint32_t S[8];
    uint32_t temp;
    unsigned index;

    /* Unpack the key and the input block */
    for (index = 0; index < 16; index += 2) {
        temp = ((uint32_t)(key[index])) |
              (((uint32_t)(key[index + 1]))  << 8)  |
              (((uint32_t)(key[index + 16])) << 16) |
              (((uint32_t)(key[index + 17])) << 24);
        K[index / 2] = temp;
        K[8 + (index / 2)] = ((temp & 0x001F001FU) << 11) |
                             ((temp >> 5) & 0x07FF07FFU);
        S[index / 2] = ((uint32_t)(input[index])) |
                      (((uint32_t)(input[index + 1]))  << 8)  |
                      (((uint32_t)(input[index + 16])) << 16) |
                      (((uint32_t)(input[index + 17])) << 24);
    }

    /* Perform all decryption rounds */
    RC += rounds - 2;
    for (; rounds > 0; rounds -= 2, RC -= 2) {
        saturnin_xor_key();
        S[0] ^= RC[1];
        saturnin_sheet(S);
        saturnin_mds_inverse(S);
        saturnin_sheet_inverse(S);
        saturnin_sbox_inverse(S);
        saturnin_mds_inverse(S);
        saturnin_sbox_inverse(S);

        saturnin_xor_key_rotated();
        S[0] ^= RC[0];
        saturnin_slice(S);
        saturnin_mds_inverse(S);
        saturnin_slice_inverse(S);
        saturnin_sbox_inverse(S);
        saturnin_mds_inverse(S);
        saturnin_sbox_inverse(S);
    }

    /* XOR the key into the state */
    saturnin_xor_key();

    /* Encode the state into the output block */
    for (index = 0; index < 16; index += 2) {
        temp = S[index / 2];
        output[index]      = (uint8_t)temp;
        output[index + 1]  = (uint8_t)(temp >> 8);
        output[index + 16] = (uint8_t)(temp >> 16);
        output[index + 17] = (uint8_t)(temp >> 24);
    }
}

/**
 * \brief Encrypts a 256-bit block with the SATURNIN block cipher and
 * then XOR's itself to generate a new key.
 *
 * \param block Block to be encrypted and then XOR'ed with itself.
 * \param key Points to the 32 byte key for the block cipher.
 * \param rounds Number of rounds to perform.
 * \param RC Round constants to use for domain separation.
 */
void saturnin_block_encrypt_xor
    (const unsigned char *block, unsigned char *key,
     unsigned rounds, const uint32_t *RC)
{
    unsigned char temp[32];
    saturnin_block_encrypt(temp, block, key, rounds, RC);
    lw_xor_block_2_src(key, block, temp, 32);
}

/**
 * \brief Encrypts (or decrypts) a data packet in CTR mode.
 *
 * \param c Output ciphertext buffer.
 * \param m Input plaintext buffer.
 * \param mlen Length of the plaintext in bytes.
 * \param k Points to the 32-byte key.
 * \param block Points to the pre-formatted nonce block.
 */
static void saturnin_ctr_encrypt
    (unsigned char *c, const unsigned char *m, unsigned long long mlen,
     const unsigned char *k, unsigned char *block)
{
    /* Note: Specification requires a 95-bit counter but we only use 32-bit.
     * This limits the maximum packet size to 128Gb.  That should be OK */
    uint32_t counter = 1;
    unsigned char out[32];
    while (mlen >= 32) {
        be_store_word32(block + 28, counter);
        saturnin_block_encrypt(out, block, k, 10, RC_10_1);
        lw_xor_block_2_src(c, out, m, 32);
        c += 32;
        m += 32;
        mlen -= 32;
        ++counter;
    }
    if (mlen > 0) {
        be_store_word32(block + 28, counter);
        saturnin_block_encrypt(out, block, k, 10, RC_10_1);
        lw_xor_block_2_src(c, out, m, (unsigned)mlen);
    }
}

/**
 * \brief Pads an authenticates a message.
 *
 * \param tag Points to the authentication tag.
 * \param block Temporary block of 32 bytes from the caller.
 * \param m Points to the message to be authenticated.
 * \param mlen Length of the message to be authenticated in bytes.
 * \param rounds Number of rounds to perform.
 * \param RC1 Round constants to use for domain separation on full blocks.
 * \param RC2 Round constants to use for domain separation on the last block.
 */
static void saturnin_authenticate
    (unsigned char *tag, unsigned char *block,
     const unsigned char *m, unsigned long long mlen,
     unsigned rounds, const uint32_t *RC1, const uint32_t *RC2)
{
    unsigned temp;
    while (mlen >= 32) {
        saturnin_block_encrypt_xor(m, tag, rounds, RC1);
        m += 32;
        mlen -= 32;
    }
    temp = (unsigned)mlen;
    memcpy(block, m, temp);
    block[temp] = 0x80;
    memset(block + temp + 1, 0, 31 - temp);
    saturnin_block_encrypt_xor(block, tag, rounds, RC2);
}

int saturnin_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char block[32];
    unsigned char *tag;
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + SATURNIN_TAG_SIZE;

    /* Format the input block from the padded nonce */
    memcpy(block, npub, 16);
    block[16] = 0x80;
    memset(block + 17, 0, 15);

    /* Encrypt the plaintext in counter mode to produce the ciphertext */
    saturnin_ctr_encrypt(c, m, mlen, k, block);

    /* Set the counter back to zero and then encrypt the nonce */
    tag = c + mlen;
    memcpy(tag, k, 32);
    memset(block + 17, 0, 15);
    saturnin_block_encrypt_xor(block, tag, 10, RC_10_2);

    /* Authenticate the associated data and the ciphertext */
    saturnin_authenticate(tag, block, ad, adlen, 10, RC_10_2, RC_10_3);
    saturnin_authenticate(tag, block, c, mlen, 10, RC_10_4, RC_10_5);
    return 0;
}

int saturnin_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char block[32];
    unsigned char tag[32];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < SATURNIN_TAG_SIZE)
        return -1;
    *mlen = clen - SATURNIN_TAG_SIZE;

    /* Format the input block from the padded nonce */
    memcpy(block, npub, 16);
    block[16] = 0x80;
    memset(block + 17, 0, 15);

    /* Encrypt the nonce to initialize the authentication phase */
    memcpy(tag, k, 32);
    saturnin_block_encrypt_xor(block, tag, 10, RC_10_2);

    /* Authenticate the associated data and the ciphertext */
    saturnin_authenticate(tag, block, ad, adlen, 10, RC_10_2, RC_10_3);
    saturnin_authenticate(tag, block, c, *mlen, 10, RC_10_4, RC_10_5);

    /* Decrypt the ciphertext in counter mode to produce the plaintext */
    memcpy(block, npub, 16);
    block[16] = 0x80;
    memset(block + 17, 0, 15);
    saturnin_ctr_encrypt(m, c, *mlen, k, block);

    /* Check the authentication tag at the end of the message */
    return aead_check_tag
        (m, *mlen, tag, c + *mlen, SATURNIN_TAG_SIZE);
}

int saturnin_short_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char block[32];
    unsigned temp;
    (void)nsec;
    (void)ad;

    /* Validate the parameters: no associated data allowed and m <= 15 bytes */
    if (adlen > 0 || mlen > 15)
        return -2;

    /* Format the input block from the nonce and plaintext */
    temp = (unsigned)mlen;
    memcpy(block, npub, 16);
    memcpy(block + 16, m, temp);
    block[16 + temp] = 0x80; /* Padding */
    memset(block + 17 + temp, 0, 15 - temp);

    /* Encrypt the input block to produce the output ciphertext */
    saturnin_block_encrypt(c, block, k, 10, RC_10_6);
    *clen = 32;
    return 0;
}

int saturnin_short_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    unsigned char block[32];
    unsigned check1, check2, len;
    int index, result;
    (void)nsec;
    (void)ad;

    /* Validate the parameters: no associated data and c is always 32 bytes */
    if (adlen > 0)
        return -2;
    if (clen != 32)
        return -1;

    /* Decrypt the ciphertext block */
    saturnin_block_decrypt(block, c, k, 10, RC_10_6);

    /* Verify that the output block starts with the nonce and that it is
     * padded correctly.  We need to do this very carefully to avoid leaking
     * any information that could be used in a padding oracle attack.  Use the
     * same algorithm as the reference implementation of SATURNIN-Short */
    check1 = 0;
    for (index = 0; index < 16; ++index)
        check1 |= npub[index] ^ block[index];
    check2 = 0xFF;
    len = 0;
    for (index = 15; index >= 0; --index) {
        unsigned temp = block[16 + index];
        unsigned temp2 = check2 & -(1 - (((temp ^ 0x80) + 0xFF) >> 8));
        len |= temp2 & (unsigned)index;
        check2 &= ~temp2;
        check1 |= check2 & ((temp + 0xFF) >> 8);
    }
    check1 |= check2;

    /* At this point, check1 is zero if the nonce and plaintext are good,
     * or non-zero if there was an error in the decrypted data */
    result = (((int)check1) - 1) >> 16;

    /* The "result" is -1 if the data is good or zero if the data is invalid.
     * Copy either the plaintext or zeroes to the output buffer.  We assume
     * that the output buffer has space for up to 15 bytes.  This may return
     * some of the padding to the caller but as long as they restrict
     * themselves to the first *mlen bytes then it shouldn't be a problem */
    for (index = 0; index < 15; ++index)
        m[index] = block[16 + index] & result;
    *mlen = len;
    return ~result;
}

int saturnin_hash
    (unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    unsigned char tag[32];
    unsigned char block[32];
    memset(tag, 0, sizeof(tag));
    saturnin_authenticate(tag, block, in, inlen, 16, RC_16_7, RC_16_8);
    memcpy(out, tag, 32);
    return 0;
}

void saturnin_hash_init(saturnin_hash_state_t *state)
{
    memset(state, 0, sizeof(saturnin_hash_state_t));
}

void saturnin_hash_update
    (saturnin_hash_state_t *state, const unsigned char *in,
     unsigned long long inlen)
{
    unsigned temp;

    /* Handle the partial left-over block from last time */
    if (state->s.count) {
        temp = 32 - state->s.count;
        if (temp > inlen) {
            temp = (unsigned)inlen;
            memcpy(state->s.block + state->s.count, in, temp);
            state->s.count += temp;
            return;
        }
        memcpy(state->s.block + state->s.count, in, temp);
        state->s.count = 0;
        in += temp;
        inlen -= temp;
        saturnin_block_encrypt_xor(state->s.block, state->s.hash, 16, RC_16_7);
    }

    /* Process full blocks that are aligned at state->s.count == 0 */
    while (inlen >= 32) {
        saturnin_block_encrypt_xor(in, state->s.hash, 16, RC_16_7);
        in += 32;
        inlen -= 32;
    }

    /* Process the left-over block at the end of the input */
    temp = (unsigned)inlen;
    memcpy(state->s.block, in, temp);
    state->s.count = temp;
}

void saturnin_hash_finalize
    (saturnin_hash_state_t *state, unsigned char *out)
{
    /* Pad the final block */
    state->s.block[state->s.count] = 0x80;
    memset(state->s.block + state->s.count + 1, 0, 31 - state->s.count);

    /* Generate the final hash value */
    saturnin_block_encrypt_xor(state->s.block, state->s.hash, 16, RC_16_8);
    memcpy(out, state->s.hash, 32);
}
