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

#include "romulus.h"
#include "internal-skinny128.h"
#include "internal-util.h"
#include <string.h>

aead_cipher_t const romulus_n1_cipher = {
    "Romulus-N1",
    ROMULUS_KEY_SIZE,
    ROMULUS1_NONCE_SIZE,
    ROMULUS_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_n1_aead_encrypt,
    romulus_n1_aead_decrypt
};

aead_cipher_t const romulus_n2_cipher = {
    "Romulus-N2",
    ROMULUS_KEY_SIZE,
    ROMULUS2_NONCE_SIZE,
    ROMULUS_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_n2_aead_encrypt,
    romulus_n2_aead_decrypt
};

aead_cipher_t const romulus_n3_cipher = {
    "Romulus-N3",
    ROMULUS_KEY_SIZE,
    ROMULUS3_NONCE_SIZE,
    ROMULUS_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_n3_aead_encrypt,
    romulus_n3_aead_decrypt
};

aead_cipher_t const romulus_m1_cipher = {
    "Romulus-M1",
    ROMULUS_KEY_SIZE,
    ROMULUS1_NONCE_SIZE,
    ROMULUS_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_m1_aead_encrypt,
    romulus_m1_aead_decrypt
};

aead_cipher_t const romulus_m2_cipher = {
    "Romulus-M2",
    ROMULUS_KEY_SIZE,
    ROMULUS2_NONCE_SIZE,
    ROMULUS_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_m2_aead_encrypt,
    romulus_m2_aead_decrypt
};

aead_cipher_t const romulus_m3_cipher = {
    "Romulus-M3",
    ROMULUS_KEY_SIZE,
    ROMULUS3_NONCE_SIZE,
    ROMULUS_TAG_SIZE,
    AEAD_FLAG_LITTLE_ENDIAN,
    romulus_m3_aead_encrypt,
    romulus_m3_aead_decrypt
};

/**
 * \brief Limit on the number of bytes of message or associated data (128Mb).
 *
 * Romulus-N1 and Romulus-M1 use a 56-bit block counter which allows for
 * payloads well into the petabyte range.  It is unlikely that an embedded
 * device will have that much memory to store a contiguous packet!
 *
 * Romulus-N2 and Romulus-M2 use a 48-bit block counter but the upper
 * 24 bits are difficult to modify in the key schedule.  So we only
 * update the low 24 bits and leave the high 24 bits fixed.
 *
 * Romulus-N3 and Romulus-M3 use a 24-bit block counter.
 *
 * For all algorithms, we limit the block counter to 2^23 so that the block
 * counter can never exceed 2^24 - 1.
 */
#define ROMULUS_DATA_LIMIT \
    ((unsigned long long)((1ULL << 23) * SKINNY_128_BLOCK_SIZE))

/**
 * \brief Initializes the key schedule for Romulus-N1 or Romulus-M1.
 *
 * \param ks Points to the key schedule to initialize.
 * \param k Points to the 16 bytes of the key.
 * \param npub Points to the 16 bytes of the nonce.  May be NULL
 * if the nonce will be updated on the fly.
 */
static void romulus1_init
    (skinny_128_384_key_schedule_t *ks,
     const unsigned char *k, const unsigned char *npub)
{
    unsigned char TK[32];
    if (npub)
        memcpy(TK, npub, 16);
    else
        memset(TK, 0, 16);
    memcpy(TK + 16, k, 16);
    skinny_128_384_init(ks, TK, sizeof(TK));
    ks->TK1[0] = 0x01; /* Initialize the 56-bit LFSR counter */
}

/**
 * \brief Initializes the key schedule for Romulus-N2 or Romulus-M2.
 *
 * \param ks Points to the key schedule to initialize.
 * \param k Points to the 16 bytes of the key.
 * \param npub Points to the 12 bytes of the nonce.  May be NULL
 * if the nonce will be updated on the fly.
 */
static void romulus2_init
    (skinny_128_384_key_schedule_t *ks,
     const unsigned char *k, const unsigned char *npub)
{
    unsigned char TK[32];
    memcpy(TK, k, 16);
    memset(TK + 16, 0, 16);
    TK[16] = 0x01; /* Initialize the high 24 bits of the LFSR counter */
    skinny_128_384_init(ks, TK, sizeof(TK));
    ks->TK1[0] = 0x01; /* Initialize the low 24 bits of the LFSR counter */
    if (npub)
        memcpy(ks->TK1 + 4, npub, 12);
}

/**
 * \brief Initializes the key schedule for Romulus-N3 or Romulus-M3.
 *
 * \param ks Points to the key schedule to initialize.
 * \param k Points to the 16 bytes of the key.
 * \param npub Points to the 12 bytes of the nonce.  May be NULL
 * if the nonce will be updated on the fly.
 */
static void romulus3_init
    (skinny_128_256_key_schedule_t *ks,
     const unsigned char *k, const unsigned char *npub)
{
    skinny_128_256_init(ks, k, 16);
    ks->TK1[0] = 0x01; /* Initialize the 24-bit LFSR counter */
    if (npub)
        memcpy(ks->TK1 + 4, npub, 12);
}

/**
 * \brief Sets the domain separation value for Romulus-N1 and M1.
 *
 * \param ks The key schedule to set the domain separation value into.
 * \param domain The domain separation value.
 */
#define romulus1_set_domain(ks, domain) ((ks)->TK1[7] = (domain))

/**
 * \brief Sets the domain separation value for Romulus-N2 and M2.
 *
 * \param ks The key schedule to set the domain separation value into.
 * \param domain The domain separation value.
 */
#define romulus2_set_domain(ks, domain) ((ks)->TK1[3] = (domain))

/**
 * \brief Sets the domain separation value for Romulus-N3 and M3.
 *
 * \param ks The key schedule to set the domain separation value into.
 * \param domain The domain separation value.
 */
#define romulus3_set_domain(ks, domain) ((ks)->TK1[3] = (domain))

/**
 * \brief Updates the 56-bit LFSR block counter for Romulus-N1 and M1.
 *
 * \param TK1 Points to the TK1 part of the key schedule containing the LFSR.
 */
STATIC_INLINE void romulus1_update_counter(uint8_t TK1[16])
{
    uint8_t mask = (uint8_t)(((int8_t)(TK1[6])) >> 7);
    TK1[6] = (TK1[6] << 1) | (TK1[5] >> 7);
    TK1[5] = (TK1[5] << 1) | (TK1[4] >> 7);
    TK1[4] = (TK1[4] << 1) | (TK1[3] >> 7);
    TK1[3] = (TK1[3] << 1) | (TK1[2] >> 7);
    TK1[2] = (TK1[2] << 1) | (TK1[1] >> 7);
    TK1[1] = (TK1[1] << 1) | (TK1[0] >> 7);
    TK1[0] = (TK1[0] << 1) ^ (mask & 0x95);
}

/**
 * \brief Updates the 24-bit LFSR block counter for Romulus-N2 or M2.
 *
 * \param TK1 Points to the TK1 part of the key schedule containing the LFSR.
 *
 * For Romulus-N2 and Romulus-M2 this will only update the low 24 bits of
 * the 48-bit LFSR.  The high 24 bits are fixed due to ROMULUS_DATA_LIMIT.
 */
STATIC_INLINE void romulus2_update_counter(uint8_t TK1[16])
{
    uint8_t mask = (uint8_t)(((int8_t)(TK1[2])) >> 7);
    TK1[2] = (TK1[2] << 1) | (TK1[1] >> 7);
    TK1[1] = (TK1[1] << 1) | (TK1[0] >> 7);
    TK1[0] = (TK1[0] << 1) ^ (mask & 0x1B);
}

/**
 * \brief Updates the 24-bit LFSR block counter for Romulus-N3 or M3.
 *
 * \param TK1 Points to the TK1 part of the key schedule containing the LFSR.
 */
#define romulus3_update_counter(TK1) romulus2_update_counter((TK1))

/**
 * \brief Process the asssociated data for Romulus-N1.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void romulus_n1_process_ad
    (skinny_128_384_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char temp;

    /* Handle the special case of no associated data */
    if (adlen == 0) {
        romulus1_update_counter(ks->TK1);
        romulus1_set_domain(ks, 0x1A);
        skinny_128_384_encrypt_tk2(ks, S, S, npub);
        return;
    }

    /* Process all double blocks except the last */
    romulus1_set_domain(ks, 0x08);
    while (adlen > 32) {
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        skinny_128_384_encrypt_tk2(ks, S, S, ad + 16);
        romulus1_update_counter(ks->TK1);
        ad += 32;
        adlen -= 32;
    }

    /* Pad and process the left-over blocks */
    romulus1_update_counter(ks->TK1);
    temp = (unsigned)adlen;
    if (temp == 32) {
        /* Left-over complete double block */
        lw_xor_block(S, ad, 16);
        skinny_128_384_encrypt_tk2(ks, S, S, ad + 16);
        romulus1_update_counter(ks->TK1);
        romulus1_set_domain(ks, 0x18);
    } else if (temp > 16) {
        /* Left-over partial double block */
        unsigned char pad[16];
        temp -= 16;
        lw_xor_block(S, ad, 16);
        memcpy(pad, ad + 16, temp);
        memset(pad + temp, 0, 15 - temp);
        pad[15] = temp;
        skinny_128_384_encrypt_tk2(ks, S, S, pad);
        romulus1_update_counter(ks->TK1);
        romulus1_set_domain(ks, 0x1A);
    } else if (temp == 16) {
        /* Left-over complete single block */
        lw_xor_block(S, ad, temp);
        romulus1_set_domain(ks, 0x18);
    } else {
        /* Left-over partial single block */
        lw_xor_block(S, ad, temp);
        S[15] ^= temp;
        romulus1_set_domain(ks, 0x1A);
    }
    skinny_128_384_encrypt_tk2(ks, S, S, npub);
}

/**
 * \brief Process the asssociated data for Romulus-N2.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void romulus_n2_process_ad
    (skinny_128_384_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char temp;

    /* Handle the special case of no associated data */
    if (adlen == 0) {
        romulus2_update_counter(ks->TK1);
        romulus2_set_domain(ks, 0x5A);
        memcpy(ks->TK1 + 4, npub, 12);
        skinny_128_384_encrypt(ks, S, S);
        return;
    }

    /* Process all double blocks except the last */
    romulus2_set_domain(ks, 0x48);
    while (adlen > 28) {
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
        ad += 28;
        adlen -= 28;
    }

    /* Pad and process the left-over blocks */
    romulus2_update_counter(ks->TK1);
    temp = (unsigned)adlen;
    if (temp == 28) {
        /* Left-over complete double block */
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
        romulus2_set_domain(ks, 0x58);
    } else if (temp > 16) {
        /* Left-over partial double block */
        temp -= 16;
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, temp);
        memset(ks->TK1 + 4 + temp, 0, 12 - temp);
        ks->TK1[15] = temp;
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
        romulus2_set_domain(ks, 0x5A);
    } else if (temp == 16) {
        /* Left-over complete single block */
        lw_xor_block(S, ad, temp);
        romulus2_set_domain(ks, 0x58);
    } else {
        /* Left-over partial single block */
        lw_xor_block(S, ad, temp);
        S[15] ^= temp;
        romulus2_set_domain(ks, 0x5A);
    }
    memcpy(ks->TK1 + 4, npub, 12);
    skinny_128_384_encrypt(ks, S, S);
}

/**
 * \brief Process the asssociated data for Romulus-N3.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 */
static void romulus_n3_process_ad
    (skinny_128_256_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen)
{
    unsigned char temp;

    /* Handle the special case of no associated data */
    if (adlen == 0) {
        romulus3_update_counter(ks->TK1);
        romulus3_set_domain(ks, 0x9A);
        memcpy(ks->TK1 + 4, npub, 12);
        skinny_128_256_encrypt(ks, S, S);
        return;
    }

    /* Process all double blocks except the last */
    romulus3_set_domain(ks, 0x88);
    while (adlen > 28) {
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
        ad += 28;
        adlen -= 28;
    }

    /* Pad and process the left-over blocks */
    romulus3_update_counter(ks->TK1);
    temp = (unsigned)adlen;
    if (temp == 28) {
        /* Left-over complete double block */
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
        romulus3_set_domain(ks, 0x98);
    } else if (temp > 16) {
        /* Left-over partial double block */
        temp -= 16;
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, temp);
        memset(ks->TK1 + 4 + temp, 0, 12 - temp);
        ks->TK1[15] = temp;
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
        romulus3_set_domain(ks, 0x9A);
    } else if (temp == 16) {
        /* Left-over complete single block */
        lw_xor_block(S, ad, temp);
        romulus3_set_domain(ks, 0x98);
    } else {
        /* Left-over partial single block */
        lw_xor_block(S, ad, temp);
        S[15] ^= temp;
        romulus3_set_domain(ks, 0x9A);
    }
    memcpy(ks->TK1 + 4, npub, 12);
    skinny_128_256_encrypt(ks, S, S);
}

/**
 * \brief Determine the domain separation value to use on the last
 * block of the associated data processing.
 *
 * \param adlen Length of the associated data in bytes.
 * \param mlen Length of the message in bytes.
 * \param t Size of the second half of a double block; 12 or 16.
 *
 * \return The domain separation bits to use to finalize the last block.
 */
static uint8_t romulus_m_final_ad_domain
    (unsigned long long adlen, unsigned long long mlen, unsigned t)
{
    uint8_t domain = 0;
    unsigned split = 16U;
    unsigned leftover;

    /* Determine which domain bits we need based on the length of the ad */
    if (adlen == 0) {
        /* No associated data, so only 1 block with padding */
        domain ^= 0x02;
        split = t;
    } else {
        /* Even or odd associated data length? */
        leftover = (unsigned)(adlen % (16U + t));
        if (leftover == 0) {
            /* Even with a full double block at the end */
            domain ^= 0x08;
        } else if (leftover < split) {
            /* Odd with a partial single block at the end */
            domain ^= 0x02;
            split = t;
        } else if (leftover > split) {
            /* Even with a partial double block at the end */
            domain ^= 0x0A;
        } else {
            /* Odd with a full single block at the end */
            split = t;
        }
    }

    /* Determine which domain bits we need based on the length of the message */
    if (mlen == 0) {
        /* No message, so only 1 block with padding */
        domain ^= 0x01;
    } else {
        /* Even or odd message length? */
        leftover = (unsigned)(mlen % (16U + t));
        if (leftover == 0) {
            /* Even with a full double block at the end */
            domain ^= 0x04;
        } else if (leftover < split) {
            /* Odd with a partial single block at the end */
            domain ^= 0x01;
        } else if (leftover > split) {
            /* Even with a partial double block at the end */
            domain ^= 0x05;
        }
    }
    return domain;
}

/**
 * \brief Process the asssociated data for Romulus-M1.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 * \param m Points to the message plaintext.
 * \param mlen Length of the message plaintext.
 */
static void romulus_m1_process_ad
    (skinny_128_384_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *m, unsigned long long mlen)
{
    unsigned char pad[16];
    uint8_t final_domain = 0x30;
    unsigned temp;

    /* Determine the domain separator to use on the final block */
    final_domain ^= romulus_m_final_ad_domain(adlen, mlen, 16);

    /* Process all associated data double blocks except the last */
    romulus1_set_domain(ks, 0x28);
    while (adlen > 32) {
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        skinny_128_384_encrypt_tk2(ks, S, S, ad + 16);
        romulus1_update_counter(ks->TK1);
        ad += 32;
        adlen -= 32;
    }

    /* Process the last associated data double block */
    temp = (unsigned)adlen;
    if (temp == 32) {
        /* Last associated data double block is full */
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        skinny_128_384_encrypt_tk2(ks, S, S, ad + 16);
        romulus1_update_counter(ks->TK1);
    } else if (temp > 16) {
        /* Last associated data double block is partial */
        temp -= 16;
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(pad, ad + 16, temp);
        memset(pad + temp, 0, sizeof(pad) - temp - 1);
        pad[sizeof(pad) - 1] = (unsigned char)temp;
        skinny_128_384_encrypt_tk2(ks, S, S, pad);
        romulus1_update_counter(ks->TK1);
    } else {
        /* Last associated data block is single.  Needs to be combined
         * with the first block of the message payload */
        romulus1_set_domain(ks, 0x2C);
        romulus1_update_counter(ks->TK1);
        if (temp == 16) {
            lw_xor_block(S, ad, 16);
        } else {
            lw_xor_block(S, ad, temp);
            S[15] ^= (unsigned char)temp;
        }
        if (mlen > 16) {
            skinny_128_384_encrypt_tk2(ks, S, S, m);
            romulus1_update_counter(ks->TK1);
            m += 16;
            mlen -= 16;
        } else if (mlen == 16) {
            skinny_128_384_encrypt_tk2(ks, S, S, m);
            m += 16;
            mlen -= 16;
        } else {
            temp = (unsigned)mlen;
            memcpy(pad, m, temp);
            memset(pad + temp, 0, sizeof(pad) - temp - 1);
            pad[sizeof(pad) - 1] = (unsigned char)temp;
            skinny_128_384_encrypt_tk2(ks, S, S, pad);
            mlen = 0;
        }
    }

    /* Process all message double blocks except the last */
    romulus1_set_domain(ks, 0x2C);
    while (mlen > 32) {
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        skinny_128_384_encrypt_tk2(ks, S, S, m + 16);
        romulus1_update_counter(ks->TK1);
        m += 32;
        mlen -= 32;
    }

    /* Process the last message double block */
    temp = (unsigned)mlen;
    if (temp == 32) {
        /* Last message double block is full */
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        skinny_128_384_encrypt_tk2(ks, S, S, m + 16);
    } else if (temp > 16) {
        /* Last message double block is partial */
        temp -= 16;
        romulus1_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(pad, m + 16, temp);
        memset(pad + temp, 0, sizeof(pad) - temp - 1);
        pad[sizeof(pad) - 1] = (unsigned char)temp;
        skinny_128_384_encrypt_tk2(ks, S, S, pad);
    } else if (temp == 16) {
        /* Last message single block is full */
        lw_xor_block(S, m, 16);
    } else if (temp > 0) {
        /* Last message single block is partial */
        lw_xor_block(S, m, temp);
        S[15] ^= (unsigned char)temp;
    }

    /* Process the last partial block */
    romulus1_set_domain(ks, final_domain);
    romulus1_update_counter(ks->TK1);
    skinny_128_384_encrypt_tk2(ks, S, S, npub);
}

/**
 * \brief Process the asssociated data for Romulus-M2.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 * \param m Points to the message plaintext.
 * \param mlen Length of the message plaintext.
 */
static void romulus_m2_process_ad
    (skinny_128_384_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *m, unsigned long long mlen)
{
    uint8_t final_domain = 0x70;
    unsigned temp;

    /* Determine the domain separator to use on the final block */
    final_domain ^= romulus_m_final_ad_domain(adlen, mlen, 12);

    /* Process all associated data double blocks except the last */
    romulus2_set_domain(ks, 0x68);
    while (adlen > 28) {
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
        ad += 28;
        adlen -= 28;
    }

    /* Process the last associated data double block */
    temp = (unsigned)adlen;
    if (temp == 28) {
        /* Last associated data double block is full */
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
    } else if (temp > 16) {
        /* Last associated data double block is partial */
        temp -= 16;
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, temp);
        memset(ks->TK1 + 4 + temp, 0, 12 - temp - 1);
        ks->TK1[15] = (unsigned char)temp;
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
    } else {
        /* Last associated data block is single.  Needs to be combined
         * with the first block of the message payload */
        romulus2_set_domain(ks, 0x6C);
        romulus2_update_counter(ks->TK1);
        if (temp == 16) {
            lw_xor_block(S, ad, 16);
        } else {
            lw_xor_block(S, ad, temp);
            S[15] ^= (unsigned char)temp;
        }
        if (mlen > 12) {
            memcpy(ks->TK1 + 4, m, 12);
            skinny_128_384_encrypt(ks, S, S);
            romulus2_update_counter(ks->TK1);
            m += 12;
            mlen -= 12;
        } else if (mlen == 12) {
            memcpy(ks->TK1 + 4, m, 12);
            skinny_128_384_encrypt(ks, S, S);
            m += 12;
            mlen -= 12;
        } else {
            temp = (unsigned)mlen;
            memcpy(ks->TK1 + 4, m, temp);
            memset(ks->TK1 + 4 + temp, 0, 12 - temp - 1);
            ks->TK1[15] = (unsigned char)temp;
            skinny_128_384_encrypt(ks, S, S);
            mlen = 0;
        }
    }

    /* Process all message double blocks except the last */
    romulus2_set_domain(ks, 0x6C);
    while (mlen > 28) {
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(ks->TK1 + 4, m + 16, 12);
        skinny_128_384_encrypt(ks, S, S);
        romulus2_update_counter(ks->TK1);
        m += 28;
        mlen -= 28;
    }

    /* Process the last message double block */
    temp = (unsigned)mlen;
    if (temp == 28) {
        /* Last message double block is full */
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(ks->TK1 + 4, m + 16, 12);
        skinny_128_384_encrypt(ks, S, S);
    } else if (temp > 16) {
        /* Last message double block is partial */
        temp -= 16;
        romulus2_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(ks->TK1 + 4, m + 16, temp);
        memset(ks->TK1 + 4 + temp, 0, 12 - temp - 1);
        ks->TK1[15] = (unsigned char)temp;
        skinny_128_384_encrypt(ks, S, S);
    } else if (temp == 16) {
        /* Last message single block is full */
        lw_xor_block(S, m, 16);
    } else if (temp > 0) {
        /* Last message single block is partial */
        lw_xor_block(S, m, temp);
        S[15] ^= (unsigned char)temp;
    }

    /* Process the last partial block */
    romulus2_set_domain(ks, final_domain);
    romulus2_update_counter(ks->TK1);
    memcpy(ks->TK1 + 4, npub, 12);
    skinny_128_384_encrypt(ks, S, S);
}

/**
 * \brief Process the asssociated data for Romulus-M3.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param npub Points to the nonce.
 * \param ad Points to the associated data.
 * \param adlen Length of the associated data in bytes.
 * \param m Points to the message plaintext.
 * \param mlen Length of the message plaintext.
 */
static void romulus_m3_process_ad
    (skinny_128_256_key_schedule_t *ks,
     unsigned char S[16], const unsigned char *npub,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *m, unsigned long long mlen)
{
    uint8_t final_domain = 0xB0;
    unsigned temp;

    /* Determine the domain separator to use on the final block */
    final_domain ^= romulus_m_final_ad_domain(adlen, mlen, 12);

    /* Process all associated data double blocks except the last */
    romulus3_set_domain(ks, 0xA8);
    while (adlen > 28) {
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
        ad += 28;
        adlen -= 28;
    }

    /* Process the last associated data double block */
    temp = (unsigned)adlen;
    if (temp == 28) {
        /* Last associated data double block is full */
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, 12);
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
    } else if (temp > 16) {
        /* Last associated data double block is partial */
        temp -= 16;
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, ad, 16);
        memcpy(ks->TK1 + 4, ad + 16, temp);
        memset(ks->TK1 + 4 + temp, 0, 12 - temp - 1);
        ks->TK1[15] = (unsigned char)temp;
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
    } else {
        /* Last associated data block is single.  Needs to be combined
         * with the first block of the message payload */
        romulus3_set_domain(ks, 0xAC);
        romulus3_update_counter(ks->TK1);
        if (temp == 16) {
            lw_xor_block(S, ad, 16);
        } else {
            lw_xor_block(S, ad, temp);
            S[15] ^= (unsigned char)temp;
        }
        if (mlen > 12) {
            memcpy(ks->TK1 + 4, m, 12);
            skinny_128_256_encrypt(ks, S, S);
            romulus3_update_counter(ks->TK1);
            m += 12;
            mlen -= 12;
        } else if (mlen == 12) {
            memcpy(ks->TK1 + 4, m, 12);
            skinny_128_256_encrypt(ks, S, S);
            m += 12;
            mlen -= 12;
        } else {
            temp = (unsigned)mlen;
            memcpy(ks->TK1 + 4, m, temp);
            memset(ks->TK1 + 4 + temp, 0, 12 - temp - 1);
            ks->TK1[15] = (unsigned char)temp;
            skinny_128_256_encrypt(ks, S, S);
            mlen = 0;
        }
    }

    /* Process all message double blocks except the last */
    romulus3_set_domain(ks, 0xAC);
    while (mlen > 28) {
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(ks->TK1 + 4, m + 16, 12);
        skinny_128_256_encrypt(ks, S, S);
        romulus3_update_counter(ks->TK1);
        m += 28;
        mlen -= 28;
    }

    /* Process the last message double block */
    temp = (unsigned)mlen;
    if (temp == 28) {
        /* Last message double block is full */
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(ks->TK1 + 4, m + 16, 12);
        skinny_128_256_encrypt(ks, S, S);
    } else if (temp > 16) {
        /* Last message double block is partial */
        temp -= 16;
        romulus3_update_counter(ks->TK1);
        lw_xor_block(S, m, 16);
        memcpy(ks->TK1 + 4, m + 16, temp);
        memset(ks->TK1 + 4 + temp, 0, 12 - temp - 1);
        ks->TK1[15] = (unsigned char)temp;
        skinny_128_256_encrypt(ks, S, S);
    } else if (temp == 16) {
        /* Last message single block is full */
        lw_xor_block(S, m, 16);
    } else if (temp > 0) {
        /* Last message single block is partial */
        lw_xor_block(S, m, temp);
        S[15] ^= (unsigned char)temp;
    }

    /* Process the last partial block */
    romulus3_set_domain(ks, final_domain);
    romulus3_update_counter(ks->TK1);
    memcpy(ks->TK1 + 4, npub, 12);
    skinny_128_256_encrypt(ks, S, S);
}

/**
 * \brief Applies the Romulus rho function.
 *
 * \param S The rolling Romulus state.
 * \param C Ciphertext message output block.
 * \param M Plaintext message input block.
 */
STATIC_INLINE void romulus_rho
    (unsigned char S[16], unsigned char C[16], const unsigned char M[16])
{
    unsigned index;
    for (index = 0; index < 16; ++index) {
        unsigned char s = S[index];
        unsigned char m = M[index];
        S[index] ^= m;
        C[index] = m ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
    }
}

/**
 * \brief Applies the inverse of the Romulus rho function.
 *
 * \param S The rolling Romulus state.
 * \param M Plaintext message output block.
 * \param C Ciphertext message input block.
 */
STATIC_INLINE void romulus_rho_inverse
    (unsigned char S[16], unsigned char M[16], const unsigned char C[16])
{
    unsigned index;
    for (index = 0; index < 16; ++index) {
        unsigned char s = S[index];
        unsigned char m = C[index] ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
        S[index] ^= m;
        M[index] = m;
    }
}

/**
 * \brief Applies the Romulus rho function to a short block.
 *
 * \param S The rolling Romulus state.
 * \param C Ciphertext message output block.
 * \param M Plaintext message input block.
 * \param len Length of the short block, must be less than 16.
 */
STATIC_INLINE void romulus_rho_short
    (unsigned char S[16], unsigned char C[16],
     const unsigned char M[16], unsigned len)
{
    unsigned index;
    for (index = 0; index < len; ++index) {
        unsigned char s = S[index];
        unsigned char m = M[index];
        S[index] ^= m;
        C[index] = m ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
    }
    S[15] ^= (unsigned char)len; /* Padding */
}

/**
 * \brief Applies the inverse of the Romulus rho function to a short block.
 *
 * \param S The rolling Romulus state.
 * \param M Plaintext message output block.
 * \param C Ciphertext message input block.
 * \param len Length of the short block, must be less than 16.
 */
STATIC_INLINE void romulus_rho_inverse_short
    (unsigned char S[16], unsigned char M[16],
     const unsigned char C[16], unsigned len)
{
    unsigned index;
    for (index = 0; index < len; ++index) {
        unsigned char s = S[index];
        unsigned char m = C[index] ^ ((s >> 1) ^ (s & 0x80) ^ (s << 7));
        S[index] ^= m;
        M[index] = m;
    }
    S[15] ^= (unsigned char)len; /* Padding */
}

/**
 * \brief Encrypts a plaintext message with Romulus-N1.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n1_encrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    unsigned temp;

    /* Handle the special case of no plaintext */
    if (mlen == 0) {
        romulus1_update_counter(ks->TK1);
        romulus1_set_domain(ks, 0x15);
        skinny_128_384_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus1_set_domain(ks, 0x04);
    while (mlen > 16) {
        romulus_rho(S, c, m);
        romulus1_update_counter(ks->TK1);
        skinny_128_384_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus1_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_short(S, c, m, temp);
        romulus1_set_domain(ks, 0x15);
    } else {
        romulus_rho(S, c, m);
        romulus1_set_domain(ks, 0x14);
    }
    skinny_128_384_encrypt(ks, S, S);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-N1.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n1_decrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, unsigned long long mlen)
{
    unsigned temp;

    /* Handle the special case of no ciphertext */
    if (mlen == 0) {
        romulus1_update_counter(ks->TK1);
        romulus1_set_domain(ks, 0x15);
        skinny_128_384_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus1_set_domain(ks, 0x04);
    while (mlen > 16) {
        romulus_rho_inverse(S, m, c);
        romulus1_update_counter(ks->TK1);
        skinny_128_384_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus1_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_inverse_short(S, m, c, temp);
        romulus1_set_domain(ks, 0x15);
    } else {
        romulus_rho_inverse(S, m, c);
        romulus1_set_domain(ks, 0x14);
    }
    skinny_128_384_encrypt(ks, S, S);
}

/**
 * \brief Encrypts a plaintext message with Romulus-N2.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n2_encrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    unsigned temp;

    /* Handle the special case of no plaintext */
    if (mlen == 0) {
        romulus2_update_counter(ks->TK1);
        romulus2_set_domain(ks, 0x55);
        skinny_128_384_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus2_set_domain(ks, 0x44);
    while (mlen > 16) {
        romulus_rho(S, c, m);
        romulus2_update_counter(ks->TK1);
        skinny_128_384_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus2_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_short(S, c, m, temp);
        romulus2_set_domain(ks, 0x55);
    } else {
        romulus_rho(S, c, m);
        romulus2_set_domain(ks, 0x54);
    }
    skinny_128_384_encrypt(ks, S, S);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-N2.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n2_decrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, unsigned long long mlen)
{
    unsigned temp;

    /* Handle the special case of no ciphertext */
    if (mlen == 0) {
        romulus2_update_counter(ks->TK1);
        romulus2_set_domain(ks, 0x55);
        skinny_128_384_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus2_set_domain(ks, 0x44);
    while (mlen > 16) {
        romulus_rho_inverse(S, m, c);
        romulus2_update_counter(ks->TK1);
        skinny_128_384_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus2_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_inverse_short(S, m, c, temp);
        romulus2_set_domain(ks, 0x55);
    } else {
        romulus_rho_inverse(S, m, c);
        romulus2_set_domain(ks, 0x54);
    }
    skinny_128_384_encrypt(ks, S, S);
}

/**
 * \brief Encrypts a plaintext message with Romulus-N3.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n3_encrypt
    (skinny_128_256_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    unsigned temp;

    /* Handle the special case of no plaintext */
    if (mlen == 0) {
        romulus3_update_counter(ks->TK1);
        romulus3_set_domain(ks, 0x95);
        skinny_128_256_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus3_set_domain(ks, 0x84);
    while (mlen > 16) {
        romulus_rho(S, c, m);
        romulus3_update_counter(ks->TK1);
        skinny_128_256_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus3_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_short(S, c, m, temp);
        romulus3_set_domain(ks, 0x95);
    } else {
        romulus_rho(S, c, m);
        romulus3_set_domain(ks, 0x94);
    }
    skinny_128_256_encrypt(ks, S, S);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-N3.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_n3_decrypt
    (skinny_128_256_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, unsigned long long mlen)
{
    unsigned temp;

    /* Handle the special case of no ciphertext */
    if (mlen == 0) {
        romulus3_update_counter(ks->TK1);
        romulus3_set_domain(ks, 0x95);
        skinny_128_256_encrypt(ks, S, S);
        return;
    }

    /* Process all blocks except the last */
    romulus3_set_domain(ks, 0x84);
    while (mlen > 16) {
        romulus_rho_inverse(S, m, c);
        romulus3_update_counter(ks->TK1);
        skinny_128_256_encrypt(ks, S, S);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Pad and process the last block */
    temp = (unsigned)mlen;
    romulus3_update_counter(ks->TK1);
    if (temp < 16) {
        romulus_rho_inverse_short(S, m, c, temp);
        romulus3_set_domain(ks, 0x95);
    } else {
        romulus_rho_inverse(S, m, c);
        romulus3_set_domain(ks, 0x94);
    }
    skinny_128_256_encrypt(ks, S, S);
}

/**
 * \brief Encrypts a plaintext message with Romulus-M1.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m1_encrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus1_set_domain(ks, 0x24);
    while (mlen > 16) {
        skinny_128_384_encrypt(ks, S, S);
        romulus_rho(S, c, m);
        romulus1_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_128_384_encrypt(ks, S, S);
    romulus_rho_short(S, c, m, (unsigned)mlen);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-M1.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m1_decrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, unsigned long long mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus1_set_domain(ks, 0x24);
    while (mlen > 16) {
        skinny_128_384_encrypt(ks, S, S);
        romulus_rho_inverse(S, m, c);
        romulus1_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_128_384_encrypt(ks, S, S);
    romulus_rho_inverse_short(S, m, c, (unsigned)mlen);
}

/**
 * \brief Encrypts a plaintext message with Romulus-M2.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m2_encrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus2_set_domain(ks, 0x64);
    while (mlen > 16) {
        skinny_128_384_encrypt(ks, S, S);
        romulus_rho(S, c, m);
        romulus2_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_128_384_encrypt(ks, S, S);
    romulus_rho_short(S, c, m, (unsigned)mlen);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-M2.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m2_decrypt
    (skinny_128_384_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, unsigned long long mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus2_set_domain(ks, 0x64);
    while (mlen > 16) {
        skinny_128_384_encrypt(ks, S, S);
        romulus_rho_inverse(S, m, c);
        romulus2_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_128_384_encrypt(ks, S, S);
    romulus_rho_inverse_short(S, m, c, (unsigned)mlen);
}

/**
 * \brief Encrypts a plaintext message with Romulus-M3.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param c Points to the buffer to receive the ciphertext.
 * \param m Points to the buffer containing the plaintext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m3_encrypt
    (skinny_128_256_key_schedule_t *ks, unsigned char S[16],
     unsigned char *c, const unsigned char *m, unsigned long long mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus3_set_domain(ks, 0xA4);
    while (mlen > 16) {
        skinny_128_256_encrypt(ks, S, S);
        romulus_rho(S, c, m);
        romulus3_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_128_256_encrypt(ks, S, S);
    romulus_rho_short(S, c, m, (unsigned)mlen);
}

/**
 * \brief Decrypts a ciphertext message with Romulus-M3.
 *
 * \param ks Points to the key schedule.
 * \param S The rolling Romulus state.
 * \param m Points to the buffer to receive the plaintext.
 * \param c Points to the buffer containing the ciphertext.
 * \param mlen Length of the plaintext in bytes.
 */
static void romulus_m3_decrypt
    (skinny_128_256_key_schedule_t *ks, unsigned char S[16],
     unsigned char *m, const unsigned char *c, unsigned long long mlen)
{
    /* Nothing to do if the message is empty */
    if (!mlen)
        return;

    /* Process all block except the last */
    romulus3_set_domain(ks, 0xA4);
    while (mlen > 16) {
        skinny_128_256_encrypt(ks, S, S);
        romulus_rho_inverse(S, m, c);
        romulus3_update_counter(ks->TK1);
        c += 16;
        m += 16;
        mlen -= 16;
    }

    /* Handle the last block */
    skinny_128_256_encrypt(ks, S, S);
    romulus_rho_inverse_short(S, m, c, (unsigned)mlen);
}

/**
 * \brief Generates the authentication tag from the rolling Romulus state.
 *
 * \param T Buffer to receive the generated tag; can be the same as S.
 * \param S The rolling Romulus state.
 */
STATIC_INLINE void romulus_generate_tag
    (unsigned char T[16], const unsigned char S[16])
{
    unsigned index;
    for (index = 0; index < 16; ++index) {
        unsigned char s = S[index];
        T[index] = (s >> 1) ^ (s & 0x80) ^ (s << 7);
    }
}

int romulus_n1_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT || mlen > ROMULUS_DATA_LIMIT)
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus1_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n1_process_ad(&ks, S, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus1_init(&ks, k, npub);

    /* Encrypts the plaintext to produce the ciphertext */
    romulus_n1_encrypt(&ks, S, c, m, mlen);

    /* Generate the authentication tag */
    romulus_generate_tag(c + mlen, S);
    return 0;
}

int romulus_n1_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT ||
            clen > (ROMULUS_DATA_LIMIT + ROMULUS_TAG_SIZE))
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus1_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n1_process_ad(&ks, S, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus1_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= ROMULUS_TAG_SIZE;
    romulus_n1_decrypt(&ks, S, m, c, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_TAG_SIZE);
}

int romulus_n2_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT || mlen > ROMULUS_DATA_LIMIT)
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus2_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n2_process_ad(&ks, S, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus2_init(&ks, k, npub);

    /* Encrypts the plaintext to produce the ciphertext */
    romulus_n2_encrypt(&ks, S, c, m, mlen);

    /* Generate the authentication tag */
    romulus_generate_tag(c + mlen, S);
    return 0;
}

int romulus_n2_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT ||
            clen > (ROMULUS_DATA_LIMIT + ROMULUS_TAG_SIZE))
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus2_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n2_process_ad(&ks, S, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus2_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= ROMULUS_TAG_SIZE;
    romulus_n2_decrypt(&ks, S, m, c, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_TAG_SIZE);
}

int romulus_n3_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT || mlen > ROMULUS_DATA_LIMIT)
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus3_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n3_process_ad(&ks, S, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus3_init(&ks, k, npub);

    /* Encrypts the plaintext to produce the ciphertext */
    romulus_n3_encrypt(&ks, S, c, m, mlen);

    /* Generate the authentication tag */
    romulus_generate_tag(c + mlen, S);
    return 0;
}

int romulus_n3_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT ||
            clen > (ROMULUS_DATA_LIMIT + ROMULUS_TAG_SIZE))
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus3_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_n3_process_ad(&ks, S, npub, ad, adlen);

    /* Re-initialize the key schedule with the key and nonce */
    romulus3_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext */
    clen -= ROMULUS_TAG_SIZE;
    romulus_n3_decrypt(&ks, S, m, c, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_TAG_SIZE);
}

int romulus_m1_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT || mlen > ROMULUS_DATA_LIMIT)
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus1_init(&ks, k, 0);

    /* Process the associated data and the plaintext message */
    memset(S, 0, sizeof(S));
    romulus_m1_process_ad(&ks, S, npub, ad, adlen, m, mlen);

    /* Generate the authentication tag, which is also the initialization
     * vector for the encryption portion of the packet processing */
    romulus_generate_tag(S, S);
    memcpy(c + mlen, S, ROMULUS_TAG_SIZE);

    /* Re-initialize the key schedule with the key and nonce */
    romulus1_init(&ks, k, npub);

    /* Encrypt the plaintext to produce the ciphertext */
    romulus_m1_encrypt(&ks, S, c, m, mlen);
    return 0;
}

int romulus_m1_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT ||
            clen > (ROMULUS_DATA_LIMIT + ROMULUS_TAG_SIZE))
        return -2;

    /* Initialize the key schedule with the key and nonce */
    romulus1_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext, using the
     * authentication tag as the initialization vector for decryption */
    clen -= ROMULUS_TAG_SIZE;
    memcpy(S, c + clen, ROMULUS_TAG_SIZE);
    romulus_m1_decrypt(&ks, S, m, c, clen);

    /* Re-initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus1_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_m1_process_ad(&ks, S, npub, ad, adlen, m, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_TAG_SIZE);
}

int romulus_m2_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT || mlen > ROMULUS_DATA_LIMIT)
        return -2;

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus2_init(&ks, k, 0);

    /* Process the associated data and the plaintext message */
    memset(S, 0, sizeof(S));
    romulus_m2_process_ad(&ks, S, npub, ad, adlen, m, mlen);

    /* Generate the authentication tag, which is also the initialization
     * vector for the encryption portion of the packet processing */
    romulus_generate_tag(S, S);
    memcpy(c + mlen, S, ROMULUS_TAG_SIZE);

    /* Re-initialize the key schedule with the key and nonce */
    romulus2_init(&ks, k, npub);

    /* Encrypt the plaintext to produce the ciphertext */
    romulus_m2_encrypt(&ks, S, c, m, mlen);
    return 0;
}

int romulus_m2_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_384_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT ||
            clen > (ROMULUS_DATA_LIMIT + ROMULUS_TAG_SIZE))
        return -2;

    /* Initialize the key schedule with the key and nonce */
    romulus2_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext, using the
     * authentication tag as the initialization vector for decryption */
    clen -= ROMULUS_TAG_SIZE;
    memcpy(S, c + clen, ROMULUS_TAG_SIZE);
    romulus_m2_decrypt(&ks, S, m, c, clen);

    /* Re-initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus2_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_m2_process_ad(&ks, S, npub, ad, adlen, m, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_TAG_SIZE);
}

int romulus_m3_aead_encrypt
    (unsigned char *c, unsigned long long *clen,
     const unsigned char *m, unsigned long long mlen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *nsec,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Set the length of the returned ciphertext */
    *clen = mlen + ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT || mlen > ROMULUS_DATA_LIMIT)
        return -2;

    /* Initialize the key schedule with the key and nonce */
    romulus3_init(&ks, k, npub);

    /* Initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus3_init(&ks, k, 0);

    /* Process the associated data and the plaintext message */
    memset(S, 0, sizeof(S));
    romulus_m3_process_ad(&ks, S, npub, ad, adlen, m, mlen);

    /* Generate the authentication tag, which is also the initialization
     * vector for the encryption portion of the packet processing */
    romulus_generate_tag(S, S);
    memcpy(c + mlen, S, ROMULUS_TAG_SIZE);

    /* Re-initialize the key schedule with the key and nonce */
    romulus3_init(&ks, k, npub);

    /* Encrypt the plaintext to produce the ciphertext */
    romulus_m3_encrypt(&ks, S, c, m, mlen);
    return 0;
}

int romulus_m3_aead_decrypt
    (unsigned char *m, unsigned long long *mlen,
     unsigned char *nsec,
     const unsigned char *c, unsigned long long clen,
     const unsigned char *ad, unsigned long long adlen,
     const unsigned char *npub,
     const unsigned char *k)
{
    skinny_128_256_key_schedule_t ks;
    unsigned char S[16];
    (void)nsec;

    /* Validate the ciphertext length and set the return "mlen" value */
    if (clen < ROMULUS_TAG_SIZE)
        return -1;
    *mlen = clen - ROMULUS_TAG_SIZE;

    /* Validate the length of the associated data and message */
    if (adlen > ROMULUS_DATA_LIMIT ||
            clen > (ROMULUS_DATA_LIMIT + ROMULUS_TAG_SIZE))
        return -2;

    /* Initialize the key schedule with the key and nonce */
    romulus3_init(&ks, k, npub);

    /* Decrypt the ciphertext to produce the plaintext, using the
     * authentication tag as the initialization vector for decryption */
    clen -= ROMULUS_TAG_SIZE;
    memcpy(S, c + clen, ROMULUS_TAG_SIZE);
    romulus_m3_decrypt(&ks, S, m, c, clen);

    /* Re-initialize the key schedule with the key and no nonce.  Associated
     * data processing varies the nonce from block to block */
    romulus3_init(&ks, k, 0);

    /* Process the associated data */
    memset(S, 0, sizeof(S));
    romulus_m3_process_ad(&ks, S, npub, ad, adlen, m, clen);

    /* Check the authentication tag */
    romulus_generate_tag(S, S);
    return aead_check_tag(m, clen, S, c + clen, ROMULUS_TAG_SIZE);
}
