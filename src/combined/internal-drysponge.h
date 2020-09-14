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

#ifndef LW_INTERNAL_DRYSPONGE_H
#define LW_INTERNAL_DRYSPONGE_H

#include "drygascon.h"
#include "drygascon128_arm_selector.h"

#include "internal-util.h"

/**
 * \file internal-drysponge.h
 * \brief Internal implementation of DrySPONGE for the DryGASCON cipher.
 *
 * References: https://github.com/sebastien-riou/DryGASCON
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Size of the GASCON-128 permutation state in bytes.
 */
#define GASCON128_STATE_SIZE 40

/**
 * \brief Size of the GASCON-256 permutation state in bytes.
 */
#define GASCON256_STATE_SIZE 72

/**
 * \brief Rate of absorption and squeezing for DrySPONGE128.
 */
#define DRYSPONGE128_RATE 16

/**
 * \brief Rate of absorption and squeezing for DrySPONGE256.
 */
#define DRYSPONGE256_RATE 16

/**
 * \brief Size of the "x" value for DrySPONGE128.
 */
#define DRYSPONGE128_XSIZE 16

/**
 * \brief Size of the "x" value for DrySPONGE256.
 */
#define DRYSPONGE256_XSIZE 16

/**
 * \brief Normal number of rounds for DrySPONGE128 when absorbing
 * and squeezing data.
 */
#define DRYSPONGE128_ROUNDS 7

/**
 * \brief Number of rounds for DrySPONGE128 during initialization.
 */
#define DRYSPONGE128_INIT_ROUNDS 11

/**
 * \brief Normal number of rounds for DrySPONGE256 when absorbing
 * and squeezing data.
 */
#define DRYSPONGE256_ROUNDS 8

/**
 * \brief Number of rounds for DrySPONGE256 during initialization.
 */
#define DRYSPONGE256_INIT_ROUNDS 12

#ifdef DRYGASCON_F_OPT

    /**
     * \brief DrySPONGE128 domain bit for a padded block.
     */
    #define DRYDOMAIN128_PADDED (1 << 0)

    /**
     * \brief DrySPONGE128 domain bit for a final block.
     */
    #define DRYDOMAIN128_FINAL (1 << 1)

    /**
     * \brief DrySPONGE128 domain value for processing the nonce.
     */
    #define DRYDOMAIN128_NONCE (1 << 2)

    /**
     * \brief DrySPONGE128 domain value for processing the associated data.
     */
    #define DRYDOMAIN128_ASSOC_DATA (2 << 2)

    /**
     * \brief DrySPONGE128 domain value for processing the message.
     */
    #define DRYDOMAIN128_MESSAGE (3 << 2)

#else

    /**
     * \brief DrySPONGE128 domain bit for a padded block.
     */
    #define DRYDOMAIN128_PADDED (1 << 8)

    /**
     * \brief DrySPONGE128 domain bit for a final block.
     */
    #define DRYDOMAIN128_FINAL (1 << 9)

    /**
     * \brief DrySPONGE128 domain value for processing the nonce.
     */
    #define DRYDOMAIN128_NONCE (1 << 10)

    /**
     * \brief DrySPONGE128 domain value for processing the associated data.
     */
    #define DRYDOMAIN128_ASSOC_DATA (2 << 10)


    /**
     * \brief DrySPONGE128 domain value for processing the message.
     */
    #define DRYDOMAIN128_MESSAGE (3 << 10)

#endif


/**
 * \brief DrySPONGE256 domain bit for a padded block.
 */
#define DRYDOMAIN256_PADDED (1 << 2)

/**
 * \brief DrySPONGE256 domain bit for a final block.
 */
#define DRYDOMAIN256_FINAL (1 << 3)

/**
 * \brief DrySPONGE256 domain value for processing the nonce.
 */
#define DRYDOMAIN256_NONCE (1 << 4)

/**
 * \brief DrySPONGE256 domain value for processing the associated data.
 */
#define DRYDOMAIN256_ASSOC_DATA (2 << 4)

/**
 * \brief DrySPONGE256 domain value for processing the message.
 */
#define DRYDOMAIN256_MESSAGE (3 << 4)

/**
 * \brief Internal state of the GASCON-128 permutation.
 */
typedef union
{
    uint64_t S[GASCON128_STATE_SIZE / 8];   /**< 64-bit words of the state */
    uint32_t W[GASCON128_STATE_SIZE / 4];   /**< 32-bit words of the state */
    uint8_t B[GASCON128_STATE_SIZE];        /**< Bytes of the state */

} gascon128_state_t;

/**
 * \brief Internal state of the GASCON-256 permutation.
 */
typedef union
{
    uint64_t S[GASCON256_STATE_SIZE / 8];   /**< 64-bit words of the state */
    uint32_t W[GASCON256_STATE_SIZE / 4];   /**< 32-bit words of the state */
    uint8_t B[GASCON256_STATE_SIZE];        /**< Bytes of the state */

} gascon256_state_t;

/**
 * \brief Structure of a rate block for DrySPONGE128.
 */
typedef union
{
    uint64_t S[DRYSPONGE128_RATE / 8];      /**< 64-bit words of the rate */
    uint32_t W[DRYSPONGE128_RATE / 4];      /**< 32-bit words of the rate */
    uint8_t B[DRYSPONGE128_RATE];           /**< Bytes of the rate */

} drysponge128_rate_t;

/**
 * \brief Structure of a rate block for DrySPONGE256.
 */
typedef union
{
    uint64_t S[DRYSPONGE256_RATE / 8];  /**< 64-bit words of the rate */
    uint32_t W[DRYSPONGE256_RATE / 4];  /**< 32-bit words of the rate */
    uint8_t B[DRYSPONGE256_RATE];       /**< Bytes of the rate */

} drysponge256_rate_t;

/**
 * \brief Structure of the "x" value for DrySPONGE128.
 */
typedef union
{
    uint64_t S[DRYSPONGE128_XSIZE / 8]; /**< 64-bit words of the rate */
    uint32_t W[DRYSPONGE128_XSIZE / 4]; /**< 32-bit words of the rate */
    uint8_t B[DRYSPONGE128_XSIZE];      /**< Bytes of the rate */

} __attribute__((aligned(16))) drysponge128_x_t;

/**
 * \brief Structure of the "x" value for DrySPONGE256.
 */
typedef union
{
    uint64_t S[DRYSPONGE256_XSIZE / 8]; /**< 64-bit words of the rate */
    uint32_t W[DRYSPONGE256_XSIZE / 4]; /**< 32-bit words of the rate */
    uint8_t B[DRYSPONGE256_XSIZE];      /**< Bytes of the rate */

} drysponge256_x_t;

/**
 * \brief Structure of the rolling DrySPONGE128 state.
 */
typedef struct
{
	gascon128_state_t c;        /**< GASCON-128 state for the capacity */
    uint32_t domain;            /**< Domain value to mix on next F call */
    uint32_t rounds;            /**< Number of rounds for next G call */
    drysponge128_rate_t r;      /**< Buffer for a rate block of data */
    drysponge128_x_t x;         /**< "x" value for the sponge */
} __attribute__((aligned(16))) drysponge128_state_t;

/**
 * \brief Structure of the rolling DrySPONGE256 state.
 */
typedef struct
{
    gascon256_state_t c;        /**< GASCON-256 state for the capacity */
    drysponge256_rate_t r;      /**< Buffer for a rate block of data */
    drysponge256_x_t x;         /**< "x" value for the sponge */
    uint32_t domain;            /**< Domain value to mix on next F call */
    uint32_t rounds;            /**< Number of rounds for next G call */

} drysponge256_state_t;

/**
 * \brief Permutes the GASCON-128 state using one iteration of CoreRound.
 *
 * \param state The GASCON-128 state to be permuted.
 * \param round The round number.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void gascon128_core_round(gascon128_state_t *state, uint8_t round);

/**
 * \brief Permutes the GASCON-256 state using one iteration of CoreRound.
 *
 * \param state The GASCON-256 state to be permuted.
 * \param round The round number.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void gascon256_core_round(gascon256_state_t *state, uint8_t round);

/**
 * \brief Performs the DrySPONGE128 G function which runs the core
 * rounds and squeezes data out of the GASGON-128 state.
 *
 * \param state The DrySPONGE128 state.
 *
 * The data that is squeezed out will be in state->r on exit.
 */
void drysponge128_g(drysponge128_state_t *state);

/**
 * \brief Performs the DrySPONGE256 G function which runs the core
 * rounds and squeezes data out of the GASGON-256 state.
 *
 * \param state The DrySPONGE256 state.
 *
 * The data that is squeezed out will be in state->r on exit.
 */
void drysponge256_g(drysponge256_state_t *state);

/**
 * \brief Performs the DrySPONGE128 G function which runs the core
 * rounds but does not squeeze out any output.
 *
 * \param state The DrySPONGE128 state.
 */
void drysponge128_g_core(drysponge128_state_t *state);

/**
 * \brief Performs the DrySPONGE256 G function which runs the core
 * rounds but does not squeeze out any output.
 *
 * \param state The DrySPONGE256 state.
 */
void drysponge256_g_core(drysponge256_state_t *state);

/**
 * \brief Performs the absorption phase of the DrySPONGE256 F function.
 *
 * \param state The DrySPONGE256 state.
 * \param input The block of input data to incorporate into the state.
 * \param len The length of the input block, which must be less than
 * or equal to DRYSPONGE256_RATE.  Smaller input blocks will be padded.
 *
 * This function must be followed by a call to drysponge256_g() or
 * drysponge256_g_core() to perform the full F operation.
 */
void drysponge256_f_absorb
    (drysponge256_state_t *state, const unsigned char *input, unsigned len);

void drygascon128_f_wrap(drysponge128_state_t *state, const unsigned char *input, unsigned len);

/**
 * \brief Determine if state alignement is safe vs timing attacks.
 *
 * \param state Points to the state to check.
 *
 * \return Non-zero if alignement is safe.
 *
 * We expect this to be completly optimized out by compiler if the alignement is enforced at build time
 */
int drysponge128_safe_alignement(const drysponge128_state_t*state);

/**
 * \brief Set up a DrySPONGE128 state to begin encryption or decryption.
 *
 * \param state The DrySPONGE128 state.
 * \param key Points to the 16 bytes of the key.
 * \param nonce Points to the 16 bytes of the nonce.
 * \param final_block Non-zero if after key setup there will be no more blocks.
 */
void drysponge128_setup
    (drysponge128_state_t *state, const unsigned char *key, unsigned int keysize,
     const unsigned char *nonce, int final_block);

/**
 * \brief Set up a DrySPONGE256 state to begin encryption or decryption.
 *
 * \param state The DrySPONGE256 state.
 * \param key Points to the 32 bytes of the key.
 * \param nonce Points to the 16 bytes of the nonce.
 * \param final_block Non-zero if after key setup there will be no more blocks.
 */
void drysponge256_setup
    (drysponge256_state_t *state, const unsigned char *key,
     const unsigned char *nonce, int final_block);

#ifdef __cplusplus
}
#endif

#endif
