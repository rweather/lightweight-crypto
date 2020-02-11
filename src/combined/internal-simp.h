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

#ifndef LW_INTERNAL_SIMP_H
#define LW_INTERNAL_SIMP_H

#include "internal-util.h"

/**
 * \file internal-simp.h
 * \brief SimP permutation family.
 *
 * SimP-256 and SimP-192 are used by the Oribatida submission to
 * round 2 of the NIST Lightweight Cryptography Competition.
 * The permutations are built around reduced-round variants of the
 * Simon-128-128 and Simon-96-96 block ciphers.
 *
 * References: https://www.isical.ac.in/~lightweight/oribatida/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief State size of the SimP-256 permutation.
 */
#define SIMP_256_STATE_SIZE 32

/**
 * \brief State size of the SimP-192 permutation.
 */
#define SIMP_192_STATE_SIZE 24

/**
 * \brief Permutes a state with SimP-256.
 *
 * \param state State to be permuted.
 * \param steps Number of steps to perform (usually 2 or 4).
 */
void simp_256_permute(unsigned char state[SIMP_256_STATE_SIZE], unsigned steps);

/**
 * \brief Permutes a state with SimP-192.
 *
 * \param state State to be permuted.
 * \param steps Number of steps to perform (usually 2 or 4).
 */
void simp_192_permute(unsigned char state[SIMP_192_STATE_SIZE], unsigned steps);

#ifdef __cplusplus
}
#endif

#endif
