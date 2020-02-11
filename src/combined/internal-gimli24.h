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

#ifndef LW_INTERNAL_GIMLI24_H
#define LW_INTERNAL_GIMLI24_H

#include "internal-util.h"

/**
 * \file internal-gimli24.h
 * \brief Internal implementation of the GIMLI-24 permutation.
 *
 * References: https://gimli.cr.yp.to/
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Permutes the GIMLI-24 state.
 *
 * \param state The GIMLI-24 state to be permuted.
 *
 * The input and output \a state will be in little-endian byte order.
 */
void gimli24_permute(uint32_t state[12]);

#ifdef __cplusplus
}
#endif

#endif
