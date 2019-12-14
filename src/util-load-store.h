/*
 * Copyright (C) 2019 Southern Storm Software, Pty Ltd.
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

#ifndef LW_UTIL_LOAD_STORE_H
#define LW_UTIL_LOAD_STORE_H

#include <stdint.h>

/* Helper macros to load and store values while converting endian-ness */

/* Load a big-endian 32-bit word from a byte buffer */
#define be_load_word32(ptr) \
    ((((uint32_t)((ptr)[0])) << 24) | \
     (((uint32_t)((ptr)[1])) << 16) | \
     (((uint32_t)((ptr)[2])) << 8) | \
      ((uint32_t)((ptr)[3])))

/* Store a big-endian 32-bit word into a byte buffer */
#define be_store_word32(ptr, _x) \
    do { \
        uint32_t x = (_x); \
        (ptr)[0] = (uint8_t)(x >> 24); \
        (ptr)[1] = (uint8_t)(x >> 16); \
        (ptr)[2] = (uint8_t)(x >> 8); \
        (ptr)[3] = (uint8_t)x; \
    } while (0)

/* Load a little-endian 32-bit word from a byte buffer */
#define le_load_word32(ptr) \
    ((((uint32_t)((ptr)[3])) << 24) | \
     (((uint32_t)((ptr)[2])) << 16) | \
     (((uint32_t)((ptr)[1])) << 8) | \
      ((uint32_t)((ptr)[0])))

/* Store a little-endian 32-bit word into a byte buffer */
#define le_store_word32(ptr, _x) \
    do { \
        uint32_t x = (_x); \
        (ptr)[0] = (uint8_t)x; \
        (ptr)[1] = (uint8_t)(x >> 8); \
        (ptr)[2] = (uint8_t)(x >> 16); \
        (ptr)[3] = (uint8_t)(x >> 24); \
    } while (0)

#endif
