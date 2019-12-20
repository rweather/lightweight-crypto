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

#ifndef LW_UTIL_AEAD_H
#define LW_UTIL_AEAD_H

/* Helper macros and functions that are common across all AEAD schemes */

/* Figure out how to inline functions using this C compiler */
#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define STATIC_INLINE static inline
#elif defined(__GNUC__) || defined(__clang__)
#define STATIC_INLINE static __inline__
#else
#define STATIC_INLINE static
#endif

/* XOR a source byte buffer against a destination */
STATIC_INLINE void lw_xor_block
    (unsigned char *dest, const unsigned char *src, unsigned len)
{
    while (len > 0) {
        *dest++ ^= *src++;
        --len;
    }
}

/* XOR two source byte buffers and put the result in a destination buffer */
STATIC_INLINE void lw_xor_block_2_src
    (unsigned char *dest, const unsigned char *src1,
     const unsigned char *src2, unsigned len)
{
    while (len > 0) {
        *dest++ = *src1++ ^ *src2++;
        --len;
    }
}

/* XOR a source byte buffer against a destination and write to another
 * destination at the same time */
STATIC_INLINE void lw_xor_block_2_dest
    (unsigned char *dest2, unsigned char *dest,
     const unsigned char *src, unsigned len)
{
    while (len > 0) {
        *dest2++ = (*dest++ ^= *src++);
        --len;
    }
}

/* XOR a source byte buffer against a destination and write to another
 * destination at the same time.  This version swaps the source value
 * into the "dest" buffer */
STATIC_INLINE void lw_xor_block_swap
    (unsigned char *dest2, unsigned char *dest,
     const unsigned char *src, unsigned len)
{
    while (len > 0) {
        unsigned char temp = *src++;
        *dest2++ = *dest ^ temp;
        *dest++ = temp;
        --len;
    }
}

/* Check an authentication tag in constant time.  Returns -1 if the
 * tag check failed or "ok" if the check succeeded */
STATIC_INLINE int lw_check_tag
    (const unsigned char *actual, const unsigned char *expected,
     unsigned size, int ok)
{
    /* Set "accum" to -1 if the tags match, or 0 if they don't match */
    int accum = 0;
    while (size > 0) {
        accum |= (*actual++ ^ *expected++);
        --size;
    }
    accum = (accum - 1) >> 16;

    /* If "accum" is 0, return -1, otherwise return "ok" */
    return ok | ~accum;
}

#endif
