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

#ifndef LW_INTERNAL_UTIL_H
#define LW_INTERNAL_UTIL_H

#include <stdint.h>

/* Figure out how to inline functions using this C compiler */
#if defined(__STDC__) && __STDC_VERSION__ >= 199901L
#define STATIC_INLINE static inline
#elif defined(__GNUC__) || defined(__clang__)
#define STATIC_INLINE static __inline__
#else
#define STATIC_INLINE static
#endif

/* Try to figure out whether the CPU is little-endian or big-endian.
 * May need to modify this to include new compiler-specific defines.
 * Alternatively, define __LITTLE_ENDIAN__ or __BIG_ENDIAN__ in your
 * compiler flags when you compile this library */
#if defined(__x86_64) || defined(__x86_64__) || \
    defined(__i386) || defined(__i386__) || \
    defined(__AVR__) || defined(__arm) || defined(__arm__) || \
    defined(_M_AMD64) || defined(_M_X64) || defined(_M_IX86) || \
    defined(_M_IA64) || defined(_M_ARM) || defined(_M_ARM_FP) || \
    (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == 1234) || \
    defined(__LITTLE_ENDIAN__)
#define LW_UTIL_LITTLE_ENDIAN 1
#elif (defined(__BYTE_ORDER__) && __BYTE_ORDER__ == 4321) || \
    defined(__BIG_ENDIAN__)
/* Big endian */
#else
#error "Cannot determine the endianess of this platform"
#endif

/* Helper macros to load and store values while converting endian-ness */

/* Load a big-endian 32-bit word from a byte buffer */
#define be_load_word32(ptr) \
    ((((uint32_t)((ptr)[0])) << 24) | \
     (((uint32_t)((ptr)[1])) << 16) | \
     (((uint32_t)((ptr)[2])) << 8) | \
      ((uint32_t)((ptr)[3])))

/* Store a big-endian 32-bit word into a byte buffer */
#define be_store_word32(ptr, x) \
    do { \
        uint32_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 24); \
        (ptr)[1] = (uint8_t)(_x >> 16); \
        (ptr)[2] = (uint8_t)(_x >> 8); \
        (ptr)[3] = (uint8_t)_x; \
    } while (0)

/* Load a little-endian 32-bit word from a byte buffer */
#define le_load_word32(ptr) \
    ((((uint32_t)((ptr)[3])) << 24) | \
     (((uint32_t)((ptr)[2])) << 16) | \
     (((uint32_t)((ptr)[1])) << 8) | \
      ((uint32_t)((ptr)[0])))

/* Store a little-endian 32-bit word into a byte buffer */
#define le_store_word32(ptr, x) \
    do { \
        uint32_t _x = (x); \
        (ptr)[0] = (uint8_t)_x; \
        (ptr)[1] = (uint8_t)(_x >> 8); \
        (ptr)[2] = (uint8_t)(_x >> 16); \
        (ptr)[3] = (uint8_t)(_x >> 24); \
    } while (0)

/* Load a big-endian 64-bit word from a byte buffer */
#define be_load_word64(ptr) \
    ((((uint64_t)((ptr)[0])) << 56) | \
     (((uint64_t)((ptr)[1])) << 48) | \
     (((uint64_t)((ptr)[2])) << 40) | \
     (((uint64_t)((ptr)[3])) << 32) | \
     (((uint64_t)((ptr)[4])) << 24) | \
     (((uint64_t)((ptr)[5])) << 16) | \
     (((uint64_t)((ptr)[6])) << 8) | \
      ((uint64_t)((ptr)[7])))

/* Store a big-endian 64-bit word into a byte buffer */
#define be_store_word64(ptr, x) \
    do { \
        uint64_t _x = (x); \
        (ptr)[0] = (uint8_t)(_x >> 56); \
        (ptr)[1] = (uint8_t)(_x >> 48); \
        (ptr)[2] = (uint8_t)(_x >> 40); \
        (ptr)[3] = (uint8_t)(_x >> 32); \
        (ptr)[4] = (uint8_t)(_x >> 24); \
        (ptr)[5] = (uint8_t)(_x >> 16); \
        (ptr)[6] = (uint8_t)(_x >> 8); \
        (ptr)[7] = (uint8_t)_x; \
    } while (0)

/* Load a little-endian 64-bit word from a byte buffer */
#define le_load_word64(ptr) \
    ((((uint64_t)((ptr)[7])) << 56) | \
     (((uint64_t)((ptr)[6])) << 48) | \
     (((uint64_t)((ptr)[5])) << 40) | \
     (((uint64_t)((ptr)[4])) << 32) | \
     (((uint64_t)((ptr)[3])) << 24) | \
     (((uint64_t)((ptr)[2])) << 16) | \
     (((uint64_t)((ptr)[1])) << 8) | \
      ((uint64_t)((ptr)[0])))

/* Store a little-endian 64-bit word into a byte buffer */
#define le_store_word64(ptr, x) \
    do { \
        uint64_t _x = (x); \
        (ptr)[0] = (uint8_t)_x; \
        (ptr)[1] = (uint8_t)(_x >> 8); \
        (ptr)[2] = (uint8_t)(_x >> 16); \
        (ptr)[3] = (uint8_t)(_x >> 24); \
        (ptr)[4] = (uint8_t)(_x >> 32); \
        (ptr)[5] = (uint8_t)(_x >> 40); \
        (ptr)[6] = (uint8_t)(_x >> 48); \
        (ptr)[7] = (uint8_t)(_x >> 56); \
    } while (0)

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

/* XOR two byte buffers and write to a destination which at the same
 * time copying the contents of src2 to dest2 */
STATIC_INLINE void lw_xor_block_copy_src
    (unsigned char *dest2, unsigned char *dest,
     const unsigned char *src1, const unsigned char *src2, unsigned len)
{
    while (len > 0) {
        unsigned char temp = *src2++;
        *dest2++ = temp;
        *dest++ = *src1++ ^ temp;
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

/* Rotation macros for 32-bit arguments */

/* Generic left rotate */
#define leftRotate(a, bits) \
    (__extension__ ({ \
        uint32_t _temp = (a); \
        (_temp << (bits)) | (_temp >> (32 - (bits))); \
    }))

/* Generic right rotate */
#define rightRotate(a, bits) \
    (__extension__ ({ \
        uint32_t _temp = (a); \
        (_temp >> (bits)) | (_temp << (32 - (bits))); \
    }))

/* Left rotate by a specific number of bits */
#define leftRotate1(a)  (leftRotate((a), 1))
#define leftRotate2(a)  (leftRotate((a), 2))
#define leftRotate3(a)  (leftRotate((a), 3))
#define leftRotate4(a)  (leftRotate((a), 4))
#define leftRotate5(a)  (leftRotate((a), 5))
#define leftRotate6(a)  (leftRotate((a), 6))
#define leftRotate7(a)  (leftRotate((a), 7))
#define leftRotate8(a)  (leftRotate((a), 8))
#define leftRotate9(a)  (leftRotate((a), 9))
#define leftRotate10(a) (leftRotate((a), 10))
#define leftRotate11(a) (leftRotate((a), 11))
#define leftRotate12(a) (leftRotate((a), 12))
#define leftRotate13(a) (leftRotate((a), 13))
#define leftRotate14(a) (leftRotate((a), 14))
#define leftRotate15(a) (leftRotate((a), 15))
#define leftRotate16(a) (leftRotate((a), 16))
#define leftRotate17(a) (leftRotate((a), 17))
#define leftRotate18(a) (leftRotate((a), 18))
#define leftRotate19(a) (leftRotate((a), 19))
#define leftRotate20(a) (leftRotate((a), 20))
#define leftRotate21(a) (leftRotate((a), 21))
#define leftRotate22(a) (leftRotate((a), 22))
#define leftRotate23(a) (leftRotate((a), 23))
#define leftRotate24(a) (leftRotate((a), 24))
#define leftRotate25(a) (leftRotate((a), 25))
#define leftRotate26(a) (leftRotate((a), 26))
#define leftRotate27(a) (leftRotate((a), 27))
#define leftRotate28(a) (leftRotate((a), 28))
#define leftRotate29(a) (leftRotate((a), 29))
#define leftRotate30(a) (leftRotate((a), 30))
#define leftRotate31(a) (leftRotate((a), 31))

/* Right rotate by a specific number of bits */
#define rightRotate1(a)  (rightRotate((a), 1))
#define rightRotate2(a)  (rightRotate((a), 2))
#define rightRotate3(a)  (rightRotate((a), 3))
#define rightRotate4(a)  (rightRotate((a), 4))
#define rightRotate5(a)  (rightRotate((a), 5))
#define rightRotate6(a)  (rightRotate((a), 6))
#define rightRotate7(a)  (rightRotate((a), 7))
#define rightRotate8(a)  (rightRotate((a), 8))
#define rightRotate9(a)  (rightRotate((a), 9))
#define rightRotate10(a) (rightRotate((a), 10))
#define rightRotate11(a) (rightRotate((a), 11))
#define rightRotate12(a) (rightRotate((a), 12))
#define rightRotate13(a) (rightRotate((a), 13))
#define rightRotate14(a) (rightRotate((a), 14))
#define rightRotate15(a) (rightRotate((a), 15))
#define rightRotate16(a) (rightRotate((a), 16))
#define rightRotate17(a) (rightRotate((a), 17))
#define rightRotate18(a) (rightRotate((a), 18))
#define rightRotate19(a) (rightRotate((a), 19))
#define rightRotate20(a) (rightRotate((a), 20))
#define rightRotate21(a) (rightRotate((a), 21))
#define rightRotate22(a) (rightRotate((a), 22))
#define rightRotate23(a) (rightRotate((a), 23))
#define rightRotate24(a) (rightRotate((a), 24))
#define rightRotate25(a) (rightRotate((a), 25))
#define rightRotate26(a) (rightRotate((a), 26))
#define rightRotate27(a) (rightRotate((a), 27))
#define rightRotate28(a) (rightRotate((a), 28))
#define rightRotate29(a) (rightRotate((a), 29))
#define rightRotate30(a) (rightRotate((a), 30))
#define rightRotate31(a) (rightRotate((a), 31))

/* Rotation macros for 64-bit arguments */

/* Generic left rotate */
#define leftRotate_64(a, bits) \
    (__extension__ ({ \
        uint64_t _temp = (a); \
        (_temp << (bits)) | (_temp >> (64 - (bits))); \
    }))

/* Generic right rotate */
#define rightRotate_64(a, bits) \
    (__extension__ ({ \
        uint64_t _temp = (a); \
        (_temp >> (bits)) | (_temp << (64 - (bits))); \
    }))

/* Left rotate by a specific number of bits */
#define leftRotate1_64(a)  (leftRotate_64((a), 1))
#define leftRotate2_64(a)  (leftRotate_64((a), 2))
#define leftRotate3_64(a)  (leftRotate_64((a), 3))
#define leftRotate4_64(a)  (leftRotate_64((a), 4))
#define leftRotate5_64(a)  (leftRotate_64((a), 5))
#define leftRotate6_64(a)  (leftRotate_64((a), 6))
#define leftRotate7_64(a)  (leftRotate_64((a), 7))
#define leftRotate8_64(a)  (leftRotate_64((a), 8))
#define leftRotate9_64(a)  (leftRotate_64((a), 9))
#define leftRotate10_64(a) (leftRotate_64((a), 10))
#define leftRotate11_64(a) (leftRotate_64((a), 11))
#define leftRotate12_64(a) (leftRotate_64((a), 12))
#define leftRotate13_64(a) (leftRotate_64((a), 13))
#define leftRotate14_64(a) (leftRotate_64((a), 14))
#define leftRotate15_64(a) (leftRotate_64((a), 15))
#define leftRotate16_64(a) (leftRotate_64((a), 16))
#define leftRotate17_64(a) (leftRotate_64((a), 17))
#define leftRotate18_64(a) (leftRotate_64((a), 18))
#define leftRotate19_64(a) (leftRotate_64((a), 19))
#define leftRotate20_64(a) (leftRotate_64((a), 20))
#define leftRotate21_64(a) (leftRotate_64((a), 21))
#define leftRotate22_64(a) (leftRotate_64((a), 22))
#define leftRotate23_64(a) (leftRotate_64((a), 23))
#define leftRotate24_64(a) (leftRotate_64((a), 24))
#define leftRotate25_64(a) (leftRotate_64((a), 25))
#define leftRotate26_64(a) (leftRotate_64((a), 26))
#define leftRotate27_64(a) (leftRotate_64((a), 27))
#define leftRotate28_64(a) (leftRotate_64((a), 28))
#define leftRotate29_64(a) (leftRotate_64((a), 29))
#define leftRotate30_64(a) (leftRotate_64((a), 30))
#define leftRotate31_64(a) (leftRotate_64((a), 31))
#define leftRotate32_64(a) (leftRotate_64((a), 32))
#define leftRotate33_64(a) (leftRotate_64((a), 33))
#define leftRotate34_64(a) (leftRotate_64((a), 34))
#define leftRotate35_64(a) (leftRotate_64((a), 35))
#define leftRotate36_64(a) (leftRotate_64((a), 36))
#define leftRotate37_64(a) (leftRotate_64((a), 37))
#define leftRotate38_64(a) (leftRotate_64((a), 38))
#define leftRotate39_64(a) (leftRotate_64((a), 39))
#define leftRotate40_64(a) (leftRotate_64((a), 40))
#define leftRotate41_64(a) (leftRotate_64((a), 41))
#define leftRotate42_64(a) (leftRotate_64((a), 42))
#define leftRotate43_64(a) (leftRotate_64((a), 43))
#define leftRotate44_64(a) (leftRotate_64((a), 44))
#define leftRotate45_64(a) (leftRotate_64((a), 45))
#define leftRotate46_64(a) (leftRotate_64((a), 46))
#define leftRotate47_64(a) (leftRotate_64((a), 47))
#define leftRotate48_64(a) (leftRotate_64((a), 48))
#define leftRotate49_64(a) (leftRotate_64((a), 49))
#define leftRotate50_64(a) (leftRotate_64((a), 50))
#define leftRotate51_64(a) (leftRotate_64((a), 51))
#define leftRotate52_64(a) (leftRotate_64((a), 52))
#define leftRotate53_64(a) (leftRotate_64((a), 53))
#define leftRotate54_64(a) (leftRotate_64((a), 54))
#define leftRotate55_64(a) (leftRotate_64((a), 55))
#define leftRotate56_64(a) (leftRotate_64((a), 56))
#define leftRotate57_64(a) (leftRotate_64((a), 57))
#define leftRotate58_64(a) (leftRotate_64((a), 58))
#define leftRotate59_64(a) (leftRotate_64((a), 59))
#define leftRotate60_64(a) (leftRotate_64((a), 60))
#define leftRotate61_64(a) (leftRotate_64((a), 61))
#define leftRotate62_64(a) (leftRotate_64((a), 62))
#define leftRotate63_64(a) (leftRotate_64((a), 63))

/* Right rotate by a specific number of bits */
#define rightRotate1_64(a)  (rightRotate_64((a), 1))
#define rightRotate2_64(a)  (rightRotate_64((a), 2))
#define rightRotate3_64(a)  (rightRotate_64((a), 3))
#define rightRotate4_64(a)  (rightRotate_64((a), 4))
#define rightRotate5_64(a)  (rightRotate_64((a), 5))
#define rightRotate6_64(a)  (rightRotate_64((a), 6))
#define rightRotate7_64(a)  (rightRotate_64((a), 7))
#define rightRotate8_64(a)  (rightRotate_64((a), 8))
#define rightRotate9_64(a)  (rightRotate_64((a), 9))
#define rightRotate10_64(a) (rightRotate_64((a), 10))
#define rightRotate11_64(a) (rightRotate_64((a), 11))
#define rightRotate12_64(a) (rightRotate_64((a), 12))
#define rightRotate13_64(a) (rightRotate_64((a), 13))
#define rightRotate14_64(a) (rightRotate_64((a), 14))
#define rightRotate15_64(a) (rightRotate_64((a), 15))
#define rightRotate16_64(a) (rightRotate_64((a), 16))
#define rightRotate17_64(a) (rightRotate_64((a), 17))
#define rightRotate18_64(a) (rightRotate_64((a), 18))
#define rightRotate19_64(a) (rightRotate_64((a), 19))
#define rightRotate20_64(a) (rightRotate_64((a), 20))
#define rightRotate21_64(a) (rightRotate_64((a), 21))
#define rightRotate22_64(a) (rightRotate_64((a), 22))
#define rightRotate23_64(a) (rightRotate_64((a), 23))
#define rightRotate24_64(a) (rightRotate_64((a), 24))
#define rightRotate25_64(a) (rightRotate_64((a), 25))
#define rightRotate26_64(a) (rightRotate_64((a), 26))
#define rightRotate27_64(a) (rightRotate_64((a), 27))
#define rightRotate28_64(a) (rightRotate_64((a), 28))
#define rightRotate29_64(a) (rightRotate_64((a), 29))
#define rightRotate30_64(a) (rightRotate_64((a), 30))
#define rightRotate31_64(a) (rightRotate_64((a), 31))
#define rightRotate32_64(a) (rightRotate_64((a), 32))
#define rightRotate33_64(a) (rightRotate_64((a), 33))
#define rightRotate34_64(a) (rightRotate_64((a), 34))
#define rightRotate35_64(a) (rightRotate_64((a), 35))
#define rightRotate36_64(a) (rightRotate_64((a), 36))
#define rightRotate37_64(a) (rightRotate_64((a), 37))
#define rightRotate38_64(a) (rightRotate_64((a), 38))
#define rightRotate39_64(a) (rightRotate_64((a), 39))
#define rightRotate40_64(a) (rightRotate_64((a), 40))
#define rightRotate41_64(a) (rightRotate_64((a), 41))
#define rightRotate42_64(a) (rightRotate_64((a), 42))
#define rightRotate43_64(a) (rightRotate_64((a), 43))
#define rightRotate44_64(a) (rightRotate_64((a), 44))
#define rightRotate45_64(a) (rightRotate_64((a), 45))
#define rightRotate46_64(a) (rightRotate_64((a), 46))
#define rightRotate47_64(a) (rightRotate_64((a), 47))
#define rightRotate48_64(a) (rightRotate_64((a), 48))
#define rightRotate49_64(a) (rightRotate_64((a), 49))
#define rightRotate50_64(a) (rightRotate_64((a), 50))
#define rightRotate51_64(a) (rightRotate_64((a), 51))
#define rightRotate52_64(a) (rightRotate_64((a), 52))
#define rightRotate53_64(a) (rightRotate_64((a), 53))
#define rightRotate54_64(a) (rightRotate_64((a), 54))
#define rightRotate55_64(a) (rightRotate_64((a), 55))
#define rightRotate56_64(a) (rightRotate_64((a), 56))
#define rightRotate57_64(a) (rightRotate_64((a), 57))
#define rightRotate58_64(a) (rightRotate_64((a), 58))
#define rightRotate59_64(a) (rightRotate_64((a), 59))
#define rightRotate60_64(a) (rightRotate_64((a), 60))
#define rightRotate61_64(a) (rightRotate_64((a), 61))
#define rightRotate62_64(a) (rightRotate_64((a), 62))
#define rightRotate63_64(a) (rightRotate_64((a), 63))

#endif
