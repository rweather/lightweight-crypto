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

#ifndef LW_INTERNAL_GIFT128_CONFIG_H
#define LW_INTERNAL_GIFT128_CONFIG_H

/**
 * \file internal-gift128-config.h
 * \brief Configures the variant of GIFT-128 to use.
 */

/**
 * \brief Select the full variant of GIFT-128.
 *
 * The full variant requires 320 bytes for the key schedule and uses the
 * fixslicing method to implement encryption and decryption.
 */
#define GIFT128_VARIANT_FULL    0

/**
 * \brief Select the small variant of GIFT-128.
 *
 * The small variant requires 80 bytes for the key schedule.  The rest
 * of the key schedule is expanded on the fly during encryption.
 *
 * The fixslicing method is used to implement encryption and the slower
 * bitslicing method is used to implement decryption.  The small variant
 * is suitable when memory is at a premium, decryption is not needed,
 * but encryption performance is still important.
 */
#define GIFT128_VARIANT_SMALL   1

/**
 * \brief Select the tiny variant of GIFT-128.
 *
 * The tiny variant requires 16 bytes for the key schedule and uses the
 * bitslicing method to implement encryption and decryption.  It is suitable
 * for use when memory is very tight and performance is not critical.
 */
#define GIFT128_VARIANT_TINY    2

/**
 * \def GIFT128_VARIANT
 * \brief Selects the default variant of GIFT-128 to use on this platform.
 */
/**
 * \def GIFT128_VARIANT_ASM
 * \brief Defined to 1 if the GIFT-128 implementation has been replaced
 * with an assembly code version.
 */
#if defined(__AVR__) && !defined(GIFT128_VARIANT_ASM)
#define GIFT128_VARIANT_ASM 1
#endif
#if !defined(GIFT128_VARIANT)
#define GIFT128_VARIANT GIFT128_VARIANT_FULL
#endif
#if !defined(GIFT128_VARIANT_ASM)
#define GIFT128_VARIANT_ASM 0
#endif

#endif
