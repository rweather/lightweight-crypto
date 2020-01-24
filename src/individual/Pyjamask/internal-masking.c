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

#include "internal-masking.h"
#include <string.h>

/* Determine if we have a CPU random number generator that can generate
 * raw 32-bit values.  Modify this to add support for new CPU's */
#if defined(__x86_64) || defined(__x86_64__)
/* Assume that we have the RDRAND instruction on x86-64 platforms */
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var) \
    do { \
        uint64_t temp = 0; \
        uint8_t ok = 0; \
        do { \
            __asm__ __volatile__ ( \
                ".byte 0x48,0x0f,0xc7,0xf0 ; setc %1" \
                : "=a"(temp), "=q"(ok) :: "cc" \
            ); \
        } while (!ok); \
        (var) = (uint32_t)temp; \
    } while (0)
#endif
#if defined (__arm__) && defined (__SAM3X8E__) && defined(ARDUINO)
/* Arduino Due */
#include <Arduino.h>
#define aead_system_random_init() \
    do { \
        static int done = 0; \
        if (!done) { \
            pmc_enable_periph_clk(ID_TRNG); \
            REG_TRNG_CR = TRNG_CR_KEY(0x524E47) | TRNG_CR_ENABLE; \
            REG_TRNG_IDR = TRNG_IDR_DATRDY; \
            done = 1; \
        } \
    } while (0)
#define aead_system_random(var) \
    do { \
        while ((REG_TRNG_ISR & TRNG_ISR_DATRDY) == 0) \
            ; \
        (var) = REG_TRNG_ODATA; \
    } while (0)
#endif
#if defined(ESP8266)
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var) ((var) = *((volatile int *)0x3FF20E44))
#endif
#if defined(ESP32)
extern uint32_t esp_random(void);
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var) ((var) = esp_random())
#endif

/* Default implementations when we don't know what system we're running on */
#if !defined(aead_system_random)
#warning "No random number source found!"
/* Use Xorshift to provide a source of random numbers as a last ditch fallback.
 * This is not cryptographically secure so it is only suitable for testing.
 * https://en.wikipedia.org/wiki/Xorshift */
static uint64_t seed = 0x6A09E667F3BCC908ULL; /* First init word from SHA-512 */
#define aead_system_random_init() do { ; } while (0)
#define aead_system_random(var) \
    do { \
        seed ^= seed << 13; \
        seed ^= seed >> 7; \
        seed ^= seed << 17; \
        if (!seed) { \
            /* Prevent the RNG from getting stuck at zero */ \
            seed = 0x6A09E667F3BCC908ULL; \
        } \
        (var) = (uint32_t)seed; \
    } while (0)
#endif

void aead_masking_init(void)
{
    aead_system_random_init();
}

void aead_masking_generate(void *data, unsigned size)
{
    uint32_t rand;
    if ((((uintptr_t)data) & ~((uintptr_t)3)) == 0) {
        /* Buffer is 32-bit aligned, so fill the buffer faster */
        while (size >= sizeof(uint32_t)) {
            aead_system_random(*((uint32_t *)data));
            data += sizeof(uint32_t);
            size -= sizeof(uint32_t);
        }
    }
    while (size >= sizeof(uint32_t)) {
        aead_system_random(rand);
        memcpy(data, &rand, sizeof(uint32_t));
        data += sizeof(uint32_t);
        size -= sizeof(uint32_t);
    }
    if (size > 0) {
        aead_system_random(rand);
        memcpy(data, &rand, size);
    }
}

uint32_t aead_masking_generate_32(void)
{
    uint32_t x;
    aead_system_random(x);
    return x;
}
