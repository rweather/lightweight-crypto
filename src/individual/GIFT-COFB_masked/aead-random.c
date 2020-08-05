/*
 * This file has been placed into the public domain by Rhys Weatherley.
 * It can be reused and modified as necessary.  It may even be completely
 * thrown away and replaced with a different system-specific implementation
 * that provides the same API.
 */

#include "aead-random.h"
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
        (var) = temp; \
    } while (0)
#define aead_system_random_is_64bit 1
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

void aead_random_init(void)
{
    aead_system_random_init();
}

uint32_t aead_random_generate_32(void)
{
#if defined(aead_system_random_is_64bit)
    uint64_t x;
    aead_system_random(x);
    return (uint32_t)x;
#else
    uint32_t x;
    aead_system_random(x);
    return x;
#endif
}

uint64_t aead_random_generate_64(void)
{
#if defined(aead_system_random_is_64bit)
    uint64_t x;
    aead_system_random(x);
    return x;
#else
    uint32_t x, y;
    aead_system_random(x);
    aead_system_random(y);
    return x | (((uint64_t)y) << 32);
#endif
}

void aead_random_generate(void *buffer, unsigned size)
{
#if defined(aead_system_random_is_64bit)
    unsigned char *buf = (unsigned char *)buffer;
    uint64_t x;
    while (size >= sizeof(uint64_t)) {
        aead_system_random(x);
        memcpy(buf, &x, sizeof(x));
        buf += sizeof(uint64_t);
        size -= sizeof(uint64_t);
    }
    if (size > 0) {
        aead_system_random(x);
        memcpy(buf, &x, size);
    }
#else
    unsigned char *buf = (unsigned char *)buffer;
    uint32_t x;
    while (size >= sizeof(uint32_t)) {
        aead_system_random(x);
        memcpy(buf, &x, sizeof(x));
        buf += sizeof(uint32_t);
        size -= sizeof(uint32_t);
    }
    if (size > 0) {
        aead_system_random(x);
        memcpy(buf, &x, size);
    }
#endif
}
