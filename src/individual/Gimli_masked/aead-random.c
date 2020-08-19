/*
 * This file has been placed into the public domain by Rhys Weatherley.
 * It can be reused and modified as necessary.  It may even be completely
 * thrown away and replaced with a different implementation that provides
 * the same API.
 *
 * If your CPU has a special TRNG instruction or peripheral register
 * that produces random values on demand, then edit the code below to
 * define the macros aead_system_random_init() and aead_system_random().
 *
 * If there is no special instruction or peripheral register specified,
 * then a PRNG based on ChaCha20 will be used.  It is recommended that
 * aead_random_reseed() be modified to seed the PRNG with the system time,
 * /dev/urandom output, or something similar.
 *
 * You can force the use of the PRNG by defining AEAD_USE_PRNG on the
 * compiler's command-line.  If there is a TRNG instruction available,
 * then it will be used to seed the PRNG with 256 bits of TRNG data
 * whenever aead_random_init() is called.
 *
 * WARNING: The functions in this file are not thread-safe!
 */

#define _GNU_SOURCE
#include "aead-random.h"
#include <string.h>
#if defined(ARDUINO)
#include <Arduino.h>
#endif
#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#endif

/**
 * \def AEAD_USE_PRNG
 * \brief Define this macro to use the ChaCha20-based PRNG even if there
 * is a system TRNG present.  Normally the TRNG is used directly.
 */
/*#define AEAD_USE_PRNG 1*/

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

/* Force the use of the PRNG if we don't have any form of system TRNG */
#if !defined(aead_system_random)
#if !defined(AEAD_USE_PRNG)
#define AEAD_USE_PRNG 1
#endif
#define aead_system_random_init() do { ; } while (0)
#endif /* !aead_system_random */

#if defined(AEAD_USE_PRNG)

/* Load a little-endian 32-bit word from a byte buffer */
#define le_load_word32(ptr) \
    ((((uint32_t)((ptr)[3])) << 24) | \
     (((uint32_t)((ptr)[2])) << 16) | \
     (((uint32_t)((ptr)[1])) << 8) | \
      ((uint32_t)((ptr)[0])))

/* Rotate a word left by a specific number of bits */
#define leftRotate(a, bits) \
    (__extension__ ({ \
        uint32_t _temp = (a); \
        (_temp << (bits)) | (_temp >> (32 - (bits))); \
    }))

/* Perform a ChaCha quarter round operation */
#define quarterRound(a, b, c, d)    \
    do { \
        uint32_t _b = (b); \
        uint32_t _a = (a) + _b; \
        uint32_t _d = leftRotate((d) ^ _a, 16); \
        uint32_t _c = (c) + _d; \
        _b = leftRotate(_b ^ _c, 12); \
        _a += _b; \
        (d) = _d = leftRotate(_d ^ _a, 8); \
        _c += _d; \
        (a) = _a; \
        (b) = leftRotate(_b ^ _c, 7); \
        (c) = _c; \
    } while (0)

/**
 * \brief Executes the ChaCha20 hash core on a block.
 *
 * \param output Output block, must not overlap with \a input.
 * \param input Input block.
 *
 * Both blocks are assumed to be in host byte order.
 */
static void aead_chacha_core(uint32_t output[16], const uint32_t input[16])
{
    uint8_t round;
    uint8_t posn;

    /* Copy the input buffer to the output prior to the first round */
    for (posn = 0; posn < 16; ++posn)
        output[posn] = input[posn];

    /* Perform the ChaCha rounds in sets of two */
    for (round = 20; round >= 2; round -= 2) {
        /* Column round */
        quarterRound(output[0], output[4], output[8],  output[12]);
        quarterRound(output[1], output[5], output[9],  output[13]);
        quarterRound(output[2], output[6], output[10], output[14]);
        quarterRound(output[3], output[7], output[11], output[15]);

        /* Diagonal round */
        quarterRound(output[0], output[5], output[10], output[15]);
        quarterRound(output[1], output[6], output[11], output[12]);
        quarterRound(output[2], output[7], output[8],  output[13]);
        quarterRound(output[3], output[4], output[9],  output[14]);
    }

    /* Add the original input to the final output */
    for (posn = 0; posn < 16; ++posn)
        output[posn] += input[posn];
}

/**
 * \brief Global PRNG state.
 *
 * The starting value is the string "expand 32-byte k" followed by zeroes.
 * It will not stay in this state for long as aead_random_init() will
 * reseed and re-key the PRNG when it is called.
 *
 * The last word is used as a block counter when multiple output blocks
 * are required.  The PRNG is reseeded every AEAD_PRNG_MAX_BLOCKS.
 */
static uint32_t aead_chacha_state[16] = {
    0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/**
 * \brief Temporary output for the generation of data between re-keying.
 */
static uint32_t aead_chacha_output[16];

/**
 * \brief Position of the next word to return from the PRNG.
 */
static uint8_t aead_chacha_posn = 16;

/**
 * \brief Number of blocks that have been generated since the last re-key.
 */
static uint16_t aead_chacha_blocks = 0;

/**
 * \brief Automatically re-key every 16K of output data.  This can be adjusted.
 */
#define AEAD_PRNG_MAX_BLOCKS 256

/**
 * \brief Re-keys the PRNG state to enforce forward secrecy.
 *
 * This function generates a new output block and then copies the first
 * 384 bits of the output to the last 384 bits of aead_chacha_state,
 * which will destroy any chance of going backwards.
 */
static void aead_chacha_rekey(void)
{
    ++(aead_chacha_state[15]);
    aead_chacha_core(aead_chacha_output, aead_chacha_state);
    memcpy(aead_chacha_state + 4, aead_chacha_output, 48);
    aead_chacha_posn = 16;
    aead_chacha_blocks = 0;
}

/* Defined if we are using the ChaCha20-based PRNG */
#define aead_system_random_is_chacha 1

#endif /* AEAD_USE_PRNG */

void aead_random_init(void)
{
    aead_system_random_init();
#if defined(aead_system_random_is_chacha)
    aead_random_reseed();
#endif
}

void aead_random_finish(void)
{
#if defined(aead_system_random_is_chacha)
    /* Re-key the random number generator to enforce forward secrecy */
    aead_chacha_rekey();
#endif
}

uint32_t aead_random_generate_32(void)
{
#if defined(aead_system_random_is_chacha)
    if (aead_chacha_posn < 16) {
        /* We still have data in the previous block */
        return aead_chacha_output[aead_chacha_posn++];
    } else {
        /* Re-key if we have generated too many blocks since the last re-key */
        ++aead_chacha_blocks;
        if (aead_chacha_blocks >= AEAD_PRNG_MAX_BLOCKS)
            aead_chacha_rekey();

        /* Increment the block counter and generate a new output block */
        ++(aead_chacha_state[15]);
        aead_chacha_core(aead_chacha_output, aead_chacha_state);
        aead_chacha_posn = 1;
        return aead_chacha_output[0];
    }
#elif defined(aead_system_random_is_64bit)
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
#if defined(aead_system_random_is_chacha)
    uint32_t x, y;
    x = aead_random_generate_32();
    y = aead_random_generate_32();
    return x | (((uint64_t)y) << 32);
#elif defined(aead_system_random_is_64bit)
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
#if defined(aead_system_random_is_chacha)
    unsigned char *buf = (unsigned char *)buffer;
    uint32_t x;
    while (size >= sizeof(uint32_t)) {
        x = aead_random_generate_32();
        memcpy(buf, &x, sizeof(x));
        buf += sizeof(uint32_t);
        size -= sizeof(uint32_t);
    }
    if (size > 0) {
        x = aead_random_generate_32();
        memcpy(buf, &x, size);
    }
#elif defined(aead_system_random_is_64bit)
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

void aead_random_reseed(void)
{
#if defined(aead_system_random_is_chacha)
    /* If we have a system TRNG, then use it to reseed the PRNG state */
#if defined(aead_system_random) && defined(aead_system_random_is_64bit)
    uint8_t index;
    uint64_t x;
    for (index = 4; index < 12; index += 2) {
        aead_system_random(x);
        aead_chacha_state[index] = (uint32_t)x;
        aead_chacha_state[index + 1] = (uint32_t)(x >> 32);
    }
#elif defined(aead_system_random)
    uint8_t index;
    for (index = 4; index < 12; ++index)
        aead_system_random(aead_chacha_state[index]);
#elif defined(ARDUINO)
    /* XOR in the current Arduino time to provide a little jitter.
     * These values may be predictable but they are better than nothing. */
    aead_chacha_state[4] ^= millis();
    aead_chacha_state[5] ^= micros();
#elif defined(__linux__)
    /* Use the getrandom() system call to seed the PRNG if we have it */
#if defined(SYS_getrandom)
    if (syscall(SYS_getrandom, aead_chacha_state + 4, 32, 0) != 32)
#endif
    {
        /* Fall back to /dev/urandom to seed the PRNG.  If for some reason
         * that fails, then use the current system time.  This is not ideal. */
        int seeded = 0;
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd >= 0) {
            if (read(fd, aead_chacha_state + 4, 32) == 32)
                seeded = 1;
            close(fd);
        }
        if (!seeded) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            aead_chacha_state[4] ^= (uint32_t)(tv.tv_sec);
            aead_chacha_state[5] ^= (uint32_t)(tv.tv_usec);
        }
    }
#endif

    /* Re-key the PRNG to enforce forward secrecy */
    aead_chacha_rekey();
#endif
}

void aead_random_set_seed(const unsigned char seed[32])
{
#if defined(aead_system_random_is_chacha)
    /* Copy the provided seed into place and then re-key the PRNG.
     * We load the seed in a way that ensures the same output on
     * both little-endian and big-endian machines. */
    int index;
    for (index = 0; index < 8; ++index)
        aead_chacha_state[index + 4] = le_load_word32(seed + index * 4);
    memset(aead_chacha_state + 12, 0, 16);
    aead_chacha_rekey();
#else
    (void)seed;
#endif
}
