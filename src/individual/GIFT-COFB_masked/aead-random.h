/*
 * This file has been placed into the public domain by Rhys Weatherley.
 * It can be reused and modified as necessary.  It may even be completely
 * thrown away and replaced with a different system-specific implementation
 * that provides the same API.
 */

#ifndef LWCRYPTO_AEAD_RANDOM_H
#define LWCRYPTO_AEAD_RANDOM_H

#include <stdint.h>

/**
 * \file aead-random.h
 * \brief Utilities that help with the generation of random masking material.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief Initializes the system random number generator for the
 * generation of masking material.
 */
void aead_random_init(void);

/**
 * \brief Generates a single random 32-bit word.
 *
 * \return The random word.
 */
uint32_t aead_random_generate_32(void);

/**
 * \brief Generates a single random 64-bit word.
 *
 * \return The random word.
 */
uint64_t aead_random_generate_64(void);

/**
 * \brief Generates a number of bytes into a buffer.
 *
 * \param buffer The buffer to generate into.
 * \param size The number of bytes to be generated.
 */
void aead_random_generate(void *buffer, unsigned size);

#ifdef __cplusplus
}
#endif

#endif
