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
 * \brief Finishes using the random number source.
 *
 * If the random API has internal state, then this function will
 * destroy the internal state to protect forward secrecy.
 */
void aead_random_finish(void);

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

/**
 * \brief Reseeds the random number generator from the system TRNG.
 *
 * This function does nothing if the random API is using the
 * system TRNG directly.
 *
 * This function is called implicitly by aead_random_init().
 */
void aead_random_reseed(void);

/**
 * \brief Restarts the random number generator with a specific 256-bit seed.
 *
 * \param seed The seed material.
 *
 * This function does nothing if the random API is using the system
 * TRNG directly.  This function is useful for creating reproducible
 * random numbers for test purposes.  It should not be used for real work.
 */
void aead_random_set_seed(const unsigned char seed[32]);

#ifdef __cplusplus
}
#endif

#endif
