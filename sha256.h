/*
 * sha256.h — Public API for SHA-256 with runtime CPU dispatch.
 *
 * Only two functions are exposed:
 *   sha256()          — compute the SHA-256 hash of a buffer
 *   sha256_impl_name() — return the name of the active transform
 */

#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

/**
 * Calculate SHA-256 hash of input buffer.
 *
 * @param input  Pointer to input data (may be NULL if len == 0)
 * @param len    Length of input data in bytes
 * @param hash   Pointer to output buffer (must be at least 32 bytes)
 *
 * Asserts and aborts on critical internal errors.
 */
void sha256(const uint8_t *input, size_t len, uint8_t *hash);

/**
 * Return the name of the active SHA-256 transform implementation.
 *
 * @return  Static string: "software" or "arm64_crypto"
 */
const char *sha256_impl_name(void);

#endif /* SHA256_H */
