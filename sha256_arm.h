/*
 * sha256_arm.h — Private internal header.
 *
 * Declares transform functions and the function pointer typedef shared
 * between sha256.c and sha256_arm.c. Also used by unit tests to call
 * individual implementations directly.
 */

#ifndef SHA256_ARM_H
#define SHA256_ARM_H

#include <stdint.h>

/*
 * Transform function pointer type.
 *
 * Alignment invariant: `state` MUST point to a 16-byte aligned buffer.
 * `block` has no alignment requirement — implementations use unaligned
 * loads for input data.
 */
typedef void (*sha256_transform_fn)(uint32_t state[8], const uint8_t block[64]);

/*
 * Software (pure C) transform — always available.
 */
void sha256_transform_sw(uint32_t state[8], const uint8_t block[64]);

#ifdef __aarch64__

/*
 * ARM64 crypto transform — SHA-2 hardware extension intrinsics.
 */
void sha256_transform_arm64_crypto(uint32_t state[8], const uint8_t block[64]);

#endif /* __aarch64__ */

#endif /* SHA256_ARM_H */
