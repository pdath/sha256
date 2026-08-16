# Requirements Document: SHA-256 with Runtime CPU Dispatch

## 1. Project Overview

### 1.1 Problem Statement

SHA-256 implementations in Bitcoin ecosystem libraries are typically selected at compile time via GCC directives (e.g., `-march=native`). This creates a deployment problem: binaries built for distribution across heterogeneous hardware (different CPUs, Docker containers) must disable CPU-accelerated instructions and default to slower software implementations to ensure portability.

Existing libraries (OpenSSL, libsodium) provide runtime dispatch but benchmarking consistently shows they are outperformed by hand-coded implementations.

### 1.2 Solution

Implement SHA-256 with multiple backend implementations and runtime CPU feature detection to automatically select the fastest available implementation for the executing hardware:

1. **Software (C)** — portable fallback, works on any platform
2. **ARM64+Crypto (hardware SHA-2 extensions)** — optimized for ARM64 CPUs with SHA-2 hardware extensions, ~4.5× faster than software

### 1.3 Constraints

This project is for a 7-day competition. The following constraints apply:

- **Operating Systems:** Ubuntu and Amazon Linux only
- **CPU Architectures:** ARM64 and ARM64+crypto only
- **Compiler:** GCC only
- **Assembly approach:** The crypto transform uses C intrinsics (`arm_neon.h`) rather than raw assembly. This simplifies call handling between C and the optimized code to help AI.
- **Scope of intrinsic implementations:** Only the SHA-256 transform (compression function) is implemented using intrinsics. Init, update, and finalize phases remain in C.
- **Out of scope:** x86/x86_64 implementations, other processor families.

---

## 2. Priorities

| Priority | Requirement | Rationale |
|----------|-------------|-----------|
| **#1** | **Correctness** | Incorrect SHA-256 output could result in loss of funds in Bitcoin applications. The software MUST `assert()` and crash on critical errors rather than returning error codes that upper layers might ignore. |
| **#2** | **Speed** | Uglier code is acceptable if it provides measurable speed gains. |

---

## 3. Functional Requirements

### 3.1 SHA-256 Library

| ID | Requirement |
|----|-------------|
| FR-01 | Provide a public function `sha256()` that calculates the SHA-256 hash of an input buffer in one call. |
| FR-02 | Provide a public function `sha256_impl_name()` that returns the name of the active transform implementation. |
| FR-03 | Internally, `sha256()` SHALL perform init, update, and finalize phases. |
| FR-04 | Provide a software-only (pure C) implementation of SHA-256 that works on any supported platform. |
| FR-05 | Provide an ARM64+crypto intrinsics implementation of the SHA-256 transform using hardware SHA-2 extensions. |
| FR-06 | At runtime, on ARM64 (`__aarch64__` defined), use `getauxval()` to check `HWCAP_SHA2`. If present, use the crypto-accelerated transform. Otherwise, use the software (C) transform. |
| FR-07 | On non-ARM64 platforms, fall back to the software-only implementation. |
| FR-08 | On critical errors, call `assert()` to crash the process rather than returning an error code. |

### 3.2 sha256sum Tool

| ID | Requirement |
|----|-------------|
| FR-09 | Provide a command-line tool (`sha256`) that calculates the SHA-256 hash of exactly one file, similar to the Linux `sha256sum` command. |
| FR-10 | Output format SHALL match `sha256sum` (lowercase hex hash followed by two spaces and the filename). |
| FR-11 | The executable SHALL be named `sha256`. |

### 3.3 Unit Tests and Benchmarks

| ID | Requirement |
|----|-------------|
| FR-12 | Provide a unit test program that validates SHA-256 correctness against known test vectors. |
| FR-13 | The unit test program SHALL also perform benchmarking of all available implementations. |
| FR-14 | Unit tests SHALL test all available implementations (software, ARM64+crypto) independently. |

---

## 4. Non-Functional Requirements

| ID | Requirement |
|----|-------------|
| NFR-01 | Language: C (compatible with both C and C++ ecosystems). |
| NFR-02 | Standard: gnu17. |
| NFR-03 | Compiler: GCC only. |
| NFR-04 | Target OS: Ubuntu, Amazon Linux. |
| NFR-05 | Target Architecture: ARM64 (aarch64). |
| NFR-06 | Build system: GNU Make (simple Makefile). |

---

## 5. Build System Requirements

### 5.1 Make Targets

| Target | Description |
|--------|-------------|
| `make` (default) | Production build with optimizations. |
| `make dev` | Development build (debug symbols, warnings). |
| `make asan` | Build with AddressSanitizer and UndefinedBehaviourSanitizer enabled, then run unit tests. |

### 5.2 Compiler Defines (provided by GCC)

| Define | Condition |
|--------|-----------|
| `__aarch64__` (set to 1) | Compiling on/for ARM64. |
| `__linux__` (set to 1) | Compiling on/for Linux. |

---

## 6. Runtime Dispatch Logic

```
#ifdef __aarch64__
    if (getauxval(AT_HWCAP) & HWCAP_SHA2)
        → use sha256_transform_arm64_crypto() transform (ARM64 + crypto extensions)
    else
        → use sha256_transform_sw() (software C implementation)
#else
    → use software C implementation
#endif
```

---

## 7. File Structure

| File | Purpose |
|------|---------|
| `sha256.c` | Public `sha256()` function, software C implementation, runtime dispatch logic, init/update/finalize phases. |
| `sha256.h` | Public header — declarations for external callers. |
| `sha256_arm.c` | ARM64+crypto intrinsic implementation: `sha256_transform_arm64_crypto()` (crypto extensions). Uses `arm_neon.h`. |
| `sha256_arm.h` | Private header — internal declarations shared between `sha256.c` and `sha256_arm.c`. |
| `sha256_unit_test.c` | Standalone test/benchmark program. |
| `main.c` | `sha256sum`-like CLI tool. Output executable: `sha256`. |
| `Makefile` | Build system with targets: default, dev, asan, valgrind. |
| `README.md` | Project documentation for the GitHub repository. |

---

## 8. Public API

```c
/* sha256.h */

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
```

---

## 9. Documentation Requirements (README.md)

The README.md SHALL include:

1. Project description
2. The problem being solved
3. Key features
4. Target users
5. Build environment setup (what to install)
6. Make target descriptions
7. Usage instructions for the `sha256` tool
8. How to verify correctness against system `sha256sum`

---

## 10. Out of Scope

The following are explicitly out of scope for this 7-day competition:

- x86/x86_64 implementations (`sha256_x86.c`)
- Other processor families (RISC-V, POWER, etc.)
- Windows or macOS support
- Alternative compilers (Clang, MSVC)
- Streaming/incremental public API (internal only)
- Multi-threaded hashing
