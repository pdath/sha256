# Technical Design Document: SHA-256 with Runtime CPU Dispatch

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                    Caller (main.c)                       │
│                                                         │
│              sha256(input, len, hash)                    │
└───────────────────────────┬─────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────┐
│                     sha256.c                             │
│                                                         │
│  ┌─────────────────────────────────────────────────┐    │
│  │         Runtime Dispatch (once at startup)       │    │
│  │                                                  │    │
│  │  #ifdef __aarch64__                              │    │
│  │    getauxval(AT_HWCAP) & HWCAP_SHA2?             │    │
│  │      YES → transform = sha256_transform_arm64_crypto   │
│  │      NO  → transform = sha256_transform_sw       │    │
│  │  #else                                           │    │
│  │    transform = sha256_transform_sw               │    │
│  │  #endif                                          │    │
│  └─────────────────────────────────────────────────┘    │
│                                                         │
│  sha256_init()  →  sha256_update()  →  sha256_final()   │
│                         │                               │
│                         ▼                               │
│              transform function pointer                  │
└────────────────────────┬────────────────┬───────────────┘
                         │                │
                 ┌───────▼──────┐  ┌──────▼─────────────┐
                 │   Software   │  │   ARM64+Crypto     │
                 │     (C)      │  │   (SHA2 ext)       │
                 │              │  │                    │
                 │  sha256.c:   │  │  sha256_arm.c:     │
                 │  _transform  │  │  _transform        │
                 │  _sw()       │  │  _arm64_crypto()   │
                 └──────────────┘  └────────────────────┘
```

---

## 2. SHA-256 Algorithm Structure

SHA-256 processes data in three phases:

### 2.1 Init

Set the hash state to the standard SHA-256 initial values (H0–H7) and zero the bit counter.

### 2.2 Update

Process the input buffer by splitting it into 64-byte (512-bit) blocks and calling the **transform** function on each. Track the total number of bytes processed. Any trailing bytes (less than 64) are carried forward for the finalize phase.

### 2.3 Final

Apply SHA-256 padding:
1. Append a `0x80` byte.
2. Pad with zeros until the block is 56 bytes (mod 64).
3. Append the 64-bit big-endian bit count.
4. Process the final block(s) with transform.
5. Write the 32-byte hash output in big-endian byte order.

### 2.4 Transform (Compression Function)

The core of SHA-256. Processes one 64-byte block:
1. Prepare the message schedule W[0..63] (16 words from input + 48 derived words).
2. Initialize working variables a–h from current state.
3. Perform 64 rounds of mixing using the SHA-256 round constants K[0..63].
4. Add working variables back to state.

This is the only phase with architecture-specific implementations.

---

## 3. Data Structures

### 3.1 SHA-256 Context

```c
/* Internal context — defined in sha256.c, not exposed in public header */
typedef struct {
    uint32_t state[8] __attribute__((aligned(16)));  /* H0–H7 hash state */
    uint64_t bitcount;                               /* Total bits processed */
    uint8_t  buffer[64] __attribute__((aligned(16))); /* Partial block buffer */
} sha256_ctx;
```

This structure is internal to the implementation. It is stack-allocated within `sha256()` and never exposed to callers. Alignment attributes ensure NEON/crypto intrinsics can safely access `state[]` and `buffer[]` as 128-bit vectors (see Section 6).

### 3.2 Transform Function Pointer Type

```c
/*
 * Transform function pointer type.
 *
 * Alignment invariant: `state` MUST point to a 16-byte aligned buffer.
 * This is guaranteed when called with sha256_ctx.state (which carries
 * __attribute__((aligned(16)))). Callers must not invoke transform
 * functions via this pointer with an unaligned state array.
 *
 * `block` has no alignment requirement — implementations use unaligned
 * vector loads (vld1q) for input data.
 */
typedef void (*sha256_transform_fn)(uint32_t state[8], const uint8_t block[64]);
```

---

## 4. Dispatch Mechanism

### 4.1 Strategy: Function Pointer with Constructor Init and Self-Test

A file-scope function pointer holds the selected transform implementation. It is set once at program startup via a GCC constructor attribute, before `main()` executes. After selection, a known-answer test is performed to verify the implementation produces correct output.

```c
/* sha256.c */
static sha256_transform_fn g_transform = NULL;
static const char *g_impl_name = NULL;

/* Known-answer test: SHA-256("abc") */
static const uint8_t self_test_input[] = { 'a', 'b', 'c' };
static const uint8_t self_test_expected[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

__attribute__((constructor))
static void sha256_select_transform(void) {
#ifdef __aarch64__
    unsigned long hwcap = getauxval(AT_HWCAP);
    if (hwcap & HWCAP_SHA2) {
        g_transform = sha256_transform_arm64_crypto;
        g_impl_name = "arm64_crypto";
    } else {
        g_transform = sha256_transform_sw;
        g_impl_name = "software";
    }
#else
    g_transform = sha256_transform_sw;
    g_impl_name = "software";
#endif

    /* Self-test: verify the selected implementation produces correct output.
     * A failure here means the transform is broken — assert and crash
     * immediately rather than risk producing incorrect hashes that could
     * result in loss of funds. */
    uint8_t result[32];
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, self_test_input, sizeof(self_test_input));
    sha256_final(&ctx, result);
    assert(memcmp(result, self_test_expected, 32) == 0);
}

const char *sha256_impl_name(void) {
    return g_impl_name;
}
```

This self-test runs once at program load (~microseconds) and guarantees that the selected transform implementation is producing correct results on the actual executing hardware. If it fails — due to broken compiler codegen, unexpected CPU behaviour, or HWCAP mismatch — the program crashes immediately with a clear assert before any caller can receive an incorrect hash.

### 4.2 Initialization Timing

The constructor runs automatically at program load, before `main()` is entered. This means:
- `g_transform` is never NULL when `sha256()` is called — no branch on the hot path.
- No thread-safety reasoning is needed (constructors run single-threaded).
- The `sha256()` function body is simpler and faster.

```c
void sha256(const uint8_t *input, size_t len, uint8_t *hash) {
    assert(input != NULL || len == 0);
    assert(hash != NULL);
    assert(g_transform != NULL);

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, hash);
}
```

The `assert(g_transform != NULL)` remains as a safety net — it will fire if the constructor mechanism fails (which should never happen on Linux/GCC), satisfying the correctness-first requirement.

### 4.3 Thread Safety

The constructor runs before `main()` in a single-threaded context. Once set, `g_transform` is read-only for the lifetime of the process. No synchronization is needed.

---

## 5. Implementation Details

### 5.1 Software Transform (`sha256_transform_sw`)

Located in `sha256.c`. An optimized C implementation of the SHA-256 compression function.

Design choices for speed:
- **Circular W[16] buffer:** Instead of a full 64-entry message schedule array, only 16 words are kept and updated in-place. Schedule entries are computed on-the-fly during rounds 16–63 using the recurrence W[i&15] = σ1(W[(i-2)&15]) + W[(i-7)&15] + σ0(W[(i-15)&15]) + W[(i-16)&15].
- **Rotating variables via macro arguments:** Instead of physically rotating a–h each round (8 assignments), the round macro accepts the working variables in rotated positions. This eliminates all variable-shuffling overhead.
- **Reduced-op Ch function:** Uses `z ^ (x & (y ^ z))` (3 operations) instead of the textbook `(x & y) ^ (~x & z)` (4 operations).
- **`__builtin_bswap32` for byte-swap:** Converts big-endian message words to host byte order on load using the GCC builtin, which compiles to a single `rev` instruction on ARM64.
- **On-the-fly schedule computation:** Message schedule words are computed just before they are needed in each round, maximizing register reuse and avoiding a separate schedule expansion pass.

```c
/* Round macros */
#define Ch(x,y,z)   ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ROTR(x,n)   (((x) >> (n)) | ((x) << (32-(n))))
#define Sigma0(x)   (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define Sigma1(x)   (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define sigma0(x)   (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define sigma1(x)   (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))
```

### 5.2 ARM64+Crypto Transform (`sha256_transform_arm64_crypto`)

Located in `sha256_arm.c`. Uses the ARM SHA-2 cryptographic extension instructions via `arm_neon.h`.

Compilation flag: `-march=armv8-a+crypto` (applied via function target attribute).

Key intrinsics used:
| Intrinsic | Operation |
|-----------|-----------|
| `vsha256hq_u32` | SHA-256 hash update (part 1 — rounds on lower state) |
| `vsha256h2q_u32` | SHA-256 hash update (part 2 — rounds on upper state) |
| `vsha256su0q_u32` | SHA-256 schedule update 0 (σ0 expansion) |
| `vsha256su1q_u32` | SHA-256 schedule update 1 (σ1 expansion) |

These instructions process 4 rounds at a time, giving a ~4× throughput improvement over scalar code.

```c
#include <arm_neon.h>

__attribute__((target("arch=armv8-a+crypto")))
void sha256_transform_arm64_crypto(uint32_t state[8], const uint8_t block[64]);
```

### 5.3 Function Target Attributes

The `sha256_arm.c` file contains the ARM64+Crypto implementation. A GCC function attribute controls instruction generation, enabling crypto instructions for the transform function without requiring file-level `-march` flags:

```c
__attribute__((target("arch=armv8-a+crypto")))
void sha256_transform_arm64_crypto(uint32_t state[8], const uint8_t block[64]) { ... }
```

This allows the file to be compiled with the default architecture flags while the specific function emits crypto instructions. No file-level `-march=armv8-a+crypto` is needed, keeping the Makefile simple and avoiding accidental use of crypto instructions in other functions.

---

## 6. Data Alignment Requirements

ARM NEON and crypto extension intrinsics operate on 128-bit (16-byte) vector types (`uint32x4_t`). While ARMv8-A relaxes many alignment requirements compared to earlier ARM architectures, proper alignment is still critical for correctness and performance:

### 6.1 Alignment Rules

| Data | Required Alignment | Mechanism |
|------|-------------------|-----------|
| `uint32x4_t` local variables | 16-byte (128-bit) | Automatic — compiler aligns stack variables |
| `sha256_ctx.state[8]` | 4-byte minimum, 16-byte preferred | Struct member alignment (see below) |
| Input block pointer (`const uint8_t block[64]`) | No strict requirement | Use `vld1q_u8()` which handles unaligned loads |

### 6.2 Context Structure Alignment

The `state[8]` array is accessed as pairs of `uint32x4_t` (4 × uint32 = 128 bits) by the crypto intrinsics. To ensure safe casting/loading without unaligned access penalties:

```c
typedef struct {
    uint32_t state[8] __attribute__((aligned(16)));  /* 16-byte aligned for NEON access */
    uint64_t bitcount;
    uint8_t  buffer[64] __attribute__((aligned(16))); /* Aligned for vector loads in transform */
} sha256_ctx;
```

### 6.3 Input Data Handling

Input data from callers will generally NOT be aligned. The transform functions handle this without copying:

- **Load from input block:** Use `vld1q_u8()` / `vld1q_u32()` which support unaligned access on ARMv8-A. Do NOT cast the input pointer directly to a `uint32x4_t*` and dereference.
- **Load from `state[]` and `buffer[]`:** These are guaranteed aligned by the struct definition, so direct NEON loads are safe.

**Design decision: no memcpy for unaligned input.** On modern ARM64 cores (Cortex-A72, A76, Neoverse N1/V1, Graviton2/3), unaligned NEON loads via `vld1q_*` execute at full speed with zero penalty. Adding a `memcpy` into an aligned staging buffer would impose a guaranteed 64-byte-per-block copy cost to avoid a penalty that is effectively zero. The rule is: **internal data structures are aligned (we control them), input data is loaded with unaligned-safe intrinsics (we don't control it).**

Note: the internal `sha256_ctx.buffer` (which IS aligned) is used for the final trailing bytes (< 64) that don't form a complete block. When this buffer is flushed to the transform during finalization, it benefits from aligned access automatically. Only full blocks read directly from the caller's input pointer encounter potentially unaligned data.

### 6.4 SHA-256 Round Constants (K)

The 64 round constants are accessed as `uint32x4_t` (4 at a time). Declare with explicit alignment:

```c
static const uint32_t K[64] __attribute__((aligned(16))) = { ... };
```

This allows `vld1q_u32(&K[i])` to always be an aligned load.

---

## 7. Byte Order Handling

SHA-256 is defined as big-endian. ARM64 is little-endian. All implementations must byte-swap 32-bit words on load and store.

- **Software:** `__builtin_bswap32()` to convert each 32-bit word on load from the input block.
- **ARM64 Crypto:** `vrev32q_u8()` to reverse bytes within each 32-bit lane on vector load; the crypto instructions operate on already-swapped data.

---

## 8. Compilation Strategy

### 8.1 File-Level Flags

| File | Base Flags | Notes |
|------|-----------|-------|
| `sha256.c` | (none beyond STD) | Software transform + dispatch logic |
| `sha256_arm.c` | (none beyond STD) | Per-function `target` attribute enables crypto |
| `main.c` | (none beyond STD) | CLI tool |
| `sha256_unit_test.c` | (none beyond STD) | Tests and benchmarks |

No file-level `-march` flags are specified. The compiler uses its default target architecture. The only architecture-specific flag (`-march=armv8-a+crypto`) is applied via the function-level `__attribute__((target(...)))` on `sha256_transform_arm64_crypto`.

### 8.2 Optimization Levels

| Target | Optimization | Debug | Extra |
|--------|-------------|-------|-------|
| `make` (production) | `-O2` | None | (asserts active) |
| `make dev` | `-O0` | `-g3` | `-Wall -Wextra -Wpedantic` |
| `make asan` | `-O1` | `-g` | `-fsanitize=address,undefined -fno-omit-frame-pointer` |

### 8.3 Linking

- Link with default system libraries only.
- No external dependencies beyond libc.
- `getauxval()` is in libc on Linux (glibc/musl) — no extra `-l` flag needed.

---

## 9. Unit Test Design

### 9.1 Test Vectors

Source: NIST FIPS 180-4 and commonly used Bitcoin test vectors.

| Test | Input | Expected Hash |
|------|-------|---------------|
| Empty string | `""` (0 bytes) | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| "abc" | 3 bytes | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| 56 bytes | "a" × 56 | (known value — boundary: exactly fills block minus length field) |
| 64 bytes | "a" × 64 | (known value — exactly one full block before padding) |
| 55 bytes | "a" × 55 | (known value — one byte short of needing second block) |
| 112 bytes | "a" × 112 | (known value — two blocks, boundary case for padding) |
| 1,000,000 "a"s | "a" × 1000000 | `cdc76e5c9914fb9281a1c7e284d73e67f1809a48a850f9a31b80beb7cfe45a11` |

### 9.2 Test Strategy

1. **Per-implementation testing:** Call each transform directly (software, crypto) to verify correctness independently, bypassing dispatch. The unit test includes `sha256_arm.h` (the private header) which declares `sha256_transform_arm64_crypto()`. The software transform `sha256_transform_sw()` is also declared in `sha256_arm.h` for test access.
2. **Dispatch testing:** Call the public `sha256()` API and verify the result.
3. **Boundary testing:** Focus on padding edge cases (0, 55, 56, 64, 119, 120, 128 byte inputs).
4. **Consistency testing:** Verify both implementations produce identical output for the same inputs.

### 9.3 Benchmark Design

```
For each implementation (software, crypto):
    Warm up (discard first N iterations)
    Time M iterations of hashing a 320-byte buffer
    Report: ns/hash
```

Use `clock_gettime(CLOCK_MONOTONIC)` for timing.

Report format:
```
SHA-256 Benchmark (320 bytes, 100000 iterations):
  Software:        XXXX.X ns/hash
  ARM64+Crypto:     XXX.X ns/hash  [selected]
```

---

## 10. CLI Tool Design (main.c)

### 10.1 Usage

```
Usage: sha256 <filename>
```

### 10.2 Operation

1. Open the file and determine its size (via `fstat`).
2. Memory-map the entire file using `mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0)`.
3. Call `sha256(mapped_ptr, size, hash)` — a single call over the mapped buffer.
4. Unmap and close.
5. Output: `<hex_hash>  <filename>\n`

This approach keeps the public API as a single-call interface. The OS handles paging file contents into memory on demand via the virtual memory subsystem — the entire file does not need to fit in physical RAM simultaneously.

### 10.3 File Size Limit

`mmap` on 64-bit ARM64 supports mapping files up to the virtual address space limit (typically 256 TB on Linux aarch64). In practice, this means any file the filesystem can hold can be hashed. No artificial size cap is needed.

For the edge case of an empty file (0 bytes), `mmap` returns `MAP_FAILED` on some systems when `size == 0`. Handle this by calling `sha256(NULL, 0, hash)` directly (the empty-string SHA-256 is well-defined).

### 10.4 Public API

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

### 10.5 Error Handling

- File not found or cannot open: print error to stderr, exit with non-zero status.
- `fstat` or `mmap` failure: print error to stderr, exit with non-zero status.
- No arguments: print usage to stderr, exit with non-zero status.

---

## 11. Makefile Design

```makefile
CC       = gcc
STD      = -std=gnu17
WARNINGS = -Wall -Wextra -Wpedantic

# Source files
SRCS     = sha256.c sha256_arm.c main.c
TEST_SRC = sha256.c sha256_arm.c sha256_unit_test.c

TARGET   = sha256
TEST_BIN = sha256_unit_test

.PHONY: all dev asan clean

# Default: production (no -DNDEBUG — asserts remain active)
all: CFLAGS = $(STD) -O2
all: $(TARGET) $(TEST_BIN)

# Dev build: debug + warnings + unit test
dev: CFLAGS = $(STD) -O0 -g3 $(WARNINGS)
dev: $(TARGET) $(TEST_BIN)

# AddressSanitizer + UndefinedBehaviourSanitizer — build and run tests
asan: CFLAGS = $(STD) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer $(WARNINGS)
asan: LDFLAGS = -fsanitize=address,undefined
asan: $(TEST_BIN)
	./$(TEST_BIN)

$(TARGET): $(SRCS:.c=.o)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

$(TEST_BIN): $(TEST_SRC:.c=.o)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f *.o $(TARGET) $(TEST_BIN)
```

Key design decisions:
- **No `-march` flags:** Architecture-specific code generation is controlled entirely by per-function `__attribute__((target(...)))` in source files.
- **No CFLAGS sentinel:** Simplicity over incremental-rebuild correctness. Use `make clean` when switching between build targets.
- **Default target builds both binaries:** `make` produces both `sha256` (CLI tool) and `sha256_unit_test` (test/benchmark binary).
- **No `-DNDEBUG`:** Asserts remain active in all builds including production per the correctness-first requirement.

---

## 12. Security Considerations

### 12.1 Assert-Based Error Handling

All internal invariants are guarded by `assert()`:
- NULL pointer checks on public API entry
- Transform function pointer is non-NULL before use
- Buffer bounds are not exceeded

Since priority #1 is correctness and `assert()` is required to crash on errors, production builds do **NOT** define `NDEBUG`. Asserts remain active in all build configurations. The code does not use asserts as control flow — they guard invariants that should never be violated.

### 12.2 Buffer Management

- The 64-byte internal buffer is stack-allocated (within `sha256_ctx`).
- No heap allocation occurs.
- No data persists after `sha256()` or `sha256_final()` returns.
- The context is zeroed or goes out of scope after finalization (consider explicit `memset` to zero for paranoid security, though this is not required by the competition).

### 12.3 Side-Channel Resistance

Not a design goal for this competition. The implementations prioritize speed. Constant-time behaviour is not guaranteed.

---

## 13. Dependencies

| Dependency | Source | Purpose |
|------------|--------|---------|
| libc (glibc) | System | Standard library, `getauxval()` |
| `arm_neon.h` | GCC builtin | ARM NEON intrinsics |
| `sys/auxv.h` | System | `getauxval()` declaration |

No third-party dependencies. No package manager required beyond the system compiler toolchain.

Build prerequisites: `gcc`, `make`.

---

## 14. Future Extensibility

The dispatch mechanism is designed to accommodate additional architectures:

```c
/* Future: x86_64 with SHA-NI */
#elif defined(__x86_64__)
    if (__builtin_cpu_supports("sha")) {
        g_transform = sha256_transform_x86_shani;
    } else if (__builtin_cpu_supports("avx2")) {
        g_transform = sha256_transform_x86_avx2;
    } else {
        g_transform = sha256_transform_sw;
    }
```

Adding a new architecture requires:
1. Implement `sha256_transform_<arch>()` in a new file.
2. Add detection logic to `sha256_select_transform()`.
3. Add the source file to the Makefile.

No changes to the public API or calling code are needed.
