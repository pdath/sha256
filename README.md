# SHA-256 with Runtime CPU Dispatch

A high-performance SHA-256 implementation for ARM64 Linux that automatically selects the fastest available backend at runtime based on CPU capabilities.

## Problem

SHA-256 implementations in crypto and blockchain libraries are typically selected at compile time via `-march=native`. This forces a choice: build for a specific CPU (breaks portability) or use the slowest common denominator (wastes hardware).

This project solves the problem with **runtime CPU dispatch**: a single binary contains multiple implementations and automatically selects the fastest one available on the executing hardware.

## Features

- **Two transform implementations:**
  - **Software (C)** — optimized portable fallback with circular schedule buffer, reduced-op round function, and `__builtin_bswap32` byte-swap
  - **ARM64+Crypto** — hardware SHA-2 extensions (`vsha256hq_u32` and friends), ~4.5× faster than software

- **Zero-cost dispatch** — implementation selected once at startup via GCC constructor; no branches on the hot path
- **Self-test at startup** — known-answer test runs before `main()` to verify correctness on the actual hardware
- **No heap allocation** — all state is stack-allocated or static
- **Assert-based error handling** — crashes immediately on internal errors rather than returning codes that might be ignored
- **Minimal public API** — `sha256(input, len, hash)` computes the hash; `sha256_impl_name()` queries the active backend

## Target Users

- Developers building Bitcoin/blockchain applications for ARM64 servers (AWS Graviton, Ampere, etc.)
- Anyone needing fast, portable SHA-256 on ARM64 Linux without external dependencies

## Build Environment Setup

Requirements:
- GCC 11+ (tested with GCC 13)
- GNU Make
- Linux on ARM64 (aarch64)

On Ubuntu/Debian:
```bash
sudo apt install build-essential
```

On Amazon Linux:
```bash
sudo yum groupinstall "Development Tools"
sudo yum install libasan libubsan
```

## Clone and Build

```bash
git clone https://github.com/pdath/sha256.git
cd sha256
make
```

This produces two binaries:
- `sha256` — CLI tool for hashing files
- `sha256_unit_test` — test suite and benchmarks

## Make Targets

| Target | Description |
|--------|-------------|
| `make` | Production build with `-O2` optimizations (builds `sha256` and `sha256_unit_test`) |
| `make dev` | Development build: `-O0 -g3` + all warnings + unit test binary |
| `make asan` | Build with AddressSanitizer + UBSan, then run all tests |
| `make clean` | Remove all build artifacts |

## Usage

### Hash a file and verify correctness

```bash
make
./sha256 main.c
sha256sum main.c
```

Both commands produce identical output, confirming correctness:
```
<hash>  main.c
```

### Run tests and benchmarks

```bash
./sha256_unit_test
```

Sample output:
```
SHA-256 Unit Tests
==================
Active implementation: arm64_crypto

Results: 24/24 tests passed

SHA-256 Benchmark (320 bytes, 100000 iterations):
  Software:        1793.6 ns/hash
  ARM64+Crypto:     396.6 ns/hash  [selected]
```

### Run under sanitizers

```bash
make clean
make asan
```

This rebuilds with `-fsanitize=address,undefined` and automatically runs the test suite.

## Architecture

```
sha256(input, len, hash)        ← public API: compute hash
sha256_impl_name()              ← public API: query active backend
    │
    ▼
sha256_init / update / final    ← internal state machine
    │
    ▼
g_transform(state, block)       ← function pointer, set once at startup
    │
    ├── sha256_transform_sw()           (optimized pure C)
    └── sha256_transform_arm64_crypto() (SHA-2 hardware instructions)
```

Dispatch logic (runs once in constructor before `main()`):
```c
if (getauxval(AT_HWCAP) & HWCAP_SHA2)
    → arm64_crypto
else
    → software
```

## File Structure

| File | Purpose |
|------|---------|
| `sha256.h` | Public API header |
| `sha256_arm.h` | Private header (transform declarations) |
| `sha256.c` | Software transform, init/update/final, dispatch, self-test |
| `sha256_arm.c` | ARM64+Crypto transform |
| `main.c` | CLI tool (mmap-based file hashing) |
| `sha256_unit_test.c` | Tests and benchmarks |
| `Makefile` | Build system |

## License

See [LICENSE](LICENSE).
