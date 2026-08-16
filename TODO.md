# TODO: SHA-256 with Runtime CPU Dispatch

## Implementation Tasks

- [x] 1. Create sha256.h (public API header)
  - Declare sha256() and sha256_impl_name(). Include guards, stdint.h, stddef.h.

- [x] 2. Create sha256_arm.h (private internal header)
  - Declare sha256_transform_sw(), sha256_transform_arm64(), sha256_transform_arm64_crypto(), and the sha256_transform_fn typedef.

- [x] 3. Implement sha256.c — software transform and core logic
  - Software sha256_transform_sw() with unrolled rounds, sha256_init(), sha256_update(), sha256_final(), sha256() public function, constructor with dispatch and self-test, sha256_impl_name().

- [x] 4. Implement sha256_arm.c — ARM64 crypto transform
  - sha256_transform_arm64_crypto() using vsha256hq_u32, vsha256h2q_u32, vsha256su0q_u32, vsha256su1q_u32 intrinsics with __attribute__((target("arch=armv8-a+crypto"))).

- [x] 5. Implement sha256_arm.c — ARM64 base transform
  - sha256_transform_arm64() using NEON intrinsics for message schedule expansion, vrev32q_u8 for byte swap. No crypto instructions. __attribute__((target("arch=armv8-a"))).

- [x] 6. Create Makefile
  - Targets: all (production), dev, asan, clean. Build sha256 executable and sha256_unit_test.

- [x] 7. Implement sha256_unit_test.c
  - Test vectors (empty, abc, 55/56/64/112 bytes, 1M a's), per-implementation testing, dispatch testing, boundary testing, consistency testing, benchmark with clock_gettime.

- [x] 8. Build and verify all tests pass with make dev
  - Compile, run unit tests, ensure all test vectors pass for all implementations.

- [x] 9. Run make asan and fix any issues
  - AddressSanitizer + UBSan — verify no memory errors or undefined behaviour.

- [x] 10. Implement main.c (sha256 CLI tool)
  - mmap-based file hashing, output format matching sha256sum, empty file edge case, error handling.

- [x] 11. Verify CLI tool against system sha256sum
  - Hash test files with both tools, compare output.

- [x] 12. Create README.md
  - Project description, problem statement, features, target users, build setup, make targets, usage, verification instructions.
