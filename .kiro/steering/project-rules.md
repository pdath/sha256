# SHA-256 Project Steering

## Project Documents — Read Before Implementing

- `REQUIREMENTS.md` — what to build, priorities, constraints
- `DESIGN.md` — how to build it, all technical decisions
- `TODO.md` — implementation task list, work in order

## Critical Rules

1. **Correctness over speed.** assert() and crash on errors. Never return an error code.
2. **No -DNDEBUG.** Asserts remain active in all builds including production.
3. **No malloc.** Zero heap allocation. All state is stack-allocated or static.
4. **No incremental public API.** Only `sha256()` and `sha256_impl_name()` are public.
5. **Alignment:** `sha256_ctx.state[]` and `sha256_ctx.buffer[]` must be `__attribute__((aligned(16)))`.
6. **Unaligned input:** Use `vld1q_u8()`/`vld1q_u32()` for input data in crypto transform. Never cast input pointers to vector types.
7. **Round constants K[64]:** Must be `__attribute__((aligned(16)))`.
8. **Byte order:** SHA-256 is big-endian, ARM64 is little-endian. Always byte-swap on load/store.
9. **C standard:** gnu17. GCC only.
10. **Function target attributes:** Use `__attribute__((target("arch=armv8-a+crypto")))` per-function in sha256_arm.c. Do NOT use file-level `-march=armv8-a+crypto`.

## Naming Convention

- `sha256_transform_sw` — software (optimized C, portable)
- `sha256_transform_arm64_crypto` — ARM64 with SHA2 crypto extensions

## Common AI Pitfalls to Avoid

- Do NOT cast `const uint8_t *block` to `uint32x4_t *` — use vld1q intrinsics.
- Do NOT forget byte-swap — ARM is little-endian, SHA-256 is big-endian.
- Do NOT make sha256_transform_sw() static — unit tests need external access.
- Do NOT expose sha256_ctx in the public header — it's internal to sha256.c.
- Do NOT use -DNDEBUG in any build target.
- Do NOT add malloc/free/calloc anywhere.
- The constructor self-test calls sha256_init/update/final — these must work without g_transform being set for the software path, OR the self-test must use the already-selected g_transform (which it does, since g_transform is set before the self-test runs).
