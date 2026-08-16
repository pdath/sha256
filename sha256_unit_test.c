/*
 * sha256_unit_test.c — Unit tests and benchmarks for SHA-256 implementations.
 *
 * Tests:
 *   - Known test vectors (NIST FIPS 180-4)
 *   - Per-implementation correctness (sw, arm64_crypto)
 *   - Dispatch/public API correctness
 *   - Boundary cases (padding edge cases)
 *   - Consistency across implementations
 *   - Benchmark (ns/hash)
 */

#include "sha256.h"
#include "sha256_arm.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* ─────────────────────────────────────────────────────────────────────────
 * Test infrastructure
 * ───────────────────────────────────────────────────────────────────────── */
static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (!(cond)) { \
        printf("  FAIL: %s\n", msg); \
    } else { \
        tests_passed++; \
    } \
} while (0)

/* Helper: compute SHA-256 using a specific transform function via
 * manual init/update/final with the given transform. We replicate
 * the internal logic here to test each transform independently. */
typedef struct {
    uint32_t state[8] __attribute__((aligned(16)));
    uint64_t bitcount;
    uint8_t  buffer[64] __attribute__((aligned(16)));
} test_ctx;

static void test_init(test_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
}

static void test_update(test_ctx *ctx, sha256_transform_fn transform,
                        const uint8_t *data, size_t len)
{
    size_t buf_idx = (size_t)(ctx->bitcount >> 3) & 0x3F;
    ctx->bitcount += (uint64_t)len << 3;

    if (buf_idx > 0) {
        size_t space = 64 - buf_idx;
        if (len >= space) {
            memcpy(ctx->buffer + buf_idx, data, space);
            transform(ctx->state, ctx->buffer);
            data += space;
            len -= space;
            buf_idx = 0;
        } else {
            memcpy(ctx->buffer + buf_idx, data, len);
            return;
        }
    }

    while (len >= 64) {
        transform(ctx->state, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

static void test_final(test_ctx *ctx, sha256_transform_fn transform,
                       uint8_t *hash)
{
    size_t buf_idx = (size_t)(ctx->bitcount >> 3) & 0x3F;
    uint64_t bitcount_be = ctx->bitcount;

    ctx->buffer[buf_idx++] = 0x80;

    if (buf_idx > 56) {
        memset(ctx->buffer + buf_idx, 0, 64 - buf_idx);
        transform(ctx->state, ctx->buffer);
        buf_idx = 0;
    }

    memset(ctx->buffer + buf_idx, 0, 56 - buf_idx);

    ctx->buffer[56] = (uint8_t)(bitcount_be >> 56);
    ctx->buffer[57] = (uint8_t)(bitcount_be >> 48);
    ctx->buffer[58] = (uint8_t)(bitcount_be >> 40);
    ctx->buffer[59] = (uint8_t)(bitcount_be >> 32);
    ctx->buffer[60] = (uint8_t)(bitcount_be >> 24);
    ctx->buffer[61] = (uint8_t)(bitcount_be >> 16);
    ctx->buffer[62] = (uint8_t)(bitcount_be >>  8);
    ctx->buffer[63] = (uint8_t)(bitcount_be);

    transform(ctx->state, ctx->buffer);

    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* Compute SHA-256 using a specific transform */
static void sha256_with_transform(sha256_transform_fn transform,
                                  const uint8_t *input, size_t len,
                                  uint8_t *hash)
{
    test_ctx ctx;
    test_init(&ctx);
    test_update(&ctx, transform, input, len);
    test_final(&ctx, transform, hash);
}

/* Convert hash to hex string */
static void hash_to_hex(const uint8_t hash[32], char hex[65])
{
    for (int i = 0; i < 32; i++) {
        sprintf(hex + i * 2, "%02x", hash[i]);
    }
    hex[64] = '\0';
}

/* Parse hex string to hash */
static void hex_to_hash(const char *hex, uint8_t hash[32])
{
    for (int i = 0; i < 32; i++) {
        unsigned int val;
        sscanf(hex + i * 2, "%02x", &val);
        hash[i] = (uint8_t)val;
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Test vectors
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct {
    const char *name;
    const uint8_t *input;
    size_t len;
    const char *expected_hex;
} test_vector;

/* Empty string — use NULL with len=0 */

/* "abc" */
static const uint8_t tv_abc[] = { 'a', 'b', 'c' };

/* 55 bytes of 'a' — one byte short of needing a second padding block */
static uint8_t tv_55a[55];

/* 56 bytes of 'a' — exactly fills block minus length field */
static uint8_t tv_56a[56];

/* 64 bytes of 'a' — exactly one full block before padding */
static uint8_t tv_64a[64];

/* 112 bytes of 'a' — two blocks, boundary case for padding */
static uint8_t tv_112a[112];

static void init_test_vectors(void)
{
    memset(tv_55a, 'a', 55);
    memset(tv_56a, 'a', 56);
    memset(tv_64a, 'a', 64);
    memset(tv_112a, 'a', 112);
}

static const test_vector vectors[] = {
    {
        "empty string (0 bytes)",
        NULL, 0,
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    },
    {
        "\"abc\" (3 bytes)",
        tv_abc, 3,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    },
    {
        "55 bytes of 'a'",
        tv_55a, 55,
        "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318"
    },
    {
        "56 bytes of 'a'",
        tv_56a, 56,
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a"
    },
    {
        "64 bytes of 'a'",
        tv_64a, 64,
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    },
    {
        "112 bytes of 'a'",
        tv_112a, 112,
        "f54353008a2553262ecdc4a34749563ba0950e8b0fc8652780b0a614b99683c1"
    },
};

#define NUM_VECTORS (sizeof(vectors) / sizeof(vectors[0]))

/* ─────────────────────────────────────────────────────────────────────────
 * Test: per-implementation correctness
 * ───────────────────────────────────────────────────────────────────────── */
static void test_implementation(const char *name, sha256_transform_fn transform)
{
    printf("\n  Testing: %s\n", name);

    uint8_t hash[32];
    uint8_t expected[32];
    char hex[65];

    for (size_t i = 0; i < NUM_VECTORS; i++) {
        sha256_with_transform(transform, vectors[i].input, vectors[i].len, hash);
        hex_to_hash(vectors[i].expected_hex, expected);
        hash_to_hex(hash, hex);

        int pass = (memcmp(hash, expected, 32) == 0);
        tests_run++;
        if (pass) {
            tests_passed++;
            printf("    PASS: %s\n", vectors[i].name);
        } else {
            printf("    FAIL: %s\n", vectors[i].name);
            printf("      expected: %s\n", vectors[i].expected_hex);
            printf("      got:      %s\n", hex);
        }
    }

    /* 1,000,000 'a' characters */
    printf("    Testing: 1,000,000 x 'a'...\n");
    test_ctx ctx;
    test_init(&ctx);

    /* Feed in chunks to avoid stack-allocating 1MB */
    uint8_t chunk[1000];
    memset(chunk, 'a', 1000);
    for (int i = 0; i < 1000; i++) {
        test_update(&ctx, transform, chunk, 1000);
    }
    test_final(&ctx, transform, hash);

    hex_to_hash("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
                expected);
    hash_to_hex(hash, hex);

    int pass = (memcmp(hash, expected, 32) == 0);
    tests_run++;
    if (pass) {
        tests_passed++;
        printf("    PASS: 1,000,000 x 'a'\n");
    } else {
        printf("    FAIL: 1,000,000 x 'a'\n");
        printf("      expected: cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0\n");
        printf("      got:      %s\n", hex);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Test: public API dispatch
 * ───────────────────────────────────────────────────────────────────────── */
static void test_dispatch(void)
{
    printf("\n  Testing: public API (dispatch → %s)\n", sha256_impl_name());

    uint8_t hash[32];
    uint8_t expected[32];
    char hex[65];

    for (size_t i = 0; i < NUM_VECTORS; i++) {
        sha256(vectors[i].input, vectors[i].len, hash);
        hex_to_hash(vectors[i].expected_hex, expected);
        hash_to_hex(hash, hex);

        int pass = (memcmp(hash, expected, 32) == 0);
        tests_run++;
        if (pass) {
            tests_passed++;
            printf("    PASS: %s\n", vectors[i].name);
        } else {
            printf("    FAIL: %s\n", vectors[i].name);
            printf("      expected: %s\n", vectors[i].expected_hex);
            printf("      got:      %s\n", hex);
        }
    }

    /* NULL input with len==0 */
    sha256(NULL, 0, hash);
    hex_to_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                expected);
    tests_run++;
    if (memcmp(hash, expected, 32) == 0) {
        tests_passed++;
        printf("    PASS: NULL input, len=0\n");
    } else {
        printf("    FAIL: NULL input, len=0\n");
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Test: consistency across implementations
 * ───────────────────────────────────────────────────────────────────────── */
static void test_consistency(void)
{
    printf("\n  Testing: consistency across implementations\n");

    sha256_transform_fn impls[2];
    const char *names[2];
    int num_impls = 0;

    impls[num_impls] = sha256_transform_sw;
    names[num_impls] = "software";
    num_impls++;

#ifdef __aarch64__
    impls[num_impls] = sha256_transform_arm64_crypto;
    names[num_impls] = "arm64_crypto";
    num_impls++;
#endif

    /* Test with various sizes including unaligned */
    size_t sizes[] = { 0, 1, 7, 31, 32, 55, 56, 63, 64, 65, 100, 127, 128, 256, 512 };
    int num_sizes = (int)(sizeof(sizes) / sizeof(sizes[0]));

    uint8_t data[512];
    for (size_t i = 0; i < sizeof(data); i++) {
        data[i] = (uint8_t)(i & 0xFF);
    }

    int all_consistent = 1;

    for (int s = 0; s < num_sizes; s++) {
        uint8_t hashes[2][32];

        for (int impl = 0; impl < num_impls; impl++) {
            sha256_with_transform(impls[impl], data, sizes[s], hashes[impl]);
        }

        /* Compare all against first */
        for (int impl = 1; impl < num_impls; impl++) {
            if (memcmp(hashes[0], hashes[impl], 32) != 0) {
                char hex0[65], hex1[65];
                hash_to_hex(hashes[0], hex0);
                hash_to_hex(hashes[impl], hex1);
                printf("    FAIL: size=%zu, %s != %s\n", sizes[s],
                       names[0], names[impl]);
                printf("      %s: %s\n", names[0], hex0);
                printf("      %s: %s\n", names[impl], hex1);
                all_consistent = 0;
            }
        }
    }

    tests_run++;
    if (all_consistent) {
        tests_passed++;
        printf("    PASS: all implementations consistent across %d sizes\n",
               num_sizes);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Test: boundary cases (padding edge cases)
 * ───────────────────────────────────────────────────────────────────────── */
static void test_boundaries(void)
{
    printf("\n  Testing: boundary cases\n");

    /* Sizes that are critical for padding: 55, 56, 63, 64, 119, 120, 127, 128 */
    size_t boundary_sizes[] = { 55, 56, 63, 64, 119, 120, 127, 128 };
    int num_boundaries = (int)(sizeof(boundary_sizes) / sizeof(boundary_sizes[0]));

    uint8_t data[128];
    memset(data, 'x', sizeof(data));

    /* Use the public API (dispatched) and software to cross-check */
    int all_pass = 1;
    for (int i = 0; i < num_boundaries; i++) {
        uint8_t hash_public[32];
        uint8_t hash_sw[32];

        sha256(data, boundary_sizes[i], hash_public);
        sha256_with_transform(sha256_transform_sw, data, boundary_sizes[i], hash_sw);

        if (memcmp(hash_public, hash_sw, 32) != 0) {
            printf("    FAIL: boundary size=%zu mismatch\n", boundary_sizes[i]);
            all_pass = 0;
        }
    }

    tests_run++;
    if (all_pass) {
        tests_passed++;
        printf("    PASS: all boundary sizes (%d cases)\n", num_boundaries);
    }

    /* Also test incremental update at various chunk sizes */
    uint8_t full_hash[32];
    uint8_t incremental_hash[32];
    uint8_t big_data[200];
    memset(big_data, 'q', sizeof(big_data));

    sha256(big_data, sizeof(big_data), full_hash);

    /* Feed 1 byte at a time */
    test_ctx ctx;
    test_init(&ctx);
    sha256_transform_fn transform = sha256_transform_sw;
#ifdef __aarch64__
    transform = sha256_transform_arm64_crypto;
#endif
    for (size_t i = 0; i < sizeof(big_data); i++) {
        test_update(&ctx, transform, &big_data[i], 1);
    }
    test_final(&ctx, transform, incremental_hash);

    tests_run++;
    if (memcmp(full_hash, incremental_hash, 32) == 0) {
        tests_passed++;
        printf("    PASS: incremental 1-byte updates (200 bytes)\n");
    } else {
        printf("    FAIL: incremental 1-byte updates mismatch\n");
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Benchmark
 * ───────────────────────────────────────────────────────────────────────── */
static double get_time_sec(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec * 1e-9;
}

static void benchmark_transform(const char *name, sha256_transform_fn transform,
                                int is_selected)
{
    /* 320-byte buffer */
    static uint8_t buf[320];
    memset(buf, 0xAB, sizeof(buf));

    uint8_t hash[32];
    int iterations = 100000;

    /* Warm up */
    for (int i = 0; i < 100; i++) {
        sha256_with_transform(transform, buf, sizeof(buf), hash);
    }

    double start = get_time_sec();
    for (int i = 0; i < iterations; i++) {
        sha256_with_transform(transform, buf, sizeof(buf), hash);
    }
    double end = get_time_sec();

    double elapsed = end - start;
    double ns_per_hash = (elapsed * 1e9) / iterations;

    printf("  %-14s %8.1f ns/hash%s\n", name, ns_per_hash,
           is_selected ? "  [selected]" : "");
}

/* ─────────────────────────────────────────────────────────────────────────
 * Main
 * ───────────────────────────────────────────────────────────────────────── */
int main(void)
{
    init_test_vectors();

    printf("SHA-256 Unit Tests\n");
    printf("==================\n");
    printf("Active implementation: %s\n", sha256_impl_name());

    /* Per-implementation testing */
    printf("\n--- Per-Implementation Tests ---\n");
    test_implementation("software (sha256_transform_sw)", sha256_transform_sw);

#ifdef __aarch64__
    test_implementation("arm64_crypto (sha256_transform_arm64_crypto)",
                        sha256_transform_arm64_crypto);
#endif

    /* Public API dispatch testing */
    printf("\n--- Dispatch Tests ---\n");
    test_dispatch();

    /* Consistency testing */
    printf("\n--- Consistency Tests ---\n");
    test_consistency();

    /* Boundary testing */
    printf("\n--- Boundary Tests ---\n");
    test_boundaries();

    /* Summary */
    printf("\n==================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);

    if (tests_passed != tests_run) {
        printf("*** FAILURES DETECTED ***\n");
        return 1;
    }

    /* Benchmark */
    printf("\nSHA-256 Benchmark (320 bytes, 100000 iterations):\n");

    const char *selected = sha256_impl_name();

    benchmark_transform("Software:",
                        sha256_transform_sw,
                        strcmp(selected, "software") == 0);

#ifdef __aarch64__
    benchmark_transform("ARM64+Crypto:",
                        sha256_transform_arm64_crypto,
                        strcmp(selected, "arm64_crypto") == 0);
#endif

    printf("\nAll tests passed.\n");
    return 0;
}
