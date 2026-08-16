/*
 * sha256.c — SHA-256 implementation with runtime CPU dispatch.
 *
 * Contains:
 *   - Software transform: sha256_transform_sw() (optimized circular buffer)
 *   - Internal state management: sha256_init(), sha256_update(), sha256_final()
 *   - Public API: sha256(), sha256_impl_name()
 *   - Constructor: runtime dispatch + self-test
 */

#include "sha256.h"
#include "sha256_arm.h"

#include <assert.h>
#include <string.h>

#ifdef __aarch64__
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

/* ─────────────────────────────────────────────────────────────────────────
 * Internal context — stack-allocated, never exposed in the public header.
 * ───────────────────────────────────────────────────────────────────────── */
typedef struct {
    uint32_t state[8] __attribute__((aligned(16)));
    uint64_t bitcount;
    uint8_t  buffer[64] __attribute__((aligned(16)));
} sha256_ctx;

/* ─────────────────────────────────────────────────────────────────────────
 * SHA-256 round constants K[64] — aligned for NEON vector loads.
 * ───────────────────────────────────────────────────────────────────────── */
static const uint32_t K[64] __attribute__((aligned(16))) = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

/* ─────────────────────────────────────────────────────────────────────────
 * Dispatch state — set once by constructor before main().
 * ───────────────────────────────────────────────────────────────────────── */
static sha256_transform_fn g_transform = NULL;
static const char *g_impl_name = NULL;

/* ─────────────────────────────────────────────────────────────────────────
 * SHA-256 helper macros
 * ───────────────────────────────────────────────────────────────────────── */
#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

#define Ch(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define Maj(x, y, z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

/* ─────────────────────────────────────────────────────────────────────────
 * Software transform — optimized pure C.
 *
 * Key optimizations:
 *   - Circular W[16] buffer (64 bytes on stack vs 256 for W[64])
 *   - Message schedule computed on-the-fly, interleaved with rounds
 *   - Rotating variables via macro arguments (2 assignments per round)
 *   - Reduced-op Ch: z ^ (x & (y ^ z)) — 3 ops instead of 4
 *   - __builtin_bswap32 for byte-swap (single instruction on most CPUs)
 *
 * NOT static — unit tests need external access.
 * ───────────────────────────────────────────────────────────────────────── */
void sha256_transform_sw(uint32_t state[8], const uint8_t block[64])
{
    uint32_t W[16];

    /* Load and byte-swap: big-endian block → host order.
     * GCC compiles memcpy+bswap32 to optimal load+rev pairs. */
    for (int i = 0; i < 16; i++) {
        uint32_t tmp;
        __builtin_memcpy(&tmp, block + i * 4, 4);
        W[i] = __builtin_bswap32(tmp);
    }

    /* Initialize working variables */
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t e = state[4];
    uint32_t f = state[5];
    uint32_t g = state[6];
    uint32_t h = state[7];

    /*
     * Round macros.  Variables are rotated in the caller rather than
     * shifted inside the macro — each round only writes d and h.
     *
     * R0: rounds 0-15 (W already loaded)
     * R1: rounds 16-63 (W updated from circular buffer on the fly)
     */
#define R0(a,b,c,d,e,f,g,h,i) do { \
    uint32_t T1 = (h) + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]; \
    uint32_t T2 = Sigma0(a) + Maj(a,b,c); \
    (d) += T1; \
    (h) = T1 + T2; \
} while(0)

#define R1(a,b,c,d,e,f,g,h,i) do { \
    W[(i)&0xf] += sigma1(W[((i)-2)&0xf]) + W[((i)-7)&0xf] \
                + sigma0(W[((i)-15)&0xf]); \
    uint32_t T1 = (h) + Sigma1(e) + Ch(e,f,g) + K[i] + W[(i)&0xf]; \
    uint32_t T2 = Sigma0(a) + Maj(a,b,c); \
    (d) += T1; \
    (h) = T1 + T2; \
} while(0)

    /* Rounds 0-15 */
    R0(a,b,c,d,e,f,g,h, 0); R0(h,a,b,c,d,e,f,g, 1);
    R0(g,h,a,b,c,d,e,f, 2); R0(f,g,h,a,b,c,d,e, 3);
    R0(e,f,g,h,a,b,c,d, 4); R0(d,e,f,g,h,a,b,c, 5);
    R0(c,d,e,f,g,h,a,b, 6); R0(b,c,d,e,f,g,h,a, 7);
    R0(a,b,c,d,e,f,g,h, 8); R0(h,a,b,c,d,e,f,g, 9);
    R0(g,h,a,b,c,d,e,f,10); R0(f,g,h,a,b,c,d,e,11);
    R0(e,f,g,h,a,b,c,d,12); R0(d,e,f,g,h,a,b,c,13);
    R0(c,d,e,f,g,h,a,b,14); R0(b,c,d,e,f,g,h,a,15);

    /* Rounds 16-63 */
    R1(a,b,c,d,e,f,g,h,16); R1(h,a,b,c,d,e,f,g,17);
    R1(g,h,a,b,c,d,e,f,18); R1(f,g,h,a,b,c,d,e,19);
    R1(e,f,g,h,a,b,c,d,20); R1(d,e,f,g,h,a,b,c,21);
    R1(c,d,e,f,g,h,a,b,22); R1(b,c,d,e,f,g,h,a,23);
    R1(a,b,c,d,e,f,g,h,24); R1(h,a,b,c,d,e,f,g,25);
    R1(g,h,a,b,c,d,e,f,26); R1(f,g,h,a,b,c,d,e,27);
    R1(e,f,g,h,a,b,c,d,28); R1(d,e,f,g,h,a,b,c,29);
    R1(c,d,e,f,g,h,a,b,30); R1(b,c,d,e,f,g,h,a,31);
    R1(a,b,c,d,e,f,g,h,32); R1(h,a,b,c,d,e,f,g,33);
    R1(g,h,a,b,c,d,e,f,34); R1(f,g,h,a,b,c,d,e,35);
    R1(e,f,g,h,a,b,c,d,36); R1(d,e,f,g,h,a,b,c,37);
    R1(c,d,e,f,g,h,a,b,38); R1(b,c,d,e,f,g,h,a,39);
    R1(a,b,c,d,e,f,g,h,40); R1(h,a,b,c,d,e,f,g,41);
    R1(g,h,a,b,c,d,e,f,42); R1(f,g,h,a,b,c,d,e,43);
    R1(e,f,g,h,a,b,c,d,44); R1(d,e,f,g,h,a,b,c,45);
    R1(c,d,e,f,g,h,a,b,46); R1(b,c,d,e,f,g,h,a,47);
    R1(a,b,c,d,e,f,g,h,48); R1(h,a,b,c,d,e,f,g,49);
    R1(g,h,a,b,c,d,e,f,50); R1(f,g,h,a,b,c,d,e,51);
    R1(e,f,g,h,a,b,c,d,52); R1(d,e,f,g,h,a,b,c,53);
    R1(c,d,e,f,g,h,a,b,54); R1(b,c,d,e,f,g,h,a,55);
    R1(a,b,c,d,e,f,g,h,56); R1(h,a,b,c,d,e,f,g,57);
    R1(g,h,a,b,c,d,e,f,58); R1(f,g,h,a,b,c,d,e,59);
    R1(e,f,g,h,a,b,c,d,60); R1(d,e,f,g,h,a,b,c,61);
    R1(c,d,e,f,g,h,a,b,62); R1(b,c,d,e,f,g,h,a,63);

#undef R0
#undef R1

    /* Add back to state */
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

/* ─────────────────────────────────────────────────────────────────────────
 * Internal SHA-256 functions (init, update, final)
 * ───────────────────────────────────────────────────────────────────────── */
static void sha256_init(sha256_ctx *ctx)
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

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len)
{
    size_t buf_idx = (size_t)(ctx->bitcount >> 3) & 0x3F;

    ctx->bitcount += (uint64_t)len << 3;

    /* If there's data in the buffer, try to fill it */
    if (buf_idx > 0) {
        size_t space = 64 - buf_idx;
        if (len >= space) {
            memcpy(ctx->buffer + buf_idx, data, space);
            g_transform(ctx->state, ctx->buffer);
            data += space;
            len -= space;
            buf_idx = 0;
        } else {
            memcpy(ctx->buffer + buf_idx, data, len);
            return;
        }
    }

    /* Process full blocks directly from input */
    while (len >= 64) {
        g_transform(ctx->state, data);
        data += 64;
        len -= 64;
    }

    /* Buffer remaining bytes */
    if (len > 0) {
        memcpy(ctx->buffer, data, len);
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t *hash)
{
    size_t buf_idx = (size_t)(ctx->bitcount >> 3) & 0x3F;

    /* Append 0x80 padding byte */
    ctx->buffer[buf_idx++] = 0x80;

    /* If not enough room for the 8-byte length, pad and process */
    if (buf_idx > 56) {
        memset(ctx->buffer + buf_idx, 0, 64 - buf_idx);
        g_transform(ctx->state, ctx->buffer);
        buf_idx = 0;
    }

    /* Pad with zeros up to byte 56 */
    memset(ctx->buffer + buf_idx, 0, 56 - buf_idx);

    /* Append 64-bit big-endian bit count */
    uint64_t bits = ctx->bitcount;
    ctx->buffer[56] = (uint8_t)(bits >> 56);
    ctx->buffer[57] = (uint8_t)(bits >> 48);
    ctx->buffer[58] = (uint8_t)(bits >> 40);
    ctx->buffer[59] = (uint8_t)(bits >> 32);
    ctx->buffer[60] = (uint8_t)(bits >> 24);
    ctx->buffer[61] = (uint8_t)(bits >> 16);
    ctx->buffer[62] = (uint8_t)(bits >>  8);
    ctx->buffer[63] = (uint8_t)(bits);

    g_transform(ctx->state, ctx->buffer);

    /* Write hash output in big-endian byte order */
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >>  8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

/* ─────────────────────────────────────────────────────────────────────────
 * Constructor: runtime dispatch + known-answer self-test.
 * Runs before main() — g_transform is never NULL when sha256() is called.
 * ───────────────────────────────────────────────────────────────────────── */
static const uint8_t self_test_input[] = { 'a', 'b', 'c' };
static const uint8_t self_test_expected[32] = {
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
    0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
    0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
    0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
};

__attribute__((constructor))
static void sha256_select_transform(void)
{
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

    /* Self-test: verify the selected implementation produces correct output. */
    uint8_t result[32];
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, self_test_input, sizeof(self_test_input));
    sha256_final(&ctx, result);
    assert(memcmp(result, self_test_expected, 32) == 0);
}

/* ─────────────────────────────────────────────────────────────────────────
 * Public API
 * ───────────────────────────────────────────────────────────────────────── */
void sha256(const uint8_t *input, size_t len, uint8_t *hash)
{
    assert(input != NULL || len == 0);
    assert(hash != NULL);
    assert(g_transform != NULL);

    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, input, len);
    sha256_final(&ctx, hash);
}

const char *sha256_impl_name(void)
{
    return g_impl_name;
}
