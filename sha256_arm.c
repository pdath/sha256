/*
 * sha256_arm.c — ARM64 SHA-256 crypto extension transform.
 *
 * Uses the SHA-2 hardware instructions (vsha256hq_u32, vsha256h2q_u32,
 * vsha256su0q_u32, vsha256su1q_u32) to process 4 rounds per instruction
 * pair, giving ~4.5× throughput over the software implementation.
 *
 * Per-function target attribute enables crypto instructions without
 * requiring file-level -march=armv8-a+crypto.
 */

#ifdef __aarch64__

#include "sha256_arm.h"

#include <arm_neon.h>

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
 * ARM64 + Crypto Extensions Transform
 *
 * Uses vsha256hq_u32, vsha256h2q_u32, vsha256su0q_u32, vsha256su1q_u32.
 * Processes 4 rounds per instruction pair.  Message schedule updates are
 * interleaved with hash rounds to exploit pipeline parallelism.
 * ───────────────────────────────────────────────────────────────────────── */
__attribute__((target("arch=armv8-a+crypto")))
void sha256_transform_arm64_crypto(uint32_t state[8], const uint8_t block[64])
{
    /* Load current state into two 128-bit vectors */
    uint32x4_t STATE0 = vld1q_u32(&state[0]);
    uint32x4_t STATE1 = vld1q_u32(&state[4]);

    /* Save original state for final addition */
    uint32x4_t ABCD_SAVE = STATE0;
    uint32x4_t EFGH_SAVE = STATE1;

    /* Load message block and byte-swap (little-endian → big-endian) */
    uint32x4_t MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 0)));
    uint32x4_t MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 16)));
    uint32x4_t MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 32)));
    uint32x4_t MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vld1q_u8(block + 48)));

    uint32x4_t TMP0, TMP1, TMP2;

    /* Rounds 0-3 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[0]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

    /* Rounds 4-7 */
    TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[4]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

    /* Rounds 8-11 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[8]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

    /* Rounds 12-15 */
    TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[12]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

    /* Rounds 16-19 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[16]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

    /* Rounds 20-23 */
    TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[20]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

    /* Rounds 24-27 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[24]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

    /* Rounds 28-31 */
    TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[28]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

    /* Rounds 32-35 */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[32]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG0 = vsha256su1q_u32(vsha256su0q_u32(MSG0, MSG1), MSG2, MSG3);

    /* Rounds 36-39 */
    TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[36]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG1 = vsha256su1q_u32(vsha256su0q_u32(MSG1, MSG2), MSG3, MSG0);

    /* Rounds 40-43 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[40]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG2 = vsha256su1q_u32(vsha256su0q_u32(MSG2, MSG3), MSG0, MSG1);

    /* Rounds 44-47 */
    TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[44]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);
    MSG3 = vsha256su1q_u32(vsha256su0q_u32(MSG3, MSG0), MSG1, MSG2);

    /* Rounds 48-51 (last schedule update) */
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K[48]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);

    /* Rounds 52-55 */
    TMP0 = vaddq_u32(MSG1, vld1q_u32(&K[52]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);

    /* Rounds 56-59 */
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K[56]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);

    /* Rounds 60-63 */
    TMP0 = vaddq_u32(MSG3, vld1q_u32(&K[60]));
    TMP1 = STATE0;
    TMP2 = STATE1;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(TMP2, TMP1, TMP0);

    /* Add original state back */
    STATE0 = vaddq_u32(STATE0, ABCD_SAVE);
    STATE1 = vaddq_u32(STATE1, EFGH_SAVE);

    /* Store result */
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

#endif /* __aarch64__ */
