#ifndef SHA2_H
#define SHA2_H
#include <stddef.h>
#include <stdint.h>

/* Minimal, self-contained SHA-256 / SHA-512 (no external deps). */

typedef struct {
    uint32_t state[8];
    uint64_t bitlen;
    uint8_t  buf[64];
    size_t   buflen;
} sha256_ctx;

void sha256_init(sha256_ctx *c);
void sha256_update(sha256_ctx *c, const void *data, size_t len);
void sha256_final(sha256_ctx *c, uint8_t out[32]);
void sha256(const void *data, size_t len, uint8_t out[32]);

typedef struct {
    uint64_t state[8];
    uint64_t bitlen_hi, bitlen_lo;
    uint8_t  buf[128];
    size_t   buflen;
} sha512_ctx;

void sha512_init(sha512_ctx *c);
void sha512_update(sha512_ctx *c, const void *data, size_t len);
void sha512_final(sha512_ctx *c, uint8_t out[64]);
void sha512(const void *data, size_t len, uint8_t out[64]);

#endif /* SHA2_H */
