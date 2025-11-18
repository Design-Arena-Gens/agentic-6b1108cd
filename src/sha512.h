#ifndef SHA512_H
#define SHA512_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint64_t state[8];
    unsigned char data[128];
    size_t datalen;
    uint64_t bitlen_hi;
    uint64_t bitlen_lo;
} sha512_ctx;

void sha512_init(sha512_ctx *ctx);
void sha512_update(sha512_ctx *ctx, const unsigned char *data, size_t len);
void sha512_final(sha512_ctx *ctx, unsigned char hash[64]);

void hmac_sha512(const unsigned char *key, size_t key_len,
                 const unsigned char *data, size_t data_len,
                 unsigned char out[64]);

#endif /* SHA512_H */
