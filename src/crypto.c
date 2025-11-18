#include "crypto.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "sha512.h"
#include "utils.h"

int hash_password(const char *password, unsigned char out[PASSWORD_HASH_LEN]) {
    if (!password || !out) {
        return -1;
    }
    sha512_ctx ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, (const unsigned char *)password, strlen(password));
    sha512_final(&ctx, out);
    return 0;
}

static void int_to_be(uint32_t value, unsigned char out[4]) {
    out[0] = (unsigned char)(value >> 24);
    out[1] = (unsigned char)(value >> 16);
    out[2] = (unsigned char)(value >> 8);
    out[3] = (unsigned char)(value);
}

int derive_master_key(const unsigned char *password_hash, size_t hash_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *out_key, size_t out_len, unsigned int iterations) {
    if (!password_hash || !salt || !out_key || hash_len == 0 || out_len == 0 || iterations == 0) {
        return -1;
    }

    unsigned int blocks = (unsigned int)((out_len + 63) / 64);
    unsigned char u[64];
    unsigned char t[64];
    unsigned char salt_block[512];
    size_t derived = 0;

    for (unsigned int block = 1; block <= blocks; ++block) {
        size_t salt_block_len = 0;
        if (salt_len > sizeof(salt_block) - 4) {
            salt_block_len = sizeof(salt_block) - 4;
        } else {
            salt_block_len = salt_len;
        }
        memcpy(salt_block, salt, salt_block_len);
        unsigned char count_bytes[4];
        int_to_be(block, count_bytes);
        memcpy(salt_block + salt_block_len, count_bytes, 4);
        salt_block_len += 4;

        hmac_sha512(password_hash, hash_len, salt_block, salt_block_len, u);
        memcpy(t, u, sizeof(t));

        for (unsigned int i = 1; i < iterations; ++i) {
            hmac_sha512(password_hash, hash_len, u, sizeof(u), u);
            for (int j = 0; j < 64; ++j) {
                t[j] ^= u[j];
            }
        }

        size_t to_copy = out_len - derived;
        if (to_copy > 64) {
            to_copy = 64;
        }
        memcpy(out_key + derived, t, to_copy);
        derived += to_copy;
    }

    secure_zero(u, sizeof(u));
    secure_zero(t, sizeof(t));
    secure_zero(salt_block, sizeof(salt_block));

    return 0;
}

int encrypt_message(const char *message,
                    const unsigned char *master_key, size_t key_len,
                    const unsigned char *salt, size_t salt_len,
                    char *ciphertext_hex, size_t hex_len) {
    if (!message || !master_key || key_len == 0 || !ciphertext_hex) {
        return -1;
    }
    if (hex_len < ENCRYPTED_HEX_LEN + 1) {
        return -1;
    }

    unsigned char info[384];
    size_t info_len = 0;
    size_t copy_salt = salt_len;
    if (copy_salt > 192) {
        copy_salt = 192;
    }
    memcpy(info + info_len, salt, copy_salt);
    info_len += copy_salt;

    size_t msg_len = strlen(message);
    size_t copy_msg = msg_len;
    if (copy_msg > sizeof(info) - info_len) {
        copy_msg = sizeof(info) - info_len;
    }
    memcpy(info + info_len, message, copy_msg);
    info_len += copy_msg;

    unsigned char previous[64];
    memset(previous, 0, sizeof(previous));
    unsigned char result[ENCRYPTED_OUTPUT_LEN];
    size_t produced = 0;
    unsigned int blocks = (ENCRYPTED_OUTPUT_LEN + 63) / 64;

    for (unsigned int block = 1; block <= blocks; ++block) {
        unsigned char buffer[64 + sizeof(info) + 1];
        size_t offset = 0;
        if (block > 1) {
            memcpy(buffer + offset, previous, sizeof(previous));
            offset += sizeof(previous);
        }
        memcpy(buffer + offset, info, info_len);
        offset += info_len;
        buffer[offset++] = (unsigned char)block;

        hmac_sha512(master_key, key_len, buffer, offset, previous);

        size_t to_copy = ENCRYPTED_OUTPUT_LEN - produced;
        if (to_copy > 64) {
            to_copy = 64;
        }
        memcpy(result + produced, previous, to_copy);
        produced += to_copy;
    }

    hex_encode(result, ENCRYPTED_OUTPUT_LEN, ciphertext_hex, hex_len);
    secure_zero(previous, sizeof(previous));
    secure_zero(result, sizeof(result));
    secure_zero(info, sizeof(info));

    return 0;
}
