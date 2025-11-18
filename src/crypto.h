#ifndef CRYPTO_H
#define CRYPTO_H

#include <stddef.h>

#define PASSWORD_HASH_LEN 64
#define DERIVED_KEY_LEN 256
#define ENCRYPTED_OUTPUT_LEN 256
#define ENCRYPTED_HEX_LEN (ENCRYPTED_OUTPUT_LEN * 2)

int hash_password(const char *password, unsigned char out[PASSWORD_HASH_LEN]);
int derive_master_key(const unsigned char *password_hash, size_t hash_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned char *out_key, size_t out_len, unsigned int iterations);
int encrypt_message(const char *message,
                    const unsigned char *master_key, size_t key_len,
                    const unsigned char *salt, size_t salt_len,
                    char *ciphertext_hex, size_t hex_len);

#endif /* CRYPTO_H */
