#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "file_ops.h"
#include "input.h"
#include "qrng.h"
#include "utils.h"

int main(void) {
    char username[128];
    char filepath[256];
    char message[512];
    char password[256];
    int generated = 0;

    if (prompt_username(username, sizeof(username)) != 0) {
        fprintf(stderr, "Failed to obtain a valid username.\n");
        return EXIT_FAILURE;
    }

    if (build_user_filepath(username, filepath, sizeof(filepath)) != 0) {
        fprintf(stderr, "Failed to build user file path.\n");
        return EXIT_FAILURE;
    }

    if (prompt_message(message, sizeof(message)) != 0) {
        fprintf(stderr, "Failed to read message.\n");
        return EXIT_FAILURE;
    }

    if (write_initial_message(filepath, message) != 0) {
        fprintf(stderr, "Failed to write initial message to file.\n");
        return EXIT_FAILURE;
    }

    if (prompt_password(password, sizeof(password), &generated) != 0) {
        fprintf(stderr, "Failed to acquire a secure password.\n");
        secure_zero(password, sizeof(password));
        return EXIT_FAILURE;
    }

    unsigned char password_hash[PASSWORD_HASH_LEN];
    if (hash_password(password, password_hash) != 0) {
        fprintf(stderr, "Failed to hash password.\n");
        secure_zero(password, sizeof(password));
        return EXIT_FAILURE;
    }

    unsigned char kdf_salt[128];
    if (qrng_fetch_bytes(kdf_salt, sizeof(kdf_salt)) != 0) {
        fprintf(stderr, "Failed to obtain QRNG salt data.\n");
        secure_zero(password, sizeof(password));
        secure_zero(password_hash, sizeof(password_hash));
        return EXIT_FAILURE;
    }

    unsigned char master_key[DERIVED_KEY_LEN];
    if (derive_master_key(password_hash, sizeof(password_hash),
                          kdf_salt, sizeof(kdf_salt),
                          master_key, sizeof(master_key), 120000) != 0) {
        fprintf(stderr, "Failed to derive encryption key.\n");
        secure_zero(password, sizeof(password));
        secure_zero(password_hash, sizeof(password_hash));
        secure_zero(master_key, sizeof(master_key));
        return EXIT_FAILURE;
    }

    unsigned char encryption_salt[ENCRYPTED_OUTPUT_LEN];
    if (qrng_fetch_bytes(encryption_salt, sizeof(encryption_salt)) != 0) {
        fprintf(stderr, "Failed to obtain QRNG encryption salt.\n");
        secure_zero(password, sizeof(password));
        secure_zero(password_hash, sizeof(password_hash));
        secure_zero(master_key, sizeof(master_key));
        return EXIT_FAILURE;
    }

    char ciphertext[ENCRYPTED_HEX_LEN + 1];
    if (encrypt_message(message, master_key, sizeof(master_key),
                        encryption_salt, sizeof(encryption_salt),
                        ciphertext, sizeof(ciphertext)) != 0) {
        fprintf(stderr, "Encryption failed.\n");
        secure_zero(password, sizeof(password));
        secure_zero(password_hash, sizeof(password_hash));
        secure_zero(master_key, sizeof(master_key));
        secure_zero(encryption_salt, sizeof(encryption_salt));
        return EXIT_FAILURE;
    }

    if (replace_with_encrypted(filepath, ciphertext) != 0) {
        fprintf(stderr, "Failed to write encrypted content to file.\n");
        secure_zero(password, sizeof(password));
        secure_zero(password_hash, sizeof(password_hash));
        secure_zero(master_key, sizeof(master_key));
        secure_zero(encryption_salt, sizeof(encryption_salt));
        secure_zero(ciphertext, sizeof(ciphertext));
        return EXIT_FAILURE;
    }

    printf("Encryption complete. Stored in %s.\n", filepath);
    if (!generated) {
        printf("Remember to store your password securely.\n");
    }

    secure_zero(password, sizeof(password));
    secure_zero(password_hash, sizeof(password_hash));
    secure_zero(master_key, sizeof(master_key));
    secure_zero(encryption_salt, sizeof(encryption_salt));
    secure_zero(ciphertext, sizeof(ciphertext));

    return EXIT_SUCCESS;
}
