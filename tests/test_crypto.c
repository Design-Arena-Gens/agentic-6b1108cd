#include <stdio.h>
#include <string.h>

#include "crypto.h"
#include "utils.h"

static int test_hash_password(void) {
    unsigned char hash[PASSWORD_HASH_LEN];
    if (hash_password("StrongPass123!", hash) != 0) {
        return 1;
    }
    char hex[PASSWORD_HASH_LEN * 2 + 1];
    hex_encode(hash, PASSWORD_HASH_LEN, hex, sizeof(hex));
    if (strcmp(hex, "6dd89f1510cf58184b5b301c7cb0be0fae79582905a478b01a8a157909bca20fcb3f6b1895f41995073606cf7b696218834183010bcebf85be7a0fe4ce95874a") != 0) {
        return 1;
    }
    return 0;
}

static int test_derive_master_key(void) {
    unsigned char password_hash[PASSWORD_HASH_LEN];
    if (hash_password("StrongPass123!", password_hash) != 0) {
        return 1;
    }
    unsigned char salt[16];
    for (size_t i = 0; i < sizeof(salt); ++i) {
        salt[i] = (unsigned char)i;
    }
    unsigned char key[DERIVED_KEY_LEN];
    if (derive_master_key(password_hash, sizeof(password_hash),
                          salt, sizeof(salt), key, sizeof(key), 5000) != 0) {
        return 1;
    }
    char hex[DERIVED_KEY_LEN * 2 + 1];
    hex_encode(key, sizeof(key), hex, sizeof(hex));
    if (strcmp(hex,
               "4e6aa0dae02642369223ceec71ec93275b7fca56052a5100e2df78c82005365672bfb6dafc4cf476fcc335cccd598a71d0d9f67a674abfc6ab70f37639c2fdb55fa3e00db4e89009dcf212ef39837aea8a0e24b0171b76b73360e4423fee06b05ff7526f82898e75a5cdd28f0dff6e2753f9aeb64bb02abfeef0dc44093b695583750ed69580c7ba015e68cf330c578fc3dea0fd6657bbb81c2228ea9ce864991350fc3480b681fa93645dad844401ba9a1cb6b7d5e4f77610ef4dbc2ec4d6ab96441e7060b24d378f90fce1e19d015d69563d2ae60e416b54be72cafda8e315e44330d811b3f0b1cde50fc9e7dd12ca89f98e696d744ce35815d8b412401875") != 0) {
        return 1;
    }
    return 0;
}

static int test_encrypt_message(void) {
    unsigned char password_hash[PASSWORD_HASH_LEN];
    if (hash_password("StrongPass123!", password_hash) != 0) {
        return 1;
    }
    unsigned char salt[16];
    for (size_t i = 0; i < sizeof(salt); ++i) {
        salt[i] = (unsigned char)i;
    }
    unsigned char key[DERIVED_KEY_LEN];
    if (derive_master_key(password_hash, sizeof(password_hash),
                          salt, sizeof(salt), key, sizeof(key), 5000) != 0) {
        return 1;
    }
    unsigned char encryption_salt[ENCRYPTED_OUTPUT_LEN];
    for (size_t i = 0; i < sizeof(encryption_salt); ++i) {
        encryption_salt[i] = (unsigned char)i;
    }

    char ciphertext[ENCRYPTED_HEX_LEN + 1];
    if (encrypt_message("Sample message for encryption", key, sizeof(key),
                        encryption_salt, sizeof(encryption_salt),
                        ciphertext, sizeof(ciphertext)) != 0) {
        return 1;
    }
    if (strlen(ciphertext) != ENCRYPTED_HEX_LEN) {
        return 1;
    }
    if (strcmp(ciphertext,
               "c75ea17dcfe9111a9a9b2897dc6fd1a9ada399535067eeef97205f4bf50929cc956bbf19aac02c673f065181ba5394d90db13f2cd0d4dea50eb05db270b2ff2a3134834e585ce68d6f3821b9a5e307d760533809bf33beacbbb2dd2e4c49467b4aee44a3199df768ee382a3f44714db93ee01b292eb4de9f70888d04d9c193f13c6cbcfe7b0ee80d3eb79cac7dddd5f7d615aa171c2c26170458e4a32d7d3dd2cfd2018b060f8163e70bb7b2f21e24a0b796e2198831ee5840600c0617eb68ad532924e1d992355657d4c411fe3046892eb4852e342e3f7698c7cc5cf86148701ecf23e57af780ca12e4ae3a4d5f64b92c9e8db7b2a2e4bab79b0b323f23c8a9") != 0) {
        return 1;
    }
    return 0;
}

int run_crypto_tests(void) {
    int failures = 0;
    failures += test_hash_password();
    failures += test_derive_master_key();
    failures += test_encrypt_message();

    if (failures == 0) {
        printf("Crypto tests passed.\n");
    } else {
        printf("Crypto tests failed (%d).\n", failures);
    }
    return failures;
}
