#include "utils.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sanitize_username(const char *input, char *output, size_t size) {
    if (!input || !output || size == 0) {
        return -1;
    }

    size_t out_idx = 0;
    for (size_t i = 0; input[i] != '\0'; ++i) {
        if (isalnum((unsigned char)input[i]) || input[i] == '_' || input[i] == '-') {
            if (out_idx + 1 >= size) {
                break;
            }
            output[out_idx++] = (char)tolower((unsigned char)input[i]);
        }
    }

    if (out_idx == 0) {
        return -1;
    }

    output[out_idx] = '\0';
    return 0;
}

void trim_newline(char *str) {
    if (!str) {
        return;
    }
    size_t len = strlen(str);
    while (len > 0 && (str[len - 1] == '\n' || str[len - 1] == '\r')) {
        str[len - 1] = '\0';
        len--;
    }
}

static int contains_class(const char *password, int (*class_fn)(int)) {
    for (size_t i = 0; password[i] != '\0'; ++i) {
        if (class_fn((unsigned char)password[i])) {
            return 1;
        }
    }
    return 0;
}

static int is_upper(int c) { return isupper(c); }
static int is_lower(int c) { return islower(c); }
static int is_digit_class(int c) { return isdigit(c); }

static int is_special(int c) {
    return ispunct(c) || c == ' ';
}

int validate_password_strength(const char *password) {
    if (!password) {
        return 0;
    }

    size_t len = strlen(password);
    if (len < 12 || len > 128) {
        return 0;
    }

    if (!contains_class(password, is_upper)) {
        return 0;
    }
    if (!contains_class(password, is_lower)) {
        return 0;
    }
    if (!contains_class(password, is_digit_class)) {
        return 0;
    }
    if (!contains_class(password, is_special)) {
        return 0;
    }

    return 1;
}

void secure_zero(void *ptr, size_t len) {
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

void hex_encode(const unsigned char *input, size_t len, char *output, size_t out_len) {
    static const char hex_table[] = "0123456789abcdef";
    if (!input || !output || out_len < (len * 2 + 1)) {
        return;
    }
    for (size_t i = 0; i < len; ++i) {
        output[2 * i] = hex_table[(input[i] >> 4) & 0x0F];
        output[2 * i + 1] = hex_table[input[i] & 0x0F];
    }
    output[len * 2] = '\0';
}

int hex_char_to_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int hex_string_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    if (!hex || !out) {
        return -1;
    }
    size_t hex_len = strlen(hex);
    if (hex_len < out_len * 2) {
        return -1;
    }
    for (size_t i = 0; i < out_len; ++i) {
        int high = hex_char_to_value(hex[2 * i]);
        int low = hex_char_to_value(hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            return -1;
        }
        out[i] = (unsigned char)((high << 4) | low);
    }
    return 0;
}
