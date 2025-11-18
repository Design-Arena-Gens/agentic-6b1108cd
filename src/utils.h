#ifndef UTILS_H
#define UTILS_H

#include <stddef.h>

int sanitize_username(const char *input, char *output, size_t size);
void trim_newline(char *str);
int validate_password_strength(const char *password);
void secure_zero(void *ptr, size_t len);
void hex_encode(const unsigned char *input, size_t len, char *output, size_t out_len);
int hex_char_to_value(char c);
int hex_string_to_bytes(const char *hex, unsigned char *out, size_t out_len);

#endif /* UTILS_H */
