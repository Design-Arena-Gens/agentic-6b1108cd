#ifndef QRNG_H
#define QRNG_H

#include <stddef.h>

int qrng_fetch_bytes(unsigned char *buffer, size_t length);
int qrng_generate_password(char *buffer, size_t size);

#endif /* QRNG_H */
