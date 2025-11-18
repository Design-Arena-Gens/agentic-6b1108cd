#define _POSIX_C_SOURCE 200809L
#include "qrng.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "utils.h"

#define QRNG_MAX_BATCH 1024
#define QRNG_PASSWORD_LEN 24

static size_t parse_uint8_array(const char *json, unsigned char *out, size_t max_count) {
    if (!json || !out) {
        return 0;
    }
    const char *data_ptr = strstr(json, "\"data\"");
    if (!data_ptr) {
        return 0;
    }
    const char *start = strchr(data_ptr, '[');
    const char *end = strchr(data_ptr, ']');
    if (!start || !end || end <= start) {
        return 0;
    }

    size_t count = 0;
    const char *cursor = start + 1;
    while (cursor < end && count < max_count) {
        while (cursor < end && (*cursor == ' ' || *cursor == '\n' || *cursor == '\r' || *cursor == '\t')) {
            cursor++;
        }
        if (cursor >= end) {
            break;
        }
        char *next = NULL;
        long value = strtol(cursor, &next, 10);
        if (cursor == next) {
            break;
        }
        if (value < 0 || value > 255) {
            return 0;
        }
        out[count++] = (unsigned char)value;
        cursor = next;
        const char *comma = strchr(cursor, ',');
        if (!comma) {
            cursor = next;
        } else {
            cursor = comma + 1;
        }
    }
    return count;
}

static int fetch_from_api(unsigned char *buffer, size_t length) {
    if (!buffer || length == 0) {
        return -1;
    }

    size_t offset = 0;
    while (offset < length) {
        size_t batch = length - offset;
        if (batch > QRNG_MAX_BATCH) {
            batch = QRNG_MAX_BATCH;
        }

        char command[256];
        snprintf(command, sizeof(command),
                 "curl -s \"https://qrng.anu.edu.au/API/jsonI.php?length=%zu&type=uint8\"",
                 batch);

        FILE *pipe = popen(command, "r");
        if (!pipe) {
            return -1;
        }

        char response[65536];
        size_t read_bytes = fread(response, 1, sizeof(response) - 1, pipe);
        pclose(pipe);

        if (read_bytes == 0) {
            return -1;
        }
        response[read_bytes] = '\0';

        unsigned char temp[QRNG_MAX_BATCH];
        size_t parsed = parse_uint8_array(response, temp, batch);
        if (parsed < batch) {
            return -1;
        }

        memcpy(buffer + offset, temp, batch);
        offset += batch;
    }

    return 0;
}

static int fetch_from_urandom(unsigned char *buffer, size_t length) {
    if (!buffer || length == 0) {
        return -1;
    }
    FILE *fp = fopen("/dev/urandom", "rb");
    if (!fp) {
        return -1;
    }
    size_t read_len = fread(buffer, 1, length, fp);
    fclose(fp);
    return read_len == length ? 0 : -1;
}

int qrng_fetch_bytes(unsigned char *buffer, size_t length) {
    if (!buffer || length == 0) {
        return -1;
    }
    const char *offline = getenv("QRNG_OFFLINE");
    if (offline && strcmp(offline, "1") == 0) {
        return fetch_from_urandom(buffer, length);
    }
    if (fetch_from_api(buffer, length) == 0) {
        return 0;
    }
    fprintf(stderr, "Warning: QRNG API unavailable, falling back to /dev/urandom.\n");
    return fetch_from_urandom(buffer, length);
}

static int classify_char(char c) {
    if (c >= 'A' && c <= 'Z') return 0;
    if (c >= 'a' && c <= 'z') return 1;
    if (c >= '0' && c <= '9') return 2;
    return 3;
}

int qrng_generate_password(char *buffer, size_t size) {
    if (!buffer || size <= QRNG_PASSWORD_LEN) {
        return -1;
    }

    static const char charset[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
        "!@#$%^&*()-_=+[]{}<>?/|";

    const size_t charset_len = sizeof(charset) - 1;
    unsigned char random_bytes[QRNG_PASSWORD_LEN];

    if (qrng_fetch_bytes(random_bytes, sizeof(random_bytes)) != 0) {
        return -1;
    }

    int class_present[4] = {0, 0, 0, 0};

    for (size_t i = 0; i < QRNG_PASSWORD_LEN; ++i) {
        unsigned char idx = (unsigned char)(random_bytes[i] % charset_len);
        buffer[i] = charset[idx];
        class_present[classify_char(buffer[i])] = 1;
    }

    /* Ensure all required classes are present */
    if (!(class_present[0] && class_present[1] && class_present[2] && class_present[3])) {
        unsigned char extra[4];
        if (qrng_fetch_bytes(extra, sizeof(extra)) != 0) {
            return -1;
        }
        static const char forced_chars[] = "AZ0!";
        for (int i = 0; i < 4; ++i) {
            if (!class_present[i]) {
                buffer[extra[i] % QRNG_PASSWORD_LEN] = forced_chars[i];
            }
        }
    }

    buffer[QRNG_PASSWORD_LEN] = '\0';
    return 0;
}
