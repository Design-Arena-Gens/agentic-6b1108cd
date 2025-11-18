#include "file_ops.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int build_user_filepath(const char *username, char *path, unsigned int size) {
    if (!username || !path || size == 0) {
        return -1;
    }
    int written = snprintf(path, size, "%s.txt", username);
    if (written < 0 || (unsigned int)written >= size) {
        return -1;
    }
    return 0;
}

int write_initial_message(const char *filepath, const char *message) {
    if (!filepath || !message) {
        return -1;
    }
    FILE *fp = fopen(filepath, "w");
    if (!fp) {
        perror("fopen");
        return -1;
    }
    if (fputs(message, fp) == EOF) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int replace_with_encrypted(const char *filepath, const char *ciphertext) {
    if (!filepath || !ciphertext) {
        return -1;
    }

    size_t path_len = strlen(filepath);
    char *temp_path = malloc(path_len + 5);
    if (!temp_path) {
        return -1;
    }
    snprintf(temp_path, path_len + 5, "%s.tmp", filepath);

    FILE *fp = fopen(temp_path, "w");
    if (!fp) {
        perror("fopen");
        free(temp_path);
        return -1;
    }

    if (fputs(ciphertext, fp) == EOF) {
        fclose(fp);
        remove(temp_path);
        free(temp_path);
        return -1;
    }
    fclose(fp);

    if (rename(temp_path, filepath) != 0) {
        perror("rename");
        remove(temp_path);
        free(temp_path);
        return -1;
    }

    free(temp_path);
    return 0;
}
