#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "file_ops.h"

static int test_build_user_filepath(void) {
    char path[64];
    if (build_user_filepath("alice", path, sizeof(path)) != 0) {
        return 1;
    }
    if (strcmp(path, "alice.txt") != 0) {
        return 1;
    }
    return 0;
}

static int test_file_write_replace(void) {
    char template[] = "test_messageXXXXXX";
    int fd = mkstemp(template);
    if (fd == -1) {
        perror("mkstemp");
        return 1;
    }
    close(fd);

    if (write_initial_message(template, "hello world") != 0) {
        unlink(template);
        return 1;
    }

    FILE *fp = fopen(template, "r");
    if (!fp) {
        unlink(template);
        return 1;
    }
    char buffer[64] = {0};
    fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    if (strcmp(buffer, "hello world") != 0) {
        unlink(template);
        return 1;
    }

    if (replace_with_encrypted(template, "abc123") != 0) {
        unlink(template);
        return 1;
    }

    fp = fopen(template, "r");
    if (!fp) {
        unlink(template);
        return 1;
    }
    memset(buffer, 0, sizeof(buffer));
    fgets(buffer, sizeof(buffer), fp);
    fclose(fp);
    unlink(template);

    if (strcmp(buffer, "abc123") != 0) {
        return 1;
    }
    return 0;
}

int run_file_ops_tests(void) {
    int failures = 0;
    failures += test_build_user_filepath();
    failures += test_file_write_replace();

    if (failures == 0) {
        printf("File operation tests passed.\n");
    } else {
        printf("File operation tests failed (%d).\n", failures);
    }
    return failures;
}
