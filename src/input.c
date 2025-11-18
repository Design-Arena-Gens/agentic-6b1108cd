#include "input.h"

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "qrng.h"
#include "utils.h"

#define MAX_ATTEMPTS 3

static int read_line(char *buffer, size_t size) {
    if (!fgets(buffer, (int)size, stdin)) {
        return -1;
    }
    trim_newline(buffer);
    return 0;
}

static int read_password_noecho(char *buffer, size_t size) {
    struct termios oldt, newt;
    if (tcgetattr(STDIN_FILENO, &oldt) != 0) {
        return -1;
    }
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    if (tcsetattr(STDIN_FILENO, TCSANOW, &newt) != 0) {
        return -1;
    }

    int result = 0;
    if (!fgets(buffer, (int)size, stdin)) {
        result = -1;
    } else {
        trim_newline(buffer);
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    return result;
}

int prompt_username(char *username, size_t size) {
    char buffer[256];
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        printf("Enter your name: ");
        fflush(stdout);
        if (read_line(buffer, sizeof(buffer)) != 0) {
            fprintf(stderr, "Failed to read input.\n");
            return -1;
        }
        if (sanitize_username(buffer, username, size) == 0) {
            return 0;
        }
        fprintf(stderr, "Invalid username. Use alphanumeric characters, '_' or '-'.\n");
    }
    return -1;
}

int prompt_message(char *message, size_t size) {
    printf("Enter a sentence or short message: ");
    fflush(stdout);
    if (read_line(message, size) != 0) {
        fprintf(stderr, "Failed to read message.\n");
        return -1;
    }
    if (strlen(message) == 0) {
        fprintf(stderr, "Message cannot be empty.\n");
        return -1;
    }
    return 0;
}

static int prompt_password_choice(void) {
    char buffer[16];
    printf("Choose password option:\n");
    printf("  1) Provide my own password\n");
    printf("  2) Generate password using QRNG\n");
    printf("Selection: ");
    fflush(stdout);
    if (read_line(buffer, sizeof(buffer)) != 0) {
        return -1;
    }
    if (strcmp(buffer, "1") == 0) {
        return 1;
    }
    if (strcmp(buffer, "2") == 0) {
        return 2;
    }
    return 0;
}

int prompt_password(char *password, size_t size, int *is_generated) {
    if (!password || size == 0) {
        return -1;
    }
    for (int attempt = 0; attempt < MAX_ATTEMPTS; ++attempt) {
        int choice = prompt_password_choice();
        if (choice == 1) {
            printf("Enter a strong password: ");
            fflush(stdout);
            if (read_password_noecho(password, size) != 0) {
                fprintf(stderr, "\nFailed to read password input.\n");
                return -1;
            }
            printf("\n");
            if (!validate_password_strength(password)) {
                fprintf(stderr, "Password does not meet strength requirements (12+ chars, mixed character types).\n");
                continue;
            }
            if (is_generated) {
                *is_generated = 0;
            }
            return 0;
        } else if (choice == 2) {
            if (qrng_generate_password(password, size) != 0) {
                fprintf(stderr, "Failed to generate password from QRNG.\n");
                continue;
            }
            printf("Generated password: %s\n", password);
            if (is_generated) {
                *is_generated = 1;
            }
            return 0;
        } else {
            fprintf(stderr, "Invalid selection. Please choose 1 or 2.\n");
        }
    }
    return -1;
}
