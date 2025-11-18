#include <stdio.h>
#include <string.h>

#include "utils.h"

static int test_sanitize_username(void) {
    char output[32];
    if (sanitize_username("Alice-123", output, sizeof(output)) != 0) {
        return 1;
    }
    if (strcmp(output, "alice-123") != 0) {
        return 1;
    }
    if (sanitize_username("!!!", output, sizeof(output)) == 0) {
        return 1;
    }
    if (sanitize_username("Bob_The_Builder", output, sizeof(output)) != 0) {
        return 1;
    }
    if (strcmp(output, "bob_the_builder") != 0) {
        return 1;
    }
    return 0;
}

static int test_validate_password_strength(void) {
    if (validate_password_strength("Short1!") != 0) {
        return 1;
    }
    if (!validate_password_strength("StrongPass123!")) {
        return 1;
    }
    if (validate_password_strength("alllowercase123!") != 0) {
        return 1;
    }
    if (validate_password_strength("ALLUPPERCASE123!") != 0) {
        return 1;
    }
    if (validate_password_strength("NoDigits!!!!") != 0) {
        return 1;
    }
    return 0;
}

int run_input_tests(void) {
    int failures = 0;
    failures += test_sanitize_username();
    failures += test_validate_password_strength();
    if (failures == 0) {
        printf("Input tests passed.\n");
    } else {
        printf("Input tests failed (%d).\n", failures);
    }
    return failures;
}
