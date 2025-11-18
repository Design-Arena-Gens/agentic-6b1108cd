#include <stdio.h>

int run_input_tests(void);
int run_file_ops_tests(void);
int run_crypto_tests(void);

int main(void) {
    int failures = 0;
    failures += run_input_tests();
    failures += run_file_ops_tests();
    failures += run_crypto_tests();

    if (failures == 0) {
        printf("All tests passed.\n");
    } else {
        printf("%d test(s) failed.\n", failures);
    }
    return failures;
}
