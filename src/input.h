#ifndef INPUT_H
#define INPUT_H

#include <stddef.h>

int prompt_username(char *username, size_t size);
int prompt_message(char *message, size_t size);
int prompt_password(char *password, size_t size, int *is_generated);

#endif /* INPUT_H */
