#ifndef FILE_OPS_H
#define FILE_OPS_H

int build_user_filepath(const char *username, char *path, unsigned int size);
int write_initial_message(const char *filepath, const char *message);
int replace_with_encrypted(const char *filepath, const char *ciphertext);

#endif /* FILE_OPS_H */
