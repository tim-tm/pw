#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>
#include <pwd.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

#define MAX_OPTION_INPUT_LEN 256

struct command {
    char name[16];
    char description[512];
    char options[64];
};

enum command_type {
    COMMAND_TYPE_UNKNOWN = -1,
    COMMAND_TYPE_GEN_PASSWORD = 0,
    COMMAND_TYPE_CHECK_PASSWORD = 1,
    COMMAND_TYPE_SET_ROOT_PASSWORD = 2,
    COMMAND_TYPE_STORE_PASSWORD = 3,
    /*COMMAND_TYPE_GET_PASSWORD = 4*/
};

const char charset_password[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '$', '%', '&', '/', '(', ')', '=', '?', '*', '{', '}', '[', ']', ':', ';', ',', '.', '-', '<', '>', '|', '^' };
const long charset_len = sizeof(charset_password)/sizeof(char);

const struct command commands[] = {
    { .name = "-g", .description = "Generate a password containing numbers, letters and special characters.", .options = "<password length>" },
    { .name = "-c", .description = "Check a password's stength.", .options = "<password>" },
    { .name = "-rs", .description = "Set the root password. The old password doesn't need to be specified if no password is set. Consider choosing a strong password since the root password provides access to all other stored passwords. This action will destroy your cache file and therefore all your stored passwords.", .options = "<password> <old password>" },
    { .name = "-s", .description = "Store a password.", .options = "<root password> <provider> <password>" },
    /*{ .name = "-g", .description = "Get a password.", .options = "<root password> <provider>" },*/
};
const int commands_len = sizeof(commands)/sizeof(struct command);

enum command_type current_type = COMMAND_TYPE_UNKNOWN;
char *options[16];
int options_len = 16;

FILE *config_file;
unsigned char *hashed_root_password;

void print_help_msg(char *prog_name);
char *generate_random_password(long length);
bool is_special(char c);
bool make_cache_file(bool overwrite);
bool check_password(char *input, const char *access_mode, bool close_file);
int aes_256_encrypt(unsigned char *text, int text_len, unsigned char *key, unsigned char *cipher);
int aes_256_decrypt(unsigned char *cipher, int cipher_len, unsigned char *key, unsigned char *text);

int main(int argc, char **argv) {
    if (argc > 1) {
        for (int i = 0; i < commands_len; ++i) {
            if (strncmp(commands[i].name, argv[1], 16) == 0) {
                current_type = i;
                for (int j = 2; j < argc; ++j) {
                    options[j-2] = argv[j];
                }
            }
        }
    } else {
        print_help_msg(argv[0]);
        return 1;
    }

    switch (current_type) {
        case COMMAND_TYPE_UNKNOWN: {
            print_help_msg("pw");
            return 1;
        } break;
        case COMMAND_TYPE_GEN_PASSWORD: {
            if (options[0] == NULL) {
                print_help_msg("pw");
                return 1;
            }

            char *eptr;
            long result = strtol(options[0], &eptr, 10);
            if (result == 0) {
                printf("Please specify a valid number!\n");
                return 1;
            }
            if (errno == EINVAL) {
                printf("Failed to read value: %d\n", errno);
                return 1;
            }

            if (result == LONG_MIN || result == LONG_MAX) {
                if (errno == ERANGE) {
                    printf("Value is out of range!\n");
                    return 1;
                }
            }

            srand(time(NULL));
            char *str = generate_random_password(result);
            if (str == NULL) {
                printf("Failed to generate password!");
                return 1;
            }
            printf("%s\n", str);
            free(str);
        } break;
        case COMMAND_TYPE_CHECK_PASSWORD: {
            if (options[0] == NULL) {
                print_help_msg("pw");
                return 1;
            }

            int str_len = strnlen(options[0], MAX_OPTION_INPUT_LEN);
            if (str_len <= 9) {
                printf("Your password is a bit short.\n");
                return 0;
            }

            long strength = 0;
            for (int i = 0; i < str_len; ++i) {   
                if (is_special(options[0][i])) {
                    strength++;
                }
                strength++;
            }
            float perc = (float)strength/(float)str_len;
            if (perc > 1.1f) {
                float f = perc-1;
                printf("Your password is decent. (%.2f%% special characters)\n", f);
            } else {
                printf("Your password should contain more special characters.\n");
            }
        } break;
        case COMMAND_TYPE_SET_ROOT_PASSWORD: {
            if (options[0] == NULL) {
                print_help_msg("pw");
                return 1;
            }
            if (!make_cache_file(false)) {
                printf("Config file could not be created.\n");
                return 1;
            }

            fseek(config_file, 0, SEEK_SET);
            unsigned char root_pw[SHA512_DIGEST_LENGTH];
            if (fread(root_pw, SHA512_DIGEST_LENGTH, 1, config_file) != 1) {
                // compute the hash of the new password that the user specified
                int opt_len = strnlen(options[0], MAX_OPTION_INPUT_LEN);
                unsigned char hash[SHA512_DIGEST_LENGTH];
                SHA512((unsigned char*)options[0], opt_len, hash);
                
                // write the new password to the cache file
                fwrite(hash, sizeof(char)*SHA512_DIGEST_LENGTH, 1, config_file);
                if (options[1] != NULL) {
                    printf("Password set. (first set, old password ignored)\n");
                } else {
                    printf("Password set.\n");
                }
            } else {
                if (options[1] == NULL) {
                    printf("Please specify the old password to set a new one.\n");
                    fclose(config_file);
                    return 1;
                }
                if (strncmp(options[0], options[1], MAX_OPTION_INPUT_LEN) == 0) {
                    printf("Old password is equal to the new one.\n");
                    fclose(config_file);
                    return 1;
                }

                // compute the hash of the old password the user specified
                int opt_len = strnlen(options[1], MAX_OPTION_INPUT_LEN);
                unsigned char hash[SHA512_DIGEST_LENGTH];
                SHA512((unsigned char*)options[1], opt_len, hash);

                // check if stored hash and the hashed input are equal
                if (memcmp(root_pw, hash, SHA512_DIGEST_LENGTH) == 0) { 
                    // compute hash of the new password
                    int opt_len = strnlen(options[0], MAX_OPTION_INPUT_LEN);
                    unsigned char hash[SHA512_DIGEST_LENGTH];
                    SHA512((unsigned char*)options[0], opt_len, hash);
                    
                    // destroy the config file be reopening it in wb+ mode
                    fclose(config_file);
                    if (!make_cache_file(true)) {
                        printf("Config file could not be overwritten!\n");
                        return 1;
                    }

                    // write new hashed password to file
                    fwrite(hash, sizeof(char)*SHA512_DIGEST_LENGTH, 1, config_file);
                    printf("Password set.\n");
                } else {
                    printf("Invalid old password.\n");
                }
            }
            fclose(config_file);
        } break;
        case COMMAND_TYPE_STORE_PASSWORD: {
            // ab+ because we want to append each stored entry
            if (!check_password(options[0], "ab+", false)) {
                printf("Invalid password.\n");
                if (hashed_root_password != NULL) free(hashed_root_password);
                if (config_file != NULL) fclose(config_file);
                return 1;
            }

            if (options[1] == NULL || options[2] == NULL) {
                printf("Please specify provider and password.\n");
                free(hashed_root_password);
                fclose(config_file);
                return 1;
            }

            int provider_len = strnlen(options[1], MAX_OPTION_INPUT_LEN);
            unsigned char provider_hash[SHA512_DIGEST_LENGTH];
            SHA512((unsigned char*)options[1], provider_len, provider_hash);
            
            int pass_len = strnlen(options[2], MAX_OPTION_INPUT_LEN);
            unsigned char pass_cipher[64];
            int pass_cipher_len = aes_256_encrypt((unsigned char*)options[2], pass_len, hashed_root_password, pass_cipher);
            if (pass_cipher_len == -1) {
                free(hashed_root_password);
                return 1;
            }

            fwrite(provider_hash, sizeof(char)*SHA512_DIGEST_LENGTH, 1, config_file);
            fwrite(pass_cipher, sizeof(char)*pass_cipher_len, 1, config_file);
            printf("Information was stored.\n");

            free(hashed_root_password);
            fclose(config_file);
        } break;
        /*case COMMAND_TYPE_GET_PASSWORD: {
            if (!check_password(options[0], "rb+", false)) {
                printf("Invalid password.\n");
                if (hashed_root_password != NULL) free(hashed_root_password);
                if (config_file != NULL) fclose(config_file);
                return 1;
            }

            if (options[1] == NULL) {
                printf("Please specify a provider.\n");
                free(hashed_root_password);
                fclose(config_file);
                return 1;
            }
            
            int provider_len = strnlen(options[1], MAX_OPTION_INPUT_LEN);
            unsigned char provider_hash[SHA512_DIGEST_LENGTH];
            SHA512((unsigned char*)options[1], provider_len, provider_hash);
            
            // skip the root password hash
            fseek(config_file, SHA512_DIGEST_LENGTH, SEEK_SET);
            unsigned char read_provider[SHA512_DIGEST_LENGTH] = {0};
            unsigned char cipher_pass[64];
            int cipher_pass_len = 0;
            while (fread(read_provider, SHA512_DIGEST_LENGTH, 1, config_file) == 1) {
                if (memcmp(provider_hash, read_provider, SHA512_DIGEST_LENGTH) == 0) {
                    printf("%s==%s", provider_hash, read_provider);
                    if (fread(cipher_pass, 16, 1, config_file) == 1) {
                        cipher_pass_len = 16;
                    } else {
                        printf("Failed to read password from cache file.\n");
                        return 1;
                    }
                    break;
                }
                // skip one hash and encrypted password
                fseek(config_file, SHA512_DIGEST_LENGTH+16, SEEK_CUR);
            }

            if (cipher_pass_len == 0) {
                printf("Provider not found.\n");
                free(hashed_root_password);
                fclose(config_file);
                return 1;
            }

            unsigned char pass[256];
            int pass_len = aes_256_decrypt(cipher_pass, cipher_pass_len, hashed_root_password, pass);
            if (pass_len == -1) {
                return 1;
            }

            printf("password=");
            for (int i = 0; i < pass_len; ++i) {
                printf("%02x", pass[i]);
            }
            printf("\n");

            free(hashed_root_password);
            fclose(config_file);
        } break;*/
    }
    return 0;
}

void print_help_msg(char *prog_name) {
    printf("%s <options>\noptions:\n", prog_name);
    for (int i = 0; i < commands_len; ++i) {
        printf("\t%s %s, %s\n", commands[i].name, commands[i].options, commands[i].description);
    }
}

char *generate_random_password(long length) {
    char *str = calloc(sizeof(char), length);
    if (str == NULL) {
        return NULL;
    }
    for (long i = 0; i < length; ++i) {
        str[i] = charset_password[rand()%charset_len];
    }
    return str;
}

bool is_special(char c) {
    return !isspace(c) && !isdigit(c) && !islower(c) && !isupper(c);
}

bool make_cache_file(bool overwrite) {
    const char *homedir;
    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
        printf("$HOME not set, falling back to: %s\n", homedir);
    }
    char conf_file[128];
    snprintf(conf_file, 128, "%s/.cache/pw_cache", homedir);
    
    if (overwrite) {
        config_file = fopen(conf_file, "wb+");
        if (config_file == NULL) {
            return false;
        }
    } else {
        config_file = fopen(conf_file, "rb+");
        if (config_file == NULL) {
            // the file may not exist, try to create it
            config_file = fopen(conf_file, "wb+");
            if (config_file == NULL) {
                // file cannot be created
                return false;
            }
        }
    }
    return true;
}

bool check_password(char *input, const char *access_mode, bool close_file) {
    if (input == NULL || access_mode == NULL) {
        return false;
    }

    const char *homedir;
    if ((homedir = getenv("HOME")) == NULL) {
        homedir = getpwuid(getuid())->pw_dir;
        printf("$HOME not set, falling back to: %s\n", homedir);
    }
    char conf_file[128];
    snprintf(conf_file, 128, "%s/.cache/pw_cache", homedir);
    
    config_file = fopen(conf_file, access_mode);
    if (config_file == NULL) {
        printf("Failed to open cache file.\n");
        return false;
    }

    hashed_root_password = calloc(sizeof(char), SHA512_DIGEST_LENGTH);
    if (hashed_root_password == NULL) {
        printf("Failed to allocate memory for password.\n");
        return false;
    }

    if (fread(hashed_root_password, SHA512_DIGEST_LENGTH, 1, config_file) != 1) {
        printf("Make sure to set a root password.\n");
        return false;
    }
    if (close_file) {
        fclose(config_file);
    }
    
    int in_len = strnlen(input, MAX_OPTION_INPUT_LEN);
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*)input, in_len, hash);

    if (memcmp(hashed_root_password, hash, SHA512_DIGEST_LENGTH) == 0) {    
        return true;
    }
    return false;
}

int aes_256_encrypt(unsigned char *text, int text_len, unsigned char *key, unsigned char *cipher) {
    if (text == NULL || text_len <= 0 || key == NULL || cipher == NULL) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("Failed to allocate memory for encryption.\n");
        return -1;
    }

    if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        printf("Failed to initialize encryption.\n");
        return -1;
    }

    int len = 0;
    int cipher_len = 0;
    if (!EVP_EncryptUpdate(ctx, cipher, &len, text, text_len)) {
        printf("Failed to perform encryption.\n");
        return -1;
    }
    cipher_len += len;

    if (!EVP_EncryptFinal_ex(ctx, cipher + len, &len)) {
        printf("Failed to finalize encryption.\n");
        return -1;
    }
    cipher_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return cipher_len;
}

int aes_256_decrypt(unsigned char *cipher, int cipher_len, unsigned char *key, unsigned char *text) {
    if (cipher == NULL || cipher_len <= 0 || key == NULL || text == NULL) {
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        printf("Failed to allocate memory for decryption.\n");
        return -1;
    }

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL)) {
        printf("Failed to initialize decryption.\n");
        return -1;
    }

    int len = 0;
    int text_len = 0;
    if (!EVP_DecryptUpdate(ctx, text, &len, cipher, cipher_len)) {
        printf("Failed to perform decryption.\n");
        return -1;
    }
    text_len += len;

    if (!EVP_DecryptFinal_ex(ctx, text + len, &len)) {
        printf("Failed to finalize encryption.\n");
        return -1;
    }
    text_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return text_len;
}
