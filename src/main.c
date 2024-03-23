#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

struct command {
    char name[16];
    char description[128];
    char options[32];
};

enum command_type {
    COMMAND_TYPE_UNKNOWN = -1,
    COMMAND_TYPE_GEN_PASSWORD = 0
};

const char charset_password[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '$', '%', '&', '/', '(', ')', '=', '?', '*', '{', '}', '[', ']', ':', ';', ',', '.', '-', '<', '>', '|', '^' };
const long charset_len = sizeof(charset_password)/sizeof(char);

const struct command commands[] = {
    { .name = "-g", .description = "Generate a password containing numbers, letters and special characters.", .options = "<password length>" },
};
const int commands_len = sizeof(commands)/sizeof(struct command);

enum command_type current_type = COMMAND_TYPE_UNKNOWN;
char *options[16];
int options_len = 16;

void print_help_msg(char *prog_name);
char *generate_random_password(long length);

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
            if (result == 0 && errno == EINVAL) {
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
        } break;
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
