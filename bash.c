// bash.c
// implements a root bash shell with signature validation

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

const char *signature_path = "/challenge/.signature";
const int path_str_length = 64;
const int max_signature_lines = 32;
const int error_code = 1;

// only accept #! launching, and match launch script path against signature
int main(int argc, char *argv[]) {
    if (argc < 2) {
        // cannot be lanched without arguments (interactive shell)
        return error_code;
    }

    FILE *file = fopen(signature_path, "r");
    if (file == NULL) {
        fprintf(stderr, "no signature file found, exiting.\n");
        return error_code;
    }

    // validate path against signature file
    char line[path_str_length];
    int valid = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
        // remove newline character
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) == 0) continue;    // skip empty lines
        if (strcmp(line, argv[1]) == 0) {
            valid = 1;
            break;
        }
    }
    fclose(file);

    if (!valid) {
        // reject to run any file not in signature
        fprintf(stderr, "script %s not authorized to launch root bash, exiting.\n", argv[1]);
        return error_code;
    }

    const char *newargv[argc + 1];
    newargv[0] = "bash";
    for (int i = 1; i < argc; i++) {
        newargv[i] = argv[i];
    }
    newargv[argc] = NULL;

    setuid(0);
    setgid(0);
    execv("/bin/bash", (char *const *)newargv);

    return error_code;
}