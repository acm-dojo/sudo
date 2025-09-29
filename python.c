#include "verify.h"

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Error: Interactive interpreter access denied. Script path required.\n");
        return ERROR_CODE;
    }
    
    if (!verify_script_authorization(argv[1], SIGNATURE_PATH)) {
        fprintf(stderr, "Error: Script authorization failed for python execution.\n");
        return ERROR_CODE;
    }
    
    char *newargv[argc + 1];
    newargv[0] = "python";
    for (int i = 1; i < argc; i++) {
        newargv[i] = argv[i];
    }
    newargv[argc] = NULL;
    
    int result = secure_exec_wrapper("/run/dojo/bin/python", newargv, 0, 0);
    
    secure_cleanup();
    return result;
}