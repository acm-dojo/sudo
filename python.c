#include "verify.h"
#include "config.h"

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
    newargv[0] = PYTHON_CMD;
    for (int i = 1; i < argc; i++) {
        newargv[i] = argv[i];
    }
    newargv[argc] = NULL;
    
    int result = secure_exec_wrapper(PYTHON_PATH, newargv, PYTHON_UID, PYTHON_GID);
    
    secure_cleanup();
    return result;
}