#ifndef CONFIG_H
#define CONFIG_H

// From verify.h
#define SIGNATURE_PATH "/challenge/.signature"
#define MAX_PATH_LENGTH 256
#define MAX_SIGNATURE_LINES 32
#define MAX_LINE_LENGTH 512
#define ERROR_CODE 1
#define SUCCESS_CODE 0
#define DEFAULT_PATH "/run/challenge/bin:/run/dojo/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games"
#define R_LIMIT_CORE_CUR 0
#define R_LIMIT_CORE_MAX 0
#define R_LIMIT_FSIZE_CUR 104857600 // 100MB
#define R_LIMIT_FSIZE_MAX 104857600 // 100MB
#define R_LIMIT_NPROC_CUR 32
#define R_LIMIT_NPROC_MAX 32

// From python.c
#define PYTHON_CMD "python"
#define PYTHON_PATH "/run/dojo/bin/python"
#define PYTHON_UID 0
#define PYTHON_GID 0

// From bash.c
#define BASH_CMD "bash"
#define BASH_PATH "/bin/bash"
#define BASH_UID 0
#define BASH_GID 0

#endif // CONFIG_H
