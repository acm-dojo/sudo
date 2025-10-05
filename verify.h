#ifndef VERIFY_H
#define VERIFY_H

#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/resource.h>
#include <grp.h>
#include <fcntl.h>
#include <dirent.h>
#include "config.h"

// Security macros
#define SECURE_ZERO(ptr, size) do { \
    volatile unsigned char *p = (volatile unsigned char *)(ptr); \
    while (size--) *p++ = 0; \
} while(0)

// Security validation functions implementation
static inline int validate_path_security(const char *path) {
    if (!path) {
        fprintf(stderr, "Error: NULL path provided\n");
        return 0;
    }
    
    size_t len = strnlen(path, MAX_PATH_LENGTH + 1);
    if (len > MAX_PATH_LENGTH) {
        fprintf(stderr, "Error: Path too long (max %d characters)\n", MAX_PATH_LENGTH);
        return 0;
    }
    
    if (len == 0) {
        fprintf(stderr, "Error: Empty path provided\n");
        return 0;
    }
    
    // Check for directory traversal patterns
    if (strstr(path, "..") || strstr(path, "//") || 
        strchr(path, '\0') != path + len) {
        fprintf(stderr, "Error: Invalid path pattern detected\n");
        return 0;
    }
    
    if (path[0] != '/') {
        fprintf(stderr, "Error: Only absolute paths allowed\n");
        return 0;
    }
    
    for (size_t i = 0; i < len; i++) {
        if (path[i] == '\0') {
            fprintf(stderr, "Error: Null byte in path\n");
            return 0;
        }
    }
    
    return 1;
}

static inline int verify_script_authorization(const char *script_path, const char *signature_path) {
    if (!validate_path_security(script_path)) {
        return 0;
    }
    
    // Trust that signature file is safe and correctly configured
    FILE *file = fopen(signature_path, "r");
    if (!file) {
        fprintf(stderr, "Error: Cannot open signature file: %s\n", strerror(errno));
        return 0;
    }
    
    char line[MAX_LINE_LENGTH];
    int valid = 0;
    int line_count = 0;
    
    while (fgets(line, sizeof(line), file) && line_count < MAX_SIGNATURE_LINES) {
        line_count++;
        
        // Remove trailing newline
        size_t line_len = strnlen(line, sizeof(line));
        if (line_len > 0 && line[line_len - 1] == '\n') {
            line[line_len - 1] = '\0';
            line_len--;
        }
        
        // Skip empty lines
        if (line_len == 0) continue;
        
        // Simple string comparison - trust signature file content
        if (strcmp(line, script_path) == 0) {
            valid = 1;
            break;
        }
    }
    
    fclose(file);
    
    if (!valid) {
        fprintf(stderr, "Error: Script '%s' not authorized for execution\n", script_path);
    }
    
    return valid;
}

static inline void close_excess_fds(void) {
    DIR *fd_dir = opendir("/proc/self/fd");
    if (fd_dir) {
        struct dirent *entry;
        while ((entry = readdir(fd_dir)) != NULL) {
            if (entry->d_name[0] == '.') continue;
            int fd = atoi(entry->d_name);
            if (fd > 2 && fd != dirfd(fd_dir)) {
                close(fd);
            }
        }
        closedir(fd_dir);
    } else {
        for (int fd = 3; fd < 256; fd++) {
            close(fd);
        }
    }
}

static inline char **load_environment_from_file(const char* env_file_path) {
    char **new_environ = NULL;
    size_t env_count = 0;

    FILE *file = fopen(env_file_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Error: Cannot open environment file '%s': %s\n", env_file_path, strerror(errno));
        return NULL;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;

    while ((read = getline(&line, &len, file)) != -1) {
        if (read > 0 && line[read - 1] == '\n') {
            line[read - 1] = '\0';
        }
        if (strlen(line) == 0 || line[0] == '#') {
            continue;
        }

        char **temp_environ = (char**)realloc(new_environ, (env_count + 2) * sizeof(char*)); // +2 for new string and NULL terminator
        if (temp_environ == NULL) {
            fprintf(stderr, "Error: Failed to allocate memory for environment\n");
            // Cleanup previously allocated strings
            for(size_t i = 0; i < env_count; ++i) free(new_environ[i]);
            free(new_environ);
            free(line);
            fclose(file);
            return NULL;
        }
        new_environ = temp_environ;

        new_environ[env_count] = strdup(line);
        if (new_environ[env_count] == NULL) {
            fprintf(stderr, "Error: Failed to duplicate environment string\n");
            // Cleanup
            for(size_t i = 0; i < env_count; ++i) free(new_environ[i]);
            free(new_environ);
            free(line);
            fclose(file);
            return NULL;
        }
        env_count++;
    }

    free(line);
    fclose(file);

    // Ensure the array is NULL-terminated, even if the file was empty
    if (new_environ) {
        new_environ[env_count] = NULL;
    } else {
        // Handle case where file is empty or only has comments
        new_environ = (char**)malloc(sizeof(char*));
        if (!new_environ) {
            fprintf(stderr, "Error: Failed to allocate memory for empty environment\n");
            return NULL;
        }
        new_environ[0] = NULL;
    }

    return new_environ;
}

static inline void setup_secure_environment(const char* env_file_path) {
    extern char **environ;

    char **new_env = load_environment_from_file(env_file_path);

    if (new_env == NULL) {
        fprintf(stderr, "CRITICAL: Failed to load secure environment. Aborting.\n");
        exit(ERROR_CODE);
    }

    environ = new_env;
}


// Set resource limits for security
static inline void set_secure_limits(void) {
    struct rlimit limit;
    
    // Limit core dumps
    limit.rlim_cur = R_LIMIT_CORE_CUR;
    limit.rlim_max = R_LIMIT_CORE_MAX;
    setrlimit(RLIMIT_CORE, &limit);
    
    // Limit file size (prevent large file attacks)
    limit.rlim_cur = R_LIMIT_FSIZE_CUR;
    limit.rlim_max = R_LIMIT_FSIZE_MAX;
    setrlimit(RLIMIT_FSIZE, &limit);
    
    // Limit number of processes
    limit.rlim_cur = R_LIMIT_NPROC_CUR;
    limit.rlim_max = R_LIMIT_NPROC_MAX;
    setrlimit(RLIMIT_NPROC, &limit);
}

static inline int secure_exec_wrapper(const char *executable, char *const argv[], uid_t uid, gid_t gid) {
    if (!executable || !argv) {
        fprintf(stderr, "Error: Invalid arguments to exec wrapper\n");
        return ERROR_CODE;
    }
    
    if (!validate_path_security(executable)) {
        return ERROR_CODE;
    }
    
    if (access(executable, X_OK) != 0) {
        fprintf(stderr, "Error: Cannot execute %s: %s\n", executable, strerror(errno));
        return ERROR_CODE;
    }
    
    // Block signals during critical section
    sigset_t mask, old_mask;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &old_mask);
    
    // Secure privilege dropping sequence
    // 1. Clear supplementary groups
    //if (setgroups(0, NULL) != 0) {
    //    fprintf(stderr, "Error: Failed to clear supplementary groups: %s\n", strerror(errno));
    //    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    //    return ERROR_CODE;
    //}
    // the above is commented out since in dockers(with CAP_SETGID false), setgroups are not permitted
    
    // 2. Set GID
    //if (setgid(gid) != 0) {
    //    fprintf(stderr, "Error: Failed to set GID: %s\n", strerror(errno));
    //    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    //    return ERROR_CODE;
    //}
    // commented out since in dockers(with CAP_SETGID false), setgid are not permitted
    
    // 3. Set UID (must be last)
    //if (setuid(uid) != 0) {
    //    fprintf(stderr, "Error: Failed to set UID: %s\n", strerror(errno));
    //    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    //    return ERROR_CODE;
    //}
    //
    //// Verify privilege drop was successful (security check)
    //if (getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid) {
    //    fprintf(stderr, "Error: Privilege drop verification failed\n");
    //    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    //    return ERROR_CODE;
    //}
    // fuck it docker
    
    // Set up secure execution environment
    setup_secure_environment(SAFE_ENV_FILE_PATH);
    set_secure_limits();
    close_excess_fds();    // Reset signal handlers to default before exec
    signal(SIGPIPE, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);
    sigprocmask(SIG_SETMASK, &old_mask, NULL);
    
    // Execute with clean environment
    execv(executable, argv);
    
    // If we reach here, execv failed
    fprintf(stderr, "Error: Failed to execute %s: %s\n", executable, strerror(errno));
    return ERROR_CODE;
}

static inline void secure_cleanup(void) {
    // none now
}

#endif // VERIFY_H