/* envvault hardening shim (LD_PRELOAD).
 *
 * Loaded into a program launched by `envvault env run --harden`. Before the
 * program's main() runs, this constructor:
 *
 *   1. marks the process non-dumpable (prctl PR_SET_DUMPABLE=0), which blocks a
 *      same-uid attacker from reading /proc/<pid>/environ AND /proc/<pid>/mem
 *      and from ptrace-attaching;
 *   2. signals the parent ("R") that it is now safe;
 *   3. ONLY THEN reads the secrets the parent sends down a pipe (the parent
 *      withholds them until this signal), and injects them with setenv() so the
 *      program sees them via getenv() like a normal environment;
 *   4. wipes the transfer buffer and removes its own bookkeeping from the env.
 *
 * The secrets never appear in the kernel-visible initial environment, so there
 * is no startup-race window: until step 2 the process holds no secret, and after
 * step 1 it is already unreadable by a same-uid attacker.
 *
 * If this shim does not run (static binary, setuid target, LD_PRELOAD ignored),
 * the parent never receives "R", never sends the secrets, and the run fails
 * closed — nothing leaks.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>

/* Parse a non-negative file descriptor from an environment variable. */
static int fd_from_env(const char *name)
{
    const char *s = getenv(name);
    if (s == NULL || *s == '\0') {
        return -1;
    }
    char *end = NULL;
    long v = strtol(s, &end, 10);
    if (end == s || *end != '\0' || v < 0) {
        return -1;
    }
    return (int)v;
}

__attribute__((constructor))
static void envvault_harden(void)
{
    int ready_fd = fd_from_env("ENVVAULT_READY_FD");
    int secret_fd = fd_from_env("ENVVAULT_SECRET_FD");
    if (ready_fd < 0 || secret_fd < 0) {
        return; /* not a hardened run */
    }

    /* 1. Become non-dumpable BEFORE any secret can arrive. */
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

    /* 2. Tell the parent we are safe; it withholds the secrets until now. */
    char ok = 'R';
    if (write(ready_fd, &ok, 1) != 1) {
        close(ready_fd);
        close(secret_fd);
        return;
    }
    close(ready_fd);

    /* 3. Read the whole payload (KEY=VALUE pairs, NUL-separated) until EOF. */
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (buf == NULL) {
        close(secret_fd);
        return;
    }
    for (;;) {
        if (len == cap) {
            size_t ncap = cap * 2;
            char *nb = (char *)realloc(buf, ncap);
            if (nb == NULL) {
                memset(buf, 0, len);
                free(buf);
                close(secret_fd);
                return;
            }
            buf = nb;
            cap = ncap;
        }
        ssize_t n = read(secret_fd, buf + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        len += (size_t)n;
    }
    close(secret_fd);

    /* 4. Split on NUL, setenv each KEY=VALUE (split on the first '='). */
    size_t i = 0;
    while (i < len) {
        char *entry = buf + i;
        size_t entlen = strnlen(entry, len - i);
        char *eq = (char *)memchr(entry, '=', entlen);
        if (eq != NULL) {
            *eq = '\0';
            (void)setenv(entry, eq + 1, 1);
            *eq = '=';
        }
        i += entlen;
        if (i < len && buf[i] == '\0') {
            i++; /* skip separator */
        } else {
            break;
        }
    }

    /* 5. Wipe the transfer buffer and our own bookkeeping. */
    memset(buf, 0, len);
    free(buf);
    unsetenv("ENVVAULT_READY_FD");
    unsetenv("ENVVAULT_SECRET_FD");
    unsetenv("LD_PRELOAD"); /* don't propagate the shim to children */
}
