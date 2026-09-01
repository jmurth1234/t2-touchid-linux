// SPDX-License-Identifier: GPL-2.0-only
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>

static const char message[] =
    "Touch the fingerprint sensor now, or wait to enter your password.\n";

int main(void)
{
    struct stat tty_state;
    size_t offset = 0;
    int tty_fd;

    /*
     * sudo sets PAM_SILENT, so conversation-based PAM messages are hidden.
     * Write one fixed, non-secret hint to the controlling terminal instead.
     * There is deliberately no input, environment, argument, or file-path
     * processing in this privileged helper.
     */
    tty_fd = open("/dev/tty", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (tty_fd >= 0 &&
        (fstat(tty_fd, &tty_state) != 0 || !S_ISCHR(tty_state.st_mode) ||
         !isatty(tty_fd))) {
        close(tty_fd);
        tty_fd = -1;
    }
    /* pam_exec's ``stdout`` option supplies sudo's terminal here when its
     * detached PAM subprocess has no controlling /dev/tty. */
    if (tty_fd < 0)
        tty_fd = STDOUT_FILENO;
    while (offset < sizeof(message) - 1) {
        ssize_t written = write(tty_fd, message + offset,
                                sizeof(message) - 1 - offset);

        if (written > 0) {
            offset += (size_t)written;
            continue;
        }
        if (written < 0 && errno == EINTR)
            continue;
        break;
    }
    if (tty_fd != STDOUT_FILENO)
        close(tty_fd);
    return 0;
}
