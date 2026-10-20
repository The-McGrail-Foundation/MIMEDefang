#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../mimedefang.h"

#define NUM_TESTS 5

static int test_num = 0;

static void
check(const char *label, int ok)
{
    test_num++;
    printf("%s %d - %s\n", ok ? "ok" : "not ok", test_num, label);
}

int
main(void)
{
    char dir[] = "/tmp/md-pidfile-XXXXXX";
    char path[256], target[256], link2[256];
    struct stat sbuf;
    int fd;

    printf("1..%d\n", NUM_TESTS);
    if (!mkdtemp(dir)) {
	perror("mkdtemp");
	return 1;
    }
    snprintf(path, sizeof(path), "%s/md.pid", dir);
    snprintf(target, sizeof(target), "%s/target", dir);
    snprintf(link2, sizeof(link2), "%s/hardlink", dir);

    /* A new file is created and world-readable */
    umask(077);
    fd = md_open_pidfile(path);
    check("creates a new pidfile", fd >= 0);
    check("pidfile is mode 0644",
	  fd >= 0 && fstat(fd, &sbuf) == 0 && (sbuf.st_mode & 0777) == 0644);
    if (fd >= 0) close(fd);
    unlink(path);

    /* A symlink to another file is refused and the target untouched */
    fd = open(target, O_WRONLY|O_CREAT, 0600);
    if (fd >= 0) close(fd);
    if (symlink(target, path) < 0) perror("symlink");
    fd = md_open_pidfile(path);
    check("refuses a symlink", fd < 0 &&
	  stat(target, &sbuf) == 0 && (sbuf.st_mode & 0777) == 0600);
    if (fd >= 0) close(fd);
    unlink(path);

    /* A hard link to another file is refused */
    if (link(target, link2) < 0) perror("link");
    fd = md_open_pidfile(link2);
    check("refuses a hard link", fd < 0);
    if (fd >= 0) close(fd);
    unlink(link2);

    /* A FIFO is refused without blocking */
    if (mkfifo(path, 0600) < 0) perror("mkfifo");
    fd = md_open_pidfile(path);
    check("refuses a FIFO", fd < 0);
    if (fd >= 0) close(fd);
    unlink(path);

    unlink(target);
    rmdir(dir);
    return 0;
}
