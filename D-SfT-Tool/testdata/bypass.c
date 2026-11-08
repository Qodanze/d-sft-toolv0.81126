/* bypass <outfile> - parent spawns dd (a DIFFERENT program) that writes 50 MB,
 * then exits 0. Tests: (a) quota accounting propagates through fork+exec,
 * (b) the kill reaches the exec'd child even though the parent already left. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: bypass <outfile>\n"); return 2; }
    pid_t pid = fork();
    if (pid == 0) {
        char of[512];
        snprintf(of, sizeof of, "of=%s", argv[1]);
        execl("/usr/bin/dd", "dd", "if=/dev/zero", of, "bs=1M", "count=50",
              (char*)NULL);
        _exit(127);
    }
    wait(NULL);
    printf("bypass parent done\n");
    return 0;
}
