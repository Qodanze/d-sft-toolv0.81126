/* quotachild <path> - the PARENT stays alive while its CHILD writes 100 MB.
 * With a 10 MB limit only the child must be terminated (and its file
 * deleted) - the parent must survive and exit 0. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: quotachild <path>\n"); return 2; }
    pid_t pid = fork();
    if (pid == 0) {
        FILE* f = fopen(argv[1], "wb");
        if (!f) _exit(3);
        static char buf[65536];
        memset(buf, 0, sizeof buf);
        for (int i = 0; i < 1600; i++)          /* 100 MB */
            if (fwrite(buf, 1, sizeof buf, f) != sizeof buf) break;
        fclose(f);
        _exit(0);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    printf("quotachild parent survived (child status %d)\n", st);
    fflush(stdout);
    return 0;
}
