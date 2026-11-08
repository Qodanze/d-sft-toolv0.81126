/* massmkdir <dir> <count> - creates <count> directories inside <dir> as fast
 * as possible (pure mkdir syscalls). Each new dir costs a disk block, so a
 * small sandbox limit must terminate this mid-loop. Also a shim speed test. */
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>

int main(int argc, char** argv)
{
    if (argc < 3) { fprintf(stderr, "usage: massmkdir <dir> <count>\n"); return 2; }
    const char* dir = argv[1];
    const int count = atoi(argv[2]);
    int made = 0;
    for (int i = 0; i < count; i++) {
        char p[512];
        snprintf(p, sizeof p, "%s/d%06d", dir, i);
        if (mkdir(p, 0755) == 0) made++;
        else if (errno == ENOSPC) { printf("massmkdir stopped at %d dirs (disk full)\n", made); return 1; }
    }
    printf("massmkdir made %d dirs\n", made);
    return 0;
}
