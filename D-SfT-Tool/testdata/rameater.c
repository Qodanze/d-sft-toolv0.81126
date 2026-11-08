/* rameater <mb> - allocates <mb> MB in 1 MB chunks (keeps them), prints
 * progress. Under an own-ram jail the allocations FAIL at the limit — the
 * app "glitches" like on a real PC with that little RAM. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: rameater <mb>\n"); return 2; }
    const int mb = atoi(argv[1]);
    char** keep = (char**)calloc((size_t)mb, sizeof(char*));
    if (!keep) { printf("alloc-failed at table\n"); return 3; }
    for (int i = 0; i < mb; i++) {
        keep[i] = (char*)malloc(1024 * 1024);
        if (!keep[i]) { printf("alloc-failed at %d MB\n", i); fflush(stdout); return 3; }
        memset(keep[i], 1, 1024 * 1024);
        printf("ram %d MB\n", i + 1);
        fflush(stdout);
    }
    printf("rameater done\n");
    fflush(stdout);
    sleep(2);
    return 0;
}
