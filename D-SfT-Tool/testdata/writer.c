/* writer <path> <mb> - writes <mb> megabytes of zeros to <path> (stdio path,
 * so the shim's close()-based accounting gets exercised too). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char** argv)
{
    if (argc < 3) { fprintf(stderr, "usage: writer <path> <mb>\n"); return 2; }
    const int mb = atoi(argv[2]);
    FILE* f = fopen(argv[1], "wb");
    if (!f) { perror("fopen"); return 1; }
    static char buf[65536];
    memset(buf, 0, sizeof buf);
    for (int i = 0; i < mb; i++) {
        for (int chunk = 0; chunk < (1024 * 1024) / (int)sizeof buf; chunk++) {
            if (fwrite(buf, 1, sizeof buf, f) != sizeof buf) {
                fprintf(stderr, "write stopped at %d MB (%s)\n", i, strerror(errno));
                fclose(f);
                return 1;
            }
        }
        printf("wrote %d MB\n", i + 1);
        fflush(stdout);
    }
    fclose(f);
    printf("writer done\n");
    return 0;
}
