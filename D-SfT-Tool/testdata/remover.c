/* remover - creates a file, writes to it, then deletes it.
 * Exercises create + delete (rm) detection. */
#include <stdio.h>

int main(int argc, char** argv)
{
    const char* path = (argc > 1) ? argv[1] : "victim.txt";
    FILE* f = fopen(path, "w");
    if (!f) { perror("fopen"); return 1; }
    fputs("to be deleted", f);
    fclose(f);
    printf("created %s\n", path);
    if (remove(path) != 0) { perror("remove"); return 1; }
    printf("removed %s\n", path);
    return 0;
}
