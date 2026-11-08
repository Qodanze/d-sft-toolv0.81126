/* mmeater <mb> — eats memory via raw mmap, NOT malloc: proves whether the
 * "own ram sandbox" is a real kernel jail or just a malloc filter */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
int main(int argc, char** argv) {
    int mb = argc > 1 ? atoi(argv[1]) : 50;
    for (int i = 0; i < mb; i++) {
        char* p = (char*)mmap(NULL, 1024*1024, PROT_READ|PROT_WRITE,
                              MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) { printf("mmap FAILED at %d MB\n", i); return 3; }
        memset(p, 1, 1024*1024);
    }
    printf("mmap ate %d MB - JAIL DID NOT STOP IT\n", mb);
    return 0;
}
