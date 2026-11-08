/* cpueater <seconds> - burns CPU (busy loop) for <seconds> of wall time.
 * Under a terminate-mode CPU limit the whole tree gets killed mid-burn;
 * under an own-cpu jail it survives but throttled to N%. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static double mono_s(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

int main(int argc, char** argv)
{
    if (argc < 2) { fprintf(stderr, "usage: cpueater <seconds>\n"); return 2; }
    const int secs = atoi(argv[1]);
    const double start = mono_s();
    volatile double x = 0;
    while (mono_s() - start < (double)secs)
        for (int i = 0; i < 200000; i++) x += i * 0.5;
    printf("cpueater done (%d s)\n", secs);
    fflush(stdout);
    return 0;
}
