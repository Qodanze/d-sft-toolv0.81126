/* echoline - reads a line from stdin and echoes it back. For input testing. */
#include <stdio.h>
#include <string.h>

int main(void)
{
    char name[256];
    printf("What is your name? ");
    fflush(stdout);
    if (!fgets(name, sizeof name, stdin)) return 1;
    name[strcspn(name, "\r\n")] = 0;
    printf("Hello, %s!\n", name);
    fflush(stdout);
    return 0;
}
