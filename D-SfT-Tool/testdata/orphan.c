/* orphan - exits 0 while leaving a setsid'd child alive on screen.
 * Classic "already said exit code 0 but the app is still on the screen" case. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void)
{
    pid_t pid = fork();
    if (pid == 0) {
        setsid();                       /* escape the process group */
        execl("/bin/sleep", "sleep", "60", (char*)NULL);
        _exit(127);
    }
    printf("orphan parent done\n");
    return 0;
}
