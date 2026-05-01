#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>

#define NB_CHILDREN         100   // number of child processes to create
#define MAX_SLEEP_MS        500   // maximum sleep between forks, in milliseconds

const static int SLEEP_WORKLOAD_SECONDS = 10;

int main(void) {
    srand(time(NULL));

    pid_t main_pid = getpid();
    printf("Main process PID %d starting, creating %d children\n", main_pid, NB_CHILDREN);

    for (int i = 0; i < NB_CHILDREN; i++) {
        pid_t pid = fork();

        if (pid < 0) {
            perror("fork failed");
            exit(1);
        }

        if (pid == 0) {
            // Child process
            printf("- Child process created with PID %d (parent %d)\n",
                   getpid(), getppid());
            // Simulate workload to keep the process alive
            sleep(SLEEP_WORKLOAD_SECONDS);
            exit(0);
        }

        // Parent process: sleep for a random duration before the next fork
        int sleep_ms = rand() % (MAX_SLEEP_MS + 1);
        usleep(sleep_ms * 1000);
    }

    printf("Main process PID %d waiting for children to finish...\n", main_pid);
    while (wait(NULL) > 0);

    return 0;
}
