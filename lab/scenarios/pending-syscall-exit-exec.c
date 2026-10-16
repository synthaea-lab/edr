// Exercises the non-leader exec scenario from #694: the leader blocks in accept
// while a worker waits until that syscall is visible, then execs a fresh image.
#define _GNU_SOURCE
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

struct worker_args {
    pid_t process_id;
    pid_t leader_tid;
};

static void *exec_worker(void *opaque) {
    const struct worker_args *args = opaque;
    char proc_path[128];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/task/%d/syscall",
             args->process_id, args->leader_tid);
    const struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    for (unsigned attempt = 0; attempt < 1000; ++attempt) {
        FILE *file = fopen(proc_path, "r");
        if (file != NULL) {
            long syscall_nr = -1;
            int scanned = fscanf(file, "%ld", &syscall_nr);
            fclose(file);
            if (scanned == 1 && syscall_nr == SYS_accept) {
                char *const argv[] = {"true", NULL};
                char *const envp[] = {"PATH=/usr/bin:/bin", NULL};
                execve("/bin/true", argv, envp);
                perror("execve /bin/true");
                return (void *)1;
            }
        }
        nanosleep(&pause, NULL);
    }
    fprintf(stderr, "leader never entered accept (proc path: %s)\n", proc_path);
    return (void *)1;
}

int main(void) {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) {
        perror("socket");
        return 1;
    }
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = 0,
    };
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 ||
        listen(listener, 1) < 0) {
        perror("bind/listen");
        close(listener);
        return 1;
    }

    struct worker_args args = {
        .process_id = getpid(),
        .leader_tid = (pid_t)syscall(SYS_gettid),
    };
    pthread_t worker;
    int error = pthread_create(&worker, NULL, exec_worker, &args);
    if (error != 0) {
        errno = error;
        perror("pthread_create");
        close(listener);
        return 1;
    }

    printf("pid=%d leader_tid=%d: waiting for accept, worker will exec /bin/true\n",
           args.process_id, args.leader_tid);
    fflush(stdout);
    (void)accept(listener, NULL, NULL);
    // Normally unreachable: exec replaces the process after the blocked leader
    // is interrupted. If accept returns first, expose the unexpected condition.
    fprintf(stderr, "accept returned before worker exec: %s\n", strerror(errno));
    return 2;
}
