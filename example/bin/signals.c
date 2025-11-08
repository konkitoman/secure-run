#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int send_pipe;

char buffer[1];

void handle_signal(int sig) {
  printf("%d: Signal received: %d\n", getpid(), sig);

  write(send_pipe, "W", 1);
}

int child(int parent) {
  int pid = getpid();
  int pipes[2];

  puts("Child:");
  pid = getpid();

  if (pipe(pipes) == -1) {
    fprintf(stderr, "%d: Chlid, cannot create pipe: %s\n", pid,
            strerror(errno));
    return 3;
  }
  send_pipe = pipes[1];
  if (signal(SIGUSR1, handle_signal) == SIG_ERR) {
    fprintf(stderr, "%d: Cannot hook SIGUSR1: %s!\n", pid, strerror(errno));
    return 4;
  }

  if (write(parent, "W", 1) == -1) {
    fprintf(stderr, "%d: Cannot write to pipe %d: %s\n", pid, parent,
            strerror(errno));
    abort();
  }

  printf("%d: Wait for SIGUSR1...\n", pid);
  if (read(pipes[0], buffer, 1) == -1) {
    fprintf(stderr, "%d: Cannot read from pipe %d: %s\n", pid, pipes[0],
            strerror(errno));
    abort();
  }

  printf("%d: Received!\n", pid);
  if (write(parent, "W", 1) == -1) {
    fprintf(stderr, "%d: Cannot write to pipe %d: %s\n", pid, parent,
            strerror(errno));
    abort();
  }

  return 0;
}

int parent(pid_t child, int from_child) {
  int pid;
  struct pollfd fds[1];

  puts("Parent:");

  pid = getpid();
  fds[0].fd = from_child;
  fds[0].events = POLLIN;
  printf("%d: Parent with child: %d\n", pid, child);
  printf("%d: Waiting for child to initialize...\n", pid);

  switch (poll(fds, 1, 1000)) {
  case 0:
    fprintf(stderr, "%d: Timeout!\n", pid);
    return 4;
  case -1:
    fprintf(stderr, "%d: POLL ERROR: %s\n", pid, strerror(errno));
    return 5;
  }
  if (read(fds[0].fd, buffer, 1) == -1) {
    fprintf(stderr, "%d: Cannot read from pipe %d: %s\n", pid, fds[0].fd,
            strerror(errno));
    abort();
  }
  printf("%d: Child was initialized!\n", pid);

  if (kill(child, SIGUSR1) == -1) {
    fprintf(stderr, "%d: Cannot send signal: %s\n", pid, strerror(errno));
    return 6;
  }

  printf("%d: Wait for child to receive signal...\n", pid);

  switch (poll(fds, 1, 1000)) {
  case 0:
    fprintf(stderr, "%d: Timeout!\n", pid);
    return 7;
  case -1:
    fprintf(stderr, "%d: POLL ERROR: %s\n", pid, strerror(errno));
    return 8;
  }
  if (read(fds[0].fd, buffer, 1) == -1) {
    fprintf(stderr, "%d: Cannot read from pipe %d: %s\n", pid, from_child,
            strerror(errno));
    abort();
  }

  printf("%d: Child received signal!\n", pid);

  return 0;
}

int main() {
  int pipes[2];
  int pid;

  puts("Process started");
  if (pipe(pipes) == -1) {
    fprintf(stderr, "%d: Cannot create pipe: %s\n", getpid(), strerror(errno));
    return 1;
  }

  pid = fork();
  switch (pid) {
  case -1:
    fprintf(stderr, "%d: Cannot fork %s\n", getpid(), strerror(errno));
    return 2;
  case 0:
    return child(pipes[1]);
  default:
    return parent(pid, pipes[0]);
  }
}
