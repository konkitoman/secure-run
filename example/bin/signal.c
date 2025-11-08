#include <stdio.h>
#include <unistd.h>
#include <signal.h>

int send_pipe;

void on_sigstop(int signal){
  printf("Received signal %d\n", signal);

  write(send_pipe, "R", 1);
}

int main(){
  int pipes[2];
  signal(SIGCHLD, on_sigstop);

  pipe(pipes);

  send_pipe = pipes[1];
  printf("Waiting for SIGCHLD...\n");
  char b;
  read(pipes[0], &b, 1);
  printf("Received %c\n", b);
}
