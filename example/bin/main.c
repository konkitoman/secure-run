#include <stdio.h>
#include <sys/param.h>
#include <sys/ptrace.h>
#include <unistd.h>

int runningUnderDebugger() {
  static int isCheckedAlready = 0, underDebugger = 0;
  if (!isCheckedAlready) {
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
      underDebugger = 1;
    else
      ptrace(PTRACE_DETACH, 0, 1, 0);

    isCheckedAlready = 1;
  }
  return underDebugger;
}

const char *g_filename = "message.txt";

void file_read_and_dump(const char *filename) {
  FILE *file = fopen(filename, "r");
  char buffer[1024];
  size_t buffer_size;
  long size;

  if (!file) {
    printf("Cannot open file\n");
    return;
  }

  fseek(file, 0, SEEK_END);
  size = ftell(file);
  fseek(file, 0, SEEK_SET);

  while ((buffer_size = MIN(size, sizeof(buffer) / sizeof(*buffer))) &&
         fread(buffer, sizeof(*buffer), buffer_size, file)) {
    fwrite(buffer, sizeof(*buffer), buffer_size, stdout);
    size -= buffer_size;
  }
}

void child() {
  printf("This is the child, with the pid: %d, debugged: %d\n", getpid(), runningUnderDebugger());

  printf("Child tries to open %s\n", g_filename);
  file_read_and_dump(g_filename);
}

void parent(__pid_t pid) {
  printf("This is the Parent and the child pid is %d, debugged: %d\n", pid, runningUnderDebugger());

  printf("Parent tries to open %s\n", g_filename);
  file_read_and_dump(g_filename);
}

int main(void) {
  printf("Process started\n");

  int res = fork();

  if (res < 0) {
    printf("Cannot fork %d\n", res);
    return 0;
  }

  if (res == 0) {
    child();
  } else {
    parent(res);
  }
}
