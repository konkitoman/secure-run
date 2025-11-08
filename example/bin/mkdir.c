#include <unistdio.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(){
  mkdirat(AT_FDCWD, "Testing", 0777);
}
