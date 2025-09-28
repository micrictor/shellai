#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#include <sys/ptrace.h>
#include <sys/wait.h>
#define _GNU_SOURCE // Required for RTLD_DEFAULT and RTLD_NEXT
#include <dlfcn.h>


int main(int argc, char *argv[]) {
  if(argc < 2) {
    fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
    exit(1);
  }

  pid_t pid = atol(argv[1]);

  if(ptrace(PTRACE_ATTACH, pid, 0, 0) < 0) {
    fprintf(stderr, "Error attaching: %d\n", errno);
    exit(1);
  }

  // Wait for the attach to complete
  int status;
  waitpid(pid, &status, WSTOPPED);

  printf("Done!\n");

  void* handle = dlopen(NULL, RTLD_LAZY);
  void *addr = dlsym(handle, "rl_insert_text");
  fprintf(stderr, "Address of rl_insert_text: %p\n", addr);

  ptrace(PTRACE_DETACH, pid, 0, 0);

  return 0;
}