#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <unistd.h>

#define longs long*

const char* syscall_names[] = {"open", "read", "write", "close", "lseek", "stat", "fchmod", "fchown", "truncate", "fork", "execve", "waitpid", "exit", "getpid", "getppid", "setsid", "getpgrp", "socket", "connect", "bind", "listen", "accept", "send", "recv", "shutdown", "brk", "mmap", "munmap", "sbrk", "ioctl", "getuid", "geteuid", "uname", "sysinfo", "getrusage", "time", "gettimeofday", "sleep", "nanosleep", "signal", "kill", "access", "chmod", "chown", "getegid", "getegid", "setgid", "getgroups", "setgroups", "capget", "capset", "ipcget", "ipcset", "msgget", "msgsnd", "msgrcv", "semget", "semop", "semctl", "shmget", "shmat", "shmdt", "shmctl", "flock", "fcntl", "sync", "fsync", "fdatasync", "getdents", "getcwd", "chdir", "fchdir", "mount", "umount", "pivot_root", "chroot", "mkdir", "rmdir", "link", "unlink", "symlink", "readlink", "rename", "realpath", "statfs", "fstatfs", "getxattr", "setxattr", "lgetxattr", "lsetxattr", "fgetxattr", "fsetxattr", "listxattr", "llistxattr", "removexattr", "lremovexattr", "fremovexattr", "getcwd", "chdir", "fchdir", "dup", "dup2", "pipe", "pipe2", "poll", "select", "epoll_create", "epoll_ctl", "epoll_wait", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "read", "write", "close", "lseek", "stat", "mmap", "munmap", "brk", "ioctl", "pread", "pwrite", "sendfile", "msync", "madvise", "mincore", "mlock", "munlock", "mlockall", "munlockall", "mprotect", "mprotect", "madvise", "mincore", "mlock", "munlock", "mlockall", "munlockall", "mremap", "vmsplice", "move_pages", "getcpu", "epoll_wait", "utimes", "fallocate", "ftruncate", "fallocate", "renameat", "linkat", "symlinkat", "unlinkat", "mkdirat", "rmdirat", "mknodat", "fchownat", "fchownat", "fchmodat", "fchmodat", "sethuid", "setgid", "setresuid", "setresgid", "getresuid", "getresgid", "setfsuid", "setfsgid", "getfsuid", "getfsgid", "setuid", "setgid", "geteuid", "getegid", "getgid", "setuid", "setgid", "getuid", "geteuid", "getegid", "getgid", "capget", "capset", "rt_sigaction", "rt_sigqueueinfo", "rt_sigpending", "rt_sigtimedwait", "sigaction", "sigpending", "sigfillset", "sigisemptyset", "sigaddset", "sigdelset", "sigprocmask", "sigsuspend", "sigaltstack", "pause", "nanosleep", "clock_gettime", "clock_getres", "clock_settime", "timer_create", "timer_delete", "timer_getoverrun", "timer_gettime", "timer_settime", "timerfd_create", "timerfd_settime", "timerfd_gettime", "clock_nanosleep", "timer_modify", "clock_nanosleep", "getitimer", "setitimer", "alarm", "setitimer", "getitimer", "getitimer", "setitimer", "getitimer", "getitimer", "setitimer", "getitimer", "getitimer", "setitimer", "getitimer", "getitimer", "setitimer", "alarm", "u
};

int main(int argc, char *argv[]) {
  if (argc != 2) {
    printf("Usage: %s <target_program>\n", argv[0]);
    return 1;
  }

  pid_t child_pid = fork();

  if (child_pid < 0) {
    perror("fork failed");
    return 1;
  }

  if (child_pid == 0) {
    printf("I am the child process (PID: %d)\n", getpid());
    // Will be replaced with actual program on which the system calls will be traced.
    open("test.txt", O_CREAT);
    write(1, "Hello World!\n", 13);
    exit(0);
  } else {
    longs regs;
    int status;
    int syscall_count = sizeof(syscall_names) / sizeof(syscall_names[0]);

    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    waitpid(child_pid, &status, 0);

    while (WIFSTOPPED(status)) {
      ptrace(PTRACE_GETREGS, child_pid, NULL, &regs);

      // Check if a valid system call was made (orig_rax >= 0)
      if (regs->orig_rax >= 0 && regs->orig_rax < syscall_count) {
        printf("Traced system call: %s\n", syscall_names[regs->orig_rax]);
      } else {
        printf("Traced unknown system call: %ld\n", regs->orig_rax);
      }
      ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
      waitpid(child_pid, &status, 0);
    }

    ptrace(PTRACE_DETACH, child_pid, NULL, NULL);
  }

  return 0;
}
