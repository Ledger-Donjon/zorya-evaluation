#include <stdlib.h>
#include <stddef.h>  
#include <stdint.h>  
#include <asm/unistd.h> 
#include <stdarg.h>  

static int global_var = 0;

// Function to perform system calls directly
static long syscall(long number, ...) {
    va_list args;
    va_start(args, number);
    long ret;
    register long r10 __asm__("r10") = va_arg(args, long);
    register long r8  __asm__("r8")  = va_arg(args, long);
    register long r9  __asm__("r9")  = va_arg(args, long);

    __asm__ volatile (
        "syscall"
        : "=a" (ret)
        : "a" (number), "D" (va_arg(args, long)), "S" (va_arg(args, long)), "d" (va_arg(args, long)), "r" (r10), "r" (r8), "r" (r9)
        : "memory"
    );
    va_end(args);
    return ret;
}

// Exit system call
static void nolibc_exit(int code) {
    syscall(__NR_exit, code);
}

// main function
int main();

// Entry point
void _start() {
    int ret = main();
    nolibc_exit(ret);
}

static void do_something(int *variable) {
    if (global_var != 0) {
        *variable = 42;
    }
}

int main(void) {
    int var;
    do_something(&var);
    return var * 2;
}
