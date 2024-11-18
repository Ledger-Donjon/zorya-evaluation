#include <stddef.h>  
#include <stdint.h>  
#include <asm/unistd.h> 
#include <stdarg.h>  

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

void vulnerableFunction(char *input) {
    char buffer[10];

    // Manual copy without bounds checking
    int i = 0;
    while (input[i] != '\0') {
        buffer[i] = input[i]; // No bounds checking here
        i++;
    }
    buffer[i] = '\0'; // Null-terminate the string (still allows overflow)
}

int main() {
    char input[] = "AAAAAAAAAAAAAAAAAA"; 
    vulnerableFunction(input);
    return 0;
}
