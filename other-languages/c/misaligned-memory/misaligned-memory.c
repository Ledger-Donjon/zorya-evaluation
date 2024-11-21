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

int main() {
    uint64_t value = 0x1122334455667788;  // A 64-bit value
    uint8_t *ptr = (uint8_t *)&value;     // Byte pointer to the value
    uint32_t *misaligned = (uint32_t *)(ptr + 1); // Misaligned pointer (offset by 1 byte)

    uint32_t result = *misaligned;       // Undefined behavior: misaligned memory access
    (void)result;                        // Suppress unused variable warning

    return 0;
}
