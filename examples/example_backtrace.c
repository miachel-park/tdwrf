#include <stdio.h>
#include <stdlib.h>
#include <execinfo.h> // Required for backtrace
#include <unistd.h>   // Required for STDOUT_FILENO

/*
 * This function obtains the current call stack and prints it to the console.
 */
void print_stack_trace(void) {
    void *buffer[128]; // Buffer to store stack frame addresses
    int nptrs;         // Number of stack frames captured
    char **strings;    // Array of strings containing symbol information

    // Get the backtrace
    nptrs = backtrace(buffer, 128);
    printf("backtrace() returned %d addresses\n", nptrs);

    // backtrace_symbols() allocates memory for an array of strings
    // which must be freed by the caller. It returns human-readable
    // function names, offsets, and addresses.
    // Note: For this to work well, the program should be compiled with
    // -g (for debug symbols) and linked with -rdynamic.
    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        perror("backtrace_symbols");
        exit(EXIT_FAILURE);
    }

    printf("--- Call Stack ---\n");
    // backtrace_symbols_fd(buffer, nptrs, STDOUT_FILENO); // Alternative direct print
    for (int i = 0; i < nptrs; i++) {
        printf("%s\n", strings[i]);
    }
    printf("------------------\n");

    // Free the memory allocated by backtrace_symbols()
    free(strings);
}

// A simple function to deepen the call stack
void func_b(void) {
    printf("Inside func_b. Now printing stack trace...\n");
    print_stack_trace();
}

// Another function in the call chain
void func_a(void) {
    printf("Inside func_a, calling func_b.\n");
    func_b();
}

int main() {
    printf("Starting main, calling func_a.\n");
    func_a();
    printf("Back in main. Program finished.\n");
    return 0;
}
