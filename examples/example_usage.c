/*
 * example_usage.c - libtdwarf usage example
 * 
 * Compile:
 *   gcc -g -O0 -std=gnu99 example_usage.c -o example_usage \
 *       -I../include -L../lib -ltdwarf -ldwarf -lelf
 *
 * Usage:
 *   ./example_usage dump <pid> [output_prefix]
 *   ./example_usage self
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "tdwarf.h"

static void print_usage(const char *prog)
{
    printf("Usage:\n");
    printf("  %s dump <pid> [output_prefix]  - Dump memory of process\n", prog);
    printf("  %s self                        - Dump self (with signal handlers)\n", prog);
    printf("\nExamples:\n");
    printf("  %s dump 12345\n", prog);
    printf("  %s dump 12345 myapp\n", prog);
    printf("  %s self\n", prog);
}

static int dump_process(pid_t pid, const char *prefix)
{
    tdwarf_context_t *ctx = NULL;
    tdwarf_config_t config;
    tdwarf_error_t err;
    char filename[256];
    
    /* Initialize library */
    err = tdwarf_init();
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", tdwarf_strerror(err));
        return 1;
    }
    
    /* Create context */
    err = tdwarf_context_create(pid, &ctx);
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to create context: %s\n", tdwarf_strerror(err));
        return 1;
    }
    
    printf("Target executable: %s\n", ctx->executable_path);
    
    /* Attach to process */
    err = tdwarf_attach(ctx);
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to attach: %s\n", tdwarf_strerror(err));
        tdwarf_context_destroy(ctx);
        return 1;
    }
    printf("Attached to process\n");
    
    /* Load debug info */
    err = tdwarf_load_debug_info(ctx);
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to load debug info: %s\n", tdwarf_strerror(err));
        tdwarf_detach(ctx);
        tdwarf_context_destroy(ctx);
        return 1;
    }
    printf("DWARF debug info loaded\n");
    
    /* Unwind stack and collect variables */
    err = tdwarf_unwind_stack(ctx);
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to unwind stack: %s\n", tdwarf_strerror(err));
        tdwarf_detach(ctx);
        tdwarf_context_destroy(ctx);
        return 1;
    }
    printf("Stack unwound: %d frames\n", ctx->frame_count);
    
    /* Configure output */
    tdwarf_config_default(&config);
    config.dump_globals = 1;
    config.dump_locals = 1;
    config.verbose = 1;
    
    /* Generate output filename */
    if (prefix && prefix[0]) {
        snprintf(filename, sizeof(filename), "%s_pid_%d.txt", prefix, pid);
    } else {
        snprintf(filename, sizeof(filename), "dump_pid_%d.txt", pid);
    }
    
    /* Write dump */
    err = tdwarf_dump_to_file(ctx, filename, &config);
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to write dump: %s\n", tdwarf_strerror(err));
    } else {
        printf("Dump written to: %s\n", filename);
    }
    
    /* Cleanup */
    tdwarf_detach(ctx);
    tdwarf_context_destroy(ctx);
    tdwarf_cleanup();
    
    return (err == TDWARF_OK) ? 0 : 1;
}

static int dump_self(void)
{
    tdwarf_error_t err;
    
    printf("Installing signal handlers...\n");
    
    err = tdwarf_init();
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", tdwarf_strerror(err));
        return 1;
    }
    
    err = tdwarf_install_signal_handlers(".");
    if (err != TDWARF_OK) {
        fprintf(stderr, "Failed to install handlers: %s\n", tdwarf_strerror(err));
        return 1;
    }
    
    printf("Signal handlers installed. PID: %d\n", getpid());
    printf("Send SIGSEGV to trigger dump: kill -SEGV %d\n", getpid());
    printf("Or press Ctrl+C to exit normally.\n\n");
    
    /* Loop until signal */
    while (1) {
        sleep(1);
        printf(".");
        fflush(stdout);
    }
    
    return 0;
}

int main(int argc, char *argv[])
{
    printf("libtdwarf Example Program\n");
    printf("Library version: %s\n\n", tdwarf_version());
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "dump") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Error: PID required\n");
            print_usage(argv[0]);
            return 1;
        }
        
        pid_t pid = atoi(argv[2]);
        const char *prefix = (argc > 3) ? argv[3] : NULL;
        
        printf("=== Dump Process %d ===\n", pid);
        return dump_process(pid, prefix);
        
    } else if (strcmp(argv[1], "self") == 0) {
        printf("=== Self Dump Mode ===\n");
        return dump_self();
        
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1]);
        print_usage(argv[0]);
        return 1;
    }
}
