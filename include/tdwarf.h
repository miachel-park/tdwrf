/*
 * libtdwarf - DWARF-based Memory Dump Library
 * Header file with local variable support
 */

#ifndef TDWARF_H
#define TDWARF_H

#include <stdint.h>
#include <stdio.h>
#include <signal.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Version information */
#define TDWARF_VERSION_MAJOR 1
#define TDWARF_VERSION_MINOR 1
#define TDWARF_VERSION_PATCH 0

/* Limits */
#define TDWARF_MAX_FRAMES      64
#define TDWARF_MAX_VARS        256
#define TDWARF_MAX_NAME_LEN    256
#define TDWARF_MAX_TYPE_LEN    128
#define TDWARF_MAX_DUMP_SIZE   4096

/* Error codes */
typedef enum {
    TDWARF_OK               =  0,
    TDWARF_ERR_INVALID_ARG  = -1,
    TDWARF_ERR_NO_MEMORY    = -2,
    TDWARF_ERR_OPEN_FAILED  = -3,
    TDWARF_ERR_NO_DWARF     = -4,
    TDWARF_ERR_PTRACE       = -5,
    TDWARF_ERR_READ_MEM     = -6,
    TDWARF_ERR_FILE_IO      = -7,
    TDWARF_ERR_NO_DEBUG     = -8,
    TDWARF_ERR_INTERNAL     = -9
} tdwarf_error_t;

/* Type kinds */
typedef enum {
    TDWARF_TYPE_UNKNOWN = 0,
    TDWARF_TYPE_INT,
    TDWARF_TYPE_UINT,
    TDWARF_TYPE_FLOAT,
    TDWARF_TYPE_DOUBLE,
    TDWARF_TYPE_CHAR,
    TDWARF_TYPE_POINTER,
    TDWARF_TYPE_ARRAY,
    TDWARF_TYPE_STRUCT,
    TDWARF_TYPE_UNION,
    TDWARF_TYPE_ENUM
} tdwarf_type_kind_t;

/* Variable information */
typedef struct tdwarf_var {
    char name[TDWARF_MAX_NAME_LEN];
    char type_name[TDWARF_MAX_TYPE_LEN];
    uint64_t address;
    size_t size;
    uint8_t data[TDWARF_MAX_DUMP_SIZE];
    size_t data_len;
    int is_local;
    int frame_level;
    tdwarf_type_kind_t type_kind;

    /* 구조체 멤버 정보 */
    struct tdwarf_var *members;
    int member_count;
    int member_capacity;
} tdwarf_var_t;

/* Stack frame information */
typedef struct tdwarf_frame {
    uint64_t pc;                              /* Program counter */
    uint64_t sp;                              /* Stack pointer */
    uint64_t bp;                              /* Base pointer / Frame pointer */
    int frame_level;
    char function_name[TDWARF_MAX_NAME_LEN];
    char source_file[512];
    int line_number;
    tdwarf_var_t *variables;                  /* Local variables array */
    int var_count;
    int var_capacity;                         /* Capacity of variables array */
} tdwarf_frame_t;

/* Configuration options */
typedef struct tdwarf_config {
    int dump_globals;     /* Dump global variables */
    int dump_locals;      /* Dump local variables */
    int dump_heap;        /* Dump heap allocations (future) */
    int max_depth;        /* Maximum struct/array depth */
    int hex_uppercase;    /* Use uppercase hex */
    int include_source;   /* Include source file info */
    int verbose;          /* Verbose output with hex dumps */
} tdwarf_config_t;

/* Main context */
typedef struct tdwarf_context {
    pid_t target_pid;
    char executable_path[1024];
    void *dwarf_handle;                       /* Internal DWARF data */
    tdwarf_frame_t frames[TDWARF_MAX_FRAMES];
    int frame_count;
    int signal_number;
    int attached;
    FILE *output_file;
} tdwarf_context_t;

/*
 * Library initialization and cleanup
 */
tdwarf_error_t tdwarf_init(void);
void tdwarf_cleanup(void);
const char* tdwarf_version(void);
const char* tdwarf_strerror(tdwarf_error_t err);

/*
 * Configuration
 */
void tdwarf_config_default(tdwarf_config_t *config);

/*
 * Context management
 */
tdwarf_error_t tdwarf_context_create(pid_t pid, tdwarf_context_t **ctx);
void tdwarf_context_destroy(tdwarf_context_t *ctx);

/*
 * Process attachment
 */
tdwarf_error_t tdwarf_attach(tdwarf_context_t *ctx);
tdwarf_error_t tdwarf_detach(tdwarf_context_t *ctx);

/*
 * Debug information
 */
tdwarf_error_t tdwarf_load_debug_info(tdwarf_context_t *ctx);

/*
 * Memory operations
 */
tdwarf_error_t tdwarf_read_memory(tdwarf_context_t *ctx, 
                                   uint64_t addr, 
                                   void *buf, 
                                   size_t len);

/*
 * Stack unwinding and variable resolution
 */
tdwarf_error_t tdwarf_unwind_stack(tdwarf_context_t *ctx);
tdwarf_error_t tdwarf_resolve_variables(tdwarf_context_t *ctx, int frame_index);

/*
 * Output functions
 */
tdwarf_error_t tdwarf_dump_to_stream(tdwarf_context_t *ctx,
                                      FILE *stream,
                                      const tdwarf_config_t *config);
tdwarf_error_t tdwarf_dump_to_file(tdwarf_context_t *ctx,
                                    const char *filename,
                                    const tdwarf_config_t *config);

/*
 * Formatting utilities
 */
int tdwarf_format_hex(const uint8_t *data, size_t len,
                      char *buf, size_t buf_size,
                      int uppercase);

/*
 * Signal handling
 */
tdwarf_error_t tdwarf_install_signal_handlers(const char *output_dir);
void tdwarf_remove_signal_handlers(void);
tdwarf_error_t tdwarf_dump_on_signal(int signum, const char *output_path);

#ifdef __cplusplus
}
#endif

#endif /* TDWARF_H */
