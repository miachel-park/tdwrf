# libtdwarf - DWARF-based Memory Dump Library

A C library for dumping process memory with variable names and values using DWARF debug information on Linux.

## Features

- **Global Variable Dump**: Automatically collects all global variables with names, types, and values
- **Local Variable Dump**: Collects local variables from each stack frame
- **Type-aware Formatting**: Displays values based on their actual types (int, double, char[], struct, etc.)
- **PIE Support**: Automatically detects and handles Position Independent Executables (PIE/non-PIE)
- **Stack Unwinding**: Traces function call stack using frame pointer chain
- **Signal Handlers**: Install automatic dump on crash (SIGSEGV, SIGBUS, etc.)
- **RHEL 7 Compatible**: Works with GCC 4.8.5 and older systems

## Requirements

- Linux (kernel 3.2+ for `process_vm_readv`)
- GCC with C99 support
- libelf (from elfutils)
- libdwarf (0.4.1+ recommended)

### Installing Dependencies

**RHEL/CentOS 7:**
```bash
sudo yum install elfutils-libelf-devel

# Build libdwarf from source
wget https://github.com/davea42/libdwarf-code/releases/download/v0.4.1/libdwarf-0.4.1.tar.xz
tar xf libdwarf-0.4.1.tar.xz
cd libdwarf-0.4.1
./configure --prefix=/usr/local
make && sudo make install
sudo ldconfig
```

**Ubuntu/Debian:**
```bash
sudo apt install libelf-dev libdwarf-dev
```

## Building

```bash
git clone https://github.com/jeiths2202/tdwrf.git
cd tdwrf

# Build library
make

# Build examples
make examples
```

## Quick Start

### 1. Compile your target program with debug symbols

```bash
gcc -g -O0 -fno-omit-frame-pointer your_program.c -o your_program
```

### 2. Run the target program

```bash
./examples/sample_target 10 &
PID=$!
```

### 3. Dump its memory

```bash
export LD_LIBRARY_PATH=./lib:$LD_LIBRARY_PATH
./examples/example_usage dump $PID
cat dump_pid_${PID}.txt
```

## Output Example

```
================================================================================
TDWARF Memory Dump Report
================================================================================
Timestamp:   2025-01-15 10:30:45
Process ID:  12345
Executable:  /path/to/sample_target
PIE:         No
Load Offset: 0x0000000000000000
================================================================================

GLOBAL VARIABLES (9 found)
--------------------------------------------------------------------------------
Name                             Type                     Address            Value
--------------------------------------------------------------------------------
g_counter                        int                      0x00000000006020A0 12345 (0x00003039)
g_pi                             double                   0x00000000006020A8 3.141593
g_message                        char[]                   0x00000000006020C0 "Hello, TDWARF Memory Dump!"
g_array                          int[]                    0x0000000000602100 10, 20, 30, 40...
g_person                         struct Person            0x0000000000602140 ...
  Hex dump (48 bytes):
    0000: E9 03 00 00 54 61 6E 61 6B 61 20 54 61 72 6F 00
    ...

STACK TRACE (3 frames)
--------------------------------------------------------------------------------

Frame #0: process_data
  PC: 0x0000000000400ABC  SP: 0x00007FFF12345600  BP: 0x00007FFF12345620

  LOCAL VARIABLES (6 found):
  Name                           Type                     Address            Value
  ----------------------------------------------------------------------------
  local_int                      int                      0x00007FFF1234561C 200 (0x000000C8)
  local_double                   double                   0x00007FFF12345610 3.000000
  local_buffer                   char[]                   0x00007FFF12345590 "Iteration 2: counter=12347..."
  iteration                      int                      0x00007FFF1234558C 2 (0x00000002)

Frame #1: main
  PC: 0x0000000000400DEF  SP: 0x00007FFF12345640  BP: 0x00007FFF12345700
  ...

================================================================================
End of TDWARF Memory Dump Report
================================================================================
```

## API Reference

### Initialization

```c
#include "tdwarf.h"

tdwarf_error_t tdwarf_init(void);
void tdwarf_cleanup(void);
const char* tdwarf_version(void);
```

### Context Management

```c
tdwarf_error_t tdwarf_context_create(pid_t pid, tdwarf_context_t **ctx);
void tdwarf_context_destroy(tdwarf_context_t *ctx);
```

### Process Attachment

```c
tdwarf_error_t tdwarf_attach(tdwarf_context_t *ctx);
tdwarf_error_t tdwarf_detach(tdwarf_context_t *ctx);
```

### Debug Information

```c
tdwarf_error_t tdwarf_load_debug_info(tdwarf_context_t *ctx);
tdwarf_error_t tdwarf_unwind_stack(tdwarf_context_t *ctx);
```

### Output

```c
tdwarf_error_t tdwarf_dump_to_file(tdwarf_context_t *ctx,
                                    const char *filename,
                                    const tdwarf_config_t *config);
tdwarf_error_t tdwarf_dump_to_stream(tdwarf_context_t *ctx,
                                      FILE *stream,
                                      const tdwarf_config_t *config);
```

### Signal Handlers

```c
tdwarf_error_t tdwarf_install_signal_handlers(const char *output_dir);
void tdwarf_remove_signal_handlers(void);
```

## Configuration Options

```c
typedef struct tdwarf_config {
    int dump_globals;     /* Dump global variables (default: 1) */
    int dump_locals;      /* Dump local variables (default: 1) */
    int dump_heap;        /* Dump heap allocations - future (default: 0) */
    int max_depth;        /* Maximum struct/array depth (default: 3) */
    int hex_uppercase;    /* Use uppercase hex (default: 1) */
    int include_source;   /* Include source file info (default: 1) */
    int verbose;          /* Verbose output with hex dumps (default: 1) */
} tdwarf_config_t;

tdwarf_config_default(&config);  /* Initialize with defaults */
```

## How It Works

1. **Attach to Process**: Uses `ptrace(PTRACE_ATTACH)` to stop the target process
2. **PIE Detection**: Checks ELF header (`ET_EXEC` vs `ET_DYN`) to determine address calculation method
3. **DWARF Parsing**: Uses libdwarf to parse `.debug_info` section for variable information
4. **Location Expression**: Interprets DWARF location expressions:
   - `DW_OP_addr`: Global variables (absolute address)
   - `DW_OP_fbreg`: Local variables (frame base + offset)
5. **Memory Reading**: Reads process memory via `/proc/<pid>/mem` or `process_vm_readv`
6. **Stack Unwinding**: Follows frame pointer chain (RBP) to trace call stack
7. **Type Formatting**: Formats values based on DWARF type information

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        libtdwarf                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │  ptrace  │───▶│   libdwarf   │───▶│   Memory     │          │
│  │  Attach  │    │   Parsing    │    │   Reading    │          │
│  └──────────┘    └──────────────┘    └──────────────┘          │
│       │                 │                   │                   │
│       ▼                 ▼                   ▼                   │
│  ┌──────────┐    ┌──────────────┐    ┌──────────────┐          │
│  │ Process  │    │   Variable   │    │    Value     │          │
│  │ Control  │    │   Location   │    │   Extraction │          │
│  └──────────┘    └──────────────┘    └──────────────┘          │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Limitations

- Requires debug symbols (`-g` flag when compiling target)
- Best results with `-O0` (no optimization) and `-fno-omit-frame-pointer`
- Local variables in optimized code may be in registers (not readable)
- Does not support multi-threaded variable resolution yet

## Troubleshooting

### "No DWARF information found"
- Ensure target is compiled with `-g` flag
- Check: `readelf --debug-dump=info target | head`

### "Failed to attach"
- Check permissions: `echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope`
- Or run as root

### Local variables not showing
- Compile target with `-fno-omit-frame-pointer`
- Use `-O0` to prevent optimizations

## License

MIT License - See LICENSE file for details.

## Author

Created by jeiths2202

## Contributing

Pull requests are welcome. For major changes, please open an issue first.
