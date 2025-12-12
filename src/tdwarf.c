/*
 * libtdwarf - DWARF-based Memory Dump Library
 * Version with local variable support for RHEL 7
 * Compatible with GCC 4.8.5
 */

#define _GNU_SOURCE
#include "tdwarf.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/uio.h>

#include <execinfo.h> // Required for backtrace
#include <libelf.h>
#include <gelf.h>
#include <libdwarf/dwarf.h>
#include <libdwarf/libdwarf.h>

/* Enable debug output */
#define TDWARF_DEBUG 1

#if TDWARF_DEBUG
#define DEBUG_PRINT(fmt, ...) fprintf(stderr, "[TDWARF DEBUG] " fmt "\n", ##__VA_ARGS__)
#else
#define DEBUG_PRINT(fmt, ...)
#endif

/* Internal structures */
typedef struct tdwarf_internal {
    Dwarf_Debug dbg;
    Elf *elf;
    int fd;
    Dwarf_Error error;
    /* Global variables collected */
    tdwarf_var_t *global_vars;
    int global_var_count;
    int global_var_capacity;
    /* PIE load address offset */
    uint64_t load_address;
    /* Is executable PIE? */
    int is_pie;
} tdwarf_internal_t;

/* Global state for signal handling */
static char g_output_dir[1024] = ".";
static struct sigaction g_old_handlers[32];
static int g_handlers_installed = 0;

/* Library initialization state */
static int g_initialized = 0;

/* Error messages */
static const char* error_messages[] = {
    "Success",
    "Invalid argument",
    "Memory allocation failed",
    "Failed to open file",
    "No DWARF information found",
    "Ptrace operation failed",
    "Failed to read memory",
    "File I/O error",
    "No debug information available",
    "Internal error"
};


static tdwarf_error_t self_backtrace(tdwarf_context_t *ctx)
{
    if ( !ctx ) {
        return TDWARF_ERR_INVALID_ARG;
    }

    // 함수 호출시 저장된 return address를 획득 하기 위해 backtrace 사용 
    void* buffer[TDWARF_MAX_FRAMES];
    int nptrs = backtrace(buffer, TDWARF_MAX_FRAMES);
    
    if (nptrs <= 0) {
        return TDWARF_ERR_INTERNAL;
    }

    ctx->frame_count = nptrs;

    // 함수 이름 문자열로 변환
    char **symbols = backtrace_symbols(buffer, nptrs);
    if (symbols == NULL) {
        return TDWARF_ERR_INTERNAL;
    }

    // 프레임 정보 채우기
    for ( int i = 0; i < nptrs; i++ ) {
        tdwarf_frame_t *frame = &ctx->frames[i];
        frame->pc = (uint64_t)(uintptr_t)buffer[i]; // 프로그램 카운터 설정
        frame->frame_level = i;

        // BS, SP는 설정 불가
        frame->sp = 0;
        frame->bp = 0;

        snprintf(frame->function_name, TDWARF_MAX_NAME_LEN, "%s", symbols[i]);
    }
    
    free(symbols);

    return TDWARF_OK;
}

static tdwarf_error_t backtrace_with_ptrace(tdwarf_context_t *ctx)
{
    struct user_regs_struct regs;
    
    if ( !ctx ) {
        return TDWARF_ERR_INVALID_ARG;
    }

    if ( ptrace(PTRACE_GETREGS, ctx->target_pid, NULL, &regs) < 0 ) {
        DEBUG_PRINT("ptrace GETREGS failed: %s", strerror(errno));
        return TDWARF_ERR_PTRACE;
    }

    ctx->frame_count = 0;

#if defined(__x86_64__)
    {
        uint64_t pc = regs.rip;
        uint64_t sp = regs.rsp;
        uint64_t bp = regs.rbp;
#elif defined(__i386__)
    {
        uint64_t pc = regs.eip;
        uint64_t sp = regs.esp;
        uint64_t bp = regs.ebp;
#elif defined(__aarch64__)
    {
        uint64_t pc = regs.pc;
        uint64_t sp = regs.sp;
        uint64_t bp = regs.regs[29];
#else
    {
        uint64_t pc = 0;
        uint64_t sp = 0;
        uint64_t bp = 0;
#endif

        DEBUG_PRINT("Initial registers: PC=0x%lX, SP=0x%lX, BP=0x%lX", 
            (unsigned long)pc, (unsigned long)sp, (unsigned long)bp);
        
        while( ctx->frame_count < TDWARF_MAX_FRAMES && bp != 0 && pc != 0) {
            uint64_t next_bp = 0;
            uint64_t next_pc = 0;
            tdwarf_frame_t *frame = &ctx->frames[ctx->frame_count];

            // --- 1. 유효성 검사: 주소 범위 유효성 ---
            // (BP, PC가 널이 아닌) 64비트 시스템에서 주소가 너무 크거나(커널 영역이나 유효 범위 밖), 
            // 너무 작아(0에 가까워) 비정상적인 경우를 검사합니다.
            // 0x1000 (4KB)는 최소한의 유효한 페이지 주소로 가정합니다.
            if ( bp < 0x1000 || pc < 0x1000 ) {
                DEBUG_PRINT("[TDWARF DEBUG] Abnormal BP/PC address detected (too small). Stopping unwind.");
                break;
            }

            // 스택 언와인딩은 낮은 주소로 진행되어야 합니다.
            // 다음 BP가 현재 BP보다 크다면 (주소 역전), 비정상적인 상황일 수 있습니다.
            // 단, 64비트 스택은 매우 크고 세그먼트가 분리될 수 있으므로, 엄격한 검사는 아닙니다.
            // 다음 next_bp 읽기 전에 현재 bp가 이미 이전 next_bp보다 작아야 합니다.
            // 이 로직은 첫 프레임 이후부터 적용 가능하므로, 2번째 프레임부터 검사합니다.
            if ( ctx->frame_count > 0 && bp > ctx->frames[ctx->frame_count - 1].bp ) {
                DEBUG_PRINT("[TDWARF DEBUG] Abnormal stack direction detected (BP increasing). Stopping unwind.");
                break;
            }

            frame->pc = pc;
            frame->sp = sp;
            frame->bp = bp;
            frame->frame_level = ctx->frame_count;
            frame->var_count = 0;

            ctx->frame_count++;

            // 다음 프레임의 BP와 PC 읽기
            if ( tdwarf_read_memory(ctx, bp + 8, &next_bp, sizeof(next_bp)) != TDWARF_OK ) {
                break;
            }
            if ( tdwarf_read_memory(ctx, bp + 16, &next_pc, sizeof(next_pc)) != TDWARF_OK ) {
                break;
            }

            // --- 2. 유효성 검사: 다음 주소 값 패턴 검사 ---
            // 64비트 환경에서 0xFFFFFFFF로 시작하는 주소는 종종 커널 주소나 비정상적인 경계를 나타냅니다.
            // 0xFFFF000000000000는 커널 영역의 일반적인 경계 값입니다.
            if ( (next_pc & 0xFFFF000000000000) == 0xFFFF000000000000 ) {
                DEBUG_PRINT("[TDWARF DEBUG] Abnormal next PC pattern (Kernel/Sentinel value) detected: 0x%lX. Stopping unwind.", (unsigned long)next_pc);
                break;
            }

            // 다음 BP가 유효한 스택 주소 범위에서 크게 벗어나 힙이나 다른 영역을 가리키는 경우 (정확한 검사는 어려움)
            // 여기서는 간단히 0x1000보다 작거나 0xFFFFFFFFFFFFFFF0와 같은 매우 높은 주소를 검사합니다.
            if ( next_bp < 0x1000 || next_bp >= 0xFFFFFFFFFFFFFFF0 ) {
                DEBUG_PRINT("[TDWARF DEBUG] Abnormal next BP address detected: 0x%lX. Stopping unwind.", (unsigned long)next_bp);
                break;
            }
            // --- End: 다음 주소 값 패턴 검사 ---

            pc = next_pc;
            bp = next_bp;
            sp = bp + 24; // 스택 프레임 크기 가정
            DEBUG_PRINT("next registers: PC=0x%lX, SP=0x%lX, BP=0x%lX", 
            (unsigned long)pc, (unsigned long)sp, (unsigned long)bp);

            // --- 3. 최종 중지 조건: BP/PC가 0이 되어 정상적으로 끝남 ---
            if ( bp == 0 || pc == 0) {
                DEBUG_PRINT("[TDWARF DEBUG] Unwind chain ended normally (BP or PC is 0).");
            }
        }
    }

    return TDWARF_OK;
}

/*
 * Helper macros for safe type conversion (avoid strict-aliasing issues)
 */
static inline int8_t read_int8(const uint8_t *p) {
    int8_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline int16_t read_int16(const uint8_t *p) {
    int16_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline int32_t read_int32(const uint8_t *p) {
    int32_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline int64_t read_int64(const uint8_t *p) {
    int64_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline uint16_t read_uint16(const uint8_t *p) {
    uint16_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline uint32_t read_uint32(const uint8_t *p) {
    uint32_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline uint64_t read_uint64(const uint8_t *p) {
    uint64_t v; memcpy(&v, p, sizeof(v)); return v;
}
static inline float read_float(const uint8_t *p) {
    float v; memcpy(&v, p, sizeof(v)); return v;
}
static inline double read_double(const uint8_t *p) {
    double v; memcpy(&v, p, sizeof(v)); return v;
}

/*
 * Decode SLEB128 (Signed LEB128)
 */
static int64_t decode_sleb128(const uint8_t *data, size_t *bytes_read)
{
    int64_t result = 0;
    size_t shift = 0;
    size_t i = 0;
    uint8_t byte;
    
    do {
        byte = data[i++];
        result |= ((int64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);
    
    /* Sign extend if negative */
    if ((shift < 64) && (byte & 0x40)) {
        result |= -(1LL << shift);
    }
    
    if (bytes_read) {
        *bytes_read = i;
    }
    return result;
}

/*
 * Decode ULEB128 (Unsigned LEB128) - Reserved for future use
 */
#if 0
static uint64_t decode_uleb128(const uint8_t *data, size_t *bytes_read)
{
    uint64_t result = 0;
    size_t shift = 0;
    size_t i = 0;
    uint8_t byte;
    
    do {
        byte = data[i++];
        result |= ((uint64_t)(byte & 0x7F)) << shift;
        shift += 7;
    } while (byte & 0x80);
    
    if (bytes_read) {
        *bytes_read = i;
    }
    return result;
}
#endif

/*
 * Library initialization
 */
tdwarf_error_t tdwarf_init(void)
{
    if (g_initialized) {
        return TDWARF_OK;
    }
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        return TDWARF_ERR_INTERNAL;
    }
    
    g_initialized = 1;
    return TDWARF_OK;
}

void tdwarf_cleanup(void)
{
    if (g_handlers_installed) {
        tdwarf_remove_signal_handlers();
    }
    g_initialized = 0;
}

const char* tdwarf_version(void)
{
    static char version[64];
    snprintf(version, sizeof(version), "%d.%d.%d",
             TDWARF_VERSION_MAJOR,
             TDWARF_VERSION_MINOR,
             TDWARF_VERSION_PATCH);
    return version;
}

const char* tdwarf_strerror(tdwarf_error_t err)
{
    int idx = -err;
    if (idx < 0 || idx >= (int)(sizeof(error_messages)/sizeof(error_messages[0]))) {
        return "Unknown error";
    }
    return error_messages[idx];
}

void tdwarf_config_default(tdwarf_config_t *config)
{
    if (!config) return;
    
    config->dump_globals = 1;
    config->dump_locals = 1;
    config->dump_heap = 0;
    config->max_depth = 3;
    config->hex_uppercase = 1;
    config->include_source = 1;
    config->verbose = 1;
}

/*
 * Check if executable is PIE
 */
static int check_is_pie(const char *exe_path)
{
    int fd;
    Elf *elf;
    GElf_Ehdr ehdr;
    int is_pie = 0;
    
    fd = open(exe_path, O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    
    elf = elf_begin(fd, ELF_C_READ, NULL);
    if (elf) {
        if (gelf_getehdr(elf, &ehdr) != NULL) {
            if (ehdr.e_type == ET_DYN) {
                is_pie = 1;
                DEBUG_PRINT("Executable type: ET_DYN (PIE or shared library)");
            } else if (ehdr.e_type == ET_EXEC) {
                is_pie = 0;
                DEBUG_PRINT("Executable type: ET_EXEC (non-PIE)");
            }
        }
        elf_end(elf);
    }
    
    close(fd);
    return is_pie;
}

/*
 * Get load address offset for PIE executables
 */
static uint64_t get_load_address(pid_t pid, const char *exe_path, int is_pie)
{
    char maps_path[64];
    char line[512];
    char *basename_exe;
    FILE *maps;
    uint64_t load_addr = 0;
    int found = 0;
    
    if (!is_pie) {
        DEBUG_PRINT("Non-PIE executable: using load_address = 0 (DWARF addresses are absolute)");
        return 0;
    }
    
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    maps = fopen(maps_path, "r");
    if (!maps) {
        DEBUG_PRINT("Cannot open %s", maps_path);
        return 0;
    }
    
    basename_exe = strrchr(exe_path, '/');
    if (basename_exe) {
        basename_exe++;
    } else {
        basename_exe = (char*)exe_path;
    }
    
    // PIE 실행 파일의 정확한 로드 주소(Base Address)를 얻으려면, 권한(r-xp)을 따지지 말고, 
    // 해당 파일 경로와 일치하는 가장 첫 번째 맵핑 주소를 찾아야 합니다.
    while( fgets(line, sizeof(line), maps) ) {
        unsigned long start_addr, end_addr, offset;
        char perms[16]; // 권한 문자열 (예: r-xp)

        // /proc/[pid]/maps 형식 파싱:
        // address           perms offset  dev   inode   pathname
        // 562ca0a0b000-562ca... r--p 00000000 08:30 ... /usr/bin/cat
        
        // sscanf로 필요한 앞부분 필드(시작주소, 끝주소, 권한, 오프셋)를 추출합니다.
        if (sscanf(line, "%lx-%lx %s %lx", &start_addr, &end_addr, perms, &offset) != 4) {
            continue; // 파싱 실패 시 다음 라인으로
        }

        // 파일경로가 포함되어 있는지 확인 
        if ( strstr(line, exe_path) || strstr(line, basename_exe) ) {
            // 오프셋이 0인지 확인 (선택 사항이지만 정확도 높임
            // 보통 첫 번째 로드 세그먼트의 파일 오프셋은 0입니다.
            // 맵 파일 포맷: address perms offset dev inode pathname
            // 예: ... r--p 00000000 ...
            if (offset == 0) {
                load_addr = (uint64_t)start_addr;
                DEBUG_PRINT("PIE executable: found load address 0x%lX for %s (offset 0)", 
                    (unsigned long)load_addr, basename_exe);
                found = 1;
                break; // Base Address를 찾았으므로 루프 종료
            }
        }
    }
    
    fclose(maps);
    return load_addr;
}

/*
 * Get executable path for a process
 */
static int get_executable_path(pid_t pid, char *buf, size_t buf_size)
{
    char proc_path[64];
    ssize_t len;
    
    if (pid == 0) {
        snprintf(proc_path, sizeof(proc_path), "/proc/self/exe");
    } else {
        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
    }
    
    len = readlink(proc_path, buf, buf_size - 1);
    if (len < 0) {
        return -1;
    }
    buf[len] = '\0';
    return 0;
}

/*
 * Context creation
 */
tdwarf_error_t tdwarf_context_create(pid_t pid, tdwarf_context_t **ctx)
{
    tdwarf_context_t *new_ctx;
    tdwarf_internal_t *internal;
    int i;
    
    if (!ctx) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    new_ctx = calloc(1, sizeof(tdwarf_context_t));
    if (!new_ctx) {
        return TDWARF_ERR_NO_MEMORY;
    }
    
    internal = calloc(1, sizeof(tdwarf_internal_t));
    if (!internal) {
        free(new_ctx);
        return TDWARF_ERR_NO_MEMORY;
    }
    internal->fd = -1;
    internal->global_var_capacity = 512;
    internal->global_vars = calloc(internal->global_var_capacity, sizeof(tdwarf_var_t));
    if (!internal->global_vars) {
        free(internal);
        free(new_ctx);
        return TDWARF_ERR_NO_MEMORY;
    }
    
    new_ctx->target_pid = (pid == 0) ? getpid() : pid;
    new_ctx->dwarf_handle = internal;
    new_ctx->attached = 0;
    
    /* Initialize frame variable arrays */
    for (i = 0; i < TDWARF_MAX_FRAMES; i++) {
        new_ctx->frames[i].variables = calloc(256, sizeof(tdwarf_var_t));
        new_ctx->frames[i].var_count = 0;
        new_ctx->frames[i].var_capacity = 256;
    }
    
    if (get_executable_path(new_ctx->target_pid, 
                            new_ctx->executable_path,
                            sizeof(new_ctx->executable_path)) < 0) {
        for (i = 0; i < TDWARF_MAX_FRAMES; i++) {
            if (new_ctx->frames[i].variables) free(new_ctx->frames[i].variables);
        }
        free(internal->global_vars);
        free(internal);
        free(new_ctx);
        return TDWARF_ERR_OPEN_FAILED;
    }
    
    *ctx = new_ctx;
    return TDWARF_OK;
}

void tdwarf_context_destroy(tdwarf_context_t *ctx)
{
    tdwarf_internal_t *internal;
    int i;
    
    if (!ctx) return;
    
    if (ctx->attached) {
        tdwarf_detach(ctx);
    }
    
    internal = (tdwarf_internal_t*)ctx->dwarf_handle;
    if (internal) {
        if (internal->dbg) {
            Dwarf_Error err;
            dwarf_finish(internal->dbg, &err);
        }
        if (internal->elf) {
            elf_end(internal->elf);
        }
        if (internal->fd >= 0) {
            close(internal->fd);
        }
        if (internal->global_vars) {
            free(internal->global_vars);
        }
        free(internal);
    }
    
    for (i = 0; i < TDWARF_MAX_FRAMES; i++) {
        if (ctx->frames[i].variables) {
            free(ctx->frames[i].variables);
        }
    }
    
    if (ctx->output_file) {
        fclose(ctx->output_file);
    }
    
    free(ctx);
}

/*
 * Ptrace attachment
 */
tdwarf_error_t tdwarf_attach(tdwarf_context_t *ctx)
{
    int status;
    
    if (!ctx) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    if (ctx->target_pid == getpid()) {
        ctx->attached = 1;
        return TDWARF_OK;
    }
    
    if (ptrace(PTRACE_ATTACH, ctx->target_pid, NULL, NULL) < 0) {
        DEBUG_PRINT("ptrace ATTACH failed: %s", strerror(errno));
        return TDWARF_ERR_PTRACE;
    }
    
    if (waitpid(ctx->target_pid, &status, 0) < 0) {
        ptrace(PTRACE_DETACH, ctx->target_pid, NULL, NULL);
        return TDWARF_ERR_PTRACE;
    }
    
    ctx->attached = 1;
    DEBUG_PRINT("Attached to PID %d", ctx->target_pid);
    return TDWARF_OK;
}

tdwarf_error_t tdwarf_detach(tdwarf_context_t *ctx)
{
    if (!ctx || !ctx->attached) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    if (ctx->target_pid != getpid()) {
        if (ptrace(PTRACE_DETACH, ctx->target_pid, NULL, NULL) < 0) {
            return TDWARF_ERR_PTRACE;
        }
    }
    
    ctx->attached = 0;
    return TDWARF_OK;
}

/*
 * Load DWARF debug information
 */
tdwarf_error_t tdwarf_load_debug_info(tdwarf_context_t *ctx)
{
    tdwarf_internal_t *internal;
    int res;
    
    if (!ctx) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    internal = (tdwarf_internal_t*)ctx->dwarf_handle;
    
    internal->is_pie = check_is_pie(ctx->executable_path);
    internal->load_address = get_load_address(ctx->target_pid, ctx->executable_path, internal->is_pie);
    DEBUG_PRINT("Final load_address offset: 0x%lX (is_pie=%d)", 
                (unsigned long)internal->load_address, internal->is_pie);
    
    internal->fd = open(ctx->executable_path, O_RDONLY);
    if (internal->fd < 0) {
        DEBUG_PRINT("Cannot open executable: %s", ctx->executable_path);
        return TDWARF_ERR_OPEN_FAILED;
    }
    
    internal->elf = elf_begin(internal->fd, ELF_C_READ, NULL);
    if (!internal->elf) {
        DEBUG_PRINT("elf_begin failed");
        close(internal->fd);
        internal->fd = -1;
        return TDWARF_ERR_OPEN_FAILED;
    }
    
    res = dwarf_elf_init(internal->elf, DW_DLC_READ, NULL, NULL,
                         &internal->dbg, &internal->error);
    if (res != DW_DLV_OK) {
        DEBUG_PRINT("dwarf_elf_init failed: res=%d", res);
        elf_end(internal->elf);
        internal->elf = NULL;
        close(internal->fd);
        internal->fd = -1;
        return TDWARF_ERR_NO_DWARF;
    }
    
    DEBUG_PRINT("DWARF initialized successfully");
    return TDWARF_OK;
}

/*
 * Read memory from target process
 */
tdwarf_error_t tdwarf_read_memory(tdwarf_context_t *ctx, 
                                   uint64_t addr, 
                                   void *buf, 
                                   size_t len)
{
    char proc_mem_path[64];
    int fd;
    ssize_t bytes_read;
    
    if (!ctx || !buf || len == 0) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    snprintf(proc_mem_path, sizeof(proc_mem_path), "/proc/%d/mem", ctx->target_pid);
    
    fd = open(proc_mem_path, O_RDONLY);
    if (fd >= 0) {
        DEBUG_PRINT("Reading memory from %s at 0x%lX, len=%zu", 
            proc_mem_path, (unsigned long)addr, len);
        if (lseek(fd, addr, SEEK_SET) == (off_t)addr) {
            bytes_read = read(fd, buf, len);
            close(fd);
            if (bytes_read == (ssize_t)len) {
                return TDWARF_OK;
            }
        } else {
            DEBUG_PRINT("lseek failed: %s", strerror(errno));
            close(fd);
        }
    } else {
        DEBUG_PRINT("Cannot open %s: %s", proc_mem_path, strerror(errno));
    }
    
    {
        struct iovec local_iov;
        struct iovec remote_iov;
        local_iov.iov_base = buf;
        local_iov.iov_len = len;
        remote_iov.iov_base = (void*)addr;
        remote_iov.iov_len = len;
        
        bytes_read = process_vm_readv(ctx->target_pid, 
                                       &local_iov, 1,
                                       &remote_iov, 1, 0);
        DEBUG_PRINT("process_vm_readv read %zd bytes from 0x%lX", 
                    bytes_read, (unsigned long)addr);
        if (bytes_read == (ssize_t)len) {
            return TDWARF_OK;
        }
        DEBUG_PRINT("process_vm_readv failed: %s", strerror(errno));
    }
    
    if (ctx->attached && ctx->target_pid != getpid()) {
        size_t offset = 0;
        DEBUG_PRINT("reading memory via ptrace PEEKDATA at 0x%lX, len=%zu", 
            (unsigned long)addr, len);
        
        while (offset < len) {
            long word;
            size_t copy_len;
            errno = 0;
            word = ptrace(PTRACE_PEEKDATA, ctx->target_pid, addr + offset, NULL);
            if (errno != 0) {
                DEBUG_PRINT("ptrace PEEKDATA failed: %s", strerror(errno));
                return TDWARF_ERR_READ_MEM;
            }
            
            copy_len = (len - offset < sizeof(long)) ? (len - offset) : sizeof(long);
            memcpy((char*)buf + offset, &word, copy_len);
            offset += sizeof(long);
        }
        return TDWARF_OK;
    }
    
    return TDWARF_ERR_READ_MEM;
}

/*
 * Get type kind from DWARF encoding
 */
static tdwarf_type_kind_t get_type_kind_from_encoding(Dwarf_Debug dbg, Dwarf_Die type_die)
{
    Dwarf_Half tag;
    Dwarf_Error error;
    Dwarf_Attribute attr;
    Dwarf_Unsigned encoding;
    int res;
    
    res = dwarf_tag(type_die, &tag, &error);
    if (res != DW_DLV_OK) {
        return TDWARF_TYPE_UNKNOWN;
    }
    
    switch (tag) {
        case DW_TAG_base_type:
            res = dwarf_attr(type_die, DW_AT_encoding, &attr, &error);
            if (res == DW_DLV_OK) {
                res = dwarf_formudata(attr, &encoding, &error);
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
                if (res == DW_DLV_OK) {
                    switch (encoding) {
                        case DW_ATE_signed:
                        case DW_ATE_signed_char:
                            return TDWARF_TYPE_INT;
                        case DW_ATE_unsigned:
                        case DW_ATE_unsigned_char:
                            return TDWARF_TYPE_UINT;
                        case DW_ATE_float:
                            return TDWARF_TYPE_FLOAT;
                        case DW_ATE_signed_fixed:
                            return TDWARF_TYPE_DOUBLE;
                        default:
                            return TDWARF_TYPE_INT;
                    }
                }
            }
            return TDWARF_TYPE_INT;
        case DW_TAG_pointer_type:
            return TDWARF_TYPE_POINTER;
        case DW_TAG_array_type:
            return TDWARF_TYPE_ARRAY;
        case DW_TAG_structure_type:
            return TDWARF_TYPE_STRUCT;
        case DW_TAG_union_type:
            return TDWARF_TYPE_UNION;
        case DW_TAG_enumeration_type:
            return TDWARF_TYPE_ENUM;
        default:
            return TDWARF_TYPE_UNKNOWN;
    }
}

/*
 * Get string attribute from DIE
 */
static int get_die_name(Dwarf_Debug dbg, Dwarf_Die die, 
                        char *buf, size_t buf_size)
{
    Dwarf_Attribute attr;
    char *name = NULL;
    Dwarf_Error error;
    int res;
    
    res = dwarf_attr(die, DW_AT_name, &attr, &error);
    if (res != DW_DLV_OK) {
        buf[0] = '\0';
        return -1;
    }
    
    res = dwarf_formstring(attr, &name, &error);
    if (res != DW_DLV_OK || !name) {
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        buf[0] = '\0';
        return -1;
    }
    
    strncpy(buf, name, buf_size - 1);
    buf[buf_size - 1] = '\0';
    
    dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    return 0;
}

/*
 * Get type name recursively
 */
static int get_type_name(Dwarf_Debug dbg, Dwarf_Die type_die,
                         char *buf, size_t buf_size)
{
    Dwarf_Half tag;
    Dwarf_Error error;
    Dwarf_Attribute attr;
    Dwarf_Off ref_offset;
    Dwarf_Die ref_die;
    char base_name[256] = {0};
    int res;
    
    if (!type_die) {
        strncpy(buf, "void", buf_size);
        return 0;
    }
    
    res = dwarf_tag(type_die, &tag, &error);
    if (res != DW_DLV_OK) {
        strncpy(buf, "<unknown>", buf_size);
        return -1;
    }
    
    switch (tag) {
        case DW_TAG_base_type:
        case DW_TAG_typedef:
            get_die_name(dbg, type_die, buf, buf_size);
            break;
            
        case DW_TAG_pointer_type:
            res = dwarf_attr(type_die, DW_AT_type, &attr, &error);
            if (res == DW_DLV_OK) {
                res = dwarf_global_formref(attr, &ref_offset, &error);
                if (res == DW_DLV_OK) {
                    res = dwarf_offdie(dbg, ref_offset, &ref_die, &error);
                    if (res == DW_DLV_OK) {
                        get_type_name(dbg, ref_die, base_name, sizeof(base_name));
                        snprintf(buf, buf_size, "%s*", base_name);
                        dwarf_dealloc(dbg, ref_die, DW_DLA_DIE);
                    }
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            } else {
                strncpy(buf, "void*", buf_size);
            }
            break;
            
        case DW_TAG_array_type:
            res = dwarf_attr(type_die, DW_AT_type, &attr, &error);
            if (res == DW_DLV_OK) {
                res = dwarf_global_formref(attr, &ref_offset, &error);
                if (res == DW_DLV_OK) {
                    res = dwarf_offdie(dbg, ref_offset, &ref_die, &error);
                    if (res == DW_DLV_OK) {
                        get_type_name(dbg, ref_die, base_name, sizeof(base_name));
                        snprintf(buf, buf_size, "%s[]", base_name);
                        dwarf_dealloc(dbg, ref_die, DW_DLA_DIE);
                    }
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
            break;
            
        case DW_TAG_structure_type:
            if (get_die_name(dbg, type_die, base_name, sizeof(base_name)) == 0) {
                snprintf(buf, buf_size, "struct %s", base_name);
            } else {
                strncpy(buf, "struct <anonymous>", buf_size);
            }
            break;
            
        case DW_TAG_union_type:
            if (get_die_name(dbg, type_die, base_name, sizeof(base_name)) == 0) {
                snprintf(buf, buf_size, "union %s", base_name);
            } else {
                strncpy(buf, "union <anonymous>", buf_size);
            }
            break;
            
        case DW_TAG_enumeration_type:
            if (get_die_name(dbg, type_die, base_name, sizeof(base_name)) == 0) {
                snprintf(buf, buf_size, "enum %s", base_name);
            } else {
                strncpy(buf, "enum <anonymous>", buf_size);
            }
            break;
            
        case DW_TAG_const_type:
        case DW_TAG_volatile_type:
            res = dwarf_attr(type_die, DW_AT_type, &attr, &error);
            if (res == DW_DLV_OK) {
                res = dwarf_global_formref(attr, &ref_offset, &error);
                if (res == DW_DLV_OK) {
                    res = dwarf_offdie(dbg, ref_offset, &ref_die, &error);
                    if (res == DW_DLV_OK) {
                        get_type_name(dbg, ref_die, base_name, sizeof(base_name));
                        snprintf(buf, buf_size, "%s %s", 
                                 (tag == DW_TAG_const_type) ? "const" : "volatile",
                                 base_name);
                        dwarf_dealloc(dbg, ref_die, DW_DLA_DIE);
                    }
                }
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
            }
            break;
            
        default:
            snprintf(buf, buf_size, "<tag:0x%x>", tag);
            break;
    }
    
    return 0;
}

/*
 * Get array element count from DW_TAG_subrange_type
 */
static size_t get_array_element_count(Dwarf_Debug dbg, Dwarf_Die array_die)
{
    Dwarf_Error error;
    Dwarf_Die child_die = NULL;
    Dwarf_Attribute attr;
    Dwarf_Unsigned count = 0;
    Dwarf_Unsigned upper_bound;
    int res;
    
    res = dwarf_child(array_die, &child_die, &error);
    if (res != DW_DLV_OK) {
        return 0;
    }
    
    while (1) {
        Dwarf_Half tag;
        Dwarf_Die sibling;
        
        res = dwarf_tag(child_die, &tag, &error);
        if (res == DW_DLV_OK && tag == DW_TAG_subrange_type) {
            res = dwarf_attr(child_die, DW_AT_count, &attr, &error);
            if (res == DW_DLV_OK) {
                res = dwarf_formudata(attr, &count, &error);
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
                if (res == DW_DLV_OK && count > 0) {
                    dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
                    DEBUG_PRINT("    Array DW_AT_count = %lu", (unsigned long)count);
                    return (size_t)count;
                }
            }
            
            res = dwarf_attr(child_die, DW_AT_upper_bound, &attr, &error);
            if (res == DW_DLV_OK) {
                res = dwarf_formudata(attr, &upper_bound, &error);
                dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
                if (res == DW_DLV_OK) {
                    count = upper_bound + 1;
                    dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
                    DEBUG_PRINT("    Array DW_AT_upper_bound = %lu, count = %lu", 
                               (unsigned long)upper_bound, (unsigned long)count);
                    return (size_t)count;
                }
            }
        }
        
        res = dwarf_siblingof(dbg, child_die, &sibling, &error);
        dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
        if (res != DW_DLV_OK) {
            break;
        }
        child_die = sibling;
    }
    
    return 0;
}

/*
 * Get type size (with proper array size calculation)
 */
static size_t get_type_size(Dwarf_Debug dbg, Dwarf_Die type_die)
{
    Dwarf_Unsigned size;
    Dwarf_Error error;
    Dwarf_Half tag;
    int res;
    
    if (!type_die) {
        return 0;
    }
    
    res = dwarf_bytesize(type_die, &size, &error);
    if (res == DW_DLV_OK && size > 0) {
        return (size_t)size;
    }
    
    res = dwarf_tag(type_die, &tag, &error);
    if (res == DW_DLV_OK && tag == DW_TAG_array_type) {
        Dwarf_Attribute attr;
        size_t element_count;
        size_t element_size = 0;
        
        element_count = get_array_element_count(dbg, type_die);
        
        res = dwarf_attr(type_die, DW_AT_type, &attr, &error);
        if (res == DW_DLV_OK) {
            Dwarf_Off type_offset;
            res = dwarf_global_formref(attr, &type_offset, &error);
            if (res == DW_DLV_OK) {
                Dwarf_Die element_die;
                res = dwarf_offdie(dbg, type_offset, &element_die, &error);
                if (res == DW_DLV_OK) {
                    element_size = get_type_size(dbg, element_die);
                    dwarf_dealloc(dbg, element_die, DW_DLA_DIE);
                }
            }
            dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        }
        
        if (element_count > 0 && element_size > 0) {
            size_t total_size = element_count * element_size;
            DEBUG_PRINT("    Array size: %zu elements * %zu bytes = %zu bytes", 
                       element_count, element_size, total_size);
            return total_size;
        }
    }
    
    return sizeof(void*);
}

/*
 * Location expression types
 */
typedef enum {
    LOC_UNKNOWN = 0,
    LOC_ADDR,       /* DW_OP_addr - absolute address */
    LOC_FBREG,      /* DW_OP_fbreg - frame base relative */
    LOC_BREG,       /* DW_OP_bregN - register relative */
    LOC_REG         /* DW_OP_regN - in register */
} loc_type_t;

typedef struct {
    loc_type_t type;
    int64_t offset;      /* For FBREG/BREG: offset from base */
    uint64_t address;    /* For ADDR: absolute address */
    int reg_num;         /* For BREG/REG: register number */
} location_info_t;

/*
 * Parse DWARF location expression
 */
static int parse_location_expr(const uint8_t *ops, size_t len, location_info_t *loc)
{
    size_t bytes_read;
    
    if (len == 0) {
        return -1;
    }
    
    memset(loc, 0, sizeof(*loc));
    
    switch (ops[0]) {
        case DW_OP_addr: /* 0x03 */
            {
                int i;
                loc->type = LOC_ADDR;
                loc->address = 0;
                for (i = 0; i < 8 && (size_t)(i + 1) < len; i++) {
                    loc->address |= ((uint64_t)ops[1 + i]) << (i * 8);
                }
            }
            break;
            
        case DW_OP_fbreg: /* 0x91 */
            loc->type = LOC_FBREG;
            loc->offset = decode_sleb128(ops + 1, &bytes_read);
            break;
            
        /* DW_OP_breg0 to DW_OP_breg31 (0x70 - 0x8f) */
        case 0x70: case 0x71: case 0x72: case 0x73:
        case 0x74: case 0x75: case 0x76: case 0x77:
        case 0x78: case 0x79: case 0x7a: case 0x7b:
        case 0x7c: case 0x7d: case 0x7e: case 0x7f:
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8a: case 0x8b:
        case 0x8c: case 0x8d: case 0x8e: case 0x8f:
            loc->type = LOC_BREG;
            loc->reg_num = ops[0] - 0x70;
            loc->offset = decode_sleb128(ops + 1, &bytes_read);
            break;
            
        /* DW_OP_reg0 to DW_OP_reg31 (0x50 - 0x6f) */
        case 0x50: case 0x51: case 0x52: case 0x53:
        case 0x54: case 0x55: case 0x56: case 0x57:
        case 0x58: case 0x59: case 0x5a: case 0x5b:
        case 0x5c: case 0x5d: case 0x5e: case 0x5f:
        case 0x60: case 0x61: case 0x62: case 0x63:
        case 0x64: case 0x65: case 0x66: case 0x67:
        case 0x68: case 0x69: case 0x6a: case 0x6b:
        case 0x6c: case 0x6d: case 0x6e: case 0x6f:
            loc->type = LOC_REG;
            loc->reg_num = ops[0] - 0x50;
            break;
            
        default:
            loc->type = LOC_UNKNOWN;
            return -1;
    }
    
    return 0;
}

/*
 * Get variable location info from DW_AT_location
 */
static int get_variable_location(Dwarf_Debug dbg, Dwarf_Die die, 
                                  const char *var_name, location_info_t *loc)
{
    Dwarf_Attribute attr;
    Dwarf_Error error;
    int res;
    Dwarf_Half form;
    
    res = dwarf_attr(die, DW_AT_location, &attr, &error);
    if (res != DW_DLV_OK) {
        return -1;
    }
    
    res = dwarf_whatform(attr, &form, &error);
    if (res != DW_DLV_OK) {
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        return -1;
    }
    
    /* DWARF 4+: exprloc form */
    if (form == DW_FORM_exprloc) {
        Dwarf_Ptr block_ptr;
        Dwarf_Unsigned block_len;
        
        res = dwarf_formexprloc(attr, &block_len, &block_ptr, &error);
        if (res == DW_DLV_OK && block_len > 0) {
            parse_location_expr((unsigned char*)block_ptr, block_len, loc);
            DEBUG_PRINT("  %s: exprloc op=0x%02x, type=%d, offset=%ld", 
                       var_name, ((unsigned char*)block_ptr)[0], loc->type, (long)loc->offset);
        }
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        return (loc->type != LOC_UNKNOWN) ? 0 : -1;
    }
    
    /* DWARF 2/3: block forms */
    if (form == DW_FORM_block1 || form == DW_FORM_block2 || 
        form == DW_FORM_block4 || form == DW_FORM_block) {
        Dwarf_Block *block;
        
        res = dwarf_formblock(attr, &block, &error);
        if (res == DW_DLV_OK && block && block->bl_len > 0) {
            parse_location_expr((unsigned char*)block->bl_data, block->bl_len, loc);
            dwarf_dealloc(dbg, block, DW_DLA_BLOCK);
        }
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
        return (loc->type != LOC_UNKNOWN) ? 0 : -1;
    }
    
    dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    return -1;
}

/*
 * Check if variable is external declaration
 */
static int is_external_declaration(Dwarf_Debug dbg, Dwarf_Die die)
{
    Dwarf_Attribute attr;
    Dwarf_Error error;
    Dwarf_Bool is_decl = 0;
    int res;
    
    res = dwarf_attr(die, DW_AT_declaration, &attr, &error);
    if (res == DW_DLV_OK) {
        dwarf_formflag(attr, &is_decl, &error);
        dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    }
    
    return is_decl ? 1 : 0;
}

/*
 * Fill variable info from type DIE
 */
static void fill_var_type_info(Dwarf_Debug dbg, Dwarf_Die var_die, tdwarf_var_t *var)
{
    Dwarf_Attribute type_attr;
    Dwarf_Error error;
    int res;
    
    res = dwarf_attr(var_die, DW_AT_type, &type_attr, &error);
    if (res == DW_DLV_OK) {
        Dwarf_Off type_offset;
        res = dwarf_global_formref(type_attr, &type_offset, &error);
        if (res == DW_DLV_OK) {
            Dwarf_Die type_die;
            res = dwarf_offdie(dbg, type_offset, &type_die, &error);
            if (res == DW_DLV_OK) {
                get_type_name(dbg, type_die, var->type_name, sizeof(var->type_name));
                var->size = get_type_size(dbg, type_die);
                var->type_kind = get_type_kind_from_encoding(dbg, type_die);
                dwarf_dealloc(dbg, type_die, DW_DLA_DIE);
            }
        }
        dwarf_dealloc(dbg, type_attr, DW_DLA_ATTR);
    }
    
    if (var->size == 0) {
        var->size = sizeof(void*);
    }
}

/*
 * Process a global variable DIE
 */
static void process_global_variable(tdwarf_context_t *ctx, Dwarf_Debug dbg, Dwarf_Die var_die)
{
    tdwarf_internal_t *internal = (tdwarf_internal_t*)ctx->dwarf_handle;
    tdwarf_var_t *var;
    location_info_t loc;
    size_t read_size;
    char var_name[256] = {0};
    
    if (internal->global_var_count >= internal->global_var_capacity) {
        return;
    }
    
    get_die_name(dbg, var_die, var_name, sizeof(var_name));
    DEBUG_PRINT("Processing global variable: %s", var_name[0] ? var_name : "<unnamed>");
    
    if (is_external_declaration(dbg, var_die)) {
        DEBUG_PRINT("  Skipping %s: external declaration", var_name);
        return;
    }
    
    if (get_variable_location(dbg, var_die, var_name, &loc) < 0) {
        DEBUG_PRINT("  Skipping %s: no location info", var_name);
        return;
    }
    
    /* Only process absolute address (global) variables here */
    if (loc.type != LOC_ADDR) {
        DEBUG_PRINT("  Skipping %s: not absolute address (type=%d)", var_name, loc.type);
        return;
    }
    
    var = &internal->global_vars[internal->global_var_count];
    memset(var, 0, sizeof(*var));
    
    strncpy(var->name, var_name, sizeof(var->name) - 1);
    var->address = loc.address + internal->load_address;
    var->is_local = 0;
    var->frame_level = -1;
    
    DEBUG_PRINT("  %s: address = 0x%lX (load_offset=0x%lX)", 
                var_name, (unsigned long)var->address, (unsigned long)internal->load_address);
    
    fill_var_type_info(dbg, var_die, var);
    DEBUG_PRINT("  %s: type=%s, size=%zu", var_name, var->type_name, var->size);
    
    read_size = (var->size > TDWARF_MAX_DUMP_SIZE) ? TDWARF_MAX_DUMP_SIZE : var->size;
    if (tdwarf_read_memory(ctx, var->address, var->data, read_size) == TDWARF_OK) {
        var->data_len = read_size;
        internal->global_var_count++;
        DEBUG_PRINT("  %s: Successfully read %zu bytes", var_name, read_size);
    } else {
        DEBUG_PRINT("  %s: Failed to read memory at 0x%lX", var_name, (unsigned long)var->address);
    }
}

/*
 * Process a local variable DIE for a specific frame
 */
static void process_local_variable(tdwarf_context_t *ctx, Dwarf_Debug dbg, 
                                    Dwarf_Die var_die, tdwarf_frame_t *frame)
{
    tdwarf_var_t *var;
    location_info_t loc;
    size_t read_size;
    char var_name[256] = {0};
    uint64_t var_addr = 0;
    
    if (frame->var_count >= frame->var_capacity) {
        return;
    }
    
    get_die_name(dbg, var_die, var_name, sizeof(var_name));
    
    if (get_variable_location(dbg, var_die, var_name, &loc) < 0) {
        return;
    }
    
    /* Calculate address based on location type */
    switch (loc.type) {
        case LOC_FBREG:
            /* Frame base relative - use RBP (frame base is typically RBP) */
            if (frame->bp == 0 || frame->bp == 0xFFFFFFFF || frame->bp == 0xFFFFFFFFFFFFFFFFULL) {
                DEBUG_PRINT("  Skipping %s: invalid frame base", var_name);
                return;
            }
            var_addr = (uint64_t)((int64_t)frame->bp + loc.offset);
            DEBUG_PRINT("  Local %s: BP(0x%lX) + offset(%ld) = 0x%lX", 
                       var_name, (unsigned long)frame->bp, (long)loc.offset, (unsigned long)var_addr);
            break;
            
        case LOC_BREG:
            /* Register relative - only handle RBP (reg 6 on x86_64) */
            if (loc.reg_num == 6) { /* RBP */
                var_addr = (uint64_t)((int64_t)frame->bp + loc.offset);
            } else if (loc.reg_num == 7) { /* RSP */
                var_addr = (uint64_t)((int64_t)frame->sp + loc.offset);
            } else {
                DEBUG_PRINT("  Skipping %s: unsupported register %d", var_name, loc.reg_num);
                return;
            }
            break;
            
        case LOC_REG:
            /* Variable is in a register - we can't read it directly */
            DEBUG_PRINT("  Skipping %s: stored in register %d", var_name, loc.reg_num);
            return;
            
        default:
            return;
    }
    
    /* Sanity check address */
    if (var_addr == 0 || var_addr > 0x7FFFFFFFFFFF) {
        DEBUG_PRINT("  Skipping %s: invalid address 0x%lX", var_name, (unsigned long)var_addr);
        return;
    }
    
    var = &frame->variables[frame->var_count];
    memset(var, 0, sizeof(*var));
    
    strncpy(var->name, var_name, sizeof(var->name) - 1);
    var->address = var_addr;
    var->is_local = 1;
    var->frame_level = frame->frame_level;
    
    fill_var_type_info(dbg, var_die, var);
    DEBUG_PRINT("  %s: type=%s, size=%zu", var_name, var->type_name, var->size);
    
    read_size = (var->size > TDWARF_MAX_DUMP_SIZE) ? TDWARF_MAX_DUMP_SIZE : var->size;
    if (tdwarf_read_memory(ctx, var->address, var->data, read_size) == TDWARF_OK) {
        var->data_len = read_size;
        frame->var_count++;
        DEBUG_PRINT("  %s: Successfully read %zu bytes at 0x%lX", var_name, read_size, (unsigned long)var_addr);
    } else {
        DEBUG_PRINT("  %s: Failed to read memory at 0x%lX", var_name, (unsigned long)var->address);
    }
}

/*
 * Get function address range from DW_TAG_subprogram
 */
static int get_function_range(Dwarf_Debug dbg, Dwarf_Die func_die, 
                               uint64_t *low_pc, uint64_t *high_pc)
{
    Dwarf_Attribute attr;
    Dwarf_Error error;
    Dwarf_Addr addr;
    Dwarf_Unsigned size;
    int res;
    Dwarf_Half form;
    
    /* Get low_pc */
    res = dwarf_attr(func_die, DW_AT_low_pc, &attr, &error);
    if (res != DW_DLV_OK) {
        return -1;
    }
    res = dwarf_formaddr(attr, &addr, &error);
    dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    if (res != DW_DLV_OK) {
        return -1;
    }
    *low_pc = addr;
    
    /* Get high_pc (can be address or offset) */
    res = dwarf_attr(func_die, DW_AT_high_pc, &attr, &error);
    if (res != DW_DLV_OK) {
        *high_pc = *low_pc + 1; /* Default to small range */
        return 0;
    }
    
    res = dwarf_whatform(attr, &form, &error);
    if (res == DW_DLV_OK) {
        if (form == DW_FORM_addr) {
            /* Absolute address */
            res = dwarf_formaddr(attr, &addr, &error);
            if (res == DW_DLV_OK) {
                *high_pc = addr;
            }
        } else {
            /* Offset from low_pc (DWARF 4+) */
            res = dwarf_formudata(attr, &size, &error);
            if (res == DW_DLV_OK) {
                *high_pc = *low_pc + size;
            }
        }
    }
    dwarf_dealloc(dbg, attr, DW_DLA_ATTR);
    
    return 0;
}

/*
 * Collect local variables from a function DIE
 */
static void collect_local_vars_from_function(tdwarf_context_t *ctx, Dwarf_Debug dbg,
                                              Dwarf_Die func_die, tdwarf_frame_t *frame)
{
    Dwarf_Error error;
    Dwarf_Die child_die = NULL;
    Dwarf_Die sibling_die;
    Dwarf_Half tag;
    int res;
    
    res = dwarf_child(func_die, &child_die, &error);
    if (res != DW_DLV_OK) {
        return;
    }
    
    while (1) {
        res = dwarf_tag(child_die, &tag, &error);
        if (res == DW_DLV_OK) {
            if (tag == DW_TAG_variable || tag == DW_TAG_formal_parameter) {
                process_local_variable(ctx, dbg, child_die, frame);
            }
            /* Recurse into lexical blocks */
            else if (tag == DW_TAG_lexical_block) {
                collect_local_vars_from_function(ctx, dbg, child_die, frame);
            }
        }
        
        res = dwarf_siblingof(dbg, child_die, &sibling_die, &error);
        dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
        if (res != DW_DLV_OK) {
            break;
        }
        child_die = sibling_die;
    }
}

/*
 * Find function containing PC and collect its local variables
 */
static void find_function_and_collect_locals(tdwarf_context_t *ctx, Dwarf_Debug dbg,
                                              Dwarf_Die cu_die, tdwarf_frame_t *frame,
                                              uint64_t load_address)
{
    Dwarf_Error error;
    Dwarf_Die child_die = NULL;
    Dwarf_Die sibling_die;
    Dwarf_Half tag;
    int res;
    uint64_t target_pc;
    
    /* Adjust PC for non-PIE vs PIE */
    target_pc = frame->pc;
    if (load_address > 0) {
        /* PIE: PC is already absolute, need to convert to relative */
        target_pc = frame->pc - load_address;
    }
    
    res = dwarf_child(cu_die, &child_die, &error);
    if (res != DW_DLV_OK) {
        return;
    }
    
    while (1) {
        res = dwarf_tag(child_die, &tag, &error);
        if (res == DW_DLV_OK && tag == DW_TAG_subprogram) {
            uint64_t low_pc, high_pc;
            char func_name[256] = {0};
            
            get_die_name(dbg, child_die, func_name, sizeof(func_name));
            
            if (get_function_range(dbg, child_die, &low_pc, &high_pc) == 0) {
                /* Check if target PC is within this function */
                if (target_pc >= low_pc && target_pc < high_pc) {
                    strncpy(frame->function_name, func_name, sizeof(frame->function_name) - 1);
                    DEBUG_PRINT("Found function: %s (0x%lX - 0x%lX) for PC 0x%lX",
                               func_name, (unsigned long)low_pc, (unsigned long)high_pc,
                               (unsigned long)frame->pc);
                    
                    /* Collect local variables */
                    collect_local_vars_from_function(ctx, dbg, child_die, frame);
                    
                    dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
                    return;
                }
            }
        }
        
        res = dwarf_siblingof(dbg, child_die, &sibling_die, &error);
        dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
        if (res != DW_DLV_OK) {
            break;
        }
        child_die = sibling_die;
    }
}

/*
 * Recursively collect global variables from DIE tree
 */
static void collect_variables_recursive(tdwarf_context_t *ctx, Dwarf_Debug dbg, Dwarf_Die die)
{
    Dwarf_Error error;
    Dwarf_Die child_die = NULL;
    Dwarf_Die sibling_die = NULL;
    Dwarf_Half tag;
    int res;
    
    res = dwarf_tag(die, &tag, &error);
    if (res != DW_DLV_OK) {
        return;
    }
    
    if (tag == DW_TAG_variable) {
        process_global_variable(ctx, dbg, die);
    }
    
    res = dwarf_child(die, &child_die, &error);
    while (res == DW_DLV_OK) {
        collect_variables_recursive(ctx, dbg, child_die);
        
        res = dwarf_siblingof(dbg, child_die, &sibling_die, &error);
        dwarf_dealloc(dbg, child_die, DW_DLA_DIE);
        child_die = sibling_die;
    }
}

/*
 * Collect all global variables and resolve local variables per frame
 */
static void collect_all_variables(tdwarf_context_t *ctx)
{
    tdwarf_internal_t *internal = (tdwarf_internal_t*)ctx->dwarf_handle;
    Dwarf_Debug dbg;
    Dwarf_Error error;
    Dwarf_Unsigned cu_header_length, abbrev_offset, next_cu_header;
    Dwarf_Half version_stamp, address_size;
    Dwarf_Die cu_die = NULL;
    int res;
    int cu_count = 0;
    int frame_idx;
    
    if (!internal || !internal->dbg) {
        DEBUG_PRINT("No DWARF debug handle");
        return;
    }
    
    dbg = internal->dbg;
    DEBUG_PRINT("Starting to collect variables...");
    DEBUG_PRINT("is_pie=%d, load_address=0x%lX", internal->is_pie, (unsigned long)internal->load_address);
    
    /* First pass: collect global variables */
    while (1) {
        res = dwarf_next_cu_header(dbg, &cu_header_length, &version_stamp,
                                   &abbrev_offset, &address_size,
                                   &next_cu_header, &error);
        if (res != DW_DLV_OK) {
            DEBUG_PRINT("dwarf_next_cu_header returned %d after %d CUs", res, cu_count);
            break;
        }
        
        cu_count++;
        DEBUG_PRINT("Processing CU #%d (DWARF version %d, addr_size %d)", 
                    cu_count, version_stamp, address_size);
        
        res = dwarf_siblingof(dbg, NULL, &cu_die, &error);
        if (res == DW_DLV_OK) {
            collect_variables_recursive(ctx, dbg, cu_die);
            dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
        }
    }
    
    DEBUG_PRINT("Finished collecting global variables. Found %d.", internal->global_var_count);
    
    /* Reset CU iteration for local variable collection */
    /* Need to re-initialize DWARF to reset CU iteration */
    dwarf_finish(internal->dbg, &error);
    
    res = dwarf_elf_init(internal->elf, DW_DLC_READ, NULL, NULL,
                         &internal->dbg, &internal->error);
    if (res != DW_DLV_OK) {
        DEBUG_PRINT("Failed to reinitialize DWARF for local variable collection");
        return;
    }
    dbg = internal->dbg;
    
    /* Second pass: collect local variables for each stack frame */
    DEBUG_PRINT("Collecting local variables for %d frames...", ctx->frame_count);
    
    for (frame_idx = 0; frame_idx < ctx->frame_count; frame_idx++) {
        tdwarf_frame_t *frame = &ctx->frames[frame_idx];
        
        DEBUG_PRINT("Frame #%d: PC=0x%lX, BP=0x%lX, SP=0x%lX",
                   frame_idx, (unsigned long)frame->pc, 
                   (unsigned long)frame->bp, (unsigned long)frame->sp);
        
        /* Skip if BP is invalid */
        if (frame->bp == 0 || frame->bp == 0xFFFFFFFF || 
            frame->bp == 0xFFFFFFFFFFFFFFFFULL) {
            DEBUG_PRINT("  Skipping frame: invalid BP");
            continue;
        }
        
        /* Reset CU iteration for this frame */
        dwarf_finish(dbg, &error);
        res = dwarf_elf_init(internal->elf, DW_DLC_READ, NULL, NULL,
                             &internal->dbg, &internal->error);
        if (res != DW_DLV_OK) {
            continue;
        }
        dbg = internal->dbg;
        
        /* Iterate through CUs to find the function containing this PC */
        while (1) {
            res = dwarf_next_cu_header(dbg, &cu_header_length, &version_stamp,
                                       &abbrev_offset, &address_size,
                                       &next_cu_header, &error);
            if (res != DW_DLV_OK) {
                break;
            }
            
            res = dwarf_siblingof(dbg, NULL, &cu_die, &error);
            if (res == DW_DLV_OK) {
                find_function_and_collect_locals(ctx, dbg, cu_die, frame, internal->load_address);
                dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
                
                /* If we found variables, we're done with this frame */
                if (frame->var_count > 0 || frame->function_name[0]) {
                    break;
                }
            }
        }
        
        DEBUG_PRINT("Frame #%d: Found %d local variables in %s",
                   frame_idx, frame->var_count, 
                   frame->function_name[0] ? frame->function_name : "<unknown>");
    }
}

/*
 * Stack unwinding
 */
tdwarf_error_t tdwarf_unwind_stack(tdwarf_context_t *ctx)
{
    if (!ctx) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    ctx->frame_count = 0;

    if (ctx->target_pid == getpid()) {
        if ( self_backtrace(ctx) != TDWARF_OK) {
            DEBUG_PRINT("Self backtrace failed");
            return TDWARF_ERR_INTERNAL;
        }
        return TDWARF_OK;
    } else {
        if ( backtrace_with_ptrace(ctx) != TDWARF_OK ) {
            return TDWARF_ERR_INTERNAL;
        }
    }
    
    DEBUG_PRINT("Stack unwinding complete: %d frames", ctx->frame_count);
    
    /* Now collect all variables (global + local per frame) */
    collect_all_variables(ctx);
    
    return TDWARF_OK;
}

tdwarf_error_t tdwarf_resolve_variables(tdwarf_context_t *ctx, int frame_index)
{
    if (!ctx || frame_index < 0 || frame_index >= ctx->frame_count) {
        return TDWARF_ERR_INVALID_ARG;
    }
    return TDWARF_OK;
}

/*
 * Format hex string
 */
int tdwarf_format_hex(const uint8_t *data, size_t len,
                      char *buf, size_t buf_size,
                      int uppercase)
{
    const char *fmt = uppercase ? "%02X" : "%02x";
    size_t pos = 0;
    size_t i;
    
    if (!data || !buf || buf_size < 3) {
        return -1;
    }
    
    for (i = 0; i < len && pos + 3 < buf_size; i++) {
        pos += snprintf(buf + pos, buf_size - pos, fmt, data[i]);
        if (i < len - 1 && pos + 2 < buf_size) {
            buf[pos++] = ' ';
        }
    }
    
    return (int)pos;
}

/*
 * Format value based on type
 */
static void format_value_by_type(const tdwarf_var_t *var, char *buf, size_t buf_size)
{
    if (var->data_len == 0) {
        snprintf(buf, buf_size, "<unavailable>");
        return;
    }
    
    /* Check for string type */
    if (strstr(var->type_name, "char") && var->size > 1) {
        size_t len = var->data_len;
        size_t str_len = strnlen((char*)var->data, len);
        if (str_len > 60) str_len = 60;
        snprintf(buf, buf_size, "\"%.*s\"%s", (int)str_len, (char*)var->data,
                 (str_len < len && var->data[str_len] != '\0') ? "..." : "");
        return;
    }
    
    switch (var->type_kind) {
        case TDWARF_TYPE_INT:
            if (var->size == 1) {
                snprintf(buf, buf_size, "%d (0x%02X)", 
                         (int)read_int8(var->data), var->data[0]);
            } else if (var->size == 2) {
                snprintf(buf, buf_size, "%d (0x%04X)", 
                         (int)read_int16(var->data), read_uint16(var->data));
            } else if (var->size == 4) {
                snprintf(buf, buf_size, "%d (0x%08X)", 
                         read_int32(var->data), read_uint32(var->data));
            } else if (var->size == 8) {
                snprintf(buf, buf_size, "%ld (0x%016lX)", 
                         (long)read_int64(var->data), (unsigned long)read_uint64(var->data));
            } else {
                char hex[128];
                size_t len = (var->data_len > 32) ? 32 : var->data_len;
                tdwarf_format_hex(var->data, len, hex, sizeof(hex), 1);
                snprintf(buf, buf_size, "%s", hex);
            }
            break;
            
        case TDWARF_TYPE_UINT:
            if (var->size == 1) {
                snprintf(buf, buf_size, "%u (0x%02X)", var->data[0], var->data[0]);
            } else if (var->size == 2) {
                snprintf(buf, buf_size, "%u (0x%04X)", 
                         read_uint16(var->data), read_uint16(var->data));
            } else if (var->size == 4) {
                snprintf(buf, buf_size, "%u (0x%08X)", 
                         read_uint32(var->data), read_uint32(var->data));
            } else if (var->size == 8) {
                snprintf(buf, buf_size, "%lu (0x%016lX)", 
                         (unsigned long)read_uint64(var->data), (unsigned long)read_uint64(var->data));
            } else {
                char hex[128];
                size_t len = (var->data_len > 32) ? 32 : var->data_len;
                tdwarf_format_hex(var->data, len, hex, sizeof(hex), 1);
                snprintf(buf, buf_size, "%s", hex);
            }
            break;
            
        case TDWARF_TYPE_FLOAT:
            if (var->size == 4) {
                snprintf(buf, buf_size, "%f", read_float(var->data));
            } else {
                snprintf(buf, buf_size, "%f", read_double(var->data));
            }
            break;
            
        case TDWARF_TYPE_DOUBLE:
            snprintf(buf, buf_size, "%f", read_double(var->data));
            break;
            
        case TDWARF_TYPE_POINTER:
            snprintf(buf, buf_size, "0x%016lX", (unsigned long)read_uint64(var->data));
            break;
            
        case TDWARF_TYPE_CHAR:
            if (var->size == 1) {
                char c = var->data[0];
                if (isprint(c)) {
                    snprintf(buf, buf_size, "'%c' (0x%02X)", c, (unsigned char)c);
                } else {
                    snprintf(buf, buf_size, "0x%02X", (unsigned char)c);
                }
            } else {
                size_t len = var->data_len;
                if (len > 64) len = 64;
                snprintf(buf, buf_size, "\"%.*s\"", (int)len, (char*)var->data);
            }
            break;
            
        default:
            {
                char hex[256];
                size_t len = (var->data_len > 64) ? 64 : var->data_len;
                tdwarf_format_hex(var->data, len, hex, sizeof(hex), 1);
                if (var->data_len > 64) {
                    snprintf(buf, buf_size, "%s ...", hex);
                } else {
                    snprintf(buf, buf_size, "%s", hex);
                }
            }
            break;
    }
}

/*
 * Dump to stream
 */
tdwarf_error_t tdwarf_dump_to_stream(tdwarf_context_t *ctx,
                                      FILE *stream,
                                      const tdwarf_config_t *config)
{
    tdwarf_internal_t *internal;
    tdwarf_config_t cfg;
    time_t now;
    char time_str[64];
    char value_buf[512];
    char hex_buf[TDWARF_MAX_DUMP_SIZE * 3 + 1];
    int i, j;
    
    if (!ctx || !stream) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    internal = (tdwarf_internal_t*)ctx->dwarf_handle;
    
    if (config) {
        cfg = *config;
    } else {
        tdwarf_config_default(&cfg);
    }
    
    now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(stream, "================================================================================\n");
    fprintf(stream, "TDWARF Memory Dump Report\n");
    fprintf(stream, "================================================================================\n");
    fprintf(stream, "Timestamp:   %s\n", time_str);
    fprintf(stream, "Process ID:  %d\n", ctx->target_pid);
    fprintf(stream, "Executable:  %s\n", ctx->executable_path);
    if (ctx->signal_number > 0) {
        fprintf(stream, "Signal:      %d (%s)\n", ctx->signal_number, 
                strsignal(ctx->signal_number));
    }
    if (internal) {
        fprintf(stream, "PIE:         %s\n", internal->is_pie ? "Yes" : "No");
        fprintf(stream, "Load Offset: 0x%016lX\n", (unsigned long)internal->load_address);
    }
    fprintf(stream, "================================================================================\n\n");
    
    /* Global Variables */
    if (cfg.dump_globals && internal && internal->global_var_count > 0) {
        fprintf(stream, "GLOBAL VARIABLES (%d found)\n", internal->global_var_count);
        fprintf(stream, "--------------------------------------------------------------------------------\n");
        fprintf(stream, "%-32s %-24s %-18s %s\n", "Name", "Type", "Address", "Value");
        fprintf(stream, "--------------------------------------------------------------------------------\n");
        
        for (i = 0; i < internal->global_var_count; i++) {
            tdwarf_var_t *var = &internal->global_vars[i];
            
            format_value_by_type(var, value_buf, sizeof(value_buf));
            
            fprintf(stream, "%-32s %-24s 0x%016lX %s\n",
                    var->name,
                    var->type_name[0] ? var->type_name : "<unknown>",
                    (unsigned long)var->address,
                    value_buf);
            
            if (cfg.verbose && var->data_len > 8) {
                size_t k;
                fprintf(stream, "  Hex dump (%zu bytes):\n", var->data_len);
                for (k = 0; k < var->data_len && k < 512; k += 16) {
                    size_t line_len = (var->data_len - k > 16) ? 16 : (var->data_len - k);
                    tdwarf_format_hex(var->data + k, line_len, hex_buf, sizeof(hex_buf), cfg.hex_uppercase);
                    fprintf(stream, "    %04zX: %s\n", k, hex_buf);
                }
            }
        }
        fprintf(stream, "\n");
    } else if (cfg.dump_globals) {
        fprintf(stream, "GLOBAL VARIABLES: None found (check -g compile flag)\n\n");
    }
    
    /* Stack frames with local variables */
    fprintf(stream, "STACK TRACE (%d frames)\n", ctx->frame_count);
    fprintf(stream, "--------------------------------------------------------------------------------\n");
    
    for (i = 0; i < ctx->frame_count; i++) {
        tdwarf_frame_t *frame = &ctx->frames[i];
        
        fprintf(stream, "\nFrame #%d: %s\n", i, 
                frame->function_name[0] ? frame->function_name : "<unknown>");
        fprintf(stream, "  PC: 0x%016lX  SP: 0x%016lX  BP: 0x%016lX\n",
                (unsigned long)frame->pc,
                (unsigned long)frame->sp,
                (unsigned long)frame->bp);
        
        if (cfg.include_source && frame->source_file[0]) {
            fprintf(stream, "  Source: %s:%d\n", 
                    frame->source_file, frame->line_number);
        }
        
        /* Local Variables */
        if (cfg.dump_locals && frame->var_count > 0) {
            fprintf(stream, "\n  LOCAL VARIABLES (%d found):\n", frame->var_count);
            fprintf(stream, "  %-30s %-24s %-18s %s\n",
                    "Name", "Type", "Address", "Value");
            fprintf(stream, "  %s\n", 
                    "----------------------------------------------------------------------------");
            
            for (j = 0; j < frame->var_count; j++) {
                tdwarf_var_t *var = &frame->variables[j];
                
                format_value_by_type(var, value_buf, sizeof(value_buf));
                
                fprintf(stream, "  %-30s %-24s 0x%016lX %s\n",
                        var->name,
                        var->type_name[0] ? var->type_name : "<unknown>",
                        (unsigned long)var->address,
                        value_buf);
                
                /* Hex dump for larger local variables */
                if (cfg.verbose && var->data_len > 8) {
                    size_t k;
                    fprintf(stream, "    Hex dump (%zu bytes):\n", var->data_len);
                    for (k = 0; k < var->data_len && k < 512; k += 16) {
                        size_t line_len = (var->data_len - k > 16) ? 16 : (var->data_len - k);
                        tdwarf_format_hex(var->data + k, line_len, hex_buf, sizeof(hex_buf), cfg.hex_uppercase);
                        fprintf(stream, "      %04zX: %s\n", k, hex_buf);
                    }
                }
            }
        } else if (cfg.dump_locals) {
            fprintf(stream, "\n  LOCAL VARIABLES: None found\n");
        }
    }
    
    fprintf(stream, "\n================================================================================\n");
    fprintf(stream, "End of TDWARF Memory Dump Report\n");
    fprintf(stream, "================================================================================\n");
    
    return TDWARF_OK;
}

tdwarf_error_t tdwarf_dump_to_file(tdwarf_context_t *ctx,
                                    const char *filename,
                                    const tdwarf_config_t *config)
{
    FILE *file;
    tdwarf_error_t err;
    
    if (!ctx || !filename) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    file = fopen(filename, "w");
    if (!file) {
        return TDWARF_ERR_FILE_IO;
    }
    
    err = tdwarf_dump_to_stream(ctx, file, config);
    fclose(file);
    
    return err;
}

/*
 * Signal handler
 */
static void tdwarf_signal_handler(int signum, siginfo_t *info, void *context)
{
    char filename[1024];
    time_t now;
    struct tm *tm_info;
    
    now = time(NULL);
    tm_info = localtime(&now);
    
    snprintf(filename, sizeof(filename), 
             "%s/tdwarf_dump_%d_%04d%02d%02d_%02d%02d%02d.txt",
             g_output_dir,
             getpid(),
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1,
             tm_info->tm_mday,
             tm_info->tm_hour,
             tm_info->tm_min,
             tm_info->tm_sec);
    
    tdwarf_dump_on_signal(signum, filename);
    
    if (g_old_handlers[signum].sa_flags & SA_SIGINFO) {
        if (g_old_handlers[signum].sa_sigaction) {
            g_old_handlers[signum].sa_sigaction(signum, info, context);
        }
    } else {
        if (g_old_handlers[signum].sa_handler != SIG_DFL &&
            g_old_handlers[signum].sa_handler != SIG_IGN) {
            g_old_handlers[signum].sa_handler(signum);
        }
    }
    
    signal(signum, SIG_DFL);
    raise(signum);
}

tdwarf_error_t tdwarf_install_signal_handlers(const char *output_dir)
{
    struct sigaction sa;
    int signals[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };
    int num_signals = sizeof(signals) / sizeof(signals[0]);
    int i;
    
    if (output_dir) {
        strncpy(g_output_dir, output_dir, sizeof(g_output_dir) - 1);
        g_output_dir[sizeof(g_output_dir) - 1] = '\0';
    }
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = tdwarf_signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESETHAND;
    sigemptyset(&sa.sa_mask);
    
    for (i = 0; i < num_signals; i++) {
        if (sigaction(signals[i], &sa, &g_old_handlers[signals[i]]) < 0) {
            return TDWARF_ERR_INTERNAL;
        }
    }
    
    g_handlers_installed = 1;
    return TDWARF_OK;
}

void tdwarf_remove_signal_handlers(void)
{
    int signals[] = { SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT };
    int num_signals = sizeof(signals) / sizeof(signals[0]);
    int i;
    
    if (!g_handlers_installed) {
        return;
    }
    
    for (i = 0; i < num_signals; i++) {
        sigaction(signals[i], &g_old_handlers[signals[i]], NULL);
    }
    
    g_handlers_installed = 0;
}

tdwarf_error_t tdwarf_dump_on_signal(int signum, const char *output_path)
{
    FILE *file;
    time_t now;
    char time_str[64];
    char line[512];
    
    if (!output_path) {
        return TDWARF_ERR_INVALID_ARG;
    }
    
    file = fopen(output_path, "w");
    if (!file) {
        return TDWARF_ERR_FILE_IO;
    }
    
    now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(file, "================================================================================\n");
    fprintf(file, "TDWARF Signal Dump Report\n");
    fprintf(file, "================================================================================\n");
    fprintf(file, "Timestamp:   %s\n", time_str);
    fprintf(file, "Process ID:  %d\n", getpid());
    fprintf(file, "Signal:      %d (%s)\n", signum, strsignal(signum));
    fprintf(file, "================================================================================\n\n");
    
    fprintf(file, "Memory Maps:\n");
    fprintf(file, "--------------------------------------------------------------------------------\n");
    
    {
        FILE *maps = fopen("/proc/self/maps", "r");
        if (maps) {
            while (fgets(line, sizeof(line), maps)) {
                fprintf(file, "%s", line);
            }
            fclose(maps);
        }
    }
    
    fprintf(file, "\n================================================================================\n");
    fprintf(file, "End of Signal Dump Report\n");
    fprintf(file, "================================================================================\n");
    
    fclose(file);
    
    return TDWARF_OK;
}
