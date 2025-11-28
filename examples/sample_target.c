/*
 * sample_target.c - 메모리 덤프 테스트용 샘플 프로그램
 * 
 * 컴파일: gcc -g -O0 sample_target.c -o sample_target
 * 실행: ./sample_target &
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

/* 전역 변수들 */
int g_counter = 12345;
double g_pi = 3.14159265358979;
char g_message[64] = "Hello, TDWARF Memory Dump!";
int g_array[10] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};

/* 구조체 정의 */
struct Person {
    int id;
    char name[32];
    int age;
    double salary;
};

struct Company {
    char company_name[64];
    int employee_count;
    struct Person ceo;
    struct Person employees[3];
};

/* 전역 구조체 */
struct Person g_person = {
    .id = 1001,
    .name = "Tanaka Taro",
    .age = 35,
    .salary = 5500000.0
};

struct Company g_company = {
    .company_name = "TechCorp Japan",
    .employee_count = 100,
    .ceo = {
        .id = 1,
        .name = "Yamada Ichiro",
        .age = 55,
        .salary = 15000000.0
    },
    .employees = {
        { .id = 2, .name = "Suzuki Hanako", .age = 28, .salary = 4000000.0 },
        { .id = 3, .name = "Sato Jiro", .age = 32, .salary = 4500000.0 },
        { .id = 4, .name = "Kim Minho", .age = 29, .salary = 4200000.0 }
    }
};

/* 포인터 변수 */
int *g_ptr = NULL;
char *g_str_ptr = NULL;

/* volatile 플래그 */
volatile int g_running = 1;

/* 시그널 핸들러 */
void signal_handler(int signum)
{
    printf("\n[PID %d] Received signal %d, shutting down...\n", getpid(), signum);
    g_running = 0;
}

/* 로컬 변수가 많은 함수 */
void process_data(int iteration)
{
    /* 로컬 변수들 */
    int local_int = iteration * 100;
    double local_double = iteration * 1.5;
    char local_buffer[128];
    int local_array[5] = {1, 2, 3, 4, 5};
    
    struct Person local_person = {
        .id = 9999,
        .name = "Local Person",
        .age = 25,
        .salary = 3000000.0
    };
    
    snprintf(local_buffer, sizeof(local_buffer), 
             "Iteration %d: counter=%d, pi=%.5f", 
             iteration, g_counter, g_pi);
    
    /* 약간의 처리 */
    local_int += local_array[0] + local_array[4];
    local_double *= 2.0;
    local_person.age = iteration % 100;
    
    /* 출력 */
    printf("[PID %d] %s (local_int=%d)\n", getpid(), local_buffer, local_int);
    
    /* 전역 변수 업데이트 */
    g_counter++;
}

/* 메인 함수 */
int main(int argc, char *argv[])
{
    int sleep_sec = 5;
    int iteration = 0;
	char sbuff[1024];
	
	memset(sbuff, 0x00, 1024);
	strcpy(sbuff, "TEST MSG");
    
    /* 힙 할당 */
    g_ptr = (int*)malloc(sizeof(int) * 10);
    g_str_ptr = (char*)malloc(256);
    
    if (g_ptr) {
        for (int i = 0; i < 10; i++) {
            g_ptr[i] = (i + 1) * 111;
        }
    }
    
    if (g_str_ptr) {
        strcpy(g_str_ptr, "This is heap-allocated string data!");
    }
    
    /* 커맨드라인 인수 처리 */
    if (argc > 1) {
        sleep_sec = atoi(argv[1]);
        if (sleep_sec < 1) sleep_sec = 5;
    }
    
    /* 시그널 핸들러 설정 */
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    printf("=========================================\n");
    printf("Sample Target Program Started\n");
    printf("=========================================\n");
    printf("PID: %d\n", getpid());
    printf("Sleep interval: %d seconds\n", sleep_sec);
    printf("-----------------------------------------\n");
    printf("Global Variables:\n");
    printf("  g_counter addr:  %p\n", (void*)&g_counter);
    printf("  g_pi addr:       %p\n", (void*)&g_pi);
    printf("  g_message addr:  %p\n", (void*)g_message);
    printf("  g_array addr:    %p\n", (void*)g_array);
    printf("  g_person addr:   %p\n", (void*)&g_person);
    printf("  g_company addr:  %p\n", (void*)&g_company);
    printf("  g_ptr (heap):    %p\n", (void*)g_ptr);
    printf("  g_str_ptr(heap): %p\n", (void*)g_str_ptr);
    printf("-----------------------------------------\n");
    printf("Press Ctrl+C to stop or use:\n");
    printf("  kill -TERM %d\n", getpid());
    printf("=========================================\n\n");
    
    /* 메인 루프 */
    while (g_running) {
        process_data(iteration);
        iteration++;
        sleep(sleep_sec);
    }
    
    /* 정리 */
    printf("\nCleaning up...\n");
    if (g_ptr) free(g_ptr);
    if (g_str_ptr) free(g_str_ptr);
    
    printf("Goodbye!\n");
    return 0;
}
