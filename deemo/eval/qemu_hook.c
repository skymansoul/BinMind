// QEMU user-mode LD_PRELOAD hook — 拦截堆分配和内存写入函数
// 编译: gcc -shared -fPIC -o libbintrace.so qemu_hook.c -ldl
// 使用: QEMU_LD_PRELOAD=./libbintrace.so qemu-x86_64 ./target_binary
//
// 输出格式 (BINMIND_TRACE):
//   ALLOC|malloc|size|ptr|counter
//   ALLOC|calloc|total_size|ptr|counter
//   ALLOC|realloc|size|new_ptr|counter|old=old_ptr
//   WRITE|memcpy|dst|src|n|counter
//   WRITE|memset|dst|fill_val|n|counter
//   WRITE|strcpy|dst|src|n|counter

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static FILE *trace_fp = NULL;
static int trace_counter = 0;

__attribute__((constructor))
static void trace_init(void) {
    const char *path = getenv("BINMIND_TRACE_FILE");
    if (!path) path = "/tmp/binmind_trace.log";
    trace_fp = fopen(path, "w");
    if (!trace_fp) trace_fp = stderr;
}

__attribute__((destructor))
static void trace_fini(void) {
    if (trace_fp && trace_fp != stderr) fclose(trace_fp);
}

void *malloc(size_t size) {
    static void *(*real_malloc)(size_t) = NULL;
    if (!real_malloc) real_malloc = dlsym(RTLD_NEXT, "malloc");
    void *ptr = real_malloc(size);
    if (trace_fp) {
        fprintf(trace_fp, "ALLOC|malloc|%zu|%p|%d\n", size, ptr, ++trace_counter);
        fflush(trace_fp);
    }
    return ptr;
}

void *calloc(size_t nmemb, size_t size) {
    static void *(*real_calloc)(size_t, size_t) = NULL;
    if (!real_calloc) real_calloc = dlsym(RTLD_NEXT, "calloc");
    void *ptr = real_calloc(nmemb, size);
    if (trace_fp) {
        fprintf(trace_fp, "ALLOC|calloc|%zu|%p|%d\n", nmemb * size, ptr, ++trace_counter);
        fflush(trace_fp);
    }
    return ptr;
}

void *realloc(void *ptr, size_t size) {
    static void *(*real_realloc)(void *, size_t) = NULL;
    if (!real_realloc) real_realloc = dlsym(RTLD_NEXT, "realloc");
    void *new_ptr = real_realloc(ptr, size);
    if (trace_fp) {
        fprintf(trace_fp, "ALLOC|realloc|%zu|%p|%d|old=%p\n",
                size, new_ptr, ++trace_counter, ptr);
        fflush(trace_fp);
    }
    return new_ptr;
}

void *memcpy(void *dst, const void *src, size_t n) {
    static void *(*real_memcpy)(void *, const void *, size_t) = NULL;
    if (!real_memcpy) real_memcpy = dlsym(RTLD_NEXT, "memcpy");
    if (trace_fp) {
        fprintf(trace_fp, "WRITE|memcpy|%p|%p|%zu|%d\n", dst, src, n, ++trace_counter);
        fflush(trace_fp);
    }
    return real_memcpy(dst, src, n);
}

void *memset(void *s, int c, size_t n) {
    static void *(*real_memset)(void *, int, size_t) = NULL;
    if (!real_memset) real_memset = dlsym(RTLD_NEXT, "memset");
    if (trace_fp) {
        fprintf(trace_fp, "WRITE|memset|%p|%d|%zu|%d\n", s, c, n, ++trace_counter);
        fflush(trace_fp);
    }
    return real_memset(s, c, n);
}

char *strcpy(char *dst, const char *src) {
    static char *(*real_strcpy)(char *, const char *) = NULL;
    if (!real_strcpy) real_strcpy = dlsym(RTLD_NEXT, "strcpy");
    size_t n = strlen(src) + 1;
    if (trace_fp) {
        fprintf(trace_fp, "WRITE|strcpy|%p|%p|%zu|%d\n", dst, src, n, ++trace_counter);
        fflush(trace_fp);
    }
    return real_strcpy(dst, src);
}
